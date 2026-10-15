package receiver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
)

// Backoff between EnsureStream's attempts while the Transmitter is
// unreachable or not ready; variables so tests can shorten them.
var (
	ensureRetryMin = time.Second
	ensureRetryMax = 30 * time.Second
)

// ensureLockPoll is how often EnsureStream tries again for the lock
// another instance holds; a variable so tests can shorten it.
var ensureLockPoll = 250 * time.Millisecond

// ensureLockIssuer is the issuer under which EnsureStream records its lock
// in the ReplayStore. A SET's issuer is the Transmitter's https URL, so
// the lock never shares a record with one.
const ensureLockIssuer = "urn:ssfgo:receiver:ensure-stream"

// EnsureStream returns a stream configured as want, reusing the
// Transmitter's existing stream where it can, so a Receiver can call it on
// every start:
//
//   - A stream with want's delivery method — and, for push, its endpoint
//     URL — is reused. If its requested events, description or push
//     authorization_header differ from want's, they are updated (PATCH).
//   - Otherwise a stream is created. If the Transmitter allows one stream
//     per Receiver (409), the streams are listed again: one with want's
//     delivery, which another instance created meanwhile, is reused; if
//     the Receiver has exactly one other, it is replaced (PUT) with want
//     if want.ReplaceOnConflict is set; otherwise the conflict is
//     returned, as the stream may be another application's.
//   - A stream it creates and then refuses — its "aud" does not include
//     Config.Audience, say — is deleted, so a misconfigured Receiver does
//     not leave a stream behind on every start.
//
// Instances of one deployment may call it at the same time, provided they
// share Config.ReplayStore, as instances must: before creating a stream an
// instance claims a lock there, held for one attempt, and lists the
// streams again once it has it. The others wait for the lock, then find
// and reuse the stream, so they share one stream rather than each receive
// every event.
//
// Requested events are compared as a set, ignoring types the Transmitter
// does not support; the authorization_header only when want sets one, as
// a read-only token does not see it. Streams that fail the checks Streams
// applies are never reused.
//
// While the Transmitter is unreachable, overloaded (429, 5xx) or has
// accepted a change without processing it (ErrNotProcessed), EnsureStream
// retries with backoff until ctx is done. Any other error — TLS and
// certificate failures included — is returned at once.
func (r *Receiver) EnsureStream(ctx context.Context, want StreamRequest) (ssf.StreamConfiguration, error) {
	wait := ensureRetryMin
	for {
		c, err := r.ensureStream(ctx, want)
		if err == nil || !retryable(ctx, err) {
			return c, err
		}
		r.cfg.Logger.WarnContext(ctx, "ssf receiver: ensure stream, will retry", "error", err, "wait", wait)
		select {
		case <-ctx.Done():
			return ssf.StreamConfiguration{}, ctx.Err()
		case <-time.After(wait):
		}
		wait = min(2*wait, ensureRetryMax)
	}
}

func (r *Receiver) ensureStream(ctx context.Context, want StreamRequest) (ssf.StreamConfiguration, error) {
	streams, err := r.reusableStreams(ctx)
	if err != nil {
		return ssf.StreamConfiguration{}, err
	}
	wire := r.wire("", want)
	if c, ok := withDelivery(streams, *wire.Delivery); ok {
		return r.reconcile(ctx, c, wire)
	}
	unlock, err := r.lockEnsure(ctx, *wire.Delivery)
	if err != nil {
		return ssf.StreamConfiguration{}, err
	}
	defer unlock()
	// Another instance may have created it while this one waited.
	if streams, err = r.reusableStreams(ctx); err != nil {
		return ssf.StreamConfiguration{}, err
	}
	if c, ok := withDelivery(streams, *wire.Delivery); ok {
		return r.reconcile(ctx, c, wire)
	}
	c, err := r.CreateStream(ctx, want)
	var apiErr *APIError
	switch {
	case errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict:
		return r.resolveConflict(ctx, want, wire, err)
	case err != nil && c.StreamID != "":
		return ssf.StreamConfiguration{}, r.deleteRefused(ctx, c, err)
	}
	return c, err
}

// lockEnsure claims the lock instances creating a stream delivering as
// want take in the ReplayStore, waiting while another holds it, and
// returns the function that releases it. The lock lasts claimLease: far
// longer than one attempt, so that an instance which crashes holding it
// delays the others only that long.
func (r *Receiver) lockEnsure(ctx context.Context, want ssf.Delivery) (func(), error) {
	sum := sha256.Sum256([]byte(strings.Join([]string{r.cfg.Issuer, r.cfg.Audience, string(want.Method), want.EndpointURL}, "\x00")))
	lock := ssf.SET{Issuer: ensureLockIssuer, JWTID: hex.EncodeToString(sum[:])}
	holder := rand.Text()
	for {
		var outcome storage.ClaimOutcome
		err := r.storeCall(ctx, lock, "ClaimSET", func() (err error) {
			outcome, err = r.cfg.ReplayStore.ClaimSET(ctx, lock.Issuer, lock.JWTID, holder, time.Now().Add(claimLease))
			return err
		})
		switch {
		case err != nil:
			return nil, fmt.Errorf("receiver: ensure stream: lock in ReplayStore: %w", err)
		case outcome == storage.ClaimHeld:
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(ensureLockPoll):
			}
			continue
		case outcome != storage.ClaimAcquired:
			return nil, fmt.Errorf("receiver: ensure stream: lock in ReplayStore: unexpected claim outcome %d", outcome)
		}
		return func() {
			ctx := context.WithoutCancel(ctx)
			if err := r.storeCall(ctx, lock, "ReleaseClaim", func() error {
				return r.cfg.ReplayStore.ReleaseClaim(ctx, lock.Issuer, lock.JWTID, holder)
			}); err != nil {
				r.cfg.Logger.WarnContext(ctx, "ssf receiver: ensure stream, release lock", "error", err)
			}
		}, nil
	}
}

// reusableStreams lists the streams that pass Streams' checks.
func (r *Receiver) reusableStreams(ctx context.Context) ([]ssf.StreamConfiguration, error) {
	streams, err := r.Streams(ctx)
	var rejected *StreamsError
	if err != nil && !errors.As(err, &rejected) {
		return nil, err
	}
	return streams, nil
}

// withDelivery returns the first of streams delivering as want does.
func withDelivery(streams []ssf.StreamConfiguration, want ssf.Delivery) (ssf.StreamConfiguration, bool) {
	for _, c := range streams {
		if sameDelivery(c.Delivery, want) {
			return c, true
		}
	}
	return ssf.StreamConfiguration{}, false
}

// resolveConflict handles a Transmitter that allows one stream per
// Receiver refusing to create another, with conflict.
func (r *Receiver) resolveConflict(ctx context.Context, want StreamRequest, wire streamRequestWire, conflict error) (ssf.StreamConfiguration, error) {
	streams, err := r.reusableStreams(ctx)
	if err != nil {
		return ssf.StreamConfiguration{}, conflict
	}
	if c, ok := withDelivery(streams, *wire.Delivery); ok {
		// Another instance created it since the streams were listed.
		return r.reconcile(ctx, c, wire)
	}
	if len(streams) != 1 {
		return ssf.StreamConfiguration{}, conflict
	}
	if !want.ReplaceOnConflict {
		return ssf.StreamConfiguration{}, fmt.Errorf("receiver: the transmitter allows one stream per receiver and stream %s delivers elsewhere; set ReplaceOnConflict to replace it: %w", streams[0].StreamID, conflict)
	}
	r.cfg.Logger.WarnContext(ctx, "ssf receiver: replacing the only stream", "stream_id", streams[0].StreamID, "method", streams[0].Delivery.Method)
	return r.ReplaceStream(ctx, streams[0].StreamID, want)
}

// deleteRefused deletes stream c, just created and refused with err.
func (r *Receiver) deleteRefused(ctx context.Context, c ssf.StreamConfiguration, err error) error {
	if derr := r.DeleteStream(context.WithoutCancel(ctx), c.StreamID); derr != nil {
		return fmt.Errorf("%w; deleting the stream also failed: %w", err, derr)
	}
	return fmt.Errorf("%w; the stream was deleted", err)
}

// sameDelivery reports whether an existing stream's delivery is the one
// wanted: the same method and, for push, the same endpoint. A poll stream's
// endpoint is the Transmitter's to choose.
func sameDelivery(have, want ssf.Delivery) bool {
	if have.Method != want.Method {
		return false
	}
	return want.Method != ssf.DeliveryPush || have.EndpointURL == want.EndpointURL
}

// reconcile updates whichever of c's Receiver-supplied properties differ
// from want, returning c unchanged if none do.
func (r *Receiver) reconcile(ctx context.Context, c ssf.StreamConfiguration, want streamRequestWire) (ssf.StreamConfiguration, error) {
	var update StreamUpdate
	changed := false
	events := want.EventsRequested
	if len(c.EventsSupported) > 0 {
		events = slices.DeleteFunc(slices.Clone(events), func(t ssf.EventType) bool { return !slices.Contains(c.EventsSupported, t) })
	}
	if !sameSet(events, c.EventsRequested) {
		update.EventsRequested = &want.EventsRequested
		changed = true
	}
	if want.Description != c.Description {
		update.Description = &want.Description
		changed = true
	}
	if !want.Delivery.AuthorizationHeader.IsZero() && want.Delivery.AuthorizationHeader != c.Delivery.AuthorizationHeader {
		update.Delivery = want.Delivery
		changed = true
	}
	if !changed {
		return c, nil
	}
	return r.UpdateStream(ctx, c.StreamID, update)
}

func sameSet(a, b []ssf.EventType) bool {
	return len(a) == len(b) && !slices.ContainsFunc(a, func(t ssf.EventType) bool { return !slices.Contains(b, t) })
}

// retryable reports whether err may clear if the request is repeated:
// the Transmitter unreachable, overloaded, or not done processing.
func retryable(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	if errors.Is(err, ErrNotProcessed) {
		return true
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500
	}
	if tlsFailure(err) {
		return false
	}
	// Only connection-level failures: net/http also reports refused
	// redirects as a *url.Error, and those will not clear by waiting.
	var opErr *net.OpError
	var dnsErr *net.DNSError
	var urlErr *url.Error
	return errors.As(err, &opErr) || errors.As(err, &dnsErr) ||
		(errors.As(err, &urlErr) && urlErr.Timeout()) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// tlsFailure reports whether err is a TLS handshake or certificate
// failure, which waiting will not clear: a TLS alert — the Transmitter
// requiring a client certificate, say — arrives as a *net.OpError, so it
// is told apart from a connection failure by the alert's operation.
func tlsFailure(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) && (opErr.Op == "remote error" || opErr.Op == "local error") {
		return true
	}
	var alert tls.AlertError
	var verify *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	var unknownCA x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &alert) || errors.As(err, &verify) || errors.As(err, &record) ||
		errors.As(err, &unknownCA) || errors.As(err, &hostname) || errors.As(err, &invalid)
}
