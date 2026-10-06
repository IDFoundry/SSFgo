package receiver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	ssf "github.com/idfoundry/ssfgo"
)

// Backoff between EnsureStream's attempts while the Transmitter is
// unreachable or not ready; variables so tests can shorten them.
var (
	ensureRetryMin = time.Second
	ensureRetryMax = 30 * time.Second
)

// EnsureStream returns a stream configured as want, reusing the
// Transmitter's existing stream where it can, so a Receiver can call it on
// every start:
//
//   - A stream with want's delivery method — and, for push, its endpoint
//     URL — is reused. If its requested events, description or push
//     authorization_header differ from want's, they are updated (PATCH).
//   - Otherwise a stream is created. If the Transmitter allows one stream
//     per Receiver (409) and the Receiver has exactly one, that stream is
//     replaced (PUT) with want instead.
//
// Requested events are compared as a set, ignoring types the Transmitter
// does not support; the authorization_header only when want sets one, as
// a read-only token does not see it. Streams that fail the checks Streams
// applies are never reused.
//
// While the Transmitter is unreachable, overloaded (429, 5xx) or has
// accepted a change without processing it (ErrNotProcessed), EnsureStream
// retries with backoff until ctx is done. Any other error is returned at
// once.
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
	streams, err := r.Streams(ctx)
	var rejected *StreamsError
	if err != nil && !errors.As(err, &rejected) {
		return ssf.StreamConfiguration{}, err
	}
	wire := r.wire("", want)
	for _, c := range streams {
		if sameDelivery(c.Delivery, *wire.Delivery) {
			return r.reconcile(ctx, c, wire)
		}
	}
	c, err := r.CreateStream(ctx, want)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict && len(streams) == 1 {
		return r.ReplaceStream(ctx, streams[0].StreamID, want)
	}
	return c, err
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
	if want.Delivery.AuthorizationHeader != "" && want.Delivery.AuthorizationHeader != c.Delivery.AuthorizationHeader {
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
	// Only connection-level failures: net/http also reports refused
	// redirects and TLS certificate errors as a *url.Error, and those
	// will not clear by waiting.
	var opErr *net.OpError
	var dnsErr *net.DNSError
	var urlErr *url.Error
	return errors.As(err, &opErr) || errors.As(err, &dnsErr) ||
		(errors.As(err, &urlErr) && urlErr.Timeout()) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
