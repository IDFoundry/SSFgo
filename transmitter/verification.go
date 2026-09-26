package transmitter

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/setcodec"
	"github.com/idfoundry/ssfgo/storage"
)

// requestVerification implements SSF 1.0 §8.1.4.2: it rate-limits the
// request against min_verification_interval, then queues a verification
// SET echoing the Receiver's state.
func (t *Transmitter) requestVerification(w http.ResponseWriter, r *http.Request, rx Receiver) {
	obj, err := readObject(w, r)
	if err != nil {
		t.writeAPIError(w, r, "verification", err)
		return
	}
	id, _, err := member[string](obj, "stream_id")
	if err == nil && id == "" {
		err = badRequest("stream_id is required")
	}
	if err != nil {
		t.writeAPIError(w, r, "verification", err)
		return
	}
	state, _, err := member[string](obj, "state")
	if err != nil {
		t.writeAPIError(w, r, "verification", err)
		return
	}

	now := t.now()
	var wait float64
	s, err := t.updateOwned(r, id, rx, func(s *storage.Stream) error {
		interval := t.cfg.MinVerificationInterval
		if interval > 0 && !s.LastVerificationRequest.IsZero() {
			if elapsed := now.Sub(s.LastVerificationRequest); elapsed < interval {
				wait = (interval - elapsed).Seconds()
				return errTooManyVerifications
			}
		}
		s.LastVerificationRequest = now
		return nil
	})
	if errors.Is(err, errTooManyVerifications) {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait))))
	}
	if err != nil {
		t.writeAPIError(w, r, "verification", err)
		return
	}
	if err := t.emit(r.Context(), s, ssf.OpaqueSubject{ID: s.ID}, ssf.Verification{State: state}); err != nil {
		t.serverError(w, r, "verification", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

var errTooManyVerifications = &apiError{http.StatusTooManyRequests, "too_many_requests", "verification was requested more often than min_verification_interval allows"}

// emit signs one SET for stream s and queues it. A disabled stream drops
// the event (SSF 1.0 §8.1.2.1); a paused one holds it until re-enabled.
func (t *Transmitter) emit(ctx context.Context, s storage.Stream, subject ssf.Subject, event ssf.Event) error {
	if s.Status == ssf.StreamDisabled {
		return nil
	}
	jti := randomID()
	token, err := setcodec.Encode(t.signer, ssf.SET{
		Issuer:   t.cfg.Issuer,
		Audience: s.Audience,
		JWTID:    jti,
		IssuedAt: t.now(),
		Subject:  subject,
		Event:    event,
	})
	if err != nil {
		return fmt.Errorf("sign %s: %w", event.EventType(), err)
	}
	return t.cfg.Store.Enqueue(ctx, s.ID, storage.QueuedEvent{JTI: jti, SET: token, EnqueuedAt: t.now()})
}

// notFoundOr maps storage.ErrNotFound to the API's 404 — the stream can be
// deleted between the ownership check and the store call.
func (t *Transmitter) notFoundOr(err error) error {
	if errors.Is(err, storage.ErrNotFound) {
		return errStreamNotFound
	}
	return err
}
