package receiver

import (
	"context"
	"errors"
	"fmt"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/setcodec"
)

// HandlerFunc handles one verified, de-duplicated SET. Returning an error
// leaves the SET unacknowledged, so the Transmitter delivers it again.
type HandlerFunc func(ctx context.Context, set ssf.SET) error

// Handle registers h for one event type, replacing any earlier handler for
// it. SETs of a registered type with no handler are acknowledged and
// otherwise ignored.
func (r *Receiver) Handle(typ ssf.EventType, h HandlerFunc) {
	r.handlersMu.Lock()
	defer r.handlersMu.Unlock()
	r.handlers[typ] = h
}

// On registers a handler for event type E that receives the event already
// typed:
//
//	receiver.On(r, func(ctx context.Context, set ssf.SET, e caep.SessionRevoked) error { ... })
func On[E ssf.Event](r *Receiver, fn func(ctx context.Context, set ssf.SET, event E) error) {
	var zero E
	r.Handle(zero.EventType(), func(ctx context.Context, set ssf.SET) error {
		e, ok := set.Event.(E)
		if !ok {
			return fmt.Errorf("receiver: event is %T, not %T", set.Event, zero)
		}
		return fn(ctx, set, e)
	})
}

// Error codes a Receiver reports for a SET it rejects (RFC 8935 §2.4;
// SSF 1.0 §8.1.4.1 for invalid_state).
const (
	ErrCodeInvalidRequest       = setcodec.CodeInvalidRequest
	ErrCodeInvalidKey           = setcodec.CodeInvalidKey
	ErrCodeInvalidIssuer        = setcodec.CodeInvalidIssuer
	ErrCodeInvalidAudience      = setcodec.CodeInvalidAudience
	ErrCodeAuthenticationFailed = "authentication_failed"
	ErrCodeInvalidState         = "invalid_state"
)

// RejectedSET is a SET the Receiver refuses: it is reported to the
// Transmitter with Code and never handled.
type RejectedSET struct {
	Code        string
	Description string
}

func (e *RejectedSET) Error() string {
	return "receiver: rejected SET: " + e.Code + ": " + e.Description
}

// process verifies, de-duplicates and dispatches one SET. It returns the
// SET's jti when known; the error is a *RejectedSET for a SET that must not
// be retried, or any other error for a handler failure that should be.
func (r *Receiver) process(ctx context.Context, token string) (string, error) {
	set, err := r.decode(ctx, token)
	if err != nil {
		return "", err
	}
	fresh, err := r.cfg.ReplayStore.MarkSET(ctx, set.Issuer, set.JWTID, r.cfg.Now().Add(r.cfg.ReplayWindow))
	if err != nil {
		return set.JWTID, fmt.Errorf("receiver: replay store: %w", err)
	}
	if !fresh {
		// A redelivery (RFC 8935 §2, RFC 8936 §2.4): acknowledge it again
		// without handling it twice.
		return set.JWTID, nil
	}
	if err := r.dispatch(ctx, set); err != nil {
		if ferr := r.cfg.ReplayStore.ForgetSET(ctx, set.Issuer, set.JWTID); ferr != nil {
			r.cfg.Logger.ErrorContext(ctx, "ssf receiver: forget failed SET", "jti", set.JWTID, "error", ferr)
		}
		return set.JWTID, err
	}
	return set.JWTID, nil
}

func (r *Receiver) decode(ctx context.Context, token string) (ssf.SET, error) {
	keys, fetched := r.currentKeys()
	opts := setcodec.VerifyOptions{
		Issuer:       r.cfg.Issuer,
		Audience:     r.cfg.Audience,
		Algorithms:   r.cfg.Algorithms,
		Keys:         keys,
		Registry:     r.cfg.Registry,
		Now:          r.cfg.Now,
		MaxClockSkew: r.cfg.MaxClockSkew,
	}
	set, err := setcodec.Decode(token, opts)
	if de, ok := setcodec.IsDecodeError(err); ok && de.Code == setcodec.CodeInvalidKey &&
		r.cfg.Now().Sub(fetched) > keyRefetchInterval {
		// Perhaps the Transmitter rotated its keys: refetch once.
		if rerr := r.refreshKeys(ctx); rerr == nil {
			opts.Keys, _ = r.currentKeys()
			set, err = setcodec.Decode(token, opts)
		}
	}
	if de, ok := setcodec.IsDecodeError(err); ok {
		return ssf.SET{}, &RejectedSET{Code: de.Code, Description: de.Err.Error()}
	}
	return set, err
}

func (r *Receiver) dispatch(ctx context.Context, set ssf.SET) error {
	if v, ok := set.Event.(ssf.Verification); ok && v.State != "" {
		// A verification the Receiver asked for must echo a state it is
		// still waiting for (SSF 1.0 §8.1.4.1). One without state is
		// Transmitter-initiated and always acceptable (§8.1.4).
		streamID := set.Subject.(ssf.OpaqueSubject).ID
		if !r.takeState(streamID, v.State) {
			return &RejectedSET{Code: ErrCodeInvalidState, Description: "the verification state does not match an outstanding request"}
		}
	}
	r.handlersMu.RLock()
	h := r.handlers[set.Event.EventType()]
	r.handlersMu.RUnlock()
	if h == nil {
		return nil
	}
	return h(ctx, set)
}

// isRejection reports whether err is a *RejectedSET.
func isRejection(err error) (*RejectedSET, bool) {
	var rej *RejectedSET
	return rej, errors.As(err, &rej)
}
