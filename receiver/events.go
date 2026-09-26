package receiver

import (
	"context"
	"errors"
	"fmt"
	"slices"

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

// Error codes a Receiver reports for a SET it rejects, beyond those
// setcodec produces (RFC 8935 §2.4; SSF 1.0 §8.1.4.1 for invalid_state).
const (
	errCodeAuthenticationFailed = "authentication_failed"
	errCodeInvalidState         = "invalid_state"
)

// rejectedSET is a SET the Receiver refuses: it is reported to the
// Transmitter with code and never handled.
type rejectedSET struct {
	code        string
	description string
}

func (e *rejectedSET) Error() string {
	return "receiver: rejected SET: " + e.code + ": " + e.description
}

// process verifies, de-duplicates and dispatches one SET. It returns the
// SET's jti when known; the error is a *rejectedSET for a SET that must not
// be retried, or any other error for a handler failure that should be.
func (r *Receiver) process(ctx context.Context, token string) (string, error) {
	set, err := r.decode(ctx, token)
	if err != nil {
		return "", err
	}
	if err := r.checkCriticalMembers(set.Subject); err != nil {
		return set.JWTID, err
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
	if _, fetched := r.currentKeys(); r.cfg.Now().Sub(fetched) > r.cfg.KeyMaxAge {
		// On failure the keys already held stay in use, rather than
		// every SET being refused while the JWKS endpoint is down.
		r.maybeRefreshKeys(ctx)
	}
	keys, _ := r.currentKeys()
	opts := setcodec.VerifyOptions{
		Issuer:       r.cfg.Issuer,
		Audience:     r.cfg.Audience,
		Algorithms:   r.cfg.Algorithms,
		Keys:         keys,
		Registry:     r.cfg.Registry,
		Now:          r.cfg.Now,
		MaxClockSkew: r.cfg.MaxClockSkew,

		LegacyEventSubject: r.cfg.AcceptLegacySubjects,
		LegacySubjectType:  r.cfg.AcceptLegacySubjects,
	}
	set, err := setcodec.Decode(token, opts)
	if de, ok := setcodec.IsDecodeError(err); ok && de.Code == setcodec.CodeInvalidKey && r.maybeRefreshKeys(ctx) {
		// Perhaps the Transmitter rotated its keys: try once more.
		opts.Keys, _ = r.currentKeys()
		set, err = setcodec.Decode(token, opts)
	}
	if de, ok := setcodec.IsDecodeError(err); ok {
		return ssf.SET{}, &rejectedSET{code: de.Code, description: de.Err.Error()}
	}
	return set, err
}

// standardSubjectMembers are the complex-subject members SSF 1.0 §3.3
// defines; ssf.ComplexSubject parses each into its own field.
var standardSubjectMembers = []string{"user", "device", "session", "application", "tenant", "org_unit", "group"}

// checkCriticalMembers rejects a SET whose subject carries a member the
// Transmitter declared critical and the Receiver does not process
// (SSF 1.0 §3.6).
func (r *Receiver) checkCriticalMembers(s ssf.Subject) error {
	complexSubject, ok := s.(ssf.ComplexSubject)
	if !ok {
		return nil
	}
	for _, name := range r.metadata.CriticalSubjectMembers {
		if slices.Contains(standardSubjectMembers, name) || slices.Contains(r.cfg.SubjectMembers, name) {
			continue
		}
		if _, present := complexSubject.Additional[name]; present {
			return &rejectedSET{code: setcodec.CodeInvalidRequest,
				description: "the subject has critical member " + name + ", which this Receiver does not process"}
		}
	}
	return nil
}

func (r *Receiver) dispatch(ctx context.Context, set ssf.SET) error {
	if v, ok := set.Event.(ssf.Verification); ok && v.State != "" {
		// A verification the Receiver asked for must echo a state it is
		// still waiting for (SSF 1.0 §8.1.4.1). One without state is
		// Transmitter-initiated and always acceptable (§8.1.4).
		streamID := set.Subject.(ssf.OpaqueSubject).ID
		if !r.takeState(streamID, v.State) {
			return &rejectedSET{code: errCodeInvalidState, description: "the verification state does not match an outstanding request"}
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

// isRejection reports whether err is a *rejectedSET.
func isRejection(err error) (*rejectedSET, bool) {
	var rej *rejectedSET
	return rej, errors.As(err, &rej)
}
