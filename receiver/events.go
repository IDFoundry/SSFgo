package receiver

import (
	"context"
	"errors"
	"fmt"
	"slices"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/peertext"
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
// maxRejectionDescription bounds the description of a rejected SET.
const maxRejectionDescription = 256

type rejectedSET struct {
	code        string
	description string
}

func (e *rejectedSET) Error() string {
	return "receiver: rejected SET: " + e.code + ": " + e.description
}

// processed is what process learned of a SET: its jti and event type when
// known, and whether it was a redelivery of one already handled.
type processed struct {
	jti       string
	eventType ssf.EventType
	duplicate bool
}

// processObserved is process, reported to Hooks.SET.
func (r *Receiver) processObserved(ctx context.Context, method ssf.DeliveryMethod, token string) (string, error) {
	start := r.cfg.Now()
	p, err := r.process(ctx, token)
	if r.cfg.Hooks.SET != nil {
		info := SETInfo{Delivery: method, JTI: p.jti, EventType: p.eventType, Duration: r.cfg.Now().Sub(start), Err: err}
		switch rej, ok := isRejection(err); {
		case ok:
			info.Outcome, info.ErrorCode = SETRejected, rej.code
		case err != nil:
			info.Outcome = SETFailed
		case p.duplicate:
			info.Outcome = SETDuplicate
		default:
			info.Outcome = SETHandled
		}
		r.observe(ctx, "SET", func() { r.cfg.Hooks.SET(ctx, info) })
	}
	return p.jti, err
}

// process verifies, de-duplicates and dispatches one SET. The error is a
// *rejectedSET for a SET that must not be retried, or any other error for
// a handler failure that should be.
func (r *Receiver) process(ctx context.Context, token string) (processed, error) {
	set, err := r.decode(ctx, token)
	if err != nil {
		return processed{}, err
	}
	p := processed{jti: set.JWTID, eventType: set.Event.EventType()}
	if err := r.checkCriticalMembers(set.Subject); err != nil {
		return p, err
	}
	// A SET is accepted only within ReplayWindow of its "iat", and its
	// replay record lasts until that window (plus clock skew) ends, so
	// there is no moment at which a captured SET is both acceptable and
	// forgotten.
	expires := set.IssuedAt.Add(r.cfg.ReplayWindow)
	if r.cfg.Now().After(expires) {
		return p, &rejectedSET{code: setcodec.CodeInvalidRequest,
			description: "the SET is older than the Receiver's replay window"}
	}
	// A redelivery that arrives while this Receiver is still handling the
	// first copy waits for that outcome and reports it, as it would have
	// had the SET not been received before (RFC 8935 §2): acknowledging it
	// at once would lose the SET if the handling then failed.
	h, first := r.startHandling(set)
	if !first {
		select {
		case <-h.done:
			p.duplicate = h.err == nil
			return p, h.err
		case <-ctx.Done():
			return p, ctx.Err()
		}
	}
	defer r.finishHandling(set, h)
	fresh, err := r.cfg.ReplayStore.MarkSET(ctx, set.Issuer, set.JWTID, expires.Add(r.cfg.MaxClockSkew))
	if err != nil {
		h.err = fmt.Errorf("receiver: replay store: %w", err)
		return p, h.err
	}
	if !fresh {
		// A redelivery (RFC 8935 §2, RFC 8936 §2.4) of a SET already
		// handled: acknowledge it again without handling it twice.
		h.err = nil
		p.duplicate = true
		return p, nil
	}
	h.err = r.dispatchOrForget(ctx, set)
	return p, h.err
}

// setKey identifies a SET across Transmitters.
type setKey struct{ issuer, jti string }

// errHandlingAborted is what a waiting redelivery reports when the first
// copy's handling ended without an outcome — a handler panic — so that the
// Transmitter retries rather than taking the SET as handled.
var errHandlingAborted = errors.New("receiver: handling of an earlier copy of this SET did not complete")

// handling is one SET being handled; done is closed once err is final.
type handling struct {
	done chan struct{}
	err  error
}

// startHandling registers set as being handled by this Receiver. If another
// copy of it already is, it returns that handling and false instead. Only
// copies reaching the same Receiver value are coordinated; across
// processes the ReplayStore alone de-duplicates.
func (r *Receiver) startHandling(set ssf.SET) (*handling, bool) {
	key := setKey{set.Issuer, set.JWTID}
	r.inflightMu.Lock()
	defer r.inflightMu.Unlock()
	if h, ok := r.inflight[key]; ok {
		return h, false
	}
	h := &handling{done: make(chan struct{}), err: errHandlingAborted}
	r.inflight[key] = h
	return h, true
}

func (r *Receiver) finishHandling(set ssf.SET, h *handling) {
	r.inflightMu.Lock()
	delete(r.inflight, setKey{set.Issuer, set.JWTID})
	r.inflightMu.Unlock()
	close(h.done)
}

// dispatchOrForget runs dispatch and, if it fails or panics, forgets the
// SET so that its redelivery is handled rather than dismissed as a
// duplicate. A panic is re-raised after the record is removed.
func (r *Receiver) dispatchOrForget(ctx context.Context, set ssf.SET) (err error) {
	done := false
	defer func() {
		if done && err == nil {
			return
		}
		if ferr := r.cfg.ReplayStore.ForgetSET(context.WithoutCancel(ctx), set.Issuer, set.JWTID); ferr != nil {
			r.cfg.Logger.ErrorContext(ctx, "ssf receiver: forget failed SET", "jti", set.JWTID, "error", ferr)
		}
	}()
	err = r.dispatch(ctx, set)
	done = true
	return err
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
		// The description quotes the SET's header, which anyone able to
		// push writes: it is logged, returned and reported to hooks.
		return ssf.SET{}, &rejectedSET{code: de.Code, description: peertext.Clean(de.Err.Error(), maxRejectionDescription)}
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
				description: "the subject has critical member " + peertext.Clean(name, maxRejectionDescription) + ", which this Receiver does not process"}
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
