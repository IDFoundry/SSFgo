package transmitter

import (
	"context"
	"errors"
	"fmt"
	"slices"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/setcodec"
	"github.com/idfoundry/ssfgo/storage"
)

// ErrUnsupportedEvent is returned by Emit for an event type not listed in
// Config.EventsSupported.
var ErrUnsupportedEvent = errors.New("transmitter: event type is not in EventsSupported")

// Emit signs event about subject and queues it on every stream that should
// receive it: streams that are not disabled, whose events_delivered
// includes the event type, and whose subject rules include subject
// (SSF 1.0 §8.1.3). Each stream gets its own SET, with its own "aud" and
// "jti"; all SETs from one call share a "txn" (SSF 1.0 §4.1.9).
//
// Emit returns once the SETs are queued. Delivery happens through each
// stream's poll endpoint, or through Run for push streams.
func (t *Transmitter) Emit(ctx context.Context, subject ssf.Subject, event ssf.Event) error {
	if err := t.checkEmit(subject, event); err != nil {
		return err
	}
	streams, err := t.cfg.Store.AllStreams(ctx)
	if err != nil {
		return fmt.Errorf("transmitter: emit: %w", err)
	}
	txn := randomID()
	var errs []error
	for _, s := range streams {
		if err := t.emitTo(ctx, s, subject, event, txn); err != nil {
			errs = append(errs, fmt.Errorf("stream %s: %w", s.ID, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("transmitter: emit: %w", err)
	}
	return nil
}

// checkEmit validates an event and its subject before anything is queued.
func (t *Transmitter) checkEmit(subject ssf.Subject, event ssf.Event) error {
	if subject == nil || event == nil {
		return errors.New("transmitter: Emit requires a subject and an event")
	}
	if err := subject.Validate(); err != nil {
		return fmt.Errorf("transmitter: emit: %w", err)
	}
	if err := event.Validate(); err != nil {
		return fmt.Errorf("transmitter: emit: %w", err)
	}
	if c, ok := event.(ssf.SubjectConstrainedEvent); ok {
		if err := c.ValidateSubject(subject); err != nil {
			return fmt.Errorf("transmitter: emit: %w", err)
		}
	}
	if !slices.Contains(t.cfg.EventsSupported, event.EventType()) {
		return fmt.Errorf("%w: %s", ErrUnsupportedEvent, event.EventType())
	}
	if t.cfg.EventValidator != nil {
		if err := t.cfg.EventValidator(subject, event); err != nil {
			return fmt.Errorf("transmitter: emit: %w", err)
		}
	}
	return nil
}

// emitTo queues event on stream s if the stream should get it: not
// disabled, the event type delivered, the subject included, and
// PermitEvent allowing it. A stream deleted meanwhile is skipped.
func (t *Transmitter) emitTo(ctx context.Context, s storage.Stream, subject ssf.Subject, event ssf.Event, txn string) error {
	if s.Status == ssf.StreamDisabled || !slices.Contains(s.EventsDelivered, event.EventType()) {
		return nil
	}
	rules, err := t.cfg.Store.SubjectRules(ctx, s.ID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !t.includes(rules, subject) {
		return nil
	}
	if t.cfg.PermitEvent != nil && !t.cfg.PermitEvent(ctx, s.ReceiverID, subject, event) {
		return nil
	}
	if err := t.enqueue(ctx, s, subject, event, txn, false); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	return nil
}

// includes applies a stream's subject rules to subject: the last rule whose
// subject matches it (SSF 1.0 §8.1.3.1) decides; with none, the
// Transmitter's default_subjects does.
func (t *Transmitter) includes(rules []storage.SubjectRule, subject ssf.Subject) bool {
	included := t.cfg.DefaultSubjects == ssf.DefaultSubjectsAll
	for _, r := range rules {
		if ssf.SubjectsMatch(r.Subject, subject) {
			included = r.Included
		}
	}
	return included
}

// SetStreamStatus changes a stream's status on the Transmitter's own
// initiative — for example an operator pausing a misbehaving Receiver —
// and tells the Receiver with a stream-updated event (SSF 1.0 §8.1.5).
// While a status set this way is paused or disabled, the Receiver cannot
// change it (its status update gets 403, SSF 1.0 §8.1.2.2); setting the
// stream enabled again releases it.
// That event is delivered even though the stream is no longer enabled.
// Disabling a stream first discards everything queued on it. Setting the current
// status again does nothing.
func (t *Transmitter) SetStreamStatus(ctx context.Context, streamID string, status ssf.StreamStatus, reason string) error {
	return t.setStatus(ctx, streamID, status, reason, true)
}

// setStatus changes a stream's status on the Transmitter's initiative and
// announces it. With lock set, a pause or disable holds until the
// Transmitter lifts it.
func (t *Transmitter) setStatus(ctx context.Context, streamID string, status ssf.StreamStatus, reason string, lock bool) error {
	if !status.IsValid() {
		return fmt.Errorf("transmitter: invalid stream status %q", status)
	}
	var previous ssf.StreamStatus
	s, err := t.cfg.Store.UpdateStream(ctx, streamID, func(s *storage.Stream) error {
		previous = s.Status
		s.Status, s.StatusReason = status, reason
		// A locked pause or disable holds until the Transmitter lifts it;
		// re-enabling hands control back to the Receiver.
		s.StatusSetByTransmitter = lock && status != ssf.StreamEnabled
		return nil
	})
	if err != nil {
		return fmt.Errorf("transmitter: set stream status: %w", err)
	}
	if previous == status {
		return nil
	}
	if status == ssf.StreamDisabled {
		if err := t.cfg.Store.PurgeEvents(ctx, streamID); err != nil {
			return fmt.Errorf("transmitter: set stream status: %w", err)
		}
	}
	event := ssf.StreamUpdated{Status: status, Reason: reason}
	if err := t.enqueue(ctx, s, ssf.OpaqueSubject{ID: s.ID}, event, "", true); err != nil {
		return fmt.Errorf("transmitter: set stream status: %w", err)
	}
	return nil
}

// enqueue signs one SET for stream s and queues it. An empty txn gets a
// fresh one. Unless control is set, a disabled stream drops it
// (SSF 1.0 §8.1.2.1).
func (t *Transmitter) enqueue(ctx context.Context, s storage.Stream, subject ssf.Subject, event ssf.Event, txn string, control bool) error {
	if s.Status == ssf.StreamDisabled && !control {
		return nil
	}
	jti := randomID()
	if txn == "" {
		// A SET with no related SETs is its own transaction. Giving it a
		// txn anyway lets a Receiver correlate every SET the same way.
		txn = randomID()
	}
	now := t.now()
	token, err := setcodec.Encode(t.signer, ssf.SET{
		Issuer:        t.cfg.Issuer,
		Audience:      s.Audience,
		JWTID:         jti,
		IssuedAt:      now,
		TransactionID: txn,
		Subject:       subject,
		Event:         event,
	})
	if err != nil {
		return fmt.Errorf("sign %s: %w", event.EventType(), err)
	}
	limit := t.cfg.Limits.QueuedSETsPerStream
	if control {
		limit = 0 // a stream-updated notice must get through
	}
	err = t.cfg.Store.Enqueue(ctx, s.ID, storage.QueuedEvent{JTI: jti, SET: token, EnqueuedAt: now, Control: control}, limit)
	if errors.Is(err, storage.ErrQueueFull) {
		t.log.WarnContext(ctx, "ssf transmitter: dropping SET, the stream's queue is full", "stream_id", s.ID, "event", event.EventType(), "limit", limit)
		return nil
	}
	if err != nil {
		return err
	}
	t.notify.notify(s.ID)
	return nil
}
