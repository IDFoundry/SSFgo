package transmitter

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
)

// Hooks are callbacks that observe a Transmitter, to feed metrics or
// traces. Each is optional. They run synchronously on the Transmitter's
// goroutines — a request's, Run's — after the change they report is
// complete, so they must not block. A hook must not panic either; if one
// does, the panic is recovered and logged, so a bug in a hook cannot take
// down the process or leave a stream undelivered. Fields marked untrusted
// carry text from a Receiver: log them, never use them as a metric label
// or return them to anyone.
type Hooks struct {
	// Emit is called after every Emit or EmitTxn that got past its checks.
	Emit func(ctx context.Context, info EmitInfo)
	// Push is called after every push delivery attempt, and when a SET is
	// dropped without one.
	Push func(ctx context.Context, info PushInfo)
	// Poll is called after every poll request a Receiver makes that
	// reaches its stream.
	Poll func(ctx context.Context, info PollInfo)
	// Stream is called after a stream is created, updated, has its status
	// changed or is deleted.
	Stream func(ctx context.Context, info StreamInfo)
}

// EmitInfo describes one Emit.
type EmitInfo struct {
	// EventType is the emitted event's type.
	EventType ssf.EventType
	// Streams is how many streams were considered, Queued on how many the
	// SET was queued; the others do not deliver its event type, exclude
	// its subject, are disabled, or PermitEvent refused it.
	Streams, Queued int
	// Err is why queuing failed on some stream.
	Err error
}

// PushOutcome is the result of a push delivery attempt.
type PushOutcome int

const (
	// PushDelivered: the Receiver accepted the SET.
	PushDelivered PushOutcome = iota + 1
	// PushRejected: the Receiver rejected the SET for good; it is dropped.
	PushRejected
	// PushRetry: the attempt failed recoverably; the SET is retried.
	PushRetry
	// PushDropped: the SET is dropped after the most attempts allowed.
	PushDropped
)

// String returns the outcome's name, such as "delivered".
func (o PushOutcome) String() string {
	switch o {
	case PushDelivered:
		return "delivered"
	case PushRejected:
		return "rejected"
	case PushRetry:
		return "retry"
	case PushDropped:
		return "dropped"
	default:
		return "unknown"
	}
}

// PushInfo describes one push delivery attempt.
type PushInfo struct {
	// StreamID and JTI identify the stream and the SET.
	StreamID, JTI string
	// Outcome is the attempt's result.
	Outcome PushOutcome
	// Attempt counts the attempts to deliver this SET, from 1.
	Attempt int
	// Duration is how long the attempt took; zero for a SET dropped
	// without one.
	Duration time.Duration
	// Detail is the Receiver's error, or why the attempt failed.
	// Untrusted: mostly the Receiver's own words, cleaned and cut to 512
	// bytes. Outcome is the field for a metric label.
	Detail string
}

// PollInfo describes one poll request served.
type PollInfo struct {
	// StreamID is the stream polled.
	StreamID string
	// Returned is how many SETs the response carried; Acknowledged and
	// Reported how many the Receiver acknowledged or reported errors for.
	Returned, Acknowledged, Reported int
	// Duration includes any time the request was held as a long poll.
	Duration time.Duration
}

// StreamChange is what happened to a stream.
type StreamChange int

const (
	// StreamCreated: a Receiver created the stream.
	StreamCreated StreamChange = iota + 1
	// StreamUpdated: the stream's configuration changed.
	StreamUpdated
	// StreamStatusChanged: the stream's status changed.
	StreamStatusChanged
	// StreamDeleted: the stream was deleted.
	StreamDeleted
)

// String returns the change's name, such as "created".
func (c StreamChange) String() string {
	switch c {
	case StreamCreated:
		return "created"
	case StreamUpdated:
		return "updated"
	case StreamStatusChanged:
		return "status_changed"
	case StreamDeleted:
		return "deleted"
	default:
		return "unknown"
	}
}

// StreamInfo describes a change to a stream.
type StreamInfo struct {
	// StreamID identifies the stream, and ReceiverID the Receiver that
	// owns it.
	StreamID, ReceiverID string
	// Change is what happened.
	Change StreamChange
	// Status is the stream's status after the change.
	Status ssf.StreamStatus
	// ByTransmitter reports a change the Transmitter made — with
	// SetStreamStatus, or on an inactivity timeout — rather than the
	// Receiver.
	ByTransmitter bool
}

func (t *Transmitter) streamChanged(ctx context.Context, s storage.Stream, change StreamChange, byTransmitter bool) {
	if t.cfg.Hooks.Stream != nil {
		t.observe(ctx, "Stream", func() {
			t.cfg.Hooks.Stream(ctx, StreamInfo{StreamID: s.ID, ReceiverID: s.ReceiverID, Change: change, Status: s.Status, ByTransmitter: byTransmitter})
		})
	}
}

// observe calls a hook, recovering and logging a panic: a hook observes
// the Transmitter, and a bug in one must not take down Run's delivery
// goroutines — and with them the process.
func (t *Transmitter) observe(ctx context.Context, hook string, call func()) {
	defer func() {
		if v := recover(); v != nil {
			t.log.ErrorContext(ctx, "ssf transmitter: hook panicked", "hook", hook, "panic", v, "stack", string(debug.Stack()))
		}
	}()
	call()
}

// Ready reports whether the Transmitter's store is reachable. For a
// readiness probe.
func (t *Transmitter) Ready(ctx context.Context) error {
	if _, err := t.cfg.Store.Stream(ctx, ""); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("transmitter: store unavailable: %w", err)
	}
	return nil
}
