// Package storage defines the persistence contracts SSFgo's roles depend
// on. SSFgo ships an in-memory implementation (storage/memstore) and a
// contract test suite (storage/storagetest) that any other implementation
// can run to show it behaves the same way.
package storage

import (
	"context"
	"errors"
	"time"

	ssf "github.com/idfoundry/ssfgo"
)

var (
	// ErrNotFound is returned when the named stream does not exist.
	ErrNotFound = errors.New("storage: not found")
	// ErrExists is returned by CreateStream when the stream ID is taken.
	ErrExists = errors.New("storage: already exists")
	// ErrTooManyStreams is returned by CreateStream when the receiver
	// already owns CreateOptions.MaxStreamsPerReceiver streams.
	ErrTooManyStreams = errors.New("storage: receiver has the maximum number of streams")
	// ErrTooManySubjectRules is returned by SetSubjectRule when a new rule
	// would exceed the limit.
	ErrTooManySubjectRules = errors.New("storage: stream has the maximum number of subject rules")
	// ErrQueueFull is returned by Enqueue when the stream's queue is at
	// the limit.
	ErrQueueFull = errors.New("storage: stream queue is full")
)

// Stream is a Transmitter's record of one event stream. The Transmitter
// derives the SSF stream configuration from it; Issuer and
// events_supported are Transmitter-wide and are not stored per stream.
type Stream struct {
	ID string
	// ReceiverID is the identity that created, and owns, the stream.
	ReceiverID string
	Audience   []string
	Delivery   ssf.Delivery

	EventsRequested []ssf.EventType
	EventsDelivered []ssf.EventType
	Description     string

	Status       ssf.StreamStatus
	StatusReason string
	// StatusSetByTransmitter records that the current status was set by
	// the Transmitter itself (for example an operator disabling an
	// abusive Receiver), so the Receiver may not change it.
	StatusSetByTransmitter bool

	// LastVerificationRequest is when the Receiver last asked for a
	// verification event; zero if never. It enforces
	// min_verification_interval.
	LastVerificationRequest time.Time

	// LastActivity is when the Receiver last did something that restarts
	// the stream's inactivity timeout (SSF 1.0 §8.1.1); zero means none
	// since CreatedAt. It may lag real activity by up to a tenth of the
	// timeout, since it is recorded no more often than that.
	LastActivity time.Time

	CreatedAt time.Time
}

// CreateOptions constrain CreateStream.
type CreateOptions struct {
	// MaxStreamsPerReceiver, if positive, makes CreateStream fail with
	// ErrTooManyStreams when the receiver already owns that many streams.
	// The check and the insert must be atomic.
	MaxStreamsPerReceiver int
}

// QueuedEvent is a signed SET waiting for delivery on a stream.
type QueuedEvent struct {
	// JTI is the SET's "jti", used to acknowledge it.
	JTI string
	// SET is the signed compact serialization.
	SET        string
	EnqueuedAt time.Time
	// Control marks a stream-updated event: it is delivered even while
	// the stream is paused or disabled, because SSF 1.0 §8.1.5 requires
	// the Receiver to be told the stream is stopping.
	Control bool
}

// SubjectRule records a Receiver's request to include (Add Subject) or
// exclude (Remove Subject) a subject from a stream (SSF 1.0 §8.1.3). A
// subject no rule matches follows the Transmitter's default_subjects.
type SubjectRule struct {
	Subject  ssf.Subject
	Included bool
}

// StreamStore persists a Transmitter's streams, their subjects, and the
// SETs queued on them.
//
// Every method is safe for concurrent use. Methods taking a stream ID
// return ErrNotFound if the stream does not exist. Returned values are
// copies: mutating them never changes stored state.
type StreamStore interface {
	// CreateStream stores a new stream.
	CreateStream(ctx context.Context, s Stream, opts CreateOptions) error
	// Stream returns one stream.
	Stream(ctx context.Context, id string) (Stream, error)
	// StreamsForReceiver returns every stream receiverID owns, oldest
	// first. It returns an empty slice, not an error, if there are none.
	StreamsForReceiver(ctx context.Context, receiverID string) ([]Stream, error)
	// AllStreams returns every stream, oldest first. The Transmitter
	// uses it to route emitted events and to find streams with SETs to
	// push.
	AllStreams(ctx context.Context) ([]Stream, error)
	// UpdateStream applies update to the stored stream atomically and
	// returns the result. If update returns an error, nothing is stored
	// and that error is returned unchanged. update must not change the
	// stream's ID.
	UpdateStream(ctx context.Context, id string, update func(*Stream) error) (Stream, error)
	// DeleteStream removes a stream together with its subjects and
	// queued events.
	DeleteStream(ctx context.Context, id string) error

	// SetSubjectRule records rule on a stream, replacing any earlier rule
	// for an equal subject (by ssf.SubjectsEqual) rather than adding a
	// second one. If maxRules is positive and adding a new rule would
	// exceed it, it returns ErrTooManySubjectRules; replacing a rule is
	// always allowed. The check and the write must be atomic.
	SetSubjectRule(ctx context.Context, streamID string, rule SubjectRule, maxRules int) error
	// SubjectRules returns a stream's rules, oldest first. A replaced
	// rule keeps its original position.
	SubjectRules(ctx context.Context, streamID string) ([]SubjectRule, error)

	// Enqueue appends a SET to a stream's delivery queue. If maxQueued is
	// positive and the queue already holds that many SETs, it returns
	// ErrQueueFull. The check and the append must be atomic.
	Enqueue(ctx context.Context, streamID string, e QueuedEvent, maxQueued int) error
	// PendingEvents returns up to max queued SETs, oldest first, without
	// removing them. max <= 0 means no limit. With controlOnly set it
	// returns only Control events.
	PendingEvents(ctx context.Context, streamID string, max int, controlOnly bool) ([]QueuedEvent, error)
	// AckEvents removes the queued SETs with the given JTIs. Unknown JTIs
	// are ignored: a Receiver may acknowledge a SET twice.
	AckEvents(ctx context.Context, streamID string, jtis []string) error
	// PurgeEvents removes every queued SET, for a stream that has been
	// disabled (SSF 1.0 §8.1.2.1).
	PurgeEvents(ctx context.Context, streamID string) error
}
