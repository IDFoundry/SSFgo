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
	// ErrReceiverHasStream is returned by CreateStream when
	// CreateOptions.SingleStreamPerReceiver is set and the receiver
	// already owns a stream.
	ErrReceiverHasStream = errors.New("storage: receiver already has a stream")
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

	// LastVerificationRequest is when the Receiver last asked for a
	// verification event; zero if never. It enforces
	// min_verification_interval.
	LastVerificationRequest time.Time

	CreatedAt time.Time
}

// CreateOptions constrain CreateStream.
type CreateOptions struct {
	// SingleStreamPerReceiver makes CreateStream fail with
	// ErrReceiverHasStream if the receiver already owns a stream. The
	// check and the insert must be atomic.
	SingleStreamPerReceiver bool
}

// QueuedEvent is a signed SET waiting for delivery on a stream.
type QueuedEvent struct {
	// JTI is the SET's "jti", used to acknowledge it.
	JTI string
	// SET is the signed compact serialization.
	SET        string
	EnqueuedAt time.Time
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
	// UpdateStream applies update to the stored stream atomically and
	// returns the result. If update returns an error, nothing is stored
	// and that error is returned unchanged. update must not change the
	// stream's ID.
	UpdateStream(ctx context.Context, id string, update func(*Stream) error) (Stream, error)
	// DeleteStream removes a stream together with its subjects and
	// queued events.
	DeleteStream(ctx context.Context, id string) error

	// AddSubject adds s to a stream. Adding a subject already present
	// (by ssf.SubjectsEqual) is not an error and stores no duplicate.
	AddSubject(ctx context.Context, streamID string, s ssf.Subject) error
	// RemoveSubject removes s from a stream. Removing a subject that is
	// not present is not an error.
	RemoveSubject(ctx context.Context, streamID string, s ssf.Subject) error
	// Subjects returns a stream's subjects in the order they were added.
	Subjects(ctx context.Context, streamID string) ([]ssf.Subject, error)

	// Enqueue appends a SET to a stream's delivery queue.
	Enqueue(ctx context.Context, streamID string, e QueuedEvent) error
	// PendingEvents returns up to max queued SETs, oldest first, without
	// removing them. max <= 0 means no limit.
	PendingEvents(ctx context.Context, streamID string, max int) ([]QueuedEvent, error)
}
