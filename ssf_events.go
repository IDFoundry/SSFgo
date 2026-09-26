package ssf

import "fmt"

// Event types defined by SSF 1.0 itself.
const (
	// VerificationEventType is the verification event (SSF 1.0 §8.1.4.1).
	VerificationEventType EventType = "https://schemas.openid.net/secevent/ssf/event-type/verification"
	// StreamUpdatedEventType is the stream-updated event (SSF 1.0 §8.1.5).
	StreamUpdatedEventType EventType = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
)

// Verification is sent over a stream to confirm it is configured
// correctly (SSF 1.0 §8.1.4.1). Its SET's "sub_id" is an OpaqueSubject
// whose ID is the stream ID.
type Verification struct {
	// State echoes the value the Receiver supplied when it requested
	// verification. It is empty for a verification the Transmitter
	// sends unprompted.
	State string `json:"state,omitempty"`
}

// EventType implements Event.
func (Verification) EventType() EventType { return VerificationEventType }

// Validate implements Event. Every member is optional.
func (Verification) Validate() error { return nil }

// ValidateSubject implements SubjectConstrainedEvent.
func (Verification) ValidateSubject(s Subject) error {
	return requireStreamSubject(VerificationEventType, s)
}

// StreamUpdated tells the Receiver that the Transmitter changed a
// stream's status (SSF 1.0 §8.1.5). Its SET's "sub_id" is an
// OpaqueSubject whose ID is the stream ID.
type StreamUpdated struct {
	Status StreamStatus `json:"status"`
	Reason string       `json:"reason,omitempty"`
}

// EventType implements Event.
func (StreamUpdated) EventType() EventType { return StreamUpdatedEventType }

// Validate implements Event.
func (e StreamUpdated) Validate() error {
	if !e.Status.IsValid() {
		return fmt.Errorf("%w: stream-updated: status %q is not enabled, paused or disabled", ErrInvalidEvent, e.Status)
	}
	return nil
}

// ValidateSubject implements SubjectConstrainedEvent.
func (StreamUpdated) ValidateSubject(s Subject) error {
	return requireStreamSubject(StreamUpdatedEventType, s)
}

func requireStreamSubject(typ EventType, s Subject) error {
	if _, ok := s.(OpaqueSubject); !ok {
		return fmt.Errorf("%w: %s requires an opaque sub_id carrying the stream ID", ErrInvalidEvent, typ)
	}
	return nil
}
