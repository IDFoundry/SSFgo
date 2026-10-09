package ssf

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

// StreamStatus is the status of an event stream (SSF 1.0 §8.1.2).
type StreamStatus string

const (
	// StreamEnabled means the Transmitter transmits events over the
	// stream.
	StreamEnabled StreamStatus = "enabled"
	// StreamPaused means the Transmitter holds events and transmits them
	// once the stream is enabled again.
	StreamPaused StreamStatus = "paused"
	// StreamDisabled means the Transmitter neither transmits nor holds
	// events.
	StreamDisabled StreamStatus = "disabled"
)

// IsValid reports whether s is one of the statuses SSF 1.0 §8.1.2
// defines.
func (s StreamStatus) IsValid() bool {
	switch s {
	case StreamEnabled, StreamPaused, StreamDisabled:
		return true
	default:
		return false
	}
}

// DeliveryMethod identifies how SETs are delivered on a stream
// (SSF 1.0 §6.1).
type DeliveryMethod string

const (
	// DeliveryPush is push-based delivery over HTTP (RFC 8935).
	DeliveryPush DeliveryMethod = "urn:ietf:rfc:8935"
	// DeliveryPoll is poll-based delivery over HTTP (RFC 8936).
	DeliveryPoll DeliveryMethod = "urn:ietf:rfc:8936"
)

// Delivery is a stream's "delivery" member (SSF 1.0 §6.1).
type Delivery struct {
	// Method is the "method" member: DeliveryPush or DeliveryPoll.
	Method DeliveryMethod `json:"method"`
	// EndpointURL is where the Transmitter pushes SETs (push, set by the
	// Receiver) or where the Receiver polls for them (poll, set by the
	// Transmitter).
	EndpointURL string `json:"endpoint_url,omitempty"`
	// AuthorizationHeader is the push-only Authorization header value
	// the Transmitter sends with every push request (SSF 1.0 §6.1.1).
	AuthorizationHeader Secret `json:"authorization_header,omitzero"`
}

// deliveryWire is Delivery as it is sent, its Authorization header
// revealed.
type deliveryWire struct {
	Method              DeliveryMethod `json:"method"`
	EndpointURL         string         `json:"endpoint_url,omitempty"`
	AuthorizationHeader string         `json:"authorization_header,omitempty"`
}

// MarshalJSON implements json.Marshaler. A Delivery's JSON is its wire
// form (SSF 1.0 §6.1), and so includes the Authorization header: it is
// for the protocol and for storage, never for a log.
func (d Delivery) MarshalJSON() ([]byte, error) {
	return json.Marshal(deliveryWire{Method: d.Method, EndpointURL: d.EndpointURL, AuthorizationHeader: d.AuthorizationHeader.Reveal()})
}

// LogValue implements slog.LogValuer: a logged Delivery withholds its
// Authorization header, which a JSON handler would otherwise take from
// MarshalJSON.
func (d Delivery) LogValue() slog.Value {
	attrs := []slog.Attr{slog.String("method", string(d.Method))}
	if d.EndpointURL != "" {
		attrs = append(attrs, slog.String("endpoint_url", d.EndpointURL))
	}
	if !d.AuthorizationHeader.IsZero() {
		attrs = append(attrs, slog.Any("authorization_header", d.AuthorizationHeader))
	}
	return slog.GroupValue(attrs...)
}

// Audience is a JWT "aud" value: one string or an array of strings
// (RFC 7519 §4.1.3). It encodes a single value as a string, and no values
// as an empty array rather than null, so every encoding decodes again.
type Audience []string

// MarshalJSON implements json.Marshaler.
func (a Audience) MarshalJSON() ([]byte, error) {
	switch len(a) {
	case 0:
		return []byte("[]"), nil
	case 1:
		return json.Marshal(a[0])
	default:
		return json.Marshal([]string(a))
	}
}

// UnmarshalJSON implements json.Unmarshaler.
func (a *Audience) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil && string(data) != "null" {
		*a = Audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil || many == nil {
		return fmt.Errorf("ssf: aud must be a string or an array of strings")
	}
	*a = many
	return nil
}

// StreamConfiguration is an event stream's configuration (SSF 1.0 §8.1.1),
// as the Transmitter returns it.
type StreamConfiguration struct {
	// StreamID is the "stream_id" the Transmitter assigned.
	StreamID string `json:"stream_id"`
	// Issuer is the Transmitter's issuer identifier, the "iss" of the
	// stream's SETs.
	Issuer string `json:"iss"`
	// Audience is the "aud" of the stream's SETs.
	Audience Audience `json:"aud"`
	// EventsSupported are the event types the Transmitter supports.
	EventsSupported []EventType `json:"events_supported,omitempty"`
	// EventsRequested are the event types the Receiver asked for.
	EventsRequested []EventType `json:"events_requested,omitempty"`
	// EventsDelivered is always encoded, as an empty array when no
	// event types are delivered.
	EventsDelivered []EventType `json:"events_delivered"`
	// Delivery is how the stream's SETs are delivered.
	Delivery Delivery `json:"delivery"`
	// MinVerificationInterval is in seconds; zero means none.
	MinVerificationInterval int `json:"min_verification_interval,omitempty"`
	// Description is the Receiver's free-text description of the stream;
	// empty if none.
	Description string `json:"description,omitempty"`
	// InactivityTimeout is in seconds; zero means none.
	InactivityTimeout int `json:"inactivity_timeout,omitempty"`
}

// MarshalJSON implements json.Marshaler, encoding a nil EventsDelivered as
// an empty array because the member is required.
func (c StreamConfiguration) MarshalJSON() ([]byte, error) {
	type plain StreamConfiguration
	if c.EventsDelivered == nil {
		c.EventsDelivered = []EventType{}
	}
	return json.Marshal(plain(c))
}

// LogValue implements slog.LogValuer: a logged StreamConfiguration
// withholds its delivery's Authorization header.
func (c StreamConfiguration) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("stream_id", c.StreamID),
		slog.String("iss", c.Issuer),
		slog.Any("aud", []string(c.Audience)),
		slog.Any("events_requested", c.EventsRequested),
		slog.Any("events_delivered", c.EventsDelivered),
		slog.Any("delivery", c.Delivery.LogValue()),
	}
	if c.Description != "" {
		attrs = append(attrs, slog.String("description", c.Description))
	}
	return slog.GroupValue(attrs...)
}

// StreamState is a stream's status as read from, or written to, the
// Status Endpoint (SSF 1.0 §8.1.2).
type StreamState struct {
	// StreamID is the stream's "stream_id".
	StreamID string `json:"stream_id"`
	// Status is the stream's status: enabled, paused or disabled.
	Status StreamStatus `json:"status"`
	// Reason is free text explaining the status; empty if none given.
	Reason string `json:"reason,omitempty"`
}

// AddSubjectRequest is the body of an Add Subject request
// (SSF 1.0 §8.1.3.2).
type AddSubjectRequest struct {
	// StreamID is the stream to add the subject to. Required.
	StreamID string
	// Subject is the subject to add. Required.
	Subject Subject
	// Verified is nil when the Receiver did not say; the Transmitter
	// should then assume the subject was verified.
	Verified *bool
}

// RemoveSubjectRequest is the body of a Remove Subject request
// (SSF 1.0 §8.1.3.3).
type RemoveSubjectRequest struct {
	// StreamID is the stream to remove the subject from. Required.
	StreamID string
	// Subject is the subject to remove. Required.
	Subject Subject
}

type subjectRequestWire struct {
	StreamID string          `json:"stream_id"`
	Subject  json.RawMessage `json:"subject"`
	Verified *bool           `json:"verified,omitempty"`
}

// MarshalJSON implements json.Marshaler.
func (r AddSubjectRequest) MarshalJSON() ([]byte, error) {
	return marshalSubjectRequest(r.StreamID, r.Subject, r.Verified)
}

// UnmarshalJSON implements json.Unmarshaler.
func (r *AddSubjectRequest) UnmarshalJSON(data []byte) error {
	id, s, verified, err := unmarshalSubjectRequest(data)
	if err != nil {
		return err
	}
	*r = AddSubjectRequest{StreamID: id, Subject: s, Verified: verified}
	return nil
}

// MarshalJSON implements json.Marshaler.
func (r RemoveSubjectRequest) MarshalJSON() ([]byte, error) {
	return marshalSubjectRequest(r.StreamID, r.Subject, nil)
}

// UnmarshalJSON implements json.Unmarshaler.
func (r *RemoveSubjectRequest) UnmarshalJSON(data []byte) error {
	id, s, _, err := unmarshalSubjectRequest(data)
	if err != nil {
		return err
	}
	*r = RemoveSubjectRequest{StreamID: id, Subject: s}
	return nil
}

func marshalSubjectRequest(streamID string, s Subject, verified *bool) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("ssf: subject is required")
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return json.Marshal(subjectRequestWire{StreamID: streamID, Subject: raw, Verified: verified})
}

func unmarshalSubjectRequest(data []byte) (string, Subject, *bool, error) {
	var w subjectRequestWire
	if err := json.Unmarshal(data, &w); err != nil {
		return "", nil, nil, fmt.Errorf("ssf: malformed subject request: %w", err)
	}
	if w.StreamID == "" {
		return "", nil, nil, fmt.Errorf("ssf: stream_id is required")
	}
	if w.Subject == nil {
		return "", nil, nil, fmt.Errorf("ssf: subject is required")
	}
	s, err := ParseSubject(w.Subject)
	if err != nil {
		return "", nil, nil, err
	}
	return w.StreamID, s, w.Verified, nil
}

// VerificationRequest is the body of a request to the Verification
// Endpoint (SSF 1.0 §8.1.4.2).
type VerificationRequest struct {
	// StreamID is the stream to verify.
	StreamID string `json:"stream_id"`
	// State is an opaque value the Transmitter echoes in the verification
	// event; empty if none.
	State string `json:"state,omitempty"`
}
