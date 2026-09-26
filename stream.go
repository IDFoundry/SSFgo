package ssf

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
