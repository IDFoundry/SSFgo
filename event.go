package ssf

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// EventType is an event type URI, the key of a SET's "events" claim
// (RFC 8417 §2.2).
type EventType string

// Event is one event family's typed representation of an event object —
// the value under its EventType in a SET's "events" claim. It does not
// include the subject: SSF 1.0 §3.1 carries the primary subject in the
// SET's top-level "sub_id" claim.
//
// Implementations are value types whose JSON encoding is the event
// object, and whose EventType does not depend on the receiver's value, so
// the zero value reports its type.
type Event interface {
	EventType() EventType
	// Validate reports whether every member the event type requires is
	// present and every member present has a permitted value.
	Validate() error
}

// SubjectConstrainedEvent is implemented by events whose definition
// restricts the SET's "sub_id" — for example SSF's verification event,
// which requires an opaque stream ID.
type SubjectConstrainedEvent interface {
	Event
	ValidateSubject(Subject) error
}

// ErrUnsupportedEventType is returned by Registry.Decode for an event type
// the registry has no decoder for.
var ErrUnsupportedEventType = errors.New("ssf: unsupported event type")

// ErrInvalidEvent is wrapped by every error that reports a malformed
// event object.
var ErrInvalidEvent = errors.New("ssf: invalid event")

type decodeFunc func(json.RawMessage) (Event, error)

// Registry maps event type URIs to decoders. There is no global registry:
// a Receiver is given one, and a Transmitter derives the event types it
// supports from one. NewRegistry returns a registry that already holds
// SSF's own events; event families add theirs with Register — for example
// caep.Register(r) and risc.Register(r).
//
// A Registry is safe for concurrent use.
type Registry struct {
	mu       sync.RWMutex
	decoders map[EventType]decodeFunc
}

// NewRegistry returns a registry holding SSF 1.0's verification and
// stream-updated events.
func NewRegistry() *Registry {
	r := &Registry{decoders: make(map[EventType]decodeFunc)}
	// These cannot fail on a fresh registry.
	_ = Register[Verification](r)
	_ = Register[StreamUpdated](r)
	return r
}

// Register adds event type E to r. E's zero value supplies the event type
// URI. Registering a type twice is an error.
func Register[E Event](r *Registry) error {
	var zero E
	typ := zero.EventType()
	if typ == "" {
		return fmt.Errorf("ssf: register %T: empty event type", zero)
	}
	return r.register(typ, func(raw json.RawMessage) (Event, error) {
		var e E
		if !isJSONObject(raw) {
			return nil, fmt.Errorf("%w: %s: event must be a JSON object", ErrInvalidEvent, typ)
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalidEvent, typ, err)
		}
		if err := e.Validate(); err != nil {
			return nil, err
		}
		return e, nil
	})
}

func (r *Registry) register(typ EventType, decode decodeFunc) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.decoders[typ]; dup {
		return fmt.Errorf("ssf: event type %s is already registered", typ)
	}
	r.decoders[typ] = decode
	return nil
}

// Supports reports whether r has a decoder for typ.
func (r *Registry) Supports(typ EventType) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.decoders[typ]
	return ok
}

// Types returns every registered event type, sorted.
func (r *Registry) Types() []EventType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]EventType, 0, len(r.decoders))
	for t := range r.decoders {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Decode decodes and validates the event object payload as typ. It
// returns an error wrapping ErrUnsupportedEventType if typ is not
// registered.
func (r *Registry) Decode(typ EventType, payload json.RawMessage) (Event, error) {
	r.mu.RLock()
	decode, ok := r.decoders[typ]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedEventType, typ)
	}
	return decode(payload)
}

func isJSONObject(raw json.RawMessage) bool {
	for _, c := range raw {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '{':
			return json.Valid(raw)
		default:
			return false
		}
	}
	return false
}
