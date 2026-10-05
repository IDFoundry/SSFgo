package scim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	ssf "github.com/idfoundry/ssfgo"
)

// The base URI for SCIM event types (RFC 9967 §7.3).
const eventTypeBase = "urn:ietf:params:scim:event:"

// RFC 9967 event types (§7.4).
const (
	FeedAddEventType       ssf.EventType = eventTypeBase + "feed:add"
	FeedRemoveEventType    ssf.EventType = eventTypeBase + "feed:remove"
	CreateNoticeEventType  ssf.EventType = eventTypeBase + "prov:create:notice"
	CreateFullEventType    ssf.EventType = eventTypeBase + "prov:create:full"
	PatchNoticeEventType   ssf.EventType = eventTypeBase + "prov:patch:notice"
	PatchFullEventType     ssf.EventType = eventTypeBase + "prov:patch:full"
	PutNoticeEventType     ssf.EventType = eventTypeBase + "prov:put:notice"
	PutFullEventType       ssf.EventType = eventTypeBase + "prov:put:full"
	DeleteEventType        ssf.EventType = eventTypeBase + "prov:delete"
	ActivateEventType      ssf.EventType = eventTypeBase + "prov:activate"
	DeactivateEventType    ssf.EventType = eventTypeBase + "prov:deactivate"
	AsyncResponseEventType ssf.EventType = eventTypeBase + "misc:asyncresp"
)

// Register adds every RFC 9967 event type to r.
func Register(r *ssf.Registry) error {
	for _, register := range []func(*ssf.Registry) error{
		ssf.Register[FeedAdd],
		ssf.Register[FeedRemove],
		ssf.Register[CreateNotice],
		ssf.Register[CreateFull],
		ssf.Register[PatchNotice],
		ssf.Register[PatchFull],
		ssf.Register[PutNotice],
		ssf.Register[PutFull],
		ssf.Register[Delete],
		ssf.Register[Activate],
		ssf.Register[Deactivate],
		ssf.Register[AsyncResponse],
	} {
		if err := register(r); err != nil {
			return err
		}
	}
	return nil
}

func invalid(typ ssf.EventType, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %s", ssf.ErrInvalidEvent, typ, fmt.Sprintf(format, args...))
}

// requireSCIMSubject enforces RFC 9967 §2.1: a SCIM event's subject is a
// SCIM resource.
func requireSCIMSubject(typ ssf.EventType, s ssf.Subject) error {
	if _, ok := s.(ssf.SCIMSubject); !ok {
		return invalid(typ, `the subject must be a "scim" subject identifier (RFC 9967 §2.1)`)
	}
	return nil
}

// FeedAdd signals that a resource was added to the event feed — not that
// it is new (RFC 9967 §2.3.1).
type FeedAdd struct{}

// EventType implements ssf.Event.
func (FeedAdd) EventType() ssf.EventType { return FeedAddEventType }

// Validate implements ssf.Event.
func (FeedAdd) Validate() error { return nil }

// ValidateSubject implements ssf.SubjectConstrainedEvent.
func (FeedAdd) ValidateSubject(s ssf.Subject) error { return requireSCIMSubject(FeedAddEventType, s) }

// FeedRemove signals that a resource was removed from the event feed —
// not that it was deleted or deactivated (RFC 9967 §2.3.2).
type FeedRemove struct{}

// EventType implements ssf.Event.
func (FeedRemove) EventType() ssf.EventType { return FeedRemoveEventType }

// Validate implements ssf.Event.
func (FeedRemove) Validate() error { return nil }

// ValidateSubject implements ssf.SubjectConstrainedEvent.
func (FeedRemove) ValidateSubject(s ssf.Subject) error {
	return requireSCIMSubject(FeedRemoveEventType, s)
}

// The provisioning events of RFC 9967 §2.4 carry exactly one of "data"
// (full mode) and "attributes" (notice mode), and optionally "version".

// full is the payload of a provisioning event in full mode.
type full struct {
	Data    json.RawMessage `json:"data"`
	Version string          `json:"version,omitempty"`
}

// notice is the payload of a provisioning event in notice mode.
type notice struct {
	Attributes []string `json:"attributes"`
	Version    string   `json:"version,omitempty"`
}

// decodeFull decodes a full-mode payload, refusing one that also carries
// "attributes".
func decodeFull(typ ssf.EventType, data []byte) (full, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return full{}, err
	}
	if _, ok := obj["attributes"]; ok {
		return full{}, invalid(typ, `a full event carries "data", not "attributes" (RFC 9967 §2.4)`)
	}
	var f full
	if err := json.Unmarshal(data, &f); err != nil {
		return full{}, err
	}
	f.Data = compact(f.Data)
	return f, nil
}

// compact returns raw in its compact form, as encoding/json writes it, so
// a decoded event equals the event re-encoded and decoded again.
func compact(raw json.RawMessage) json.RawMessage {
	var buf bytes.Buffer
	if len(raw) == 0 || json.Compact(&buf, raw) != nil {
		return raw
	}
	return buf.Bytes()
}

// decodeNotice decodes a notice-mode payload, refusing one that also
// carries "data".
func decodeNotice(typ ssf.EventType, data []byte) (notice, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return notice{}, err
	}
	if _, ok := obj["data"]; ok {
		return notice{}, invalid(typ, `a notice event carries "attributes", not "data" (RFC 9967 §2.4)`)
	}
	var n notice
	err := json.Unmarshal(data, &n)
	return n, err
}

func validateFull(typ ssf.EventType, data json.RawMessage) error {
	var obj map[string]json.RawMessage
	if len(data) == 0 || json.Unmarshal(data, &obj) != nil || obj == nil {
		return invalid(typ, `"data" must be a JSON object`)
	}
	return nil
}

func validateNotice(typ ssf.EventType, attributes []string) error {
	if len(attributes) == 0 {
		return invalid(typ, `"attributes" must name at least one attribute`)
	}
	if slices.Contains(attributes, "") {
		return invalid(typ, `"attributes" must not contain an empty name`)
	}
	return nil
}

// CreateFull signals that a SCIM resource was created, carrying its final
// representation, including the "id" the service provider assigned
// (RFC 9967 §2.4.1).
type CreateFull struct {
	// Data is the resource as the service provider would return it.
	// Required.
	Data json.RawMessage `json:"data"`
	// Version is the resource's ETag after the change.
	Version string `json:"version,omitempty"`
}

// EventType implements ssf.Event.
func (CreateFull) EventType() ssf.EventType { return CreateFullEventType }

// Validate implements ssf.Event.
func (e CreateFull) Validate() error { return validateFull(CreateFullEventType, e.Data) }

// ValidateSubject implements ssf.SubjectConstrainedEvent.
func (CreateFull) ValidateSubject(s ssf.Subject) error {
	return requireSCIMSubject(CreateFullEventType, s)
}

// UnmarshalJSON implements json.Unmarshaler.
func (e *CreateFull) UnmarshalJSON(data []byte) error {
	f, err := decodeFull(CreateFullEventType, data)
	*e = CreateFull(f)
	return err
}

// CreateNotice signals that a SCIM resource was created, naming its
// attributes (RFC 9967 §2.4.1).
type CreateNotice struct {
	// Attributes names the attributes set. Required.
	Attributes []string `json:"attributes"`
	// Version is the resource's ETag after the change.
	Version string `json:"version,omitempty"`
}

// EventType implements ssf.Event.
func (CreateNotice) EventType() ssf.EventType { return CreateNoticeEventType }

// Validate implements ssf.Event.
func (e CreateNotice) Validate() error { return validateNotice(CreateNoticeEventType, e.Attributes) }

// ValidateSubject implements ssf.SubjectConstrainedEvent.
func (CreateNotice) ValidateSubject(s ssf.Subject) error {
	return requireSCIMSubject(CreateNoticeEventType, s)
}

// UnmarshalJSON implements json.Unmarshaler.
func (e *CreateNotice) UnmarshalJSON(data []byte) error {
	n, err := decodeNotice(CreateNoticeEventType, data)
	*e = CreateNotice(n)
	return err
}

// PatchFull signals that a SCIM resource was changed with SCIM PATCH,
// carrying the PATCH request (RFC 9967 §2.4.2).
type PatchFull struct {
	// Data is the SCIM PatchOp request. Required.
	Data json.RawMessage `json:"data"`
	// Version is the resource's ETag after the change.
	Version string `json:"version,omitempty"`
}

// EventType implements ssf.Event.
func (PatchFull) EventType() ssf.EventType { return PatchFullEventType }

// Validate implements ssf.Event.
func (e PatchFull) Validate() error { return validateFull(PatchFullEventType, e.Data) }

// ValidateSubject implements ssf.SubjectConstrainedEvent.
func (PatchFull) ValidateSubject(s ssf.Subject) error {
	return requireSCIMSubject(PatchFullEventType, s)
}

// UnmarshalJSON implements json.Unmarshaler.
func (e *PatchFull) UnmarshalJSON(data []byte) error {
	f, err := decodeFull(PatchFullEventType, data)
	*e = PatchFull(f)
	return err
}

// PatchNotice signals that a SCIM resource was changed with SCIM PATCH,
// naming the attributes changed (RFC 9967 §2.4.2).
type PatchNotice struct {
	// Attributes names the attributes added, changed or removed.
	// Required.
	Attributes []string `json:"attributes"`
	// Version is the resource's ETag after the change.
	Version string `json:"version,omitempty"`
}

// EventType implements ssf.Event.
func (PatchNotice) EventType() ssf.EventType { return PatchNoticeEventType }

// Validate implements ssf.Event.
func (e PatchNotice) Validate() error { return validateNotice(PatchNoticeEventType, e.Attributes) }

// ValidateSubject implements ssf.SubjectConstrainedEvent.
func (PatchNotice) ValidateSubject(s ssf.Subject) error {
	return requireSCIMSubject(PatchNoticeEventType, s)
}

// UnmarshalJSON implements json.Unmarshaler.
func (e *PatchNotice) UnmarshalJSON(data []byte) error {
	n, err := decodeNotice(PatchNoticeEventType, data)
	*e = PatchNotice(n)
	return err
}

// PutFull signals that a SCIM resource was replaced with SCIM PUT,
// carrying the PUT request body (RFC 9967 §2.4.3).
type PutFull struct {
	// Data is the SCIM PUT request body. Required.
	Data json.RawMessage `json:"data"`
	// Version is the resource's ETag after the change.
	Version string `json:"version,omitempty"`
}

// EventType implements ssf.Event.
func (PutFull) EventType() ssf.EventType { return PutFullEventType }

// Validate implements ssf.Event.
func (e PutFull) Validate() error { return validateFull(PutFullEventType, e.Data) }

// ValidateSubject implements ssf.SubjectConstrainedEvent.
func (PutFull) ValidateSubject(s ssf.Subject) error { return requireSCIMSubject(PutFullEventType, s) }

// UnmarshalJSON implements json.Unmarshaler.
func (e *PutFull) UnmarshalJSON(data []byte) error {
	f, err := decodeFull(PutFullEventType, data)
	*e = PutFull(f)
	return err
}

// PutNotice signals that a SCIM resource was replaced with SCIM PUT,
// naming the attributes changed (RFC 9967 §2.4.3).
type PutNotice struct {
	// Attributes names the attributes changed. Required.
	Attributes []string `json:"attributes"`
	// Version is the resource's ETag after the change.
	Version string `json:"version,omitempty"`
}

// EventType implements ssf.Event.
func (PutNotice) EventType() ssf.EventType { return PutNoticeEventType }

// Validate implements ssf.Event.
func (e PutNotice) Validate() error { return validateNotice(PutNoticeEventType, e.Attributes) }

// ValidateSubject implements ssf.SubjectConstrainedEvent.
func (PutNotice) ValidateSubject(s ssf.Subject) error {
	return requireSCIMSubject(PutNoticeEventType, s)
}

// UnmarshalJSON implements json.Unmarshaler.
func (e *PutNotice) UnmarshalJSON(data []byte) error {
	n, err := decodeNotice(PutNoticeEventType, data)
	*e = PutNotice(n)
	return err
}

// Delete signals that a SCIM resource was deleted, and so also left the
// feed (RFC 9967 §2.4.4).
type Delete struct{}

// EventType implements ssf.Event.
func (Delete) EventType() ssf.EventType { return DeleteEventType }

// Validate implements ssf.Event.
func (Delete) Validate() error { return nil }

// ValidateSubject implements ssf.SubjectConstrainedEvent.
func (Delete) ValidateSubject(s ssf.Subject) error { return requireSCIMSubject(DeleteEventType, s) }

// Activate signals that a resource, such as a User, is ready for use — an
// account that may log in, say — as Transmitter and Receiver agree
// (RFC 9967 §2.4.5).
type Activate struct{}

// EventType implements ssf.Event.
func (Activate) EventType() ssf.EventType { return ActivateEventType }

// Validate implements ssf.Event.
func (Activate) Validate() error { return nil }

// ValidateSubject implements ssf.SubjectConstrainedEvent.
func (Activate) ValidateSubject(s ssf.Subject) error {
	return requireSCIMSubject(ActivateEventType, s)
}

// Deactivate signals that a resource, such as a User, was deactivated and
// disabled — typically meaning it may no longer have an active session
// (RFC 9967 §2.4.6).
type Deactivate struct{}

// EventType implements ssf.Event.
func (Deactivate) EventType() ssf.EventType { return DeactivateEventType }

// Validate implements ssf.Event.
func (Deactivate) Validate() error { return nil }

// ValidateSubject implements ssf.SubjectConstrainedEvent.
func (Deactivate) ValidateSubject(s ssf.Subject) error {
	return requireSCIMSubject(DeactivateEventType, s)
}

// Methods a SCIM bulk operation, and so an asynchronous response, names
// (RFC 7644 §3.7).
var asyncMethods = []string{"POST", "PUT", "PATCH", "DELETE"}

// AsyncResponse signals that an asynchronous SCIM request completed
// (RFC 9967 §2.5.1.3). Its payload is one SCIM bulk response operation
// (RFC 7644 §3.7.3). The SET's "txn" must be the value the service
// provider returned to the client in Set-Txn: emit it with
// transmitter.EmitTxn.
type AsyncResponse struct {
	// Method is the request's HTTP method: POST, PUT, PATCH or DELETE.
	// Required.
	Method string `json:"method"`
	// BulkID is the "bulkId" of a bulk request's operation.
	BulkID string `json:"bulkId,omitempty"`
	// Version is the resource's ETag after the request.
	Version string `json:"version,omitempty"`
	// Location is the URI of the resource the request created or changed.
	Location string `json:"location,omitempty"`
	// Status is the HTTP status code of the outcome, such as "200".
	// Required.
	Status string `json:"status"`
	// Response is a SCIM error response (RFC 7644 §3.12), required when
	// Status is not 2xx.
	Response json.RawMessage `json:"response,omitempty"`
}

// EventType implements ssf.Event.
func (AsyncResponse) EventType() ssf.EventType { return AsyncResponseEventType }

// Validate implements ssf.Event.
func (e AsyncResponse) Validate() error {
	if !slices.Contains(asyncMethods, e.Method) {
		return invalid(AsyncResponseEventType, `"method" must be one of POST, PUT, PATCH or DELETE`)
	}
	if len(e.Status) != 3 || e.Status[0] < '1' || e.Status[0] > '5' ||
		e.Status[1] < '0' || e.Status[1] > '9' || e.Status[2] < '0' || e.Status[2] > '9' {
		return invalid(AsyncResponseEventType, `"status" must be an HTTP status code`)
	}
	if e.Status[0] != '2' {
		var obj map[string]json.RawMessage
		if len(e.Response) == 0 || json.Unmarshal(e.Response, &obj) != nil || obj == nil {
			return invalid(AsyncResponseEventType, `an unsuccessful request needs a "response" object (RFC 9967 §2.5.1.3)`)
		}
	}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (e *AsyncResponse) UnmarshalJSON(data []byte) error {
	type plain AsyncResponse
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	p.Response = compact(p.Response)
	*e = AsyncResponse(p)
	return nil
}

// ValidateSubject implements ssf.SubjectConstrainedEvent.
func (AsyncResponse) ValidateSubject(s ssf.Subject) error {
	return requireSCIMSubject(AsyncResponseEventType, s)
}
