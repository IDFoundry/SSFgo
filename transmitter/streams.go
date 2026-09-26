package transmitter

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
)

// maxRequestBytes bounds every stream management request body.
const maxRequestBytes = 64 * 1024

// readObject reads r's body as a JSON object, keyed by member name so the
// caller can tell an absent member from a present one.
func readObject(w http.ResponseWriter, r *http.Request) (map[string]json.RawMessage, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	if err != nil {
		return nil, badRequest("the request body could not be read: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return nil, badRequest("the request body must be a JSON object")
	}
	return obj, nil
}

func member[T any](obj map[string]json.RawMessage, name string) (value T, present bool, err error) {
	raw, ok := obj[name]
	if !ok {
		return value, false, nil
	}
	if err := json.Unmarshal(raw, &value); err != nil || string(raw) == "null" {
		return value, true, badRequest("%q has the wrong type", name)
	}
	return value, true, nil
}

// receiverFields are the Receiver-Supplied stream properties
// (SSF 1.0 §8.1.1), each nil when absent from the request.
type receiverFields struct {
	eventsRequested *[]ssf.EventType
	delivery        *ssf.Delivery
	description     *string
}

func (t *Transmitter) parseReceiverFields(obj map[string]json.RawMessage, rx Receiver) (receiverFields, error) {
	var f receiverFields
	if v, ok, err := member[[]ssf.EventType](obj, "events_requested"); err != nil {
		return f, err
	} else if ok {
		f.eventsRequested = &v
	}
	if v, ok, err := member[string](obj, "description"); err != nil {
		return f, err
	} else if ok {
		f.description = &v
	}
	if v, ok, err := member[ssf.Delivery](obj, "delivery"); err != nil {
		return f, err
	} else if ok {
		if err := t.validateDelivery(v, rx); err != nil {
			return f, err
		}
		f.delivery = &v
	}
	return f, nil
}

func (t *Transmitter) validateDelivery(d ssf.Delivery, rx Receiver) error {
	switch d.Method {
	case ssf.DeliveryPush, ssf.DeliveryPoll:
	case "":
		return badRequest("delivery.method is required")
	default:
		return badRequest("delivery method %q is not recognized", d.Method)
	}
	if !t.cfg.supportsDelivery(d.Method) {
		return badRequest("delivery method %q is not supported by this Transmitter", d.Method)
	}
	if d.Method == ssf.DeliveryPush {
		u, err := url.Parse(d.EndpointURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Fragment != "" {
			return badRequest("push delivery requires an https endpoint_url")
		}
		if u.User != nil {
			return badRequest("push endpoint_url must not contain credentials; use authorization_header")
		}
		if t.cfg.AllowPushEndpoint != nil {
			if err := t.cfg.AllowPushEndpoint(rx, u); err != nil {
				return badRequest("push endpoint_url is not allowed: %v", err)
			}
		}
	}
	return nil
}

// applyDelivery stores d on s, defaulting to poll (SSF 1.0 §8.1.1.1) and
// filling in the Transmitter-supplied poll endpoint (SSF 1.0 §6.1.2).
func (t *Transmitter) applyDelivery(s *storage.Stream, d *ssf.Delivery) error {
	if d == nil {
		if !t.cfg.supportsDelivery(ssf.DeliveryPoll) {
			return badRequest("delivery is required: this Transmitter does not support poll delivery")
		}
		d = &ssf.Delivery{Method: ssf.DeliveryPoll}
	}
	next := *d
	if next.Method == ssf.DeliveryPoll {
		next = ssf.Delivery{Method: ssf.DeliveryPoll, EndpointURL: t.url(t.paths.pollPrefix + s.ID)}
	}
	s.Delivery = next
	return nil
}

func (t *Transmitter) applyEventsRequested(s *storage.Stream, requested []ssf.EventType) {
	s.EventsRequested = requested
	s.EventsDelivered = []ssf.EventType{}
	for _, e := range requested {
		// Unknown event types are ignored, as SSF 1.0 §8.1.1 requires.
		if slices.Contains(t.cfg.EventsSupported, e) && !slices.Contains(s.EventsDelivered, e) {
			s.EventsDelivered = append(s.EventsDelivered, e)
		}
	}
}

// configuration renders a stored stream as its SSF stream configuration.
func (t *Transmitter) configuration(s storage.Stream) ssf.StreamConfiguration {
	return ssf.StreamConfiguration{
		StreamID:                s.ID,
		Issuer:                  t.cfg.Issuer,
		Audience:                s.Audience,
		EventsSupported:         t.cfg.EventsSupported,
		EventsRequested:         s.EventsRequested,
		EventsDelivered:         s.EventsDelivered,
		Delivery:                s.Delivery,
		MinVerificationInterval: int(t.cfg.MinVerificationInterval.Seconds()),
		Description:             s.Description,
	}
}

func (t *Transmitter) createStream(w http.ResponseWriter, r *http.Request, rx Receiver) {
	obj, err := readObject(w, r)
	if err != nil {
		t.writeAPIError(w, r, "create stream", err)
		return
	}
	fields, err := t.parseReceiverFields(obj, rx)
	if err != nil {
		t.writeAPIError(w, r, "create stream", err)
		return
	}
	s := storage.Stream{
		ID:         randomID(),
		ReceiverID: rx.ID,
		Audience:   slices.Clone(rx.Audience),
		Status:     ssf.StreamEnabled,
		CreatedAt:  t.now(),
	}
	if fields.description != nil {
		s.Description = *fields.description
	}
	if fields.eventsRequested != nil {
		t.applyEventsRequested(&s, *fields.eventsRequested)
	} else {
		t.applyEventsRequested(&s, nil)
	}
	if err := t.applyDelivery(&s, fields.delivery); err != nil {
		t.writeAPIError(w, r, "create stream", err)
		return
	}

	err = t.cfg.Store.CreateStream(r.Context(), s, storage.CreateOptions{SingleStreamPerReceiver: !t.cfg.MultipleStreamsPerReceiver})
	if errors.Is(err, storage.ErrReceiverHasStream) {
		writeError(w, http.StatusConflict, "conflict", "this Transmitter allows one stream per Receiver, and one already exists")
		return
	}
	if err != nil {
		t.serverError(w, r, "create stream", err)
		return
	}
	writeJSON(w, http.StatusCreated, t.configuration(s))
}

// ownedStream returns stream id if it exists and belongs to rx. A stream
// owned by another Receiver is reported as not found, so stream IDs cannot
// be probed.
func (t *Transmitter) ownedStream(r *http.Request, id string, rx Receiver) (storage.Stream, error) {
	s, err := t.cfg.Store.Stream(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) || (err == nil && s.ReceiverID != rx.ID) {
		return storage.Stream{}, errStreamNotFound
	}
	return s, err
}

// updateOwned applies update to stream id if it belongs to rx.
func (t *Transmitter) updateOwned(r *http.Request, id string, rx Receiver, update func(*storage.Stream) error) (storage.Stream, error) {
	s, err := t.cfg.Store.UpdateStream(r.Context(), id, func(s *storage.Stream) error {
		if s.ReceiverID != rx.ID {
			return errStreamNotFound
		}
		return update(s)
	})
	if errors.Is(err, storage.ErrNotFound) {
		return storage.Stream{}, errStreamNotFound
	}
	return s, err
}

func (t *Transmitter) readStreams(w http.ResponseWriter, r *http.Request, rx Receiver) {
	if id := r.URL.Query().Get("stream_id"); id != "" {
		s, err := t.ownedStream(r, id, rx)
		if err != nil {
			t.writeAPIError(w, r, "read stream", err)
			return
		}
		writeJSON(w, http.StatusOK, t.configuration(s))
		return
	}
	streams, err := t.cfg.Store.StreamsForReceiver(r.Context(), rx.ID)
	if err != nil {
		t.serverError(w, r, "list streams", err)
		return
	}
	out := make([]ssf.StreamConfiguration, 0, len(streams))
	for _, s := range streams {
		out = append(out, t.configuration(s))
	}
	writeJSON(w, http.StatusOK, out)
}

func (t *Transmitter) updateStream(w http.ResponseWriter, r *http.Request, rx Receiver) {
	t.modifyStream(w, r, rx, false)
}

func (t *Transmitter) replaceStream(w http.ResponseWriter, r *http.Request, rx Receiver) {
	t.modifyStream(w, r, rx, true)
}

// modifyStream implements PATCH (SSF 1.0 §8.1.1.3) and, with replace set,
// PUT (§8.1.1.4): with PUT, an absent Receiver-Supplied property is reset
// rather than left unchanged.
func (t *Transmitter) modifyStream(w http.ResponseWriter, r *http.Request, rx Receiver, replace bool) {
	op := "update stream"
	if replace {
		op = "replace stream"
	}
	obj, err := readObject(w, r)
	if err != nil {
		t.writeAPIError(w, r, op, err)
		return
	}
	id, _, err := member[string](obj, "stream_id")
	if err != nil {
		t.writeAPIError(w, r, op, err)
		return
	}
	if id == "" {
		t.writeAPIError(w, r, op, badRequest("stream_id is required"))
		return
	}
	fields, err := t.parseReceiverFields(obj, rx)
	if err != nil {
		t.writeAPIError(w, r, op, err)
		return
	}
	s, err := t.updateOwned(r, id, rx, func(s *storage.Stream) error {
		if err := t.checkTransmitterFields(obj, *s); err != nil {
			return err
		}
		switch {
		case fields.eventsRequested != nil:
			t.applyEventsRequested(s, *fields.eventsRequested)
		case replace:
			t.applyEventsRequested(s, nil)
		}
		switch {
		case fields.description != nil:
			s.Description = *fields.description
		case replace:
			s.Description = ""
		}
		if fields.delivery != nil || replace {
			return t.applyDelivery(s, fields.delivery)
		}
		return nil
	})
	if err != nil {
		t.writeAPIError(w, r, op, err)
		return
	}
	writeJSON(w, http.StatusOK, t.configuration(s))
}

// checkTransmitterFields enforces that any Transmitter-Supplied property in
// an update or replace request matches its current value (SSF 1.0
// §8.1.1.3, §8.1.1.4).
func (t *Transmitter) checkTransmitterFields(obj map[string]json.RawMessage, s storage.Stream) error {
	current := t.configuration(s)
	if v, ok, err := member[string](obj, "iss"); err != nil {
		return err
	} else if ok && v != current.Issuer {
		return badRequest("iss does not match")
	}
	if v, ok, err := member[ssf.Audience](obj, "aud"); err != nil {
		return err
	} else if ok && !sameSet(v, current.Audience) {
		return badRequest("aud cannot be changed")
	}
	if v, ok, err := member[[]ssf.EventType](obj, "events_supported"); err != nil {
		return err
	} else if ok && !sameSet(v, current.EventsSupported) {
		return badRequest("events_supported does not match")
	}
	if v, ok, err := member[[]ssf.EventType](obj, "events_delivered"); err != nil {
		return err
	} else if ok && !sameSet(v, current.EventsDelivered) {
		return badRequest("events_delivered does not match")
	}
	if v, ok, err := member[int](obj, "min_verification_interval"); err != nil {
		return err
	} else if ok && v != current.MinVerificationInterval {
		return badRequest("min_verification_interval does not match")
	}
	if v, ok, err := member[int](obj, "inactivity_timeout"); err != nil {
		return err
	} else if ok && v != current.InactivityTimeout {
		return badRequest("inactivity_timeout does not match")
	}
	return nil
}

func sameSet[S ~[]E, E comparable](a, b S) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	for _, x := range b {
		if !slices.Contains(a, x) {
			return false
		}
	}
	return true
}

func (t *Transmitter) deleteStream(w http.ResponseWriter, r *http.Request, rx Receiver) {
	id := r.URL.Query().Get("stream_id")
	if id == "" {
		t.writeAPIError(w, r, "delete stream", badRequest("the stream_id query parameter is required"))
		return
	}
	if _, err := t.ownedStream(r, id, rx); err != nil {
		t.writeAPIError(w, r, "delete stream", err)
		return
	}
	err := t.cfg.Store.DeleteStream(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		t.writeAPIError(w, r, "delete stream", errStreamNotFound)
		return
	}
	if err != nil {
		t.serverError(w, r, "delete stream", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
