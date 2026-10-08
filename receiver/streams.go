package receiver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	ssf "github.com/idfoundry/ssfgo"
)

// StreamRequest holds the Receiver-supplied properties of a stream
// (SSF 1.0 §8.1.1).
type StreamRequest struct {
	// Delivery is how SETs should reach the Receiver. For push, set
	// Method, EndpointURL and optionally AuthorizationHeader; for poll,
	// set only Method — the Transmitter supplies the endpoint. Nil asks
	// for poll: the request then names poll explicitly, since SSF 1.0
	// §8.1.1 makes "delivery" required.
	Delivery *ssf.Delivery
	// EventsRequested defaults to every event type in the Registry
	// except SSF's own verification and stream-updated events, which are
	// sent regardless.
	EventsRequested []ssf.EventType
	Description     string
	// ReplaceOnConflict lets EnsureStream replace the Receiver's only
	// stream when the Transmitter allows one stream per Receiver and that
	// stream's delivery differs from Delivery. That stream may belong to
	// another application using the same credentials, so replacing it is
	// the caller's decision; without it EnsureStream returns the conflict.
	// Other methods ignore it.
	ReplaceOnConflict bool
}

type streamRequestWire struct {
	StreamID        string          `json:"stream_id,omitempty"`
	EventsRequested []ssf.EventType `json:"events_requested,omitempty"`
	Delivery        *ssf.Delivery   `json:"delivery,omitempty"`
	Description     string          `json:"description,omitempty"`
}

func (r *Receiver) wire(id string, req StreamRequest) streamRequestWire {
	events := req.EventsRequested
	if events == nil {
		for _, t := range r.cfg.Registry.Types() {
			if t != ssf.VerificationEventType && t != ssf.StreamUpdatedEventType {
				events = append(events, t)
			}
		}
	}
	delivery := req.Delivery
	if delivery == nil {
		delivery = &ssf.Delivery{Method: ssf.DeliveryPoll}
	}
	return streamRequestWire{StreamID: id, EventsRequested: events, Delivery: delivery, Description: req.Description}
}

// ErrIssuerMismatch is returned, together with the stream, when a stream's
// "iss" is not Config.Issuer (SSF 1.0 §8.1.1.1): the stream must not be
// used. The caller decides whether to delete it; nothing else removes it
// from the Transmitter.
var ErrIssuerMismatch = errors.New("receiver: stream issuer is not the configured issuer")

// ErrAudienceMismatch is returned, together with the stream, when a
// stream's "aud" does not include Config.Audience: SETs on it would all be
// rejected. The caller decides whether to delete the stream.
var ErrAudienceMismatch = errors.New("receiver: stream audience does not include the receiver's audience")

// checkStream validates a stream configuration the Transmitter returned
// (SSF 1.0 §8.1.1.1: "iss" must match; §8.1.1.1.1: validate "aud").
func (r *Receiver) checkStream(c ssf.StreamConfiguration) error {
	if c.Issuer != r.cfg.Issuer {
		return fmt.Errorf("%w: stream %s names issuer %q, not %q", ErrIssuerMismatch, c.StreamID, c.Issuer, r.cfg.Issuer)
	}
	if c.StreamID == "" {
		return errors.New("receiver: stream configuration has no stream_id")
	}
	if !slices.Contains(c.Audience, r.cfg.Audience) && !r.acceptStreamAudience(c) {
		return fmt.Errorf("%w: stream %s has aud %v", ErrAudienceMismatch, c.StreamID, []string(c.Audience))
	}
	return nil
}

// CreateStream creates a stream (SSF 1.0 §8.1.1.1).
func (r *Receiver) CreateStream(ctx context.Context, req StreamRequest) (ssf.StreamConfiguration, error) {
	var c ssf.StreamConfiguration
	if err := r.call(ctx, http.MethodPost, r.metadata.ConfigurationEndpoint, r.wire("", req), &c, http.StatusCreated, http.StatusOK); err != nil {
		return ssf.StreamConfiguration{}, err
	}
	return c, r.checkStream(c)
}

// Stream reads one stream's configuration (SSF 1.0 §8.1.1.2).
func (r *Receiver) Stream(ctx context.Context, streamID string) (ssf.StreamConfiguration, error) {
	var c ssf.StreamConfiguration
	if err := r.call(ctx, http.MethodGet, withStreamID(r.metadata.ConfigurationEndpoint, streamID), nil, &c, http.StatusOK); err != nil {
		return ssf.StreamConfiguration{}, err
	}
	return c, r.checkStream(c)
}

// Streams lists every stream the Transmitter holds for this Receiver. It
// returns the streams that pass the checks CreateStream applies; any that
// fail are reported in a *StreamsError, so the caller can still use the
// others and delete the failures.
func (r *Receiver) Streams(ctx context.Context) ([]ssf.StreamConfiguration, error) {
	var cs []ssf.StreamConfiguration
	if err := r.call(ctx, http.MethodGet, r.metadata.ConfigurationEndpoint, nil, &cs, http.StatusOK); err != nil {
		return nil, err
	}
	ok := make([]ssf.StreamConfiguration, 0, len(cs))
	var rejected []RejectedStream
	for _, c := range cs {
		if err := r.checkStream(c); err != nil {
			rejected = append(rejected, RejectedStream{Stream: c, Err: err})
			continue
		}
		ok = append(ok, c)
	}
	if len(rejected) > 0 {
		return ok, &StreamsError{Rejected: rejected}
	}
	return ok, nil
}

// StreamsError reports the streams Streams left out because they failed
// its checks. errors.Is matches it against ErrIssuerMismatch and
// ErrAudienceMismatch when any stream failed that way.
type StreamsError struct {
	Rejected []RejectedStream
}

// RejectedStream is one stream Streams left out, and why.
type RejectedStream struct {
	Stream ssf.StreamConfiguration
	Err    error
}

func (e *StreamsError) Error() string {
	msgs := make([]string, len(e.Rejected))
	for i, r := range e.Rejected {
		msgs[i] = r.Err.Error()
	}
	return fmt.Sprintf("receiver: %d stream(s) failed their checks: %s", len(e.Rejected), strings.Join(msgs, "; "))
}

// Unwrap returns each rejected stream's error.
func (e *StreamsError) Unwrap() []error {
	errs := make([]error, len(e.Rejected))
	for i, r := range e.Rejected {
		errs[i] = r.Err
	}
	return errs
}

// StreamUpdate changes some of a stream's Receiver-supplied properties;
// nil fields are left unchanged (SSF 1.0 §8.1.1.3).
type StreamUpdate struct {
	EventsRequested *[]ssf.EventType
	Delivery        *ssf.Delivery
	Description     *string
}

// UpdateStream applies update with PATCH (SSF 1.0 §8.1.1.3). A 202 from
// the Transmitter returns ErrNotProcessed.
func (r *Receiver) UpdateStream(ctx context.Context, streamID string, update StreamUpdate) (ssf.StreamConfiguration, error) {
	body := map[string]any{"stream_id": streamID}
	if update.EventsRequested != nil {
		body["events_requested"] = *update.EventsRequested
	}
	if update.Delivery != nil {
		body["delivery"] = *update.Delivery
	}
	if update.Description != nil {
		body["description"] = *update.Description
	}
	var c ssf.StreamConfiguration
	if err := r.call(ctx, http.MethodPatch, r.metadata.ConfigurationEndpoint, body, &c, http.StatusOK, http.StatusAccepted); err != nil {
		return ssf.StreamConfiguration{}, err
	}
	return c, r.checkStream(c)
}

// ReplaceStream replaces every Receiver-supplied property with PUT
// (SSF 1.0 §8.1.1.4). Unlike CreateStream, a nil EventsRequested is sent
// as the Registry's event types. A 202 from the Transmitter returns
// ErrNotProcessed.
func (r *Receiver) ReplaceStream(ctx context.Context, streamID string, req StreamRequest) (ssf.StreamConfiguration, error) {
	var c ssf.StreamConfiguration
	if err := r.call(ctx, http.MethodPut, r.metadata.ConfigurationEndpoint, r.wire(streamID, req), &c, http.StatusOK, http.StatusAccepted); err != nil {
		return ssf.StreamConfiguration{}, err
	}
	return c, r.checkStream(c)
}

// DeleteStream deletes a stream (SSF 1.0 §8.1.1.5) and discards any
// acknowledgements still pending for it.
func (r *Receiver) DeleteStream(ctx context.Context, streamID string) error {
	if err := r.call(ctx, http.MethodDelete, withStreamID(r.metadata.ConfigurationEndpoint, streamID), nil, nil, http.StatusNoContent, http.StatusOK); err != nil {
		return err
	}
	r.pollMu.Lock()
	delete(r.acks, streamID)
	r.pollMu.Unlock()
	r.forgetStreamAudience(streamID)
	return nil
}

// Status reads a stream's status (SSF 1.0 §8.1.2.1).
func (r *Receiver) Status(ctx context.Context, streamID string) (ssf.StreamState, error) {
	var s ssf.StreamState
	err := r.call(ctx, http.MethodGet, withStreamID(r.metadata.StatusEndpoint, streamID), nil, &s, http.StatusOK)
	return s, err
}

// SetStatus asks the Transmitter to change a stream's status
// (SSF 1.0 §8.1.2.2). A 202 from the Transmitter returns ErrNotProcessed.
func (r *Receiver) SetStatus(ctx context.Context, streamID string, status ssf.StreamStatus, reason string) (ssf.StreamState, error) {
	var s ssf.StreamState
	err := r.call(ctx, http.MethodPost, r.metadata.StatusEndpoint,
		ssf.StreamState{StreamID: streamID, Status: status, Reason: reason}, &s, http.StatusOK, http.StatusAccepted)
	if err != nil {
		return ssf.StreamState{}, err
	}
	return s, nil
}

// AddSubject asks for events about subject on a stream (SSF 1.0
// §8.1.3.2). verified is nil when the Receiver makes no claim.
func (r *Receiver) AddSubject(ctx context.Context, streamID string, subject ssf.Subject, verified *bool) error {
	return r.call(ctx, http.MethodPost, r.metadata.AddSubjectEndpoint,
		ssf.AddSubjectRequest{StreamID: streamID, Subject: subject, Verified: verified}, nil, http.StatusOK, http.StatusNoContent)
}

// RemoveSubject asks for no more events about subject on a stream
// (SSF 1.0 §8.1.3.3).
func (r *Receiver) RemoveSubject(ctx context.Context, streamID string, subject ssf.Subject) error {
	return r.call(ctx, http.MethodPost, r.metadata.RemoveSubjectEndpoint,
		ssf.RemoveSubjectRequest{StreamID: streamID, Subject: subject}, nil, http.StatusNoContent, http.StatusOK)
}

// RequestVerification asks the Transmitter to send a verification event on
// a stream (SSF 1.0 §8.1.4.2) and returns the random state it will echo.
// A verification event that arrives with a state this Receiver did not
// request, or has already seen, is rejected as invalid_state
// (SSF 1.0 §8.1.4.1).
func (r *Receiver) RequestVerification(ctx context.Context, streamID string) (string, error) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	state := hex.EncodeToString(b)
	r.stateMu.Lock()
	pending := append(r.states[streamID], state)
	if len(pending) > maxPendingStates {
		// A verification that never arrived is forgotten rather than
		// kept forever.
		pending = pending[len(pending)-maxPendingStates:]
	}
	r.states[streamID] = pending
	r.stateMu.Unlock()

	err := r.call(ctx, http.MethodPost, r.metadata.VerificationEndpoint,
		ssf.VerificationRequest{StreamID: streamID, State: state}, nil, http.StatusNoContent, http.StatusOK)
	if err != nil {
		r.takeState(streamID, state)
		return "", err
	}
	return state, nil
}

// maxPendingStates bounds the outstanding verification requests
// remembered per stream.
const maxPendingStates = 16

// takeState consumes an outstanding verification state.
func (r *Receiver) takeState(streamID, state string) bool {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	pending := r.states[streamID]
	i := slices.Index(pending, state)
	if i < 0 {
		return false
	}
	r.states[streamID] = slices.Delete(pending, i, i+1)
	if len(r.states[streamID]) == 0 {
		delete(r.states, streamID)
	}
	return true
}

func withStreamID(endpoint, streamID string) string {
	if endpoint == "" {
		return ""
	}
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}
	return endpoint + sep + "stream_id=" + url.QueryEscape(streamID)
}
