package transmitter

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
)

// pollRecheck bounds how long a long poll sleeps between storage checks,
// so SETs queued by another process are still picked up promptly.
const pollRecheck = time.Second

// maxLoggedSetErrs bounds the log lines one poll request can produce.
const maxLoggedSetErrs = 10

// setError is one entry of a poll request's "setErrs" (RFC 8936 §2.2).
type setError struct {
	Err         string `json:"err"`
	Description string `json:"description"`
}

type pollRequest struct {
	MaxEvents         *int                `json:"maxEvents"`
	ReturnImmediately bool                `json:"returnImmediately"`
	Ack               []string            `json:"ack"`
	SetErrs           map[string]setError `json:"setErrs"`
}

type pollResponse struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable,omitempty"`
}

// poll implements RFC 8936 poll delivery on a stream's endpoint_url:
// acknowledge what the Receiver acknowledges, then return queued SETs,
// waiting for one if the Receiver asked to (§2.5). A SET stays queued,
// and is returned again by later polls, until it is acknowledged.
func (t *Transmitter) poll(w http.ResponseWriter, r *http.Request, rx Receiver) {
	id := r.PathValue("stream_id")
	req, err := readPollRequest(w, r)
	if err != nil {
		t.writeAPIError(w, r, "poll", err)
		return
	}
	s, err := t.ownedStream(r, id, rx)
	if err != nil {
		t.writeAPIError(w, r, "poll", err)
		return
	}
	if s.Delivery.Method != ssf.DeliveryPoll {
		t.writeAPIError(w, r, "poll", badRequest("this stream does not use poll delivery"))
		return
	}
	t.touch(r.Context(), s)
	start, returned := t.now(), 0
	if t.cfg.Hooks.Poll != nil {
		defer t.observe(r.Context(), "Poll", func() {
			t.cfg.Hooks.Poll(r.Context(), PollInfo{StreamID: id, Returned: returned,
				Acknowledged: len(req.Ack), Reported: len(req.SetErrs), Duration: t.now().Sub(start)})
		})
	}

	if err := t.acknowledge(r, id, req); err != nil {
		t.writeAPIError(w, r, "poll", t.notFoundOr(err))
		return
	}
	if req.MaxEvents != nil && *req.MaxEvents == 0 {
		// Acknowledge-only request (RFC 8936 §2.4.2).
		writeJSON(w, http.StatusOK, pollResponse{Sets: map[string]string{}})
		return
	}
	if !req.ReturnImmediately {
		// One long poll per stream waits at a time; another is answered
		// at once, as RFC 8936 §2.5 allows, so a Receiver cannot tie up
		// any number of requests rechecking storage every second.
		if t.polling.start(id) {
			defer t.polling.end(id)
		} else {
			req.ReturnImmediately = true
		}
	}
	resp, err := t.awaitSETs(r, id, req)
	if err != nil {
		t.writeAPIError(w, r, "poll", t.notFoundOr(err))
		return
	}
	if resp != nil {
		returned = len(resp.Sets)
		writeJSON(w, http.StatusOK, resp)
	}
}

// readPollRequest reads and checks a poll request body; an empty body is
// a poll with every member at its default.
func readPollRequest(w http.ResponseWriter, r *http.Request) (pollRequest, error) {
	var req pollRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	if err != nil {
		return req, badRequest("the request body could not be read: %v", err)
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return req, badRequest("the request body must be a poll request object: %v", err)
		}
	}
	if req.MaxEvents != nil && *req.MaxEvents < 0 {
		return req, badRequest("maxEvents must not be negative")
	}
	return req, nil
}

// acknowledge removes the SETs a poll acknowledges or reports as rejected,
// logging at most maxLoggedSetErrs of the rejections.
func (t *Transmitter) acknowledge(r *http.Request, id string, req pollRequest) error {
	done := slices.Clone(req.Ack)
	logged := 0
	for jti, e := range req.SetErrs {
		if logged < maxLoggedSetErrs {
			t.log.WarnContext(r.Context(), "ssf transmitter: receiver rejected a SET", "stream_id", id, "jti", jti, "err", e.Err, "description", e.Description)
			logged++
		}
		done = append(done, jti)
	}
	if n := len(req.SetErrs); n > logged {
		t.log.WarnContext(r.Context(), "ssf transmitter: receiver rejected further SETs", "stream_id", id, "count", n-logged)
	}
	if len(done) == 0 {
		return nil
	}
	return t.cfg.Store.AckEvents(r.Context(), id, done)
}

// longPolls tracks which streams have a long poll waiting.
type longPolls struct {
	mu     sync.Mutex
	active map[string]bool
}

// start marks stream id as long-polled, unless it already is.
func (l *longPolls) start(id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[id] {
		return false
	}
	l.active[id] = true
	return true
}

func (l *longPolls) end(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.active, id)
}

// awaitSETs returns the SETs to answer a poll with, waiting up to
// LongPollTimeout for one unless the Receiver asked to return
// immediately. It returns nil, nil if the request was cancelled.
func (t *Transmitter) awaitSETs(r *http.Request, id string, req pollRequest) (*pollResponse, error) {
	limit := 0
	if req.MaxEvents != nil {
		limit = *req.MaxEvents + 1 // one extra, to report moreAvailable
	}
	deadline := time.Now().Add(t.cfg.Limits.LongPollTimeout)
	for {
		wake, done := t.notify.wait(id)
		events, err := t.deliverable(r, id, limit)
		if err != nil {
			done()
			return nil, err
		}
		if len(events) > 0 || req.ReturnImmediately || !time.Now().Before(deadline) {
			done()
			resp := &pollResponse{Sets: map[string]string{}}
			if req.MaxEvents != nil && len(events) > *req.MaxEvents {
				events, resp.MoreAvailable = events[:*req.MaxEvents], true
			}
			for _, e := range events {
				resp.Sets[e.JTI] = e.SET
			}
			return resp, nil
		}
		timer := time.NewTimer(min(pollRecheck, time.Until(deadline)))
		select {
		case <-wake:
		case <-timer.C:
		case <-r.Context().Done():
			timer.Stop()
			done()
			return nil, nil
		}
		timer.Stop()
		done()
	}
}

// deliverable returns the SETs that may be transmitted on stream id now:
// all of them while it is enabled, only control events otherwise
// (SSF 1.0 §8.1.2.1, §8.1.5).
func (t *Transmitter) deliverable(r *http.Request, id string, limit int) ([]storage.QueuedEvent, error) {
	s, err := t.cfg.Store.Stream(r.Context(), id)
	if err != nil {
		return nil, err
	}
	return t.cfg.Store.PendingEvents(r.Context(), id, limit, s.Status != ssf.StreamEnabled)
}
