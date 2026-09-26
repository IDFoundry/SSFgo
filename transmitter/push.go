package transmitter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
)

const (
	// pushScanInterval is how often Run looks for push streams with SETs
	// queued, in addition to being woken when a SET is queued here.
	pushScanInterval = time.Second
)

// pushState tracks, per stream, whether a delivery goroutine is running
// and when a failed stream may be retried.
type pushState struct {
	mu      sync.Mutex
	streams map[string]*pushStream
	policy  PushRetryPolicy
}

type pushStream struct {
	busy     bool
	failures int
	retryAt  time.Time
}

func newPushState(policy PushRetryPolicy) *pushState {
	return &pushState{streams: map[string]*pushStream{}, policy: policy}
}

// failures returns how many consecutive attempts on stream id have failed:
// the attempts spent on the SET at the head of its queue.
func (p *pushState) failures(id string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st, ok := p.streams[id]; ok {
		return st.failures
	}
	return 0
}

// reset clears stream id's failure count, after its head SET is dropped.
func (p *pushState) reset(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st, ok := p.streams[id]; ok {
		st.failures = 0
	}
}

// claim marks stream id busy if it is idle and not backing off.
func (p *pushState) claim(id string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.streams[id]
	if !ok {
		st = &pushStream{}
		p.streams[id] = st
	}
	if st.busy || now.Before(st.retryAt) {
		return false
	}
	st.busy = true
	return true
}

// release marks stream id idle, recording whether its last attempt failed.
func (p *pushState) release(id string, failed bool, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.streams[id]
	st.busy = false
	if !failed {
		st.failures, st.retryAt = 0, time.Time{}
		return
	}
	st.failures++
	backoff := p.policy.MinBackoff << min(st.failures-1, 20)
	if backoff <= 0 || backoff > p.policy.MaxBackoff {
		backoff = p.policy.MaxBackoff
	}
	st.retryAt = now.Add(backoff)
}

// Run delivers SETs queued on push streams (RFC 8935) until ctx is done,
// then waits for in-flight deliveries to finish and returns ctx.Err().
// SETs on each stream are delivered one at a time, oldest first. Start Run
// once per process if any stream may use push delivery.
func (t *Transmitter) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	ticker := time.NewTicker(pushScanInterval)
	defer ticker.Stop()
	for {
		wake := t.notify.wait(anyStream)
		streams, err := t.cfg.Store.AllStreams(ctx)
		if err != nil && ctx.Err() == nil {
			t.log.ErrorContext(ctx, "ssf transmitter: list streams for push", "error", err)
		}
		for _, s := range streams {
			if s.Delivery.Method != ssf.DeliveryPush || !t.pushes.claim(s.ID, time.Now()) {
				continue
			}
			wg.Go(func() {
				failed := t.drain(ctx, s.ID)
				t.pushes.release(s.ID, failed, time.Now())
			})
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
		case <-ticker.C:
		}
	}
}

// drain pushes stream id's deliverable SETs until none remain or one fails
// recoverably, which it reports by returning true.
func (t *Transmitter) drain(ctx context.Context, id string) (failed bool) {
	for ctx.Err() == nil {
		s, err := t.cfg.Store.Stream(ctx, id)
		if err != nil || s.Delivery.Method != ssf.DeliveryPush {
			return false
		}
		events, err := t.cfg.Store.PendingEvents(ctx, id, 1, s.Status != ssf.StreamEnabled)
		if err != nil || len(events) == 0 {
			return false
		}
		e := events[0]
		if limit := t.cfg.PushRetry.MaxAttempts; limit > 0 && t.pushes.failures(id) >= limit {
			t.log.ErrorContext(ctx, "ssf transmitter: dropping SET after the maximum push attempts", "stream_id", id, "jti", e.JTI, "attempts", limit)
			t.pushes.reset(id)
			if err := t.cfg.Store.AckEvents(ctx, id, []string{e.JTI}); err != nil && !errors.Is(err, storage.ErrNotFound) {
				return true
			}
			continue
		}
		switch outcome, detail := t.push(ctx, s.Delivery, e); outcome {
		case pushDelivered:
		case pushRejected:
			// The Receiver says the SET itself is invalid; retrying will
			// not change that (RFC 8935 §2.3).
			t.log.WarnContext(ctx, "ssf transmitter: receiver rejected a pushed SET", "stream_id", id, "jti", e.JTI, "error", detail)
		default:
			t.log.WarnContext(ctx, "ssf transmitter: push delivery failed, will retry", "stream_id", id, "jti", e.JTI, "error", detail)
			return true
		}
		if err := t.cfg.Store.AckEvents(ctx, id, []string{e.JTI}); err != nil && !errors.Is(err, storage.ErrNotFound) {
			t.log.ErrorContext(ctx, "ssf transmitter: remove pushed SET from queue", "stream_id", id, "error", err)
			return true
		}
	}
	return false
}

type pushOutcome int

const (
	pushDelivered pushOutcome = iota
	pushRejected
	pushRetry
)

// maxPushResponseBytes bounds how much of a Receiver's response is read.
const maxPushResponseBytes = 16 * 1024

// push transmits one SET (RFC 8935 §2.1).
func (t *Transmitter) push(ctx context.Context, d ssf.Delivery, e storage.QueuedEvent) (pushOutcome, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.EndpointURL, bytes.NewReader([]byte(e.SET)))
	if err != nil {
		return pushRetry, err.Error()
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")
	if d.AuthorizationHeader != "" {
		req.Header.Set("Authorization", d.AuthorizationHeader)
	}
	res, err := t.client.Do(req)
	if err != nil {
		return pushRetry, err.Error()
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(res.Body, maxPushResponseBytes))
	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		// RFC 8935 §2.2 specifies 202; any success is taken as receipt.
		return pushDelivered, ""
	case res.StatusCode == http.StatusBadRequest:
		var e struct {
			Err         string `json:"err"`
			Description string `json:"description"`
		}
		if json.Unmarshal(body, &e) == nil && e.Err != "" {
			return pushRejected, fmt.Sprintf("%s: %s", e.Err, e.Description)
		}
		return pushRetry, "HTTP 400 without an RFC 8935 error body"
	default:
		return pushRetry, fmt.Sprintf("HTTP %d", res.StatusCode)
	}
}
