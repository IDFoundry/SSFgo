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
	"github.com/idfoundry/ssfgo/internal/peertext"
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
	busy    bool
	retryAt time.Time
	// failures counts the consecutive failed attempts on the SET head, the
	// head of the queue when they were made.
	failures int
	head     string
}

func newPushState(policy PushRetryPolicy) *pushState {
	return &pushState{streams: map[string]*pushStream{}, policy: policy}
}

// attempt returns which attempt at delivering SET jti on stream id the
// next is. Failures count against the SET they happened to: a SET that
// reaches the head of the queue some other way than its predecessor being
// done with — a control SET queued after a purge, or while a paused stream
// sends only control SETs — starts from its first attempt.
func (p *pushState) attempt(id, jti string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.streams[id]
	if !ok {
		return 1
	}
	if st.head != jti {
		st.head, st.failures = jti, 0
	}
	return st.failures + 1
}

// reset clears stream id's failure count, after its head SET is dropped.
func (p *pushState) reset(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st, ok := p.streams[id]; ok {
		st.failures = 0
	}
}

// prune forgets idle streams that are no longer push streams, or no longer
// exist, so deleted streams leave no state behind.
func (p *pushState) prune(streams []storage.Stream) {
	push := make(map[string]bool, len(streams))
	for _, s := range streams {
		if s.Delivery.Method == ssf.DeliveryPush {
			push[s.ID] = true
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, st := range p.streams {
		if !push[id] && !st.busy {
			delete(p.streams, id)
		}
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
// If Config.Inactivity is set, it also applies inactivity timeouts every
// 30 seconds.
// SETs on each stream are delivered one at a time, oldest first. Start Run
// if any stream may use push delivery — in one process only when several
// Transmitter instances share a store: Run coordinates deliveries within
// its process, so instances each running it would push the same SETs.
func (t *Transmitter) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	ticker := time.NewTicker(pushScanInterval)
	defer ticker.Stop()
	nextExpiry := time.Now()
	for {
		if t.cfg.Inactivity.Timeout > 0 && !time.Now().Before(nextExpiry) {
			t.expireInactive(ctx)
			nextExpiry = time.Now().Add(inactivityCheckInterval)
		}
		wake, done := t.notify.wait(anyStream)
		t.startPushes(ctx, &wg)
		select {
		case <-ctx.Done():
			done()
			return ctx.Err()
		case <-wake:
		case <-ticker.C:
		}
		done()
	}
}

// expireInactive applies inactivity timeouts, logging a failure.
func (t *Transmitter) expireInactive(ctx context.Context) {
	if err := t.ExpireInactiveStreams(ctx); err != nil && ctx.Err() == nil {
		t.log.ErrorContext(ctx, "ssf transmitter: inactivity", "error", err)
	}
}

// startPushes starts draining, in wg, every push stream no other
// goroutine is draining and whose backoff has passed.
func (t *Transmitter) startPushes(ctx context.Context, wg *sync.WaitGroup) {
	streams, err := t.cfg.Store.AllStreams(ctx)
	if err != nil && ctx.Err() == nil {
		t.log.ErrorContext(ctx, "ssf transmitter: list streams for push", "error", err)
	}
	if err == nil {
		t.pushes.prune(streams)
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
}

// drain pushes stream id's deliverable SETs until none remain or one fails
// recoverably, which it reports by returning true.
func (t *Transmitter) drain(ctx context.Context, id string) (failed bool) {
	for ctx.Err() == nil {
		s, err := t.cfg.Store.Stream(ctx, id)
		if err != nil && !errors.Is(err, storage.ErrNotFound) && ctx.Err() == nil {
			t.log.ErrorContext(ctx, "ssf transmitter: read stream for push", "stream_id", id, "error", err)
		}
		if err != nil || s.Delivery.Method != ssf.DeliveryPush {
			return false
		}
		events, err := t.cfg.Store.PendingEvents(ctx, id, 1, s.Status != ssf.StreamEnabled)
		if err != nil && ctx.Err() == nil {
			t.log.ErrorContext(ctx, "ssf transmitter: read push queue", "stream_id", id, "error", err)
		}
		if err != nil || len(events) == 0 {
			return false
		}
		if t.deliverOne(ctx, s, events[0]) {
			return true
		}
	}
	return false
}

// deliverOne pushes one SET and removes it from the queue once it has
// been delivered, rejected by the Receiver, or given up on. It reports
// whether the stream should back off and retry.
func (t *Transmitter) deliverOne(ctx context.Context, s storage.Stream, e storage.QueuedEvent) (retry bool) {
	attempt := t.pushes.attempt(s.ID, e.JTI)
	report := func(outcome PushOutcome, took time.Duration, detail string) {
		if t.cfg.Hooks.Push != nil {
			t.observe(ctx, "Push", func() {
				t.cfg.Hooks.Push(ctx, PushInfo{StreamID: s.ID, JTI: e.JTI, Outcome: outcome, Attempt: attempt, Duration: took, Detail: detail})
			})
		}
	}
	if limit := t.cfg.PushRetry.MaxAttempts; limit > 0 && attempt > limit {
		t.log.ErrorContext(ctx, "ssf transmitter: dropping SET after the maximum push attempts", "stream_id", s.ID, "jti", e.JTI, "attempts", limit)
		attempt = limit
		report(PushDropped, 0, "the maximum push attempts were made")
		t.pushes.reset(s.ID)
		return t.dequeue(ctx, s.ID, e.JTI)
	}
	start := time.Now()
	outcome, detail := t.push(ctx, s.Delivery, e)
	took := time.Since(start)
	// Mostly the Receiver's own words: it is logged and reported to hooks.
	detail = peertext.Clean(detail, maxPushDetail)
	switch outcome {
	case pushDelivered:
		report(PushDelivered, took, "")
	case pushRejected:
		// The Receiver says the SET itself is invalid; retrying will not
		// change that (RFC 8935 §2.3).
		t.log.WarnContext(ctx, "ssf transmitter: receiver rejected a pushed SET", "stream_id", s.ID, "jti", e.JTI, "error", detail)
		report(PushRejected, took, detail)
	case pushRejectedTransient:
		if attempt < transientRejectAttempts {
			t.log.WarnContext(ctx, "ssf transmitter: receiver rejected a pushed SET, will retry", "stream_id", s.ID, "jti", e.JTI, "error", detail)
			report(PushRetry, took, detail)
			return true
		}
		t.log.ErrorContext(ctx, "ssf transmitter: dropping SET the receiver kept rejecting", "stream_id", s.ID, "jti", e.JTI, "attempts", transientRejectAttempts, "error", detail)
		report(PushDropped, took, detail)
	default:
		t.log.WarnContext(ctx, "ssf transmitter: push delivery failed, will retry", "stream_id", s.ID, "jti", e.JTI, "error", detail)
		report(PushRetry, took, detail)
		return true
	}
	// The SET is done with: the next one starts with no failures.
	t.pushes.reset(s.ID)
	return t.dequeue(ctx, s.ID, e.JTI)
}

// transientRejectAttempts is how many times a SET is tried while the
// Receiver rejects it with an error that may clear on its own (see
// transientRejection). With the default backoff the attempts span about
// four minutes — longer than a Receiver takes to refetch a rotated JWKS —
// and the bound keeps one such SET from holding up its stream for good.
const transientRejectAttempts = 8

// maxPushDetail bounds what a failed push's description keeps of the
// Receiver's error code and description.
const maxPushDetail = 512

// transientRejection reports whether a Receiver's RFC 8935 error code may
// clear without the SET changing (RFC 8935 §2.3, §4): invalid_key while
// the Receiver has yet to fetch a rotated signing key, or
// authentication_failed and access_denied while a credential is being
// updated.
func transientRejection(code string) bool {
	switch code {
	case "invalid_key", "authentication_failed", "access_denied":
		return true
	}
	return false
}

// dequeue removes a SET from a stream's queue, reporting whether that
// failed and the stream should retry.
func (t *Transmitter) dequeue(ctx context.Context, id, jti string) (retry bool) {
	err := t.cfg.Store.AckEvents(ctx, id, []string{jti})
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		t.log.ErrorContext(ctx, "ssf transmitter: remove pushed SET from queue", "stream_id", id, "error", err)
		return true
	}
	return false
}

type pushOutcome int

const (
	pushDelivered pushOutcome = iota
	pushRejected
	pushRejectedTransient
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
			if transientRejection(e.Err) {
				return pushRejectedTransient, fmt.Sprintf("%s: %s", e.Err, e.Description)
			}
			return pushRejected, fmt.Sprintf("%s: %s", e.Err, e.Description)
		}
		return pushRetry, "HTTP 400 without an RFC 8935 error body"
	default:
		return pushRetry, fmt.Sprintf("HTTP %d", res.StatusCode)
	}
}
