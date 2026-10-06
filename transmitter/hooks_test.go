package transmitter_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/transmitter"
)

// txHooks records what the Transmitter's hooks report.
type txHooks struct {
	mu      sync.Mutex
	emits   []transmitter.EmitInfo
	pushes  []transmitter.PushInfo
	polls   []transmitter.PollInfo
	streams []transmitter.StreamInfo
}

func (h *txHooks) hooks() transmitter.Hooks {
	return transmitter.Hooks{
		Emit: func(_ context.Context, i transmitter.EmitInfo) {
			h.mu.Lock()
			h.emits = append(h.emits, i)
			h.mu.Unlock()
		},
		Push: func(_ context.Context, i transmitter.PushInfo) {
			h.mu.Lock()
			h.pushes = append(h.pushes, i)
			h.mu.Unlock()
		},
		Poll: func(_ context.Context, i transmitter.PollInfo) {
			h.mu.Lock()
			h.polls = append(h.polls, i)
			h.mu.Unlock()
		},
		Stream: func(_ context.Context, i transmitter.StreamInfo) {
			h.mu.Lock()
			h.streams = append(h.streams, i)
			h.mu.Unlock()
		},
	}
}

func TestHooksReportStreamsEmitsAndPolls(t *testing.T) {
	var h txHooks
	f := newFixture(t, func(c *transmitter.Config) { c.Hooks = h.hooks() })
	ctx := context.Background()
	md := f.metadata()
	c := pollStream(f, "alice")
	pollStream(f, "bob")
	expect(t, f.do("PATCH", md.ConfigurationEndpoint, "alice", map[string]any{"stream_id": c.StreamID, "description": "x"}), http.StatusOK)
	expect(t, f.do("POST", md.StatusEndpoint, "alice", map[string]any{"stream_id": c.StreamID, "status": ssf.StreamPaused}), http.StatusOK)
	if err := f.tx.SetStreamStatus(ctx, c.StreamID, ssf.StreamEnabled, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.tx.Emit(ctx, alice, revoked()); err != nil {
		t.Fatal(err)
	}
	p := f.poll(c, "alice", nil)
	var jti string
	for j := range p.Sets {
		jti = j
	}
	f.poll(c, "alice", map[string]any{"returnImmediately": true, "ack": []string{jti}})
	expect(t, f.do("DELETE", md.ConfigurationEndpoint+"?stream_id="+c.StreamID, "alice", nil), http.StatusNoContent)

	h.mu.Lock()
	defer h.mu.Unlock()
	var changes []transmitter.StreamChange
	byTx := 0
	for _, s := range h.streams {
		if s.StreamID == c.StreamID {
			changes = append(changes, s.Change)
			if s.ByTransmitter {
				byTx++
			}
		}
	}
	want := []transmitter.StreamChange{transmitter.StreamCreated, transmitter.StreamUpdated, transmitter.StreamStatusChanged, transmitter.StreamStatusChanged, transmitter.StreamDeleted}
	if len(changes) != len(want) || byTx != 1 {
		t.Fatalf("stream changes %v (%d by the Transmitter), want %v (1)", changes, byTx, want)
	}
	for i := range want {
		if changes[i] != want[i] {
			t.Errorf("change %d = %v, want %v", i, changes[i], want[i])
		}
	}
	// default_subjects is ALL: both streams get the event.
	if len(h.emits) != 1 || h.emits[0].Streams != 2 || h.emits[0].Queued != 2 || h.emits[0].Err != nil {
		t.Errorf("emit reports %+v, want one queuing on both streams", h.emits)
	}
	// The first poll returns the event and the stream-updated event the
	// re-enabling sent; the second acknowledges one of them.
	if len(h.polls) != 2 || h.polls[0].Returned != 2 || h.polls[1].Acknowledged != 1 || h.polls[1].Returned != 1 {
		t.Errorf("poll reports %+v", h.polls)
	}
}

func TestHooksReportPushes(t *testing.T) {
	var h txHooks
	rx := newPushReceiver(t)
	rx.respond = func(n int) (int, string) {
		if n == 1 {
			return http.StatusServiceUnavailable, ""
		}
		return http.StatusAccepted, ""
	}
	f := newFixture(t, func(c *transmitter.Config) { c.HTTPClient = rx.srv.Client(); c.Hooks = h.hooks() })
	pushStream(f, rx, "")
	runTransmitter(t, f)
	if err := f.tx.Emit(context.Background(), bob, revoked()); err != nil {
		t.Fatal(err)
	}
	rx.wait(t, 2)
	waitFor(t, func() bool { h.mu.Lock(); defer h.mu.Unlock(); return len(h.pushes) == 2 })
	h.mu.Lock()
	defer h.mu.Unlock()
	first, second := h.pushes[0], h.pushes[1]
	if first.Outcome != transmitter.PushRetry || first.Attempt != 1 || second.Outcome != transmitter.PushDelivered || second.Attempt != 2 {
		t.Errorf("push reports %+v, %+v", first, second)
	}
}

type brokenStore struct{ storage.StreamStore }

func (brokenStore) Stream(context.Context, string) (storage.Stream, error) {
	return storage.Stream{}, errors.New("database down")
}

func TestTransmitterReady(t *testing.T) {
	f := newFixture(t)
	if err := f.tx.Ready(context.Background()); err != nil {
		t.Errorf("Ready: %v", err)
	}
	broken := newFixture(t, func(c *transmitter.Config) { c.Store = brokenStore{c.Store} })
	if err := broken.tx.Ready(context.Background()); err == nil {
		t.Error("Ready with the store down")
	}
}
