package receiver_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/transmitter"
)

func withInactivity(timeout time.Duration) func(*transmitter.Config) {
	return func(c *transmitter.Config) {
		c.MultipleStreamsPerReceiver = true
		c.Inactivity = transmitter.InactivityPolicy{Timeout: timeout, Action: transmitter.InactivityPause}
	}
}

func TestKeepAlive(t *testing.T) {
	e := newEnvTx(t, withInactivity(time.Second))
	ctx := context.Background()
	kept, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	idle, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if kept.InactivityTimeout != 1 {
		t.Fatalf("inactivity_timeout = %d, want 1", kept.InactivityTimeout)
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error)
	go func() { done <- e.rx.KeepAlive(runCtx, kept.StreamID) }()
	time.Sleep(1600 * time.Millisecond)
	if err := e.tx.ExpireInactiveStreams(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("KeepAlive = %v, want context.Canceled", err)
	}

	for _, tc := range []struct {
		id   string
		want ssf.StreamStatus
	}{{kept.StreamID, ssf.StreamEnabled}, {idle.StreamID, ssf.StreamPaused}} {
		s, err := e.store.Stream(ctx, tc.id)
		if err != nil {
			t.Fatal(err)
		}
		if s.Status != tc.want {
			t.Errorf("stream %s status = %s, want %s", tc.id, s.Status, tc.want)
		}
	}
}

func TestKeepAliveWithoutTimeout(t *testing.T) {
	e := newEnv(t)
	stream, err := e.rx.CreateStream(context.Background(), receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.rx.KeepAlive(ctx, stream.StreamID); err != nil {
		t.Errorf("KeepAlive on a stream without inactivity_timeout = %v, want nil", err)
	}
}

func TestKeepAliveDeletedStream(t *testing.T) {
	e := newEnvTx(t, withInactivity(time.Hour))
	stream, err := e.rx.CreateStream(context.Background(), receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.rx.DeleteStream(context.Background(), stream.StreamID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.rx.KeepAlive(ctx, stream.StreamID); !errors.Is(err, receiver.ErrNotFound) {
		t.Errorf("KeepAlive on a deleted stream = %v, want ErrNotFound", err)
	}
}

// scriptedTokens is a TokenSource whose next calls succeed, fail, or block
// until the request is cancelled, as the test sets.
type scriptedTokens struct {
	mode     atomic.Int32 // tokensOK, tokensFail or tokensBlock
	failures atomic.Int32
	blocked  atomic.Bool
}

const (
	tokensOK int32 = iota
	tokensFail
	tokensBlock
)

func (s *scriptedTokens) Token(ctx context.Context) (string, error) {
	switch s.mode.Load() {
	case tokensFail:
		s.failures.Add(1)
		return "", errors.New("token endpoint unavailable")
	case tokensBlock:
		s.blocked.Store(true)
		<-ctx.Done()
		return "", ctx.Err()
	}
	return "rx-token", nil
}

func withTokens(tokens receiver.TokenSource) func(*receiver.Config) {
	return func(c *receiver.Config) { c.TokenSource = tokens }
}

// TestKeepAliveRetries checks that a failed keep-alive is retried after a
// quarter of the interval rather than a whole one, and that KeepAlive
// carries on once the Transmitter is reachable again.
func TestKeepAliveRetries(t *testing.T) {
	tokens := &scriptedTokens{}
	e := newEnvTx(t, withInactivity(2*time.Second), withTokens(tokens))
	ctx := context.Background()
	stream, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- e.rx.KeepAlive(runCtx, stream.StreamID) }()
	time.Sleep(100 * time.Millisecond) // the first, successful read

	// Interval 1s, so a retry comes after 250ms: three failures take about
	// 500ms, where waiting a whole interval each time would take 2s.
	tokens.mode.Store(tokensFail)
	start := time.Now()
	waitFor(t, func() bool { return tokens.failures.Load() >= 3 })
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Errorf("three failed keep-alives took %v; they were not retried early", took)
	}
	tokens.mode.Store(tokensOK)

	time.Sleep(2500 * time.Millisecond) // past the 2s timeout
	if err := e.tx.ExpireInactiveStreams(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("KeepAlive = %v, want context.Canceled", err)
	}
	if s, _ := e.store.Stream(ctx, stream.StreamID); s.Status != ssf.StreamEnabled {
		t.Errorf("stream status = %s after keep-alive recovered, want enabled", s.Status)
	}
}

// TestKeepAliveFailsBeforeTimeoutKnown checks that KeepAlive keeps trying
// when it cannot read the stream even once.
func TestKeepAliveFailsBeforeTimeoutKnown(t *testing.T) {
	receiver.SetKeepAliveUnknownInterval(t, 200*time.Millisecond)
	tokens := &scriptedTokens{}
	e := newEnvTx(t, withInactivity(time.Hour), withTokens(tokens))
	ctx := context.Background()
	stream, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}

	tokens.mode.Store(tokensFail)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.rx.KeepAlive(runCtx, stream.StreamID) }()
	waitFor(t, func() bool { return tokens.failures.Load() >= 3 })
	select {
	case err := <-done:
		t.Fatalf("KeepAlive gave up after failures: %v", err)
	default:
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("KeepAlive = %v, want context.Canceled", err)
	}
}

// TestKeepAliveCancelledInFlight checks that cancelling during a request
// returns the context's error, not the request's.
func TestKeepAliveCancelledInFlight(t *testing.T) {
	tokens := &scriptedTokens{}
	e := newEnvTx(t, withInactivity(time.Hour), withTokens(tokens))
	ctx := context.Background()
	stream, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}

	tokens.mode.Store(tokensBlock)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- e.rx.KeepAlive(runCtx, stream.StreamID) }()
	waitFor(t, tokens.blocked.Load)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("KeepAlive = %v, want context.Canceled", err)
	}
}
