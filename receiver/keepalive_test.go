package receiver_test

import (
	"context"
	"errors"
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
