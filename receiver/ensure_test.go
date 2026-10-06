package receiver_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/transmitter"
)

func streamCount(t *testing.T, rx *receiver.Receiver) int {
	t.Helper()
	streams, err := rx.Streams(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return len(streams)
}

// Called on every start, EnsureStream creates the stream once and then
// reuses it.
func TestEnsureStreamCreatesThenReuses(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	first, err := e.rx.EnsureStream(ctx, receiver.StreamRequest{Description: "orders"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := e.rx.EnsureStream(ctx, receiver.StreamRequest{Description: "orders"})
	if err != nil {
		t.Fatal(err)
	}
	if again.StreamID != first.StreamID || streamCount(t, e.rx) != 1 {
		t.Errorf("second call gave stream %s, %d streams; want the first, %s, alone", again.StreamID, streamCount(t, e.rx), first.StreamID)
	}
}

// A reused stream is brought up to date: the events requested and the
// description.
func TestEnsureStreamUpdates(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	first, err := e.rx.EnsureStream(ctx, receiver.StreamRequest{Description: "old"})
	if err != nil {
		t.Fatal(err)
	}
	want := []ssf.EventType{caep.SessionRevokedEventType}
	got, err := e.rx.EnsureStream(ctx, receiver.StreamRequest{Description: "new", EventsRequested: want})
	if err != nil {
		t.Fatal(err)
	}
	if got.StreamID != first.StreamID || got.Description != "new" || !slices.Equal(got.EventsRequested, want) {
		t.Errorf("updated stream = %+v", got)
	}
}

// Push streams are told apart by endpoint; a new authorization_header is
// applied to the existing stream.
func TestEnsureStreamPush(t *testing.T) {
	e := newEnvTx(t, func(c *transmitter.Config) { c.MultipleStreamsPerReceiver = true })
	ctx := context.Background()
	push := func(endpoint, auth string) receiver.StreamRequest {
		return receiver.StreamRequest{Delivery: &ssf.Delivery{Method: ssf.DeliveryPush, EndpointURL: endpoint, AuthorizationHeader: auth}}
	}
	a, err := e.rx.EnsureStream(ctx, push("https://rx.example/a", "Bearer one"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.rx.EnsureStream(ctx, push("https://rx.example/b", "Bearer one"))
	if err != nil {
		t.Fatal(err)
	}
	if a.StreamID == b.StreamID {
		t.Error("a different push endpoint reused the stream")
	}
	rotated, err := e.rx.EnsureStream(ctx, push("https://rx.example/a", "Bearer two"))
	if err != nil {
		t.Fatal(err)
	}
	if rotated.StreamID != a.StreamID || rotated.Delivery.AuthorizationHeader != "Bearer two" {
		t.Errorf("rotated stream = %+v, want %s with the new header", rotated, a.StreamID)
	}
	if n := streamCount(t, e.rx); n != 2 {
		t.Errorf("%d streams, want 2", n)
	}
}

// A Transmitter allowing one stream per Receiver has its stream replaced
// when the delivery method changes.
func TestEnsureStreamReplacesOnlyStream(t *testing.T) {
	e := newEnv(t) // one stream per Receiver
	ctx := context.Background()
	poll, err := e.rx.EnsureStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	pushed, err := e.rx.EnsureStream(ctx, receiver.StreamRequest{Delivery: &ssf.Delivery{Method: ssf.DeliveryPush, EndpointURL: "https://rx.example/push"}})
	if err != nil {
		t.Fatal(err)
	}
	if pushed.StreamID != poll.StreamID || pushed.Delivery.Method != ssf.DeliveryPush {
		t.Errorf("stream = %+v, want %s switched to push", pushed, poll.StreamID)
	}
}

// While the Transmitter is unavailable EnsureStream retries; an error that
// will not clear is returned at once.
func TestEnsureStreamRetries(t *testing.T) {
	receiver.SetEnsureRetry(t, 10*time.Millisecond)
	e := newEnv(t)
	tx := e.txSrv.Config.Handler
	// The handler can still be answering a request EnsureStream gave up
	// on, so the test changes what it answers only atomically.
	var failures, status atomic.Int32
	status.Store(http.StatusServiceUnavailable)
	e.txSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failures.Add(-1) >= 0 {
			w.WriteHeader(int(status.Load()))
			return
		}
		tx.ServeHTTP(w, r)
	})
	ctx := context.Background()

	failures.Store(3)
	if _, err := e.rx.EnsureStream(ctx, receiver.StreamRequest{}); err != nil {
		t.Errorf("after three 503s: %v", err)
	}

	failures.Store(1000)
	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := e.rx.EnsureStream(short, receiver.StreamRequest{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("while unavailable until the deadline: %v", err)
	}

	status.Store(http.StatusForbidden)
	failures.Store(1000)
	start := time.Now()
	var apiErr *receiver.APIError
	if _, err := e.rx.EnsureStream(ctx, receiver.StreamRequest{}); !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("403: %v", err)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Error("a 403 was retried")
	}
}
