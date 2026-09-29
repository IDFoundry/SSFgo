package transmitter_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/transmitter"
)

// Benchmarks for the Transmitter on memstore. Signing dominates: each
// stream an event is routed to gets its own RS256-signed SET. Run with
//
//	go test -run '^$' -bench . ./transmitter

// roomy lifts the limits a benchmark would otherwise hit.
func roomy(c *transmitter.Config) {
	c.Limits = transmitter.Limits{StreamsPerReceiver: 10_000, QueuedSETsPerStream: 1 << 30}
}

var benchSubject = ssf.EmailSubject{Email: "alice@example.com"}

// BenchmarkEmit measures Emit routing one event to n poll streams.
func BenchmarkEmit(b *testing.B) {
	for _, n := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("streams=%d", n), func(b *testing.B) {
			f := newFixture(b, roomy)
			for range n {
				pollStream(f, "alice")
			}
			ctx := context.Background()
			b.ReportAllocs()
			for b.Loop() {
				if err := f.tx.Emit(ctx, benchSubject, revoked()); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(n*b.N)/b.Elapsed().Seconds(), "SETs/s")
		})
	}
}

// BenchmarkPoll measures one poll request over HTTPS that returns ten
// queued SETs, without acknowledging them.
func BenchmarkPoll(b *testing.B) {
	f := newFixture(b, roomy)
	c := pollStream(f, "alice")
	ctx := context.Background()
	for range 10 {
		if err := f.tx.Emit(ctx, benchSubject, revoked()); err != nil {
			b.Fatal(err)
		}
	}
	body := map[string]any{"returnImmediately": true, "maxEvents": 10}
	b.ReportAllocs()
	for b.Loop() {
		r := f.do("POST", c.Delivery.EndpointURL, "alice", body)
		if r.status != http.StatusOK {
			b.Fatalf("poll: %d %s", r.status, r.body)
		}
	}
}

// BenchmarkPush measures push delivery over HTTPS: b.N SETs queued on one
// stream, then delivered one at a time by Run, as RFC 8935 requires.
func BenchmarkPush(b *testing.B) {
	var received atomic.Int64
	done := make(chan struct{})
	rx := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		if received.Add(1) == int64(b.N) {
			close(done)
		}
	}))
	b.Cleanup(rx.Close)
	f := newFixture(b, roomy, func(c *transmitter.Config) { c.HTTPClient = rx.Client() })
	f.create("bob", map[string]any{"events_requested": interopEvents,
		"delivery": map[string]any{"method": ssf.DeliveryPush, "endpoint_url": rx.URL + "/events"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for range b.N {
		if err := f.tx.Emit(ctx, benchSubject, revoked()); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	go func() { _ = f.tx.Run(ctx) }()
	select {
	case <-done:
	case <-time.After(time.Minute):
		b.Fatalf("delivered %d of %d SETs", received.Load(), b.N)
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "SETs/s")
}
