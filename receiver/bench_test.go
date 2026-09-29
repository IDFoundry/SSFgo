package receiver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/transmitter"
)

// BenchmarkPushHandler measures the Receiver taking delivery of one pushed
// SET: signature and claim verification, the replay check and dispatch to
// a handler. Run with
//
//	go test -run '^$' -bench . ./receiver
func BenchmarkPushHandler(b *testing.B) {
	e := newEnvTx(b, func(c *transmitter.Config) {
		c.Limits = transmitter.Limits{QueuedSETsPerStream: 1 << 30}
	})
	var rec recorder
	rec.install(e.rx)
	ctx := context.Background()
	stream, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		b.Fatal(err)
	}
	// Distinct SETs, so none is recognised as a replay.
	for range b.N {
		if err := e.tx.Emit(ctx, alice, revoked()); err != nil {
			b.Fatal(err)
		}
	}
	queued, err := e.store.PendingEvents(ctx, stream.StreamID, 0, false)
	if err != nil || len(queued) != b.N {
		b.Fatalf("queued %d SETs, %v; want %d", len(queued), err, b.N)
	}
	h := e.rx.PushHandler(receiver.PushOptions{})

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(queued[i].SET))
		req.Header.Set("Content-Type", "application/secevent+jwt")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusAccepted {
			b.Fatalf("push %d: %d %s", i, w.Code, w.Body)
		}
	}
}
