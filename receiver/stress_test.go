package receiver_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
)

// TestConcurrentDelivery emits events from many goroutines at once and
// checks each is handled exactly once — no loss, no duplicate — through
// both delivery methods, end to end.
func TestConcurrentDelivery(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	const emitters, perEmitter = 20, 25
	for _, method := range []ssf.DeliveryMethod{ssf.DeliveryPoll, ssf.DeliveryPush} {
		t.Run(string(method), func(t *testing.T) {
			e := newEnv(t)
			var mu sync.Mutex
			seen := map[string]int{}
			receiver.On(e.rx, func(_ context.Context, set ssf.SET, _ caep.SessionRevoked) error {
				mu.Lock()
				defer mu.Unlock()
				seen[set.Subject.(ssf.EmailSubject).Email]++
				return nil
			})

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req := receiver.StreamRequest{}
			if method == ssf.DeliveryPush {
				pushSrv := httptest.NewTLSServer(e.rx.PushHandler(receiver.PushOptions{}))
				defer pushSrv.Close()
				e.setTransmitterClient(pushSrv.Client())
				req.Delivery = &ssf.Delivery{Method: ssf.DeliveryPush, EndpointURL: pushSrv.URL}
				go func() { _ = e.tx.Run(ctx) }()
			}
			stream, err := e.rx.CreateStream(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if method == ssf.DeliveryPoll {
				go func() { _ = e.rx.RunPoller(ctx, stream) }()
			}

			var wg sync.WaitGroup
			for g := range emitters {
				wg.Go(func() {
					for i := range perEmitter {
						subject := ssf.EmailSubject{Email: fmt.Sprintf("user-%d-%d@example.com", g, i)}
						if err := e.tx.Emit(context.Background(), subject, revoked()); err != nil {
							t.Error(err)
						}
					}
				})
			}
			wg.Wait()

			deadline := time.Now().Add(30 * time.Second)
			for {
				mu.Lock()
				n := len(seen)
				mu.Unlock()
				if n == emitters*perEmitter {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("handled %d distinct events, want %d", n, emitters*perEmitter)
				}
				time.Sleep(50 * time.Millisecond)
			}
			mu.Lock()
			defer mu.Unlock()
			for subject, count := range seen {
				if count != 1 {
					t.Errorf("%s handled %d times", subject, count)
				}
			}
		})
	}
}
