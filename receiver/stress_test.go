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
			counts := &subjectCounts{seen: map[string]int{}}
			receiver.On(e.rx, func(_ context.Context, set ssf.SET, _ caep.SessionRevoked) error {
				counts.add(set.Subject.(ssf.EmailSubject).Email)
				return nil
			})
			startDelivery(t, e, method)
			emitConcurrently(t, e, emitters, perEmitter)
			counts.waitFor(t, emitters*perEmitter)
		})
	}
}

// startDelivery creates a stream using method and starts delivering on it
// until the test ends.
func startDelivery(t *testing.T, e *env, method ssf.DeliveryMethod) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req := receiver.StreamRequest{}
	if method == ssf.DeliveryPush {
		pushSrv := httptest.NewTLSServer(e.rx.PushHandler(receiver.PushOptions{}))
		t.Cleanup(pushSrv.Close)
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
}

func emitConcurrently(t *testing.T, e *env, emitters, perEmitter int) {
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
}

// subjectCounts counts how often each subject's event was handled.
type subjectCounts struct {
	mu   sync.Mutex
	seen map[string]int
}

func (c *subjectCounts) add(subject string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen[subject]++
}

// waitFor waits until want distinct subjects were handled, then checks
// none was handled twice.
func (c *subjectCounts) waitFor(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		c.mu.Lock()
		n := len(c.seen)
		c.mu.Unlock()
		if n == want {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("handled %d distinct events, want %d", n, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for subject, count := range c.seen {
		if count != 1 {
			t.Errorf("%s handled %d times", subject, count)
		}
	}
}
