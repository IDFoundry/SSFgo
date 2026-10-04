package transmitter

import (
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
)

// A notifier entry lasts only while someone waits on it, so streams that
// are created, polled and deleted leave nothing behind.
func TestNotifierForgetsIdleKeys(t *testing.T) {
	n := newNotifier()
	for i := range 1000 {
		_, done := n.wait(randomID())
		if i%2 == 0 {
			n.notify(anyStream) // only wakes anyStream waiters
		}
		done()
	}
	// A key notified while waited on, then waited on again.
	wake, done := n.wait("s")
	n.notify("s")
	<-wake
	_, done2 := n.wait("s")
	done() // the first waiter's entry is gone; this must not drop the second's
	if len(n.waiting) != 1 {
		t.Fatalf("%d entries while one waiter remains, want 1", len(n.waiting))
	}
	done2()
	if len(n.waiting) != 0 {
		t.Errorf("%d notifier entries left with no one waiting", len(n.waiting))
	}
}

// Push state is dropped for streams that no longer push.
func TestPushStatePruned(t *testing.T) {
	p := newPushState(PushRetryPolicy{MinBackoff: time.Second, MaxBackoff: time.Minute})
	var live []storage.Stream
	for i := range 1000 {
		id := randomID()
		p.claim(id, time.Now())
		p.release(id, true, time.Now())
		if i < 3 {
			live = append(live, storage.Stream{ID: id, Delivery: ssf.Delivery{Method: ssf.DeliveryPush}})
		}
	}
	busy := randomID()
	p.claim(busy, time.Now())
	p.prune(live)
	if len(p.streams) != 4 {
		t.Errorf("%d push states after pruning, want the 3 live streams and the busy one", len(p.streams))
	}
}
