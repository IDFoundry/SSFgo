package receiver_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

// secondInstance returns another Receiver with e's configuration, sharing
// its ReplayStore, as a second process of the same deployment would.
func secondInstance(t *testing.T, e *env) *receiver.Receiver {
	t.Helper()
	rx, err := receiver.New(context.Background(), e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return rx
}

func TestPushRedeliveryToAnotherInstanceDuringHandling(t *testing.T) {
	e := newEnv(t)
	other := secondInstance(t, e)
	started, release := make(chan struct{}), make(chan struct{})
	receiver.On(e.rx, func(context.Context, ssf.SET, caep.SessionRevoked) error {
		close(started)
		<-release
		return errors.New("handler failed")
	})
	var otherCalls int
	receiver.On(other, func(context.Context, ssf.SET, caep.SessionRevoked) error {
		otherCalls++
		return nil
	})
	token := sign(t, e, nil)

	// The first copy is being handled by one instance when the Transmitter
	// retries and reaches the other. The retry must not be acknowledged:
	// the first instance's handling may yet fail.
	first := make(chan pushResult, 1)
	go func() { first <- push(t, e.rx.PushHandler(receiver.PushOptions{}), "", token) }()
	<-started
	if got := push(t, other.PushHandler(receiver.PushOptions{}), "", token); got.status != 500 {
		t.Fatalf("retry to the other instance: %d while the first was handling it, want 500 so the Transmitter retries", got.status)
	}
	close(release)
	if got := <-first; got.status != 500 {
		t.Fatalf("first delivery: %d, want 500", got.status)
	}
	// The first handling failed, so the next retry is handled.
	if got := push(t, other.PushHandler(receiver.PushOptions{}), "", token); got.status != 202 || otherCalls != 1 {
		t.Errorf("later retry: %d after %d handler calls, want 202 after 1", got.status, otherCalls)
	}
}

func TestPollRedeliveryToAnotherInstanceDuringHandling(t *testing.T) {
	e := newEnv(t)
	other := secondInstance(t, e)
	started, release := make(chan struct{}), make(chan struct{})
	receiver.On(e.rx, func(context.Context, ssf.SET, caep.SessionRevoked) error {
		close(started)
		<-release
		return errors.New("handler failed")
	})
	receiver.On(other, func(context.Context, ssf.SET, caep.SessionRevoked) error { return nil })
	token := sign(t, e, func(s *ssf.SET) { s.JWTID = "polled" })

	first := make(chan pushResult, 1)
	go func() { first <- push(t, e.rx.PushHandler(receiver.PushOptions{}), "", token) }()
	<-started
	// The other instance polls the same SET while the first handles it:
	// it must neither acknowledge it nor report it as an error, so the
	// Transmitter delivers it again.
	ack, errs := receiver.ProcessPolled(other, "stream", map[string]string{"polled": token})
	if len(ack) != 0 || len(errs) != 0 {
		t.Errorf("polled while handled elsewhere: ack %v, errors %v; want neither", ack, errs)
	}
	close(release)
	<-first
	if ack, _ := receiver.ProcessPolled(other, "stream", map[string]string{"polled": token}); len(ack) != 1 {
		t.Errorf("polled after the first handling failed: ack %v, want it handled and acknowledged", ack)
	}
}

func TestRedeliveryAfterCrashMidHandling(t *testing.T) {
	replay := memstore.NewReplayStore()
	e := newEnv(t, func(c *receiver.Config) { c.ReplayStore = replay })
	var calls atomic.Int32
	receiver.On(e.rx, func(context.Context, ssf.SET, caep.SessionRevoked) error {
		calls.Add(1)
		return nil
	})
	token := sign(t, e, func(s *ssf.SET) { s.JWTID = "crash" })
	// A process claimed the SET and crashed while handling it: its claim
	// is never renewed, completed or released.
	if _, err := replay.ClaimSET(context.Background(), e.cfg.Issuer, "crash", "crashed", time.Now().Add(200*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	h := e.rx.PushHandler(receiver.PushOptions{})
	if got := push(t, h, "", token); got.status != 500 || calls.Load() != 0 {
		t.Fatalf("redelivery during the crashed claim's lease: %d after %d handler calls, want 500 after 0", got.status, calls.Load())
	}
	time.Sleep(300 * time.Millisecond)
	if got := push(t, h, "", token); got.status != 202 || calls.Load() != 1 {
		t.Errorf("redelivery once the lease ended: %d after %d handler calls, want 202 after 1", got.status, calls.Load())
	}
	if got := push(t, h, "", token); got.status != 202 || calls.Load() != 1 {
		t.Errorf("another redelivery: %d after %d handler calls, want 202 (a duplicate) after 1", got.status, calls.Load())
	}
}

func TestPollAcknowledgementLostInRestart(t *testing.T) {
	// A polled SET's acknowledgement waits, in memory, for the next poll.
	// If the process stops first, the Transmitter returns the SET to the
	// restarted process, which must acknowledge it without handling it
	// again: the shared replay store, not the lost acknowledgement,
	// records that it was handled.
	e := newEnv(t)
	var calls atomic.Int32
	receiver.On(e.rx, func(context.Context, ssf.SET, caep.SessionRevoked) error {
		calls.Add(1)
		return nil
	})
	token := sign(t, e, func(s *ssf.SET) { s.JWTID = "unacked" })
	// Handled, and its acknowledgement lost with the process.
	_, _ = receiver.ProcessPolled(e.rx, "stream", map[string]string{"unacked": token})

	restarted := secondInstance(t, e)
	receiver.On(restarted, func(context.Context, ssf.SET, caep.SessionRevoked) error {
		calls.Add(1)
		return nil
	})
	ack, errs := receiver.ProcessPolled(restarted, "stream", map[string]string{"unacked": token})
	if len(ack) != 1 || len(errs) != 0 || calls.Load() != 1 {
		t.Errorf("returned to the restarted process: ack %v, errors %v after %d handler calls; want it acknowledged after 1", ack, errs, calls.Load())
	}
}

func TestClaimRenewedWhileHandling(t *testing.T) {
	receiver.SetClaimLease(t, 150*time.Millisecond)
	e := newEnv(t)
	other := secondInstance(t, e)
	release := make(chan struct{})
	receiver.On(e.rx, func(context.Context, ssf.SET, caep.SessionRevoked) error {
		<-release
		return nil
	})
	var otherCalls atomic.Int32
	receiver.On(other, func(context.Context, ssf.SET, caep.SessionRevoked) error {
		otherCalls.Add(1)
		return nil
	})
	token := sign(t, e, nil)

	first := make(chan pushResult, 1)
	go func() { first <- push(t, e.rx.PushHandler(receiver.PushOptions{}), "", token) }()
	// The handler outlasts several leases; renewal keeps the claim.
	time.Sleep(500 * time.Millisecond)
	if got := push(t, other.PushHandler(receiver.PushOptions{}), "", token); got.status != 500 || otherCalls.Load() != 0 {
		t.Fatalf("retry to the other instance during a long handling: %d after %d calls, want 500 after 0", got.status, otherCalls.Load())
	}
	close(release)
	if got := <-first; got.status != 202 {
		t.Fatalf("first delivery: %d, want 202", got.status)
	}
	if got := push(t, other.PushHandler(receiver.PushOptions{}), "", token); got.status != 202 || otherCalls.Load() != 0 {
		t.Errorf("retry after the handling succeeded: %d after %d calls, want 202 (a duplicate) after 0", got.status, otherCalls.Load())
	}
}
