package ssftest_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/ssftest"
	"github.com/idfoundry/ssfgo/transmitter"
)

var alice = ssf.EmailSubject{Email: "alice@example.com"}

func revoked() caep.SessionRevoked {
	return caep.SessionRevoked{Common: caep.Common{ReasonAdmin: ssf.LocalizedText{"en": "test"}}}
}

func caepRegistry(t *testing.T) *ssf.Registry {
	t.Helper()
	r := ssf.NewRegistry()
	if err := caep.Register(r); err != nil {
		t.Fatal(err)
	}
	return r
}

// A Receiver under test polls the test Transmitter, and copes with it
// being unavailable.
func TestReceiverPolling(t *testing.T) {
	ctx := context.Background()
	tx := ssftest.NewTransmitter(t)
	rx, err := receiver.New(ctx, tx.ReceiverConfig(caepRegistry(t)))
	if err != nil {
		t.Fatal(err)
	}
	var revokedFor []ssf.Subject
	receiver.On(rx, func(_ context.Context, set ssf.SET, _ caep.SessionRevoked) error {
		revokedFor = append(revokedFor, set.Subject)
		return nil
	})
	stream, err := rx.EnsureStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Emit(ctx, alice, revoked()); err != nil {
		t.Fatal(err)
	}

	tx.SetAvailable(false)
	if _, err := rx.Poll(ctx, stream, receiver.PollOptions{}); err == nil {
		t.Error("poll succeeded while the Transmitter was unavailable")
	}
	tx.SetAvailable(true)
	if _, err := rx.Poll(ctx, stream, receiver.PollOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(revokedFor) != 1 || !ssf.SubjectsEqual(revokedFor[0], alice) {
		t.Errorf("handled session-revoked for %v, want alice once", revokedFor)
	}
}

// A Receiver under test takes push delivery from the test Transmitter.
func TestReceiverPush(t *testing.T) {
	ctx := context.Background()
	// The Receiver's push endpoint exists first, so the Transmitter can be
	// given a client that trusts it.
	app := httptest.NewUnstartedServer(nil)
	app.StartTLS()
	t.Cleanup(app.Close)
	tx := ssftest.NewTransmitter(t, func(c *transmitter.Config) { c.HTTPClient = app.Client() })

	rx, err := receiver.New(ctx, tx.ReceiverConfig(caepRegistry(t)))
	if err != nil {
		t.Fatal(err)
	}
	handled := make(chan ssf.SET, 1)
	receiver.On(rx, func(_ context.Context, set ssf.SET, _ caep.SessionRevoked) error {
		handled <- set
		return nil
	})
	app.Config.Handler = rx.PushHandler(receiver.PushOptions{AuthorizationHeader: ssf.NewSecret("Bearer push")})
	if _, err := rx.EnsureStream(ctx, receiver.StreamRequest{Delivery: &ssf.Delivery{
		Method: ssf.DeliveryPush, EndpointURL: app.URL + "/events", AuthorizationHeader: ssf.NewSecret("Bearer push"),
	}}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Emit(ctx, alice, revoked()); err != nil {
		t.Fatal(err)
	}
	select {
	case set := <-handled:
		if !ssf.SubjectsEqual(set.Subject, alice) {
			t.Errorf("pushed SET about %v", set.Subject)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no SET pushed")
	}
}

// A Transmitter under test — here SSFgo's own — delivers to the test
// Receiver.
func TestTransmitterPush(t *testing.T) {
	ctx := context.Background()
	rx := ssftest.NewReceiver(t)
	tx := ssftest.NewTransmitter(t, func(c *transmitter.Config) { c.HTTPClient = rx.PushClient() })
	rx.Connect(tx.ReceiverConfig(nil))
	if _, err := rx.Receiver().CreateStream(ctx, rx.PushStreamRequest()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Emit(ctx, alice, revoked()); err != nil {
		t.Fatal(err)
	}
	sets := rx.WaitFor(1)
	if _, ok := sets[0].Event.(caep.SessionRevoked); !ok || !ssf.SubjectsEqual(sets[0].Subject, alice) {
		t.Errorf("received %+v", sets[0])
	}
}
