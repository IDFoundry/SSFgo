package easyssf

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/easyssf/easyssf-go/receiver"
	"github.com/idfoundry/ssfgo/ssftest"
	"github.com/idfoundry/ssfgo/transmitter"
)

// TestEasySSFGo runs easyssf-go against an SSFgo Transmitter, with each
// delivery method. It needs nothing outside the test, so it always runs.
func TestEasySSFGo(t *testing.T) {
	for _, delivery := range []string{"push", "poll"} {
		t.Run(delivery, func(t *testing.T) {
			// easyssf-go's push endpoint, on a TLS test server; the
			// Transmitter pushes with a client that trusts it.
			mux := http.NewServeMux()
			push := httptest.NewTLSServer(mux)
			t.Cleanup(push.Close)
			tx := ssftest.NewTransmitter(t, func(c *transmitter.Config) { c.HTTPClient = push.Client() })

			p := newGoPeer(t, tx, delivery, push.URL)
			mux.Handle("POST "+p.rcv.PushEndpointPath(), p.rcv.PushHandler())
			run(t, tx, p, delivery)
		})
	}
}

// goPeer is easyssf-go's Receiver, registering its own stream.
type goPeer struct {
	rcv      *receiver.Receiver
	delivery string
	got      chan received
	stop     func()
}

func newGoPeer(t *testing.T, tx *ssftest.Transmitter, delivery, pushBase string) *goPeer {
	t.Helper()
	ctx := context.Background()
	token, err := tx.ReceiverConfig(nil).TokenSource.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}

	cfg := receiver.DefaultConfig()
	cfg.Enabled = true
	cfg.TransmitterIssuer = tx.Issuer()
	cfg.TransmitterAccessToken = token
	cfg.DeliveryMethod = delivery
	cfg.Stream.Management = "receiver"
	cfg.Stream.EventsRequested = []string{"CaepSessionRevoked", "RiscAccountDisabled"}
	cfg.Stream.DeleteOnShutdown = true
	if delivery == "push" {
		cfg.Push.DeliveryEndpointURL = pushBase + "/ssf/push"
		cfg.Push.ExpectedAuthHeader = "Bearer push-" + t.Name()
	} else {
		cfg.Poll.Interval = receiver.D(200 * time.Millisecond)
	}

	p := &goPeer{delivery: delivery, got: make(chan received, len(events))}
	record := func(_ context.Context, event *receiver.Context) error {
		for _, typ := range event.EventTypes() {
			p.got <- received{EventType: typ, Email: event.SubjectFor(typ).Email(), Delivery: delivery}
		}
		return nil
	}
	p.rcv, err = receiver.New(cfg,
		receiver.WithHTTPClient(tx.Client()),
		receiver.WithLogger(slog.New(slog.NewTextHandler(testWriter{t}, nil))),
		receiver.WithHandler(
			receiver.ForEventFunc("CaepSessionRevoked", record),
			receiver.ForEventFunc("RiscAccountDisabled", record)))
	if err != nil {
		t.Fatalf("easyssf-go refused its configuration: %v", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	p.rcv.Start(runCtx)
	p.stop = sync.OnceFunc(func() {
		stopCtx, stop := context.WithTimeout(context.Background(), waitTimeout)
		defer stop()
		p.rcv.Stop(stopCtx)
		cancel()
	})
	t.Cleanup(p.stop)
	return p
}

func (p *goPeer) Stop(*testing.T) { p.stop() }

func (p *goPeer) transmitter() *receiver.Transmitter { return p.rcv.Transmitters()[0] }

func (p *goPeer) StreamID(t *testing.T) string {
	t.Helper()
	var id string
	waitUntil(t, "easyssf-go registers its stream", func() bool {
		id = p.transmitter().Stream.StreamID()
		return id != ""
	})
	return id
}

func (p *goPeer) Verify(t *testing.T) {
	t.Helper()
	tr := p.transmitter()
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	if err := tr.StreamClient.RequestVerification(ctx, tr.Stream.StreamID(), tr.Verification.NewState()); err != nil {
		t.Fatalf("easyssf-go's verification request failed: %v", err)
	}
	if !tr.Verification.IsPending() {
		t.Fatal("easyssf-go has no verification pending after requesting one")
	}
	waitUntil(t, "easyssf-go accepts the verification event", func() bool { return !tr.Verification.IsPending() })
}

func (p *goPeer) Next(t *testing.T) received {
	t.Helper()
	select {
	case r := <-p.got:
		return r
	case <-time.After(waitTimeout):
		t.Fatalf("easyssf-go handled no event within %s", waitTimeout)
		return received{}
	}
}

// waitUntil polls cond until it holds, failing the test after waitTimeout.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// testWriter sends a peer's log to the test's, so a failure shows why.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	w.t.Helper()
	w.t.Log(strings.TrimRight(string(b), "\n"))
	return len(b), nil
}

var _ io.Writer = testWriter{}
