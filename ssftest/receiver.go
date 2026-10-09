package ssftest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/scim"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

// WaitTimeout bounds how long Receiver.WaitFor waits.
var WaitTimeout = 10 * time.Second

// Receiver is an SSFgo Receiver with a push endpoint on a TLS test server,
// for testing a Transmitter. It verifies and records every SET it is
// pushed or polls.
//
// It is set up in two steps, since the Transmitter under test needs the
// Receiver's PushClient when it is built, and the Receiver needs the
// Transmitter's issuer: NewReceiver starts the push endpoint, and Connect
// connects the Receiver to the Transmitter.
type Receiver struct {
	t    testing.TB
	rx   *receiver.Receiver
	srv  *httptest.Server
	auth string

	mu       sync.Mutex
	received []ssf.SET
	arrived  chan struct{}
}

// NewReceiver starts the Receiver's push endpoint, closed when the test
// ends. Call Connect before anything else but PushClient and
// PushStreamRequest.
func NewReceiver(t testing.TB) *Receiver {
	t.Helper()
	secret := make([]byte, 16)
	_, _ = rand.Read(secret)
	rr := &Receiver{t: t, auth: "Bearer " + hex.EncodeToString(secret), arrived: make(chan struct{}, 1)}
	rr.srv = httptest.NewUnstartedServer(http.NotFoundHandler())
	rr.srv.StartTLS()
	t.Cleanup(rr.srv.Close)
	return rr
}

// Connect connects the Receiver to the Transmitter cfg names. cfg must set
// Issuer, Audience, TokenSource and an HTTPClient that trusts the
// Transmitter; Connect fills in a registry of every SSF, CAEP, RISC and
// SCIM event type, every signature algorithm, development assurance,
// recommended limits, an in-memory replay store and a quiet logger where
// they are unset. The test fails if the Receiver cannot be built.
func (rr *Receiver) Connect(cfg receiver.Config) {
	t := rr.t
	t.Helper()
	if cfg.Registry == nil {
		cfg.Registry = ssf.NewRegistry()
		for _, register := range []func(*ssf.Registry) error{caep.Register, risc.Register, scim.Register} {
			if err := register(cfg.Registry); err != nil {
				t.Fatalf("ssftest: registry: %v", err)
			}
		}
	}
	if cfg.Algorithms == nil {
		cfg.Algorithms = ssf.SignatureAlgorithms()
	}
	if cfg.Assurance == 0 {
		cfg.Assurance = ssf.AssuranceDevelopment
	}
	if cfg.Limits == (receiver.Limits{}) {
		cfg.Limits = receiver.RecommendedLimits()
	}
	if cfg.ReplayStore == nil {
		cfg.ReplayStore = memstore.NewReplayStore()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	rx, err := receiver.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("ssftest: receiver: %v", err)
	}
	for _, typ := range cfg.Registry.Types() {
		rx.Handle(typ, rr.record)
	}
	rr.rx = rx
	rr.srv.Config.Handler = rx.PushHandler(receiver.PushOptions{AuthorizationHeader: ssf.NewSecret(rr.auth)})
}

func (rr *Receiver) record(_ context.Context, set ssf.SET) error {
	rr.mu.Lock()
	rr.received = append(rr.received, set)
	rr.mu.Unlock()
	select {
	case rr.arrived <- struct{}{}:
	default:
	}
	return nil
}

// Receiver returns the underlying Receiver, for stream management and
// polling; nil before Connect.
func (rr *Receiver) Receiver() *receiver.Receiver { return rr.rx }

// PushStreamRequest asks for a push stream to this Receiver's endpoint,
// with the Authorization header it requires.
func (rr *Receiver) PushStreamRequest() receiver.StreamRequest {
	return receiver.StreamRequest{Delivery: &ssf.Delivery{
		Method:              ssf.DeliveryPush,
		EndpointURL:         rr.srv.URL + "/ssf/push",
		AuthorizationHeader: ssf.NewSecret(rr.auth),
	}}
}

// PushClient is an HTTP client that trusts the Receiver's test
// certificate: the Transmitter under test pushes with it. (Its default
// push client refuses loopback addresses.)
func (rr *Receiver) PushClient() *http.Client { return rr.srv.Client() }

// Received returns every SET received so far, in order of arrival.
func (rr *Receiver) Received() []ssf.SET {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	return append([]ssf.SET(nil), rr.received...)
}

// WaitFor waits until at least n SETs have arrived, then returns them; the
// test fails if they do not within WaitTimeout. A poll stream's SETs
// arrive only as the test polls.
func (rr *Receiver) WaitFor(n int) []ssf.SET {
	rr.t.Helper()
	deadline := time.After(WaitTimeout)
	for {
		if got := rr.Received(); len(got) >= n {
			return got
		}
		select {
		case <-rr.arrived:
		case <-deadline:
			rr.t.Fatalf("ssftest: %d SET(s) received within %v, want %d", len(rr.Received()), WaitTimeout, n)
			return nil
		}
	}
}
