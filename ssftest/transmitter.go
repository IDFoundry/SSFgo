package ssftest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/scim"
	"github.com/idfoundry/ssfgo/storage/memstore"
	"github.com/idfoundry/ssfgo/transmitter"
)

// ReceiverAudience is the audience the test Transmitter assigns to the
// Receiver it authenticates, and the one ReceiverConfig expects.
const ReceiverAudience = "https://receiver.ssftest.example"

// receiverToken is the access token the test Transmitter accepts.
const receiverToken = "ssftest-receiver-token"

// Transmitter is an SSFgo Transmitter on a TLS test server, for testing a
// Receiver. It authenticates one Receiver, with the access token
// ReceiverConfig supplies, and permits it every event.
type Transmitter struct {
	t         testing.TB
	srv       *httptest.Server
	tx        *transmitter.Transmitter
	available atomic.Bool
}

// NewTransmitter starts a Transmitter, closed when the test ends. It
// supports every SSF, CAEP, RISC and SCIM event type, both delivery
// methods, and default_subjects "ALL", and runs push delivery. Options
// adjust its configuration before it starts — for example setting
// HTTPClient to a client that trusts the Receiver's push endpoint.
func NewTransmitter(t testing.TB, options ...func(*transmitter.Config)) *Transmitter {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ssftest: signing key: %v", err)
	}
	tt := &Transmitter{t: t}
	tt.available.Store(true)
	tt.srv = httptest.NewUnstartedServer(nil)
	tt.srv.StartTLS()
	t.Cleanup(tt.srv.Close)

	cfg := transmitter.Config{
		Assurance:       ssf.AssuranceDevelopment,
		Limits:          transmitter.RecommendedLimits(),
		PushRetry:       transmitter.RecommendedPushRetry(),
		Issuer:          tt.srv.URL + "/ssftest",
		SigningKeys:     []transmitter.SigningKey{{Signer: key, Algorithm: ssf.RS256, KeyID: "ssftest"}},
		EventsSupported: allEventTypes(t),
		DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPush, ssf.DeliveryPoll},
		DefaultSubjects: ssf.DefaultSubjectsAll,
		Store:           memstore.NewStreamStore(),
		Authorize: func(_ context.Context, token string) (transmitter.Receiver, error) {
			if token != receiverToken {
				return transmitter.Receiver{}, transmitter.ErrInvalidToken
			}
			return transmitter.Receiver{ID: "ssftest-receiver", Audience: []string{ReceiverAudience}, Access: transmitter.AccessManage}, nil
		},
		PermitEvent:                transmitter.PermitAll,
		MultipleStreamsPerReceiver: true,
		Logger:                     slog.New(slog.DiscardHandler),
	}
	for _, o := range options {
		o(&cfg)
	}
	tt.tx, err = transmitter.New(cfg)
	if err != nil {
		t.Fatalf("ssftest: transmitter: %v", err)
	}
	handler := tt.tx.Handler()
	tt.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tt.available.Load() {
			http.Error(w, "ssftest: transmitter unavailable", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tt.tx.Run(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })
	return tt
}

// allEventTypes is every event type SSFgo implements.
func allEventTypes(t testing.TB) []ssf.EventType {
	r := ssf.NewRegistry()
	for _, register := range []func(*ssf.Registry) error{caep.Register, risc.Register, scim.Register} {
		if err := register(r); err != nil {
			t.Fatalf("ssftest: registry: %v", err)
		}
	}
	return r.Types()
}

// Issuer is the Transmitter's issuer identifier.
func (tt *Transmitter) Issuer() string { return tt.tx.Metadata().Issuer }

// Client is an HTTP client that trusts the Transmitter's test certificate.
func (tt *Transmitter) Client() *http.Client { return tt.srv.Client() }

// ReceiverConfig returns a receiver.Config for this Transmitter: its
// issuer, ReceiverAudience, the access token it accepts, a client that
// trusts it, RS256, an in-memory replay store and a quiet logger. Set any
// other field, or override these, before calling receiver.New.
func (tt *Transmitter) ReceiverConfig(registry *ssf.Registry) receiver.Config {
	return receiver.Config{
		Assurance:   ssf.AssuranceDevelopment,
		Limits:      receiver.RecommendedLimits(),
		Issuer:      tt.Issuer(),
		Audience:    ReceiverAudience,
		Registry:    registry,
		Algorithms:  []ssf.SignatureAlgorithm{ssf.RS256},
		TokenSource: receiver.StaticToken(receiverToken),
		ReplayStore: memstore.NewReplayStore(),
		HTTPClient:  tt.Client(),
		Logger:      slog.New(slog.DiscardHandler),
	}
}

// Emit signs event about subject and queues it on every stream that should
// receive it, as transmitter.Transmitter.Emit does.
func (tt *Transmitter) Emit(ctx context.Context, subject ssf.Subject, event ssf.Event) error {
	return tt.tx.Emit(ctx, subject, event)
}

// SetAvailable makes the Transmitter answer every request with 503 while
// false, to test how a Receiver copes with an outage.
func (tt *Transmitter) SetAvailable(available bool) { tt.available.Store(available) }

// Transmitter returns the underlying Transmitter, for everything else —
// SetStreamStatus or SendVerification, say.
func (tt *Transmitter) Transmitter() *transmitter.Transmitter { return tt.tx }
