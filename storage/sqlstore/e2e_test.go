package sqlstore_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"log/slog"
	"net/http/httptest"
	"sync"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/storage/sqlstore"
	"github.com/idfoundry/ssfgo/transmitter"
)

// TestEndToEnd runs an SSFgo Transmitter and Receiver on sqlstore, and
// restarts the Transmitter on the same database: the stream, its subject
// rule and a SET queued before the restart are all still there.
func TestEndToEnd(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) { testEndToEnd(t, d.open(t), d.dialect) })
	}
}

func testEndToEnd(t *testing.T, db *sql.DB, d sqlstore.Dialect) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	issuer := srv.URL + "/tx"
	const audience = "https://rx.example"
	quiet := slog.New(slog.DiscardHandler)

	// start builds a Transmitter instance on db and serves it.
	start := func() *transmitter.Transmitter {
		store, err := sqlstore.NewStreamStore(db, d)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := transmitter.New(transmitter.Config{
			Assurance:       ssf.AssuranceDevelopment,
			Limits:          transmitter.RecommendedLimits(),
			PushRetry:       transmitter.RecommendedPushRetry(),
			PermitEvent:     transmitter.PermitAll,
			Issuer:          issuer,
			SigningKeys:     []transmitter.SigningKey{{Signer: key, Algorithm: ssf.RS256, KeyID: "k1"}},
			EventsSupported: []ssf.EventType{caep.SessionRevokedEventType},
			DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPoll},
			DefaultSubjects: ssf.DefaultSubjectsNone,
			Store:           store,
			Authorize: func(context.Context, string) (transmitter.Receiver, error) {
				return transmitter.Receiver{ID: "rx", Audience: []string{audience}, Access: transmitter.AccessManage}, nil
			},
			Logger: quiet,
		})
		if err != nil {
			t.Fatal(err)
		}
		srv.Config.Handler = tx.Handler()
		return tx
	}
	tx := start()

	registry := ssf.NewRegistry()
	if err := caep.Register(registry); err != nil {
		t.Fatal(err)
	}
	replay, err := sqlstore.NewReplayStore(db, d)
	if err != nil {
		t.Fatal(err)
	}
	rx, err := receiver.New(ctx, receiver.Config{
		Assurance: ssf.AssuranceDevelopment,
		Limits:    receiver.RecommendedLimits(),
		Issuer:    issuer, Audience: audience, Registry: registry,
		Algorithms:  []ssf.SignatureAlgorithm{ssf.RS256},
		TokenSource: receiver.StaticToken("token"),
		ReplayStore: replay,
		HTTPClient:  srv.Client(),
		Logger:      quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu      sync.Mutex
		revoked []string
	)
	receiver.On(rx, func(_ context.Context, set ssf.SET, _ caep.SessionRevoked) error {
		mu.Lock()
		defer mu.Unlock()
		revoked = append(revoked, set.JWTID)
		return nil
	})
	handled := func() int { mu.Lock(); defer mu.Unlock(); return len(revoked) }

	stream, err := rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	alice := ssf.EmailSubject{Email: "alice@example.com"}
	if err := rx.AddSubject(ctx, stream.StreamID, alice, nil); err != nil {
		t.Fatal(err)
	}
	event := caep.SessionRevoked{Common: caep.Common{ReasonAdmin: ssf.LocalizedText{"en": "test"}}}
	if err := tx.Emit(ctx, alice, event); err != nil {
		t.Fatal(err)
	}
	if res, err := rx.Poll(ctx, stream, receiver.PollOptions{}); err != nil || res.Received != 1 {
		t.Fatalf("first poll = %+v, %v", res, err)
	}
	if err := rx.Acknowledge(ctx, stream); err != nil {
		t.Fatal(err)
	}

	// Queue a SET, then restart the Transmitter.
	if err := tx.Emit(ctx, alice, event); err != nil {
		t.Fatal(err)
	}
	tx = start()
	if _, err := rx.Stream(ctx, stream.StreamID); err != nil {
		t.Fatalf("stream after restart: %v", err)
	}
	if res, err := rx.Poll(ctx, stream, receiver.PollOptions{}); err != nil || res.Received != 1 {
		t.Fatalf("poll after restart = %+v, %v; want the SET queued before it", res, err)
	}
	// The subject rule survived too: a subject with no rule gets nothing
	// under DefaultSubjectsNone.
	if err := tx.Emit(ctx, ssf.EmailSubject{Email: "bob@example.com"}, event); err != nil {
		t.Fatal(err)
	}
	if err := tx.Emit(ctx, alice, event); err != nil {
		t.Fatal(err)
	}
	if res, err := rx.Poll(ctx, stream, receiver.PollOptions{}); err != nil || res.Received != 1 {
		t.Fatalf("poll after restart = %+v, %v; want only alice's SET", res, err)
	}
	if n := handled(); n != 3 {
		t.Errorf("handled %d events, want 3", n)
	}
}
