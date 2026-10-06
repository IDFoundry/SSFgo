// Command session-revocation shows the scenario SSF exists for: an identity
// provider revokes a user's session, and a relying party that trusted that
// session ends its own sessions for the user and stops accepting the
// user's access tokens, within moments.
//
// Everything runs in one process on loopback so the example is
// self-contained: the identity provider embeds an SSFgo Transmitter, the
// relying party embeds an SSFgo Receiver, and SETs travel between them by
// push delivery over TLS. The relying party uses the revocation package to
// act on the event, EnsureStream to set up its stream, and Hooks to observe
// both roles.
//
//	go run ./examples/session-revocation
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/caep/interop"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/revocation"
	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/storage/memstore"
	"github.com/idfoundry/ssfgo/transmitter"
)

func main() {
	if err := run(context.Background(), os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// sessions is the relying party's own session store.
type sessions struct {
	mu     sync.Mutex
	byUser map[string][]string // iss_sub "iss|sub" -> session IDs
}

func (s *sessions) login(user ssf.IssSubSubject, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := user.Issuer + "|" + user.Subject
	s.byUser[key] = append(s.byUser[key], id)
}

func (s *sessions) revokeAll(user ssf.IssSubSubject) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := user.Issuer + "|" + user.Subject
	ids := s.byUser[key]
	delete(s.byUser, key)
	return ids
}

// lockedWriter serialises writes: handlers run on the push server's
// goroutines while the main flow also prints.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func run(ctx context.Context, w io.Writer) error {
	out := &lockedWriter{w: w}
	say := func(format string, args ...any) { _, _ = fmt.Fprintf(out, format+"\n", args...) }
	quiet := slog.New(slog.DiscardHandler)

	// --- Identity provider: an SSF Transmitter. ---
	idpServer := httptest.NewUnstartedServer(nil)
	idpServer.StartTLS()
	defer idpServer.Close()
	issuer := idpServer.URL + "/ssf"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	const rpToken = "relying-party-access-token" // in production: OAuth client credentials
	var rpServer atomic.Pointer[httptest.Server] // the relying party, created below

	txCfg := transmitter.Config{
		Issuer:          issuer,
		SigningKeys:     []transmitter.SigningKey{{Signer: key, Algorithm: ssf.RS256, KeyID: "idp-2026"}},
		EventsSupported: interop.EventTypes(),
		DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPush, ssf.DeliveryPoll},
		DefaultSubjects: ssf.DefaultSubjectsAll,
		Store:           memstore.NewStreamStore(),
		Authorize: func(_ context.Context, token string) (transmitter.Receiver, error) {
			if token != rpToken {
				return transmitter.Receiver{}, transmitter.ErrInvalidToken
			}
			return transmitter.Receiver{ID: "relying-party", Audience: []string{"https://rp.example"}, Access: transmitter.AccessManage}, nil
		},
		// One relying party, entitled to every event: a multi-tenant
		// identity provider decides here who may see what.
		PermitEvent: transmitter.PermitAll,
		Hooks: transmitter.Hooks{Push: func(_ context.Context, i transmitter.PushInfo) {
			say("IdP: push attempt %d: %s in %v", i.Attempt, i.Outcome, i.Duration.Round(time.Millisecond))
		}},
		Logger: quiet,
	}
	if err := interop.ApplyTransmitter(&txCfg); err != nil {
		return err
	}
	// The default push client refuses private addresses; this demo pushes
	// to loopback, so it trusts the relying party's test server instead.
	pushClient := lazyClient(rpServer.Load)
	txCfg.HTTPClient = pushClient
	tx, err := transmitter.New(txCfg)
	if err != nil {
		return err
	}
	idpServer.Config.Handler = tx.Handler()
	runCtx, stop := context.WithCancel(ctx)
	ran := make(chan struct{})
	go func() { defer close(ran); _ = tx.Run(runCtx) }()
	// Stop push delivery, and wait for it, before returning.
	defer func() { stop(); <-ran }()

	// --- Relying party: an SSF Receiver. ---
	store := &sessions{byUser: map[string][]string{}}
	registry := ssf.NewRegistry()
	if err := caep.Register(registry); err != nil {
		return err
	}
	rx, err := receiver.New(ctx, receiver.Config{
		Issuer:      issuer,
		Audience:    "https://rp.example",
		Registry:    registry,
		Algorithms:  []ssf.SignatureAlgorithm{ssf.RS256},
		TokenSource: receiver.StaticToken(rpToken),
		ReplayStore: memstore.NewReplayStore(),
		HTTPClient:  idpServer.Client(),
		Hooks: receiver.Hooks{SET: func(_ context.Context, i receiver.SETInfo) {
			say("RP:  %s SET %s", i.Outcome, i.EventType)
		}},
		Logger: quiet,
	})
	if err != nil {
		return err
	}
	if err := rx.Ready(ctx); err != nil {
		return err
	}

	// The revocation package records what session-revoked means — alice's
	// tokens issued before it are revoked — and OnRevoke ends her local
	// sessions too.
	revoked := make(chan struct{})
	var once sync.Once
	rev, err := revocation.New(memstore.NewRevocationStore(), revocation.Options{
		Issuers:   revocation.SameIssuer, // the IdP is its own Transmitter
		Events:    revocation.RecommendedEvents(),
		Retention: time.Hour, // the longest access token lifetime
		OnRevoke: func(_ context.Context, _ []storage.RevocationKey, set ssf.SET) error {
			user, ok := set.Subject.(ssf.IssSubSubject)
			if !ok {
				return nil
			}
			reason := ""
			if e, ok := set.Event.(caep.SessionRevoked); ok {
				reason = e.ReasonAdmin["en"]
			}
			say("RP:  session-revoked for %s (%s) → ended local sessions %v", user.Subject, reason, store.revokeAll(user))
			once.Do(func() { close(revoked) })
			return nil
		},
	})
	if err != nil {
		return err
	}
	rev.Register(rx)
	receiver.On(rx, func(_ context.Context, _ ssf.SET, v ssf.Verification) error {
		say("RP:  stream verified")
		return nil
	})

	const pushAuth = "Bearer rp-push-secret"
	rp := httptest.NewTLSServer(rx.PushHandler(receiver.PushOptions{AuthorizationHeader: pushAuth}))
	defer rp.Close()
	rpServer.Store(rp)

	// EnsureStream creates the stream on the first start and reuses it on
	// later ones.
	stream, err := rx.EnsureStream(ctx, receiver.StreamRequest{
		Delivery:        &ssf.Delivery{Method: ssf.DeliveryPush, EndpointURL: rp.URL + "/ssf/events", AuthorizationHeader: pushAuth},
		EventsRequested: []ssf.EventType{caep.SessionRevokedEventType},
	})
	if err != nil {
		return err
	}
	say("RP:  stream %s with %s", stream.StreamID, issuer)
	if _, err := rx.RequestVerification(ctx, stream.StreamID); err != nil {
		return err
	}

	// A user signs in to the relying party through the identity provider,
	// which issues her an access token.
	alice := ssf.IssSubSubject{Issuer: issuer, Subject: "alice"}
	store.login(alice, "rp-session-1")
	store.login(alice, "rp-session-2")
	aliceToken := revocation.Token{Issuer: issuer, Subject: "alice", IssuedAt: time.Now().Add(-time.Minute)}
	say("RP:  alice signed in (2 sessions)")

	// An administrator revokes alice's session at the identity provider.
	time.Sleep(200 * time.Millisecond)
	say("IdP: administrator revokes alice's session")
	err = tx.Emit(ctx, alice, caep.SessionRevoked{Common: caep.Common{
		EventTimestamp:   ssf.NewNumericDate(time.Now()),
		InitiatingEntity: caep.InitiatedByAdmin,
		ReasonAdmin:      ssf.LocalizedText{"en": "Suspicious activity"},
	}})
	if err != nil {
		return err
	}

	select {
	case <-revoked:
	case <-time.After(10 * time.Second):
		return fmt.Errorf("the relying party did not receive the revocation")
	}
	// The access token alice was issued before the revocation is refused
	// from now on; rev.Middleware does this for an HTTP API.
	refused, err := rev.IsRevoked(ctx, aliceToken)
	if err != nil {
		return err
	}
	say("RP:  alice's earlier access token revoked: %v", refused)
	return nil
}
