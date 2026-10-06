package revocation_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/revocation"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/scim"
	"github.com/idfoundry/ssfgo/ssftest"
	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

const idp = "https://idp.example"

var (
	now      = time.Unix(1_800_000_000, 0)
	alice    = ssf.IssSubSubject{Issuer: idp, Subject: "alice"}
	before   = now.Add(-time.Hour)
	after    = now.Add(time.Minute)
	reason   = caep.Common{ReasonAdmin: ssf.LocalizedText{"en": "test"}}
	sessionA = ssf.ComplexSubject{User: alice, Session: ssf.OpaqueSubject{ID: "sid-a"}}
)

func newRevoker(opts revocation.Options) *revocation.Revoker {
	opts.Now = func() time.Time { return now }
	return revocation.New(memstore.NewRevocationStore(), opts)
}

func set(subject ssf.Subject, event ssf.Event) ssf.SET {
	return ssf.SET{Issuer: idp, IssuedAt: now, Subject: subject, Event: event}
}

func revoked(t *testing.T, r *revocation.Revoker, tok revocation.Token) bool {
	t.Helper()
	got, err := r.IsRevoked(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestEventsRevoke(t *testing.T) {
	ctx := context.Background()
	aliceA := revocation.Token{Issuer: idp, Subject: "alice", SessionID: "sid-a", IssuedAt: before}
	aliceB := revocation.Token{Issuer: idp, Subject: "alice", SessionID: "sid-b", IssuedAt: before}
	bob := revocation.Token{Issuer: idp, Subject: "bob", IssuedAt: before}
	for name, c := range map[string]struct {
		set          ssf.SET
		opts         revocation.Options
		a, b, bobRev bool
	}{
		"session-revoked naming a session": {set: set(sessionA, caep.SessionRevoked{Common: reason}), a: true},
		"session-revoked naming the user":  {set: set(alice, caep.SessionRevoked{Common: reason}), a: true, b: true},
		"account-disabled":                 {set: set(sessionA, risc.AccountDisabled{}), a: true, b: true},
		"account-purged via aliases": {set: set(ssf.AliasesSubject{Identifiers: []ssf.Subject{
			ssf.OpaqueSubject{ID: "x"}, alice,
		}}, risc.AccountPurged{}), a: true, b: true},
		"credential-change is not revoking by default": {set: set(alice, caep.CredentialChange{
			Common: reason, CredentialType: caep.CredentialPassword, ChangeType: caep.ChangeUpdate,
		})},
		"unless configured": {set: set(alice, caep.CredentialChange{
			Common: reason, CredentialType: caep.CredentialPassword, ChangeType: caep.ChangeUpdate,
		}), opts: revocation.Options{Events: []ssf.EventType{caep.CredentialChangeEventType}}, a: true, b: true},
		"email without MatchEmail": {set: set(ssf.EmailSubject{Email: "alice@example.com"}, risc.AccountDisabled{})},
		"SCIM needs KeysFor":       {set: set(ssf.SCIMSubject{URI: "/Users/1"}, scim.Deactivate{})},
		"SCIM with KeysFor": {set: set(ssf.SCIMSubject{URI: "/Users/1"}, scim.Deactivate{}), opts: revocation.Options{
			KeysFor: func(ssf.SET) []storage.RevocationKey {
				return []storage.RevocationKey{{Kind: storage.RevokeUser, Issuer: idp, Value: "bob"}}
			},
		}, bobRev: true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRevoker(c.opts)
			if err := r.Handle(ctx, c.set); err != nil {
				t.Fatal(err)
			}
			if got := revoked(t, r, aliceA); got != c.a {
				t.Errorf("alice's session A revoked = %v, want %v", got, c.a)
			}
			if got := revoked(t, r, aliceB); got != c.b {
				t.Errorf("alice's session B revoked = %v, want %v", got, c.b)
			}
			if got := revoked(t, r, bob); got != c.bobRev {
				t.Errorf("bob revoked = %v, want %v", got, c.bobRev)
			}
		})
	}
}

func TestMatchEmail(t *testing.T) {
	r := newRevoker(revocation.Options{MatchEmail: true})
	if err := r.Handle(context.Background(), set(ssf.EmailSubject{Email: "Alice@Example.com"}, risc.AccountDisabled{})); err != nil {
		t.Fatal(err)
	}
	if !revoked(t, r, revocation.Token{Email: "alice@example.COM", IssuedAt: before}) {
		t.Error("email revocation not matched case-insensitively")
	}
}

// Tokens issued at or before the event are revoked; later ones — the user
// signing in again — are not. CAEP's event_timestamp, not the SET's iat,
// says when the event happened.
func TestRevocationTime(t *testing.T) {
	r := newRevoker(revocation.Options{})
	event := caep.SessionRevoked{Common: caep.Common{ReasonAdmin: reason.ReasonAdmin, EventTimestamp: ssf.NewNumericDate(now.Add(-10 * time.Minute))}}
	if err := r.Handle(context.Background(), set(alice, event)); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		iat  time.Time
		want bool
	}{
		"before the event":                {before, true},
		"after the event, before the SET": {now.Add(-5 * time.Minute), false},
		"after":                           {after, false},
		"no iat":                          {time.Time{}, true},
	} {
		if got := revoked(t, r, revocation.Token{Issuer: idp, Subject: "alice", IssuedAt: c.iat}); got != c.want {
			t.Errorf("%s: revoked = %v, want %v", name, got, c.want)
		}
	}
}

func TestOnRevoke(t *testing.T) {
	var got []storage.RevocationKey
	failure := errors.New("session store down")
	r := newRevoker(revocation.Options{OnRevoke: func(_ context.Context, keys []storage.RevocationKey, _ ssf.SET) error {
		got = keys
		return failure
	}})
	err := r.Handle(context.Background(), set(sessionA, caep.SessionRevoked{Common: reason}))
	if !errors.Is(err, failure) || len(got) != 1 || got[0].Value != "sid-a" {
		t.Errorf("Handle = %v, OnRevoke got %v", err, got)
	}
}

type failingStore struct{ storage.RevocationStore }

func (failingStore) RevokedAt(context.Context, storage.RevocationKey, time.Time) (time.Time, bool, error) {
	return time.Time{}, false, errors.New("down")
}

func TestMiddleware(t *testing.T) {
	r := newRevoker(revocation.Options{})
	if err := r.Handle(context.Background(), set(alice, risc.AccountDisabled{})); err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	extract := func(req *http.Request) (revocation.Token, bool) {
		sub := req.Header.Get("X-Sub")
		return revocation.Token{Issuer: idp, Subject: sub, IssuedAt: before}, sub != ""
	}
	serve := func(h http.Handler, sub string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if sub != "" {
			req.Header.Set("X-Sub", sub)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	h := r.Middleware(extract, ok)
	if rec := serve(h, "alice"); rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("revoked token: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	if rec := serve(h, "bob"); rec.Code != http.StatusOK {
		t.Errorf("valid token: %d", rec.Code)
	}
	if rec := serve(h, ""); rec.Code != http.StatusOK {
		t.Errorf("unauthenticated request not passed through: %d", rec.Code)
	}
	broken := revocation.New(failingStore{}, revocation.Options{}).Middleware(extract, ok)
	if rec := serve(broken, "bob"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("store failure: %d, want 503", rec.Code)
	}
}

// End to end: a Transmitter revokes a session, the Receiver polls, and the
// middleware refuses that session's token but not the user's other ones.
func TestEndToEnd(t *testing.T) {
	ctx := context.Background()
	tx := ssftest.NewTransmitter(t)
	registry := ssf.NewRegistry()
	if err := caep.Register(registry); err != nil {
		t.Fatal(err)
	}
	rx, err := receiver.New(ctx, tx.ReceiverConfig(registry))
	if err != nil {
		t.Fatal(err)
	}
	rev := revocation.New(memstore.NewRevocationStore(), revocation.Options{})
	rev.Register(rx)
	stream, err := rx.EnsureStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Now().Add(-time.Minute)
	subject := ssf.ComplexSubject{User: ssf.IssSubSubject{Issuer: idp, Subject: "alice"}, Session: ssf.OpaqueSubject{ID: "sid-a"}}
	if err := tx.Emit(ctx, subject, caep.SessionRevoked{Common: reason}); err != nil {
		t.Fatal(err)
	}
	if _, err := rx.Poll(ctx, stream, receiver.PollOptions{}); err != nil {
		t.Fatal(err)
	}
	if !revoked(t, rev, revocation.Token{Issuer: idp, Subject: "alice", SessionID: "sid-a", IssuedAt: issued}) {
		t.Error("the revoked session's token is still accepted")
	}
	if revoked(t, rev, revocation.Token{Issuer: idp, Subject: "alice", SessionID: "sid-b", IssuedAt: issued}) {
		t.Error("another session of the user was revoked too")
	}
}
