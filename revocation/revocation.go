package revocation

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/scim"
	"github.com/idfoundry/ssfgo/storage"
)

// Options configures a Revoker. Every field is optional.
type Options struct {
	// Events lists the event types that revoke tokens. Defaults to
	// DefaultEvents.
	Events []ssf.EventType
	// MatchEmail also maps email subjects, so a Token's Email is checked:
	// for an application whose users are known by email address. Off by
	// default, since an address can change hands.
	MatchEmail bool
	// KeysFor, if set, maps a SET to what it revokes instead of the
	// default mapping — for subjects that mapping does not cover, such as
	// SCIM resources. Returning no keys revokes nothing.
	KeysFor func(ssf.SET) []storage.RevocationKey
	// OnRevoke, if set, is called after a SET's revocations are recorded —
	// to end the application's own sessions, say. An error fails the SET's
	// handling, so the Transmitter delivers it again.
	OnRevoke func(ctx context.Context, keys []storage.RevocationKey, set ssf.SET) error
	// Retention is how long a revocation is kept. It must be at least the
	// lifetime of the longest-lived token it should catch. Defaults to 24
	// hours.
	Retention time.Duration
	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
}

// DefaultEvents returns the event types a Revoker handles by default:
// CAEP session-revoked, RISC account-disabled, account-purged and the
// deprecated sessions-revoked, and SCIM deactivate and delete.
// Credential-change is not among them: a changed password need not end
// every session.
func DefaultEvents() []ssf.EventType {
	return []ssf.EventType{
		caep.SessionRevokedEventType,
		risc.AccountDisabledEventType, risc.AccountPurgedEventType,
		risc.SessionsRevokedEventType, //nolint:staticcheck // SA1019: older Transmitters still send it
		scim.DeactivateEventType, scim.DeleteEventType,
	}
}

// Revoker records the revocations security events mean and checks tokens
// against them.
type Revoker struct {
	store storage.RevocationStore
	opts  Options
}

// New returns a Revoker that records revocations in store.
func New(store storage.RevocationStore, opts Options) *Revoker {
	if opts.Events == nil {
		opts.Events = DefaultEvents()
	}
	opts.Events = slices.Clone(opts.Events)
	if opts.Retention <= 0 {
		opts.Retention = 24 * time.Hour
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Revoker{store: store, opts: opts}
}

// Register installs Handle on rx for each of Options.Events, replacing any
// handler already registered for them. An application with its own
// handlers for those events calls Handle from them instead.
func (r *Revoker) Register(rx *receiver.Receiver) {
	for _, typ := range r.opts.Events {
		rx.Handle(typ, r.Handle)
	}
}

// Handle records the revocation set means, if its event type is one of
// Options.Events, then calls Options.OnRevoke. Any other SET is ignored.
func (r *Revoker) Handle(ctx context.Context, set ssf.SET) error {
	if set.Event == nil || !slices.Contains(r.opts.Events, set.Event.EventType()) {
		return nil
	}
	var keys []storage.RevocationKey
	if r.opts.KeysFor != nil {
		keys = r.opts.KeysFor(set)
	} else {
		keys = r.keysFor(set)
	}
	if len(keys) == 0 {
		return nil
	}
	now := r.opts.Now()
	at := revokedAt(set, now)
	expires := now.Add(r.opts.Retention)
	for _, k := range keys {
		if err := r.store.Revoke(ctx, k, at, expires); err != nil {
			return fmt.Errorf("revocation: record %s %s: %w", k.Kind, k.Value, err)
		}
	}
	if r.opts.OnRevoke != nil {
		return r.opts.OnRevoke(ctx, keys, set)
	}
	return nil
}

// revokedAt is when the revocation took effect: a CAEP event's
// event_timestamp, else when the SET was issued — never in the future.
func revokedAt(set ssf.SET, now time.Time) time.Time {
	at := set.IssuedAt
	if e, ok := set.Event.(caep.SessionRevoked); ok && !e.EventTimestamp.IsZero() {
		at = e.EventTimestamp.Time
	}
	if at.After(now) {
		return now
	}
	return at
}

// keysFor is the default mapping from a SET's subject to what it revokes.
// session-revoked revokes only the session when the subject names one.
func (r *Revoker) keysFor(set ssf.SET) []storage.RevocationKey {
	users, sessions := r.mapSubject(set.Subject, set.Issuer)
	if _, ok := set.Event.(caep.SessionRevoked); ok && len(sessions) > 0 {
		return sessions
	}
	return users
}

// mapSubject maps s to the user and session keys it names. A session's
// identifier is scoped to the issuer of the user's iss_sub when there is
// one, else to the SET's issuer.
func (r *Revoker) mapSubject(s ssf.Subject, setIssuer string) (users, sessions []storage.RevocationKey) {
	switch s := s.(type) {
	case ssf.IssSubSubject:
		users = append(users, storage.RevocationKey{Kind: storage.RevokeUser, Issuer: s.Issuer, Value: s.Subject})
	case ssf.EmailSubject:
		if r.opts.MatchEmail {
			users = append(users, storage.RevocationKey{Kind: storage.RevokeEmail, Value: strings.ToLower(s.Email)})
		}
	case ssf.AliasesSubject:
		for _, id := range s.Identifiers {
			u, _ := r.mapSubject(id, setIssuer)
			users = append(users, u...)
		}
	case ssf.ComplexSubject:
		if s.User != nil {
			users, _ = r.mapSubject(s.User, setIssuer)
		}
		issuer := setIssuer
		if u, ok := s.User.(ssf.IssSubSubject); ok {
			issuer = u.Issuer
		}
		switch id := s.Session.(type) {
		case ssf.OpaqueSubject:
			sessions = append(sessions, storage.RevocationKey{Kind: storage.RevokeSession, Issuer: issuer, Value: id.ID})
		case ssf.IssSubSubject:
			sessions = append(sessions, storage.RevocationKey{Kind: storage.RevokeSession, Issuer: id.Issuer, Value: id.Subject})
		}
	}
	return users, sessions
}

// Token is what a Revoker needs to know about a token the application has
// already validated. Any field may be empty except IssuedAt; a token with
// no IssuedAt counts as issued before every revocation.
type Token struct {
	// Issuer is the identity provider that issued the token ("iss").
	Issuer string
	// Subject is the user's identifier at Issuer ("sub").
	Subject string
	// SessionID is the session the token belongs to ("sid").
	SessionID string
	// Email is the user's email address, checked only for revocations
	// recorded with Options.MatchEmail.
	Email string
	// IssuedAt is when the token was issued ("iat").
	IssuedAt time.Time
}

// IsRevoked reports whether tok's user or session, or its email address,
// was revoked at or after tok was issued.
func (r *Revoker) IsRevoked(ctx context.Context, tok Token) (bool, error) {
	var keys []storage.RevocationKey
	if tok.Subject != "" {
		keys = append(keys, storage.RevocationKey{Kind: storage.RevokeUser, Issuer: tok.Issuer, Value: tok.Subject})
	}
	if tok.SessionID != "" {
		keys = append(keys, storage.RevocationKey{Kind: storage.RevokeSession, Issuer: tok.Issuer, Value: tok.SessionID})
	}
	if tok.Email != "" {
		keys = append(keys, storage.RevocationKey{Kind: storage.RevokeEmail, Value: strings.ToLower(tok.Email)})
	}
	now := r.opts.Now()
	for _, k := range keys {
		at, ok, err := r.store.RevokedAt(ctx, k, now)
		if err != nil {
			return false, fmt.Errorf("revocation: check %s %s: %w", k.Kind, k.Value, err)
		}
		if ok && (tok.IssuedAt.IsZero() || !tok.IssuedAt.After(at)) {
			return true, nil
		}
	}
	return false, nil
}

// Middleware refuses requests whose token has been revoked. extract
// returns the token of a request the application has authenticated, or
// false for one it has not, which passes through untouched: Middleware
// checks revocation, not authentication. A revoked token gets 401 with an
// RFC 6750 invalid_token challenge; a store failure gets 503, failing
// closed.
func (r *Revoker) Middleware(extract func(*http.Request) (Token, bool), next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		tok, ok := extract(req)
		if !ok {
			next.ServeHTTP(w, req)
			return
		}
		revoked, err := r.IsRevoked(req.Context(), tok)
		if err != nil {
			http.Error(w, "revocation status unavailable", http.StatusServiceUnavailable)
			return
		}
		if revoked {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="the token has been revoked"`)
			http.Error(w, "the token has been revoked", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	})
}
