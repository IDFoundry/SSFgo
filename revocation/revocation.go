package revocation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/internal/assurance"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/scim"
	"github.com/idfoundry/ssfgo/storage"
)

// MaxRetention bounds Options.Retention: long enough for any token, short
// enough that a revocation's expiry is always representable by every store.
const MaxRetention = 10 * 365 * 24 * time.Hour

// Options configures a Revoker. Issuers, Events and Retention are
// required: there are no implicit defaults, and RecommendedEvents is the
// usual choice for Events.
type Options struct {
	// Issuers says which token issuer each Transmitter speaks for. A SET
	// from a Transmitter it does not name revokes nothing, and neither
	// does a subject naming any other issuer — so one Transmitter cannot
	// revoke the users of another identity provider. Required.
	Issuers TokenIssuers
	// Events lists the event types that revoke tokens. Required;
	// RecommendedEvents is the usual choice.
	Events []ssf.EventType
	// Retention is how long a revocation is kept. It must be at least the
	// lifetime of the longest-lived token it should catch, and at most
	// MaxRetention. Required.
	Retention time.Duration
	// Assurance is the deployment the Revoker is for. Required. Under
	// ssf.AssuranceProduction its store must declare itself durable
	// (storage.Capabilities): an in-memory one forgets its revocations on
	// restart, and revoked tokens are accepted again.
	Assurance ssf.Assurance
	// HorizontallyScaled declares that several Revoker instances share the
	// store. Under ssf.AssuranceProduction, it must then declare itself
	// consistent across instances.
	HorizontallyScaled bool
	// MaxClockSkew is how far a token's "iat" may run ahead of the
	// revocation time and still count as issued before it, for identity
	// providers whose clocks run ahead of the Transmitter's. Zero allows
	// none; it may not be negative.
	MaxClockSkew time.Duration
	// MatchEmail also maps email subjects, so a Token's Email is checked:
	// for an application whose users are known by email address. Off by
	// default, since an address can change hands. Addresses are scoped to
	// the token issuer and compared ignoring ASCII case only.
	MatchEmail bool
	// KeysFor, if set, maps a SET to what it revokes instead of the
	// default mapping — for subjects that mapping does not cover, such as
	// SCIM resources. Returning no keys revokes nothing. Issuers is not
	// applied to the keys it returns.
	KeysFor func(ssf.SET) []storage.RevocationKey
	// OnRevoke, if set, is called after a SET's revocations are recorded —
	// to end the application's own sessions, say. It runs on the
	// Receiver's goroutine for the SET and must not block for long. An
	// error fails the SET's handling, so the Transmitter delivers it again.
	OnRevoke func(ctx context.Context, keys []storage.RevocationKey, set ssf.SET) error
	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
}

// TokenIssuers says which token issuer each Transmitter speaks for: the
// "iss" of the access tokens whose users and sessions its events concern.
type TokenIssuers interface {
	// TokenIssuer returns the token issuer for the Transmitter whose SETs
	// carry setIssuer, and false if that Transmitter is not trusted.
	TokenIssuer(setIssuer string) (string, bool)
}

// StaticTokenIssuers maps Transmitter issuers to the token issuers they
// speak for, compared exactly. A Transmitter it does not list is not
// trusted.
type StaticTokenIssuers map[string]string

// TokenIssuer implements TokenIssuers.
func (m StaticTokenIssuers) TokenIssuer(setIssuer string) (string, bool) {
	iss, ok := m[setIssuer]
	return iss, ok && iss != ""
}

// SameIssuer is the TokenIssuers for an identity provider that is its own
// Transmitter: each Transmitter speaks for tokens carrying its own issuer.
// It trusts every Transmitter the Receiver accepts SETs from, so a
// Revoker shared by Receivers of several identity providers needs
// StaticTokenIssuers instead.
var SameIssuer TokenIssuers = sameIssuer{}

type sameIssuer struct{}

func (sameIssuer) TokenIssuer(setIssuer string) (string, bool) { return setIssuer, setIssuer != "" }

// RecommendedEvents returns the event types a Revoker usually handles:
// CAEP session-revoked, RISC account-disabled, account-purged and the
// deprecated sessions-revoked, and SCIM deactivate and delete.
// Credential-change is not among them: a changed password need not end
// every session.
func RecommendedEvents() []ssf.EventType {
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

// New returns a Revoker that records revocations in store. It reports
// every problem with opts at once.
func New(store storage.RevocationStore, opts Options) (*Revoker, error) {
	var errs []error
	if store == nil {
		errs = append(errs, errors.New("a store is required"))
	}
	if opts.Issuers == nil {
		errs = append(errs, errors.New("Options.Issuers is required (StaticTokenIssuers, or SameIssuer)"))
	}
	if len(opts.Events) == 0 {
		errs = append(errs, errors.New("Options.Events is required (RecommendedEvents is the usual choice)"))
	}
	if opts.Retention <= 0 || opts.Retention > MaxRetention {
		errs = append(errs, fmt.Errorf("Options.Retention must be positive and at most %v", MaxRetention))
	}
	errs = append(errs, assurance.Check(opts.Assurance, opts.HorizontallyScaled,
		[]assurance.Store{{Field: "the store", Store: store}}, nil)...)
	if opts.MaxClockSkew < 0 {
		errs = append(errs, errors.New("Options.MaxClockSkew must not be negative"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("revocation: invalid options: %w", err)
	}
	opts.Events = slices.Clone(opts.Events)
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Revoker{store: store, opts: opts}, nil
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
	} else if issuer, ok := r.opts.Issuers.TokenIssuer(set.Issuer); ok {
		keys = r.keysFor(set, issuer)
	}
	if len(keys) == 0 {
		return nil
	}
	now := r.opts.Now()
	at := revokedAt(set, now)
	expires := now.Add(r.opts.Retention + r.opts.MaxClockSkew)
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

// keysFor is the default mapping from a SET's subject to what it revokes,
// for the Transmitter that speaks for tokens of issuer. session-revoked
// revokes only the session when the subject names one.
func (r *Revoker) keysFor(set ssf.SET, issuer string) []storage.RevocationKey {
	users, sessions := r.mapSubject(set.Subject, issuer)
	if _, ok := set.Event.(caep.SessionRevoked); ok && len(sessions) > 0 {
		return sessions
	}
	return users
}

// mapSubject maps s to the user and session keys it names among the
// tokens of issuer. An identifier naming another issuer maps to nothing.
func (r *Revoker) mapSubject(s ssf.Subject, issuer string) (users, sessions []storage.RevocationKey) {
	switch s := s.(type) {
	case ssf.IssSubSubject:
		if s.Issuer == issuer {
			users = append(users, storage.RevocationKey{Kind: storage.RevokeUser, Issuer: issuer, Value: s.Subject})
		}
	case ssf.EmailSubject:
		if r.opts.MatchEmail {
			users = append(users, storage.RevocationKey{Kind: storage.RevokeEmail, Issuer: issuer, Value: foldASCII(s.Email)})
		}
	case ssf.AliasesSubject:
		for _, id := range s.Identifiers {
			u, _ := r.mapSubject(id, issuer)
			users = append(users, u...)
		}
	case ssf.ComplexSubject:
		if s.User != nil {
			users, _ = r.mapSubject(s.User, issuer)
		}
		switch id := s.Session.(type) {
		case ssf.OpaqueSubject:
			sessions = append(sessions, storage.RevocationKey{Kind: storage.RevokeSession, Issuer: issuer, Value: id.ID})
		case ssf.IssSubSubject:
			if id.Issuer == issuer {
				sessions = append(sessions, storage.RevocationKey{Kind: storage.RevokeSession, Issuer: issuer, Value: id.Subject})
			}
		}
	}
	return users, sessions
}

// foldASCII lowercases ASCII letters only. strings.ToLower also folds
// characters such as the Kelvin sign into ASCII, which would let one
// address revoke another.
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
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
// was revoked at or after tok was issued — allowing for MaxClockSkew.
func (r *Revoker) IsRevoked(ctx context.Context, tok Token) (bool, error) {
	var keys []storage.RevocationKey
	if tok.Subject != "" {
		keys = append(keys, storage.RevocationKey{Kind: storage.RevokeUser, Issuer: tok.Issuer, Value: tok.Subject})
	}
	if tok.SessionID != "" {
		keys = append(keys, storage.RevocationKey{Kind: storage.RevokeSession, Issuer: tok.Issuer, Value: tok.SessionID})
	}
	if tok.Email != "" {
		keys = append(keys, storage.RevocationKey{Kind: storage.RevokeEmail, Issuer: tok.Issuer, Value: foldASCII(tok.Email)})
	}
	now := r.opts.Now()
	for _, k := range keys {
		at, ok, err := r.store.RevokedAt(ctx, k, now)
		if err != nil {
			return false, fmt.Errorf("revocation: check %s %s: %w", k.Kind, k.Value, err)
		}
		if ok && (tok.IssuedAt.IsZero() || !tok.IssuedAt.After(at.Add(r.opts.MaxClockSkew))) {
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
