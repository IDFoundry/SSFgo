# Session revocation in Go

When an identity provider revokes a session or disables an account, a
relying party that accepted its tokens should stop accepting them at once
— not when they expire. The identity provider says so with a security
event: CAEP session-revoked, RISC account-disabled or account-purged, a
SCIM deactivate or delete. The [`revocation`](../../revocation) package
records what each means and checks the application's tokens against it.

It does not validate tokens: your token validation does that, and asks
the `Revoker` only whether a token it accepted has since been revoked.

## What a revocation covers

| The event's subject | Revokes |
|---|---|
| iss_sub `{iss, sub}` | every token of that user |
| complex subject with a `user` | every token of that user |
| complex subject with a `session` (session-revoked) | only that session's tokens |
| email (with `MatchEmail`) | every token of that address |
| aliases | the union of its identifiers |
| SCIM resource | what `KeysFor` says |

A token counts as revoked if it was issued at or before the event — the
CAEP `event_timestamp`, or the SET's `iat`. A token issued afterwards —
the user signing in again — is not.

## Wire it up

```go
store, err := sqlstore.NewRevocationStore(db, sqlstore.Postgres)
if err != nil {
	return err
}
rev, err := revocation.New(store, revocation.Options{
	// Which token issuer each Transmitter speaks for. A Transmitter not
	// listed, or a subject naming another issuer, revokes nothing.
	Issuers: revocation.StaticTokenIssuers{
		"https://ssf.idp.example.com": "https://idp.example.com",
	},
	Events:       revocation.RecommendedEvents(),
	Retention:    time.Hour,        // at least your longest token lifetime
	MaxClockSkew: 10 * time.Second, // if the IdP's clock may run ahead of the Transmitter's
	Assurance:    ssf.AssuranceProduction,
	OnRevoke: func(ctx context.Context, keys []storage.RevocationKey, set ssf.SET) error {
		return endLocalSessions(ctx, keys) // yours: optional, your own sessions too
	},
})
if err != nil {
	return err
}
rev.Register(rx) // handles Events on the Receiver
```

- **`Issuers`.** An identity provider that is its own Transmitter, with
  the same issuer, can use `revocation.SameIssuer`. Use
  `StaticTokenIssuers` when the Transmitter's issuer differs from your
  tokens', or when one `Revoker` serves several identity providers: each
  Transmitter then revokes only its own users.
- **`Retention`.** A revocation is kept this long. It must cover your
  longest-lived token, or an old token outlives the record that revokes
  it.
- **`Assurance`.** Production needs a durable store: an in-memory one
  forgets its revocations on restart, and revoked tokens are accepted
  again.
- **`OnRevoke`.** Runs after the revocation is recorded. An error makes
  the Transmitter deliver the SET again.

## Check tokens

For an HTTP API, `Middleware` answers 401 with an `invalid_token`
challenge for a revoked token, and 503 if the store fails:

```go
api = rev.Middleware(func(r *http.Request) (revocation.Token, bool) {
	claims, ok := accessTokenClaims(r.Context()) // yours: set by your token validation
	if !ok {
		return revocation.Token{}, false // not authenticated: passes through
	}
	return revocation.Token{
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		SessionID: claims.SessionID, // "sid", if your tokens carry it
		IssuedAt:  claims.IssuedAt,
	}, true
}, api)
```

Anywhere else, ask directly:

```go
revoked, err := rev.IsRevoked(ctx, revocation.Token{Issuer: "https://idp.example.com", Subject: "alice", IssuedAt: issuedAt})
if err != nil {
	return err // fail closed
}
if revoked {
	return errRevoked
}
```

## SCIM resources

A SCIM subject names a resource, not a token's subject, so the default
mapping cannot place it. `KeysFor` maps it instead:

```go
opts.KeysFor = func(set ssf.SET) []storage.RevocationKey {
	resource, ok := set.Subject.(ssf.SCIMSubject)
	if !ok {
		return nil
	}
	sub, ok := subjectForSCIM(resource.URI) // yours: your SCIM users' token subjects
	if !ok {
		return nil
	}
	return []storage.RevocationKey{{Kind: storage.RevokeUser, Issuer: "https://idp.example.com", Value: sub}}
}
```

`KeysFor` replaces the default mapping for every event, so handle the
other subjects there too if you need them.

## See also

- [`examples/session-revocation`](../../examples/session-revocation):
  an identity provider revoking a session and a relying party acting on
  it, in one process.
- [Storage and scaling](storage-and-scaling.md) for the store.
