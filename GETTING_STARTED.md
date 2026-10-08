# Getting started

This walks through embedding each role in a Go service: a **Transmitter**
— an identity provider, say, sending security events — and a **Receiver**
— a relying party acting on them. Each part builds one program, step by
step; the parts that are yours, such as verifying an access token, are
marked. [`examples/session-revocation`](examples/session-revocation) runs
both roles in one process if you'd rather start from working code, and
[UPGRADING.md](UPGRADING.md) covers moving from an earlier version.

Every setting that decides security is explicit: there are no implicit
defaults, and the `Recommended*` functions give starting values
([design rules](docs/design-rules.md)). `New` reports every missing or
invalid setting at once, naming the field.

## Part 1: a Transmitter

### 1. A signing key

The Transmitter signs every SET. Any `crypto.Signer` works, so the key
can stay in a KMS or HSM — see [Keys in a KMS or HSM](docs/guides/keys.md):

```go
key, err := loadSigningKey() // yours: a KMS-backed crypto.Signer, say
if err != nil {
	return err
}
// How the key is held. Production requires it durable — SETs are signed
// when queued, so a key made at each start strands them on restart —
// and, with several instances, shared by all of them.
custody := ssf.KeyCustody{Durable: true, CrossInstanceConsistent: true}
```

RS256 is what the CAEP Interoperability Profile requires; PS, ES and
EdDSA algorithms are available too (`ssf.SignatureAlgorithms()`).

### 2. A store

Streams, their subjects and queued SETs live in a `storage.StreamStore`.
`memstore` is for tests and development; in production use
`storage/sqlstore`, on PostgreSQL or SQLite:

```go
// go get github.com/idfoundry/ssfgo/storage/sqlstore
db, err := sql.Open("pgx", dsn) // any database/sql driver
if err != nil {
	return err
}
if err := sqlstore.CreateSchema(ctx, db, sqlstore.Postgres); err != nil {
	return err
}
streams, err := sqlstore.NewStreamStore(ctx, db, sqlstore.Postgres)
if err != nil {
	return err
}
```

### 3. Who is calling, and what they may see

Receivers call the stream management API with an OAuth access token.
Checking it is yours — the Transmitter only asks who it belongs to:

```go
authorize := func(ctx context.Context, token string) (transmitter.Receiver, error) {
	client, err := verifyAccessToken(ctx, token) // yours: your OAuth resource-server check
	if err != nil {
		return transmitter.Receiver{}, transmitter.ErrInvalidToken
	}
	return transmitter.Receiver{
		ID:       client.ID,
		Audience: []string{client.URI},                       // the "aud" of its SETs
		Access:   transmitter.AccessFromScopes(client.Scopes), // ssf.read, ssf.manage
	}, nil
}
```

`PermitEvent` decides whether a Receiver may receive an event about a
subject (SSF 1.0 §9.2). Subject rules can't stand in for it: with
`DefaultSubjectsAll` any Receiver would get every event by creating a
stream.

```go
permitEvent := func(ctx context.Context, receiverID string, subject ssf.Subject, _ ssf.Event) bool {
	return tenantOwns(ctx, receiverID, subject) // yours
}
```

A single-tenant Transmitter whose every Receiver may see everything sets
`PermitEvent: transmitter.PermitAll`.

### 4. The configuration

```go
cfg := transmitter.Config{
	Issuer:          "https://idp.example.com",
	SigningKeys:     []transmitter.SigningKey{{Signer: key, Algorithm: ssf.RS256, KeyID: "2026-10", Custody: custody}},
	EventsSupported: []ssf.EventType{caep.SessionRevokedEventType, caep.CredentialChangeEventType},
	DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPush, ssf.DeliveryPoll},
	DefaultSubjects: ssf.DefaultSubjectsNone, // Receivers add the subjects they want

	Store:     streams,
	Assurance: ssf.AssuranceProduction, // refuses in-memory stores, undeclared keys and loopback issuers
	Limits:    transmitter.RecommendedLimits(),
	PushRetry: transmitter.RecommendedPushRetry(),

	Authorize:   authorize,   // step 3
	PermitEvent: permitEvent, // step 3
}
```

- `Issuer` is an https URL, and the Transmitter serves its metadata at
  `/.well-known/ssf-configuration` under the same host (SSF 1.0 §7.2).
- With `DefaultSubjectsNone`, a stream receives events only about
  subjects its Receiver added; `DefaultSubjectsAll` sends every event
  `PermitEvent` allows.
- `interop.ApplyTransmitter(&cfg)` holds the configuration to the CAEP
  Interoperability Profile.

### 5. Serve, and deliver

```go
tx, err := transmitter.New(cfg)
if err != nil {
	return err // every problem with cfg, each naming its field
}
go func() { _ = tx.Run(ctx) }() // push delivery; returns when ctx is done
go func() { log.Fatal(http.ListenAndServeTLS(":443", certFile, keyFile, tx.Handler())) }()
```

- `Handler()` serves the metadata, the JWKS and the stream management
  API. It routes on the full path, so mount it at the root of the
  issuer's host.
- `Run` delivers pushed SETs, retrying with `PushRetry`'s backoff. Poll
  streams need nothing more: Receivers collect from the handler.
- Several instances can share a PostgreSQL store with
  `HorizontallyScaled: true`; run `Run` in one of them only.
- `tx.Ready(ctx)` backs a readiness probe.

### 6. Emit events

```go
err = tx.Emit(ctx, ssf.IssSubSubject{Issuer: "https://idp.example.com", Subject: "alice"},
	caep.SessionRevoked{Common: caep.Common{
		EventTimestamp:   ssf.NewNumericDate(time.Now()),
		InitiatingEntity: caep.InitiatedByAdmin,
		ReasonAdmin:      ssf.LocalizedText{"en": "Suspicious activity"},
	}})
```

`Emit` signs a SET for every stream that requested the event type,
matches the subject and is permitted by `PermitEvent`, and queues it.
It returns once they are queued.

### 7. Rotate the signing key

The first of `SigningKeys` signs; every key listed is published. To
rotate, put the new key first and keep the old one until every Receiver
has refetched the JWKS — a Receiver refetches when it meets an unknown
`kid`, and at least every `receiver.Limits.KeyMaxAge`:

```go
cfg.SigningKeys = []transmitter.SigningKey{
	{Signer: newKey, Algorithm: ssf.RS256, KeyID: "2027-01", Custody: custody},
	{Signer: key, Algorithm: ssf.RS256, KeyID: "2026-10", Custody: custody}, // remove after KeyMaxAge
}
```

## Part 2: a Receiver

### 1. Event types and credentials

A Receiver decodes the event types its registry knows, and rejects
others. It calls the Transmitter with an access token from a
`TokenSource` — the client credentials grant, for example:

```go
registry := ssf.NewRegistry()
for _, register := range []func(*ssf.Registry) error{caep.Register, risc.Register, scim.Register} {
	if err := register(registry); err != nil {
		return err
	}
}
tokens := &receiver.ClientCredentials{
	TokenURL:     "https://idp.example.com/oauth2/token",
	ClientID:     "rp",
	ClientSecret: ssf.NewSecret(os.Getenv("SSF_CLIENT_SECRET")), // withheld from logs and %v
	AuthMethod:   receiver.ClientSecretBasic,
	Scopes:       []string{"ssf.manage"},
}
```

### 2. A replay store

Every SET handled is recorded, so a redelivered one is acknowledged
without being handled twice, and a captured one cannot be replayed. In
production use `storage/sqlstore`:

```go
replay, err := sqlstore.NewReplayStore(ctx, db, sqlstore.Postgres)
if err != nil {
	return err
}
```

### 3. The configuration

```go
rx, err := receiver.New(ctx, receiver.Config{
	Issuer:      "https://idp.example.com",
	Audience:    "https://rp.example.com", // must be in every SET's "aud"
	Registry:    registry,
	Algorithms:  []ssf.SignatureAlgorithm{ssf.RS256},
	TokenSource: tokens,
	ReplayStore: replay,
	Assurance:   ssf.AssuranceProduction,
	Limits:      receiver.RecommendedLimits(), // replay window, key age, clock skew
})
if err != nil {
	return err
}
```

`New` fetches the Transmitter's metadata and keys. The access token goes
only to the issuer's origin; list any other origin the metadata points
at in `TrustedOrigins`. A Transmitter that gives each stream its own
audience, `<client_id>/<stream_id>`, needs your client ID as `Audience`
and `AudiencePerStream`. `interop.ApplyReceiver` holds the Transmitter to
the CAEP Interoperability Profile.

### 4. Handle events

Handlers are typed. Return an error to have the Transmitter deliver the
SET again:

```go
receiver.On(rx, func(ctx context.Context, set ssf.SET, e caep.SessionRevoked) error {
	return endSessions(ctx, set.Subject) // yours
})
```

To stop accepting the access tokens of revoked sessions as well, the
[`revocation`](revocation) package records what such events mean and
checks tokens against it, or answers 401 as `net/http` middleware — see
[Session revocation](docs/guides/session-revocation.md). Its recommended
events include RISC's and SCIM's, so the registry above holds all three
families.

### 5. A stream: push or poll

With push, the Transmitter sends SETs to an endpoint you serve. Give it
a secret Authorization header to send, and check it:

```go
pushAuth := ssf.NewSecret("Bearer " + randomToken())
http.Handle("/ssf/events", rx.PushHandler(receiver.PushOptions{AuthorizationHeader: pushAuth}))

stream, err := rx.EnsureStream(ctx, receiver.StreamRequest{
	Delivery: &ssf.Delivery{
		Method:              ssf.DeliveryPush,
		EndpointURL:         "https://rp.example.com/ssf/events",
		AuthorizationHeader: pushAuth,
	},
	EventsRequested: []ssf.EventType{caep.SessionRevokedEventType},
})
if err != nil {
	return err
}
```

With poll, the Receiver collects SETs itself, and needs no endpoint:

```go
stream, err = rx.EnsureStream(ctx, receiver.StreamRequest{
	EventsRequested: []ssf.EventType{caep.SessionRevokedEventType},
}) // a nil Delivery asks for poll
if err != nil {
	return err
}
go func() { _ = rx.RunPoller(ctx, stream) }()
```

`EnsureStream` creates the stream on the first start and reuses it,
updating what changed, on later ones, so call it on every start. It
waits out a Transmitter that is briefly unavailable. If the Transmitter
advertises an `inactivity_timeout`, run `rx.KeepAlive(ctx,
stream.StreamID)` to keep the stream active.

With `DefaultSubjectsNone` on the Transmitter, add the subjects you care
about:

```go
if err := rx.AddSubject(ctx, stream.StreamID, ssf.IssSubSubject{Issuer: "https://idp.example.com", Subject: "alice"}, nil); err != nil {
	return err
}
```

### 6. Check it works

`RequestVerification` asks the Transmitter to send a verification event
on the stream (SSF 1.0 §8.1.4); handle `ssf.Verification` to see it
arrive. `rx.Ready(ctx)` backs a readiness probe, and `Hooks` in the
configuration report every SET's outcome, every poll and every key
refresh to your metrics:

```go
receiver.On(rx, func(ctx context.Context, _ ssf.SET, _ ssf.Verification) error {
	slog.InfoContext(ctx, "SSF stream verified")
	return nil
})
if _, err := rx.RequestVerification(ctx, stream.StreamID); err != nil {
	return err
}
```

## Testing

[`ssftest`](ssftest) runs the other role in-process, on TLS test
servers: `ssftest.NewTransmitter` to test a Receiver,
`ssftest.NewReceiver` to test a Transmitter.

## Next

- [ARCHITECTURE.md](ARCHITECTURE.md): how the library is put together.
- [SECURITY.md](SECURITY.md): the security model, and what stays yours.
- [COMPATIBILITY.md](COMPATIBILITY.md): what a release may change.
