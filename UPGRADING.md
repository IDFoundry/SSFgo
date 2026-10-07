# Upgrading

This page covers every breaking change since v0.5: who each one affects
and what to change. [CHANGELOG.md](CHANGELOG.md) has the full history,
and [COMPATIBILITY.md](COMPATIBILITY.md) what counts as breaking.

`transmitter.New`, `receiver.New` and `revocation.New` fail at startup
when a new requirement isn't met, reporting every problem at once and
naming each field, so a skipped step cannot reach runtime. Where a
change can't be caught that way — a different result at runtime — the
section says so.

Packages added since v0.5 — `revocation`, `ssftest`, `scim`, the hooks,
`Receiver.EnsureStream` — have nothing to upgrade from, and are not
listed.

## v1.0.0 (unreleased)

### Every role declares its assurance level (transmitter, receiver)

**Affects:** every `transmitter.Config` and `receiver.Config`.

**Why:** an in-memory store loses everything on restart. A Receiver on
one accepts replays of SETs it already handled, and a Transmitter loses
its streams and queued SETs. Production deployments now say so, and are
refused stores that do not declare themselves durable
([design rule 10](docs/design-rules.md#10-production-refuses-development-shortcuts)).

**What to change:** set `Assurance`. For production, use durable stores
— `storage/sqlstore` — and set `HorizontallyScaled` if several instances
share them, which needs PostgreSQL:

```go
cfg := transmitter.Config{
	// ...
	Store:              streams,                  // sqlstore.NewStreamStore(db, sqlstore.Postgres)
	Assurance:          ssf.AssuranceProduction,  // ssf.AssuranceDevelopment with memstore
	HorizontallyScaled: true,
}
```

Under `AssuranceProduction` the issuer, and the Receiver's
`MetadataURL`, must not be loopback hosts. A custom store declares what
it guarantees by implementing `storage.StoreAssurance`; one that doesn't
counts as neither durable nor shared.

### Signing keys declare their custody (transmitter, receiver, *production only*)

**Affects:** a `transmitter.Config` or `receiver.Config` with
`Assurance: ssf.AssuranceProduction` — every Transmitter signing key,
and a `receiver.ClientCredentials` key for `private_key_jwt`.

**Why:** a Transmitter signs SETs when it queues them. A key generated
at each start strands every SET queued before a restart — Receivers no
longer find its key, and reject it — and instances with keys of their
own sign SETs that only some JWKS documents verify
([design rule 17](docs/design-rules.md#17-keys-are-operations-never-raw-private-keys)).

**What to change:** keep the key in a KMS, an HSM or durable storage,
and declare it — on the key, or by a signer implementing
`ssf.KeyCustodyAssurance`:

```go
cfg.SigningKeys = []transmitter.SigningKey{{
	Signer: kmsSigner, Algorithm: ssf.RS256, KeyID: "set-signing-3",
	Custody: ssf.KeyCustody{Durable: true, CrossInstanceConsistent: true},
}}
```

For a `private_key_jwt` client key, set
`ClientCredentials.SigningKeyCustody`. See
[Keys in a KMS or HSM](docs/guides/keys.md).

### Limits and retries are explicit (transmitter, receiver)

**Affects:** every `transmitter.Config` and `receiver.Config`.

**Why:** these settings decide how much a Receiver trusts and how much a
Receiver can claim from a Transmitter. Zero used to mean "a default the
library picked"
([design rule 2](docs/design-rules.md#2-no-implicit-defaults-for-security-relevant-configuration)).

**What to change:** set `Limits`, and on a push Transmitter `PushRetry`.
The `Recommended*` functions give the former defaults:

```go
// Before
rcfg := receiver.Config{ReplayWindow: 7 * 24 * time.Hour /* ... */}
tcfg := transmitter.Config{LongPollTimeout: 30 * time.Second /* ... */}

// After
rcfg := receiver.Config{Limits: receiver.RecommendedLimits() /* ... */}
limits := transmitter.RecommendedLimits()
limits.LongPollTimeout = 30 * time.Second
tcfg := transmitter.Config{
	Limits:    limits,
	PushRetry: transmitter.RecommendedPushRetry(), // push Transmitters only
	// ...
}
```

`receiver.Config.ReplayWindow`, `KeyMaxAge` and `MaxClockSkew` move into
`receiver.Config.Limits`; `transmitter.Config.LongPollTimeout` moves into
`transmitter.Config.Limits`.

**Changes at runtime:** a zero `receiver.Limits.MaxClockSkew` now allows
no skew; it used to mean one minute. `RecommendedLimits` gives one
minute.

### Credentials are `ssf.Secret` (ssf, receiver)

**Affects:** code that sets or reads `ssf.Delivery.AuthorizationHeader`,
`receiver.PushOptions.AuthorizationHeader` or
`receiver.ClientCredentials.ClientSecret`.

**Why:** as strings they reached logs, `%v` output and error messages
([design rule 4](docs/design-rules.md#4-secrets-are-a-type-not-a-string)).
An `ssf.Secret` withholds its value from all of them.

**What to change:** wrap values with `ssf.NewSecret`, and read them with
`Reveal`:

```go
// Before
opts := receiver.PushOptions{AuthorizationHeader: "Bearer " + token}

// After
opts := receiver.PushOptions{AuthorizationHeader: ssf.NewSecret("Bearer " + token)}
```

A `Delivery`'s JSON is its wire form and still carries the header; don't
log one as JSON. `receiver.StaticToken` is unchanged, but no longer
prints its token.

### `PermitEvent` is required (transmitter)

**Affects:** a `transmitter.Config` without `PermitEvent`.

**Why:** SSF 1.0 §9.2 asks a Transmitter to check it may share an event
before sending it. Left nil, every Receiver silently received every event
about every subject its stream rules matched — with
`default_subjects` "ALL", everything.

**What to change:** decide which Receiver may see which subject's events:

```go
cfg.PermitEvent = func(ctx context.Context, receiverID string, subject ssf.Subject, event ssf.Event) bool {
	return tenants.Owns(ctx, receiverID, subject)
}
```

For a single-tenant Transmitter whose every Receiver may see everything,
`cfg.PermitEvent = transmitter.PermitAll` says so explicitly.

### Renamed and replaced identifiers

**Affects:** code using any of these. The compiler finds every one.

| Before | After |
|---|---|
| `ssf.OAuth2AuthorizationScheme` (variable) | `ssf.OAuth2SpecURN` (constant) |
| `interop.Events`, `interop.SubjectFormats` (variables) | `interop.EventTypes()`, `interop.SubjectFormats()` |
| `interop.Apply` | `interop.ApplyTransmitter` (and new `interop.ApplyReceiver`) |
| `memstore.Store`, `memstore.New` | `memstore.StreamStore`, `memstore.NewStreamStore` |
| `caep.AssuranceLevelChange.Namespace` as `string` | `caep.AssuranceNamespace` |
| `receiver.RejectedSET`, `receiver.ErrCode*` | unexported; no public API used them |

### Storage contract (custom stores)

**Affects:** an implementation of `storage.StreamStore` other than
memstore or sqlstore.

**Why:** limits are checked inside the store, atomically with the write,
so concurrent requests cannot exceed them.

**What to change:**

- `CreateOptions.MaxStreamsPerReceiver` replaces
  `SingleStreamPerReceiver`; return `ErrTooManyStreams` (formerly
  `ErrReceiverHasStream`) when the Receiver already owns that many.
- `SetSubjectRule` and `Enqueue` take a limit, and return
  `ErrTooManySubjectRules` and `ErrQueueFull` at it.
- Store `storage.Stream.StatusSetByTransmitter`.
- A replaced subject rule becomes the newest, so `SubjectRules` returns
  it last.
- Optionally implement `storage.StoreAssurance`, or production refuses
  the store.

Run `storagetest.StreamStore`, `storagetest.ReplayStore` and
`storagetest.RevocationStore` against your stores: they check all of it.

### Behaviour a Receiver may notice

These need no code change, but may change what an application sees:

- `Receiver.Streams` returns the streams that pass its checks, and
  reports the others in a `*receiver.StreamsError`, instead of failing
  the whole list.
- `APIError.Error()` shows a JSON error's code and description, cleaned,
  or the body's length — no longer the raw body. `APIError.Body` still
  holds it.
- The Receiver sends its access token only to the issuer's origin and
  `receiver.Config.TrustedOrigins`; list any other origin the
  Transmitter's metadata or streams point at.
- SETs before their `nbf`, subjects naming a member twice, proprietary
  format names that are neither registry-style nor absolute URIs, and
  complex subjects with a critical member the Receiver does not process
  (`receiver.Config.SubjectMembers` lists the ones it does) are rejected.
- `UpdateStream`, `ReplaceStream` and `SetStatus` return
  `receiver.ErrNotProcessed` for a 202 answer.
- `ClientCredentials.TokenURL` must be `https`.
