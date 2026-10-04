# Architecture

SSFgo is a Go implementation of the OpenID Shared Signals Framework
([SSF 1.0][ssf]) with the two event families defined on top of it:
Continuous Access Evaluation ([CAEP 1.0][caep]) and Risk Incident Sharing
and Coordination ([RISC 1.0][risc]). It provides an embeddable
Transmitter and an embeddable Receiver.

The guiding rule for every public API, inherited from FAPIgo:

> **Expose business decisions, not protocol mechanisms.**

An application decides *what happened* (a session was revoked, a
credential changed), *who may manage streams*, and *which durable
infrastructure to use*. It must never have to — or be able to — hand-build
a Security Event Token, skip signature or audience validation, or weaken
replay protection.

## Package layout

```text
github.com/idfoundry/ssfgo     // package ssf: shared value types only
├── caep/                      // CAEP 1.0 event types (8)
│   └── interop/               // CAEP Interoperability Profile presets for both roles
├── risc/                      // RISC 1.0 event types (14, sessions-revoked deprecated)
├── transmitter/               // Transmitter role
├── receiver/                  // Receiver role
├── storage/                   // storage contracts
│   ├── memstore/              // in-memory implementation
│   ├── sqlstore/              // PostgreSQL and SQLite (a separate module)
│   │   └── cmd/conformance-transmitter/ // the conformance Transmitter on sqlstore
│   └── storagetest/           // exported contract tests for third-party backends
├── internal/
│   ├── jose/                  // minimal JWS: RS256, PS256, ES256, EdDSA; JWK/JWKS
│   ├── critical/              // RFC 7515 "crit" check
│   ├── setcodec/              // SET encode (sign) / decode (verify) per SSF §4
│   ├── clientassertion/       // RFC 7523 client assertions (HS256 kept out of jose)
│   ├── conformance/txharness/ // the conformance Transmitter, on any StreamStore
│   └── testcert/              // throwaway TLS certificates for the harnesses
├── cmd/conformance-transmitter/ // the conformance Transmitter on memstore
├── cmd/conformance-receiver/  // drives the Receiver through OIDF Receiver plans
├── examples/session-revocation/ // both roles in one process
└── conformance/               // suite configs, run scripts, recorded results
```

### The root `ssf` package

Holds only value types that both roles and both event families share:

- **Subject identifiers** (`Subject`): every RFC 9493 format, the SSF §3.5
  formats (`jwt_id`, `saml_assertion_id`, `ip-addresses`), SSF §3.3
  complex subjects, and `ProprietarySubject` for formats agreed out of
  band (SSF §3.4). `Subject` is a closed interface — the set of concrete
  types is fixed by this package, so a switch over it is exhaustive.
- **Events** (`Event`, `EventType`, `Registry`): the contract every event
  family implements, and an explicit registry mapping event-type URIs to
  decoders. There is no global registry: the Receiver is given one, and
  the Transmitter derives `events_supported` from one.
- **SSF's own events**: `Verification` (§8.1.4.1) and `StreamUpdated`
  (§8.1.5). These belong to SSF, not CAEP.
- **`SET`**: the verified, decoded view of a Security Event Token that
  handlers receive.
- **Generic JSON value types**: `NumericDate`, `LocalizedText`.
- **Management API wire types** shared by both roles:
  `TransmitterMetadata`, `StreamConfiguration`, `Delivery`, `StreamState`
  and the subject and verification request bodies, plus `WellKnownURL`.

`ssf` never imports `caep` or `risc`.

### Dependency rules

```text
caep        ──► ssf
risc        ──► ssf, caep (value types only: credential_type)
transmitter ──► ssf, storage, internal/*
receiver    ──► ssf, storage, internal/*
caep/interop ─► ssf, caep, transmitter, receiver
```

- `transmitter` and `receiver` never import each other. They share
  protocol implementation through `internal/`, not role-level types.
- Nothing in the library imports `caep` or `risc` except `caep/interop`
  and applications. Event families are plugged in through `ssf.Registry`.
- `risc` may import `caep` only for value types RISC normatively
  references (RISC §2.7: `credential_type` takes CAEP's values). It never
  aliases or converts events between families: the deprecated RISC
  `sessions-revoked` and CAEP `session-revoked` are distinct types.
- The module has no third-party dependencies. `storage/sqlstore` is a
  separate module so that stays true: its package imports only the
  standard library and the core module, and the database drivers it is
  tested with are required by its own `go.mod` alone.

## Wire-format decisions

These are deliberate and cite the requirement they implement.

| Decision | Source |
|---|---|
| Primary subject is the top-level `sub_id` claim; the SET never carries `sub` or `exp` | SSF §3.1, §4.1.2, §4.1.7 |
| JOSE header `typ` is `secevent+jwt` (decode also accepts `application/secevent+jwt`) | SSF §4.1.1, RFC 8417 §2.3, RFC 7515 §4.1.9 |
| Exactly one event per SET, both when encoding and decoding | CAEP Interop §2.8.1 (SSF §4.2.1 SHOULD) |
| Unknown members in events and subjects are ignored on decode, never emitted on encode | SSF §4.2.3, RFC 9493 §3 |
| `event_timestamp` is a JSON number of seconds | CAEP §2 |
| `reason_admin` / `reason_user` are non-empty objects keyed by BCP 47 tag | CAEP §2 |
| The verification and stream-updated events require an `opaque` `sub_id` | SSF §8.1.4.1, §8.1.5 |
| RISC identifier-changed/recycled require an `email` or `phone_number` `sub_id` | RISC §2.5, §2.6 |
| The caller states the accepted signature algorithms; the header `alg` is never trusted as policy | RFC 8725 §3.1 |
| RS256 is supported (unlike FAPIgo) because CAEP Interop §2.6 requires it | CAEP Interop §2.6 |

## Delivery (v0.3)

Delivery is a per-stream durable queue of signed SETs with two drains,
not a single `Deliver(set)` call.

- **Emit.** `Transmitter.Emit(ctx, subject, event)` validates the event
  (including an optional profile validator such as
  `caep/interop.ValidateEvent`), then queues one SET per stream that
  should get it — not disabled, event type in `events_delivered`, subject
  included — each with its own `aud` and `jti` and a shared `txn`.
- **Poll** (RFC 8936). Each stream's `endpoint_url` is served by the same
  handler. A poll acknowledges `ack` and `setErrs` first, then returns up
  to `maxEvents` SETs with `moreAvailable`; `maxEvents: 0` is
  acknowledge-only. SETs stay queued, and are returned again, until
  acknowledged. Without `returnImmediately` the request long-polls, woken
  when a SET is queued in this process and re-checking storage every
  second otherwise.
- **Push** (RFC 8935). `Transmitter.Run(ctx)` — started by the
  application, never by `New` — pushes each push stream's SETs one at a
  time, oldest first. 2xx is delivered; a 400 with an RFC 8935 error body
  means the Receiver rejects that SET, which is logged and dropped; any
  other failure is retried with exponential backoff (1 s to 5 min).

**Subjects.** Add and Remove Subject requests are stored as include and
exclude rules. The last rule whose subject matches the event subject (SSF
§8.1.3.1) decides; with no match, `default_subjects` does. A rule store is
needed because under `ALL`, removing a subject must be remembered.

**Status.** An enabled stream delivers everything; a paused one holds
SETs; a disabled one discards its queue and accepts nothing new. The one
exception is the stream-updated event sent when the Transmitter changes a
status itself — with `SetStreamStatus` or on an inactivity timeout
(§8.1.5): it is a control event,
delivered even though the stream is no longer enabled, because the spec
requires the Receiver to be told before the stream stops. Status changes
the Receiver requests send no event.

**Scale.** `Run` and `Emit` scan `AllStreams`, and `Run` then reads each
push stream's queue every second. That is fine for modest stream counts
in `memstore` or `storage/sqlstore`; a large deployment's storage backend
is where a better index belongs, and the contract can grow one (as an
optional interface, see [COMPATIBILITY.md](COMPATIBILITY.md)) without
changing the Transmitter's behaviour. See [Performance](#performance).

## Performance

Benchmarks live next to the code they measure; CI runs each once so they
keep working, but does not compare timings. Run them with:

```bash
go test -run '^$' -bench . ./transmitter ./receiver
(cd storage/sqlstore && go test -run '^$' -bench . ./...)   # SSFGO_TEST_POSTGRES for PostgreSQL
```

Measured September 2026 on an Intel Xeon W-2140B (8 cores), Go 1.27,
RS256 with a 2048-bit key:

| Benchmark | Result |
|---|---|
| `transmitter` `Emit`, 1 / 10 / 100 poll streams (memstore) | 1.2 / 12 / 124 ms per event — about 800 SETs/s |
| `transmitter` `Poll`, 10 SETs over HTTPS | 0.14 ms |
| `transmitter` `Push`, one stream over HTTPS | about 4,500 SETs/s |
| `receiver` `PushHandler` (verify, replay check, dispatch) | 0.05 ms per SET |
| `sqlstore` `Emit`, 10 streams, SQLite | 16 ms per event — about 630 SETs/s |
| `sqlstore` operations, SQLite | 0.05–0.35 ms each |

- **Signing dominates `Emit`.** Each stream gets its own signed SET (its
  own `aud` and `jti`), and `Emit` signs them one after another, so
  throughput is about one RS256 signature (1.2 ms) per SET whatever the
  number of streams. ES256 (35 µs) and EdDSA (24 µs) keys sign 35–50
  times faster, but a Transmitter following the CAEP Interoperability
  Profile must sign with RS256 (§2.6); others can choose.
- **Verification is cheap.** A Receiver verifies an RS256 SET in a small
  fraction of the time the Transmitter takes to sign it.
- **Push is sequential per stream** — one SET at a time, oldest first, by
  design (see Delivery) — while different streams are pushed concurrently.
- **Databases add round trips.** `Emit` makes a few queries per stream
  (subject rules, then a locked count and insert), so on PostgreSQL its
  cost follows network latency: against PostgreSQL 17 in Docker Desktop,
  where each query took about 0.7 ms, it managed about 220 SETs/s for ten
  streams.

## Hardening (v0.5)

- **Push SSRF.** `transmitter.NewPushClient`, the default push client,
  checks the address actually dialled is public unicast (so DNS
  rebinding cannot reach internal hosts), follows no redirects and uses no
  proxy. Deployments with Receivers on a private network pass their own
  `HTTPClient`.
- **Retries.** `Config.PushRetry` sets the backoff bounds and an optional
  attempt cap after which a SET is dropped and logged.
- **Keys.** The Receiver refetches the JWKS after `KeyMaxAge` (24 h by
  default) so retired keys stop being trusted, and when a SET names an
  unknown key; all refetches are rate-limited to one a minute and a failed
  refetch keeps the keys already held. A refetch runs on its own context
  and is shared by concurrent callers, so a push client that hangs up can
  neither cancel it nor waste the allowance on a fetch that never
  completes.
- **Credentials.** The Receiver sends its access token only to the
  issuer's origin and `Config.TrustedOrigins`, so neither the metadata
  nor a stream configuration can steer it elsewhere. A request with an
  `Authorization` header or a body follows redirects only within its
  origin, since a 307/308 replays the body — a client secret or assertion,
  or a push `authorization_header`.
- **Legacy Transmitters.** `receiver.Config.AcceptLegacySubjects` opts in
  to pre-SSF-1.0 SETs — the subject inside the event, Google's
  `subject_type` — without loosening anything for other Receivers.
- **Client authentication.** `ClientCredentials` supports
  `client_secret_basic`, `client_secret_post`, `client_secret_jwt` (HS256)
  and `private_key_jwt`. HS256 lives in `internal/clientassertion`, never
  in `internal/jose`, so a shared-secret MAC can never verify a SET.

See [SECURITY.md](SECURITY.md) for the security model as a whole.

## Receiver (v0.4)

`receiver.New(ctx, Config)` fetches the Transmitter Configuration Metadata
from the well-known location derived from `Config.Issuer`, refuses it
unless it names exactly that issuer (SSF §7.2.4), and fetches the
Transmitter's JWKS.

- **Management client.** Methods for every §8 operation. Returned stream
  configurations are checked: `iss` must match, and `aud` must include
  `Config.Audience` (otherwise every SET on the stream would be rejected;
  the stream is returned with `ErrAudienceMismatch` so the caller can
  delete it). Access tokens come from a `TokenSource` — `StaticToken`, or
  `ClientCredentials`, which caches and is invalidated once on a 401.
  `KeepAlive` keeps a stream inside its `inactivity_timeout`.
- **Delivery.** `PushHandler` answers 202 once a SET is verified and
  handled, 400 with an RFC 8935 error body for a SET it rejects, and 500
  when a handler fails, so the Transmitter retries. `Poll` acknowledges
  what the previous poll processed (`ack`), reports rejections
  (`setErrs`), and leaves SETs whose handler failed unacknowledged so they
  are redelivered; `RunPoller` long-polls in a loop.
- **Processing.** Every SET is decoded by `internal/setcodec` against the
  Transmitter's keys (refetched at most once a minute when a SET names an
  unknown key), then recorded in a `storage.ReplayStore` so a redelivered
  SET is acknowledged without being handled twice. A verification event
  carrying a `state` must match one `RequestVerification` issued and has
  not yet been used (§8.1.4.1); one without `state` is accepted
  (§8.1.4). A SET whose complex subject carries a member the Transmitter
  declares critical, and the Receiver does not process, is rejected
  (§3.6): the §3.3 members always count as processed, others only when
  listed in `Config.SubjectMembers`. Handlers are registered per event
  type, typed with `receiver.On[E]`; an event of a registered type with no
  handler is acknowledged and ignored.

## Stream management (v0.2)

`transmitter.New(Config)` returns one `http.Handler` serving the metadata
document, the JWKS and every §8 endpoint. All paths derive from the
issuer, so the handler is mounted at the host root and several
Transmitters can share a host through issuer paths.

**Authorization.** The Transmitter never interprets access tokens. It
takes the bearer token from the `Authorization` header only (never the
query string, CAEP Interop §2.7.2) and hands it to the application's
`AuthorizeFunc`, which returns the `Receiver`: an ID, the audience of its
streams, and an `Access` level (`AccessRead` ≈ `ssf.read`,
`AccessManage` ≈ `ssf.manage`, CAEP Interop §2.7.3). Streams belong to the
Receiver that created them; another Receiver's stream is reported as 404,
so stream IDs cannot be probed.

**Storage.** `storage.StreamStore` holds streams, their subjects and the
per-stream queue of signed SETs. `UpdateStream` takes a function applied
atomically, so read-modify-write operations (PATCH, status changes,
verification rate limiting) cannot lose updates in a durable backend.
`storagetest.StreamStore` is the contract every backend must pass.
`storage/sqlstore` passes it on PostgreSQL and SQLite: on PostgreSQL each
atomic operation locks the stream's row (`SELECT ... FOR UPDATE`) or, when
creating a stream under a per-Receiver limit, takes a transaction-scoped
advisory lock on the Receiver, so Transmitter instances can share one
database; on SQLite, write transactions begin `IMMEDIATE`. Subject rules
are matched with `ssf.SubjectsEqual` in Go, not by comparing stored JSON,
since equal subjects can be encoded differently.

**Decisions the spec leaves open:**

| Question | SSFgo's answer |
|---|---|
| Several streams per Receiver? | `Config.MultipleStreamsPerReceiver`; if false, 409 (§8.1.1.1) |
| Receiver asks for poll with its own `endpoint_url` | Ignored: the Transmitter supplies poll URLs (§6.1.2) |
| `authorization_header` in read responses | Returned to the owning Receiver, so read-modify-replace (§8.1.1.4) keeps it |
| Transmitter-supplied property in PATCH/PUT | Must equal the current value, else 400 (§8.1.1.3) |
| Receiver-requested status change | Applied without a stream-updated event (§8.1.2 requires one only for Transmitter-initiated changes); refused with 403 while a status the Transmitter set with `SetStreamStatus` is in force |
| Which Receiver may see which events | `Config.PermitEvent`, checked per stream at `Emit` (§9.2) |
| How much one Receiver may store | `Config.Limits`: streams, subject rules and queued SETs |
| Transmitter-initiated verification | On demand (`SendVerification`) or on every new stream (`Config.VerifyNewStreams`); never limited by `min_verification_interval`, which binds Receivers |
| What restarts `inactivity_timeout` | Any management request that references the stream, and polls on a poll stream; listing all streams does not. Recorded at most once per tenth of the timeout |
| Inactivity pause or disable | Sends stream-updated, but — unlike `SetStreamStatus` — does not lock the status, so the Receiver can re-enable the stream |
| Receiver keep-alive | `KeepAlive` reads the stream's configuration every half of the advertised timeout: a management request any Transmitter must count as activity, which also picks up a changed timeout. It never re-enables a stream the Transmitter has already paused |
| Verification on a disabled stream | 204, but nothing is queued (§8.1.2.1: disabled holds no events) |
| `min_verification_interval` exceeded | 429 with `Retry-After` |

The conformance harness in `internal/conformance/txharness` adds a minimal
client-credentials token endpoint for the suite; it is not part of the
library.

## Conformance

The correctness bar is the OIDF conformance suite, not only this repo's
tests. As of September 2026 every SSF test plan is labelled "alpha — not
currently part of certification program", so **v1.0 means the matrix
below passes reliably**; certification is submitted once OIDF opens it.

| Plan | Variants | Gate |
|---|---|---|
| CAEP Interop Transmitter | push, poll × static, dynamic auth | required |
| CAEP Interop Receiver | push, poll × static, dynamic auth | required |
| Base Receiver "supported events" (CAEP + RISC) | push, poll | required (only external check of RISC) |
| Remaining base SSF plans | — | reported, non-blocking |

Every suite failure becomes a local regression test before it is fixed.

[ssf]: https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html
[caep]: https://openid.net/specs/openid-caep-1_0-final.html
[risc]: https://openid.net/specs/openid-risc-1_0-final.html
