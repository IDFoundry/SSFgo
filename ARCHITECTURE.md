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
├── caep/                      // CAEP 1.0 event types (8) + typed handlers
│   └── interop/               // CAEP Interoperability Profile preset + startup checker
├── risc/                      // RISC 1.0 event types (14, sessions-revoked deprecated)
├── transmitter/               // Transmitter role
├── receiver/                  // Receiver role (v0.4+)
├── storage/                   // storage contracts
│   ├── memstore/              // in-memory implementation
│   └── storagetest/           // exported contract tests for third-party backends
├── internal/
│   ├── jose/                  // minimal JWS: RS256, PS256, ES256, EdDSA; JWK/JWKS
│   ├── critical/              // RFC 7515 "crit" check
│   └── setcodec/              // SET encode (sign) / decode (verify) per SSF §4
├── cmd/conformance-transmitter/ // Transmitter wired up for the OIDF suite
├── examples/
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
```

- `transmitter` and `receiver` never import each other. They share
  protocol implementation through `internal/`, not role-level types.
- Nothing in the library imports `caep` or `risc` except `caep/interop`
  and applications. Event families are plugged in through `ssf.Registry`.
- `risc` may import `caep` only for value types RISC normatively
  references (RISC §2.7: `credential_type` takes CAEP's values). It never
  aliases or converts events between families: the deprecated RISC
  `sessions-revoked` and CAEP `session-revoked` are distinct types.
- The module has no third-party dependencies.

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

## Delivery model (v0.3)

Delivery is a per-stream durable queue with two drains, not a single
`Deliver(set)` call. v0.2 introduced the queue (`Enqueue`,
`PendingEvents`, used by verification requests); v0.3 adds acknowledgement
and the drains:

- **Push** (RFC 8935): a worker POSTs queued SETs to the Receiver's
  `endpoint_url` with the configured `authorization_header`, expects 202,
  parses RFC 8935 §2.3 error bodies, and retries with backoff.
- **Poll** (RFC 8936): an `http.Handler` serving `maxEvents`,
  `returnImmediately`, `ack` and `setErrs`, with long-polling.

Stream status acts on the queue: `enabled` delivers, `paused` holds,
`disabled` drops (SSF §8.1.2).

`Transmitter.Emit(ctx, subject, event)` routes one event to every stream
whose `events_delivered` contains its type and whose subjects match (SSF
§8.1.3.1), minting a separate SET — own `aud`, own `jti` — per stream.

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

**Decisions the spec leaves open:**

| Question | SSFgo's answer |
|---|---|
| Several streams per Receiver? | `Config.MultipleStreamsPerReceiver`; if false, 409 (§8.1.1.1) |
| Receiver asks for poll with its own `endpoint_url` | Ignored: the Transmitter supplies poll URLs (§6.1.2) |
| `authorization_header` in read responses | Returned to the owning Receiver, so read-modify-replace (§8.1.1.4) keeps it |
| Transmitter-supplied property in PATCH/PUT | Must equal the current value, else 400 (§8.1.1.3) |
| Receiver-requested status change | Applied without a stream-updated event (§8.1.2 requires one only for Transmitter-initiated changes) |
| Verification on a disabled stream | 204, but nothing is queued (§8.1.2.1: disabled holds no events) |
| `min_verification_interval` exceeded | 429 with `Retry-After` |

The conformance harness in `cmd/conformance-transmitter` adds a minimal
client-credentials token endpoint for the suite; it is not part of the
library.

## Conformance

The correctness bar is the OIDF conformance suite, not only this repo's
tests. As of September 2026 every SSF test plan is labelled "alpha — not
currently part of certification program", so **v1.0 means the matrix
below passes reliably**; certification is submitted once OIDF opens it.

| Plan | Variants | Gate |
|---|---|---|
| CAEP Interop Transmitter | push, poll | required |
| CAEP Interop Receiver | push, poll × static, dynamic auth | required |
| Base Receiver "supported events" (CAEP + RISC) | push, poll | required (only external check of RISC) |
| Remaining base SSF plans | — | reported, non-blocking |

Every suite failure becomes a local regression test before it is fixed.

[ssf]: https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html
[caep]: https://openid.net/specs/openid-caep-1_0-final.html
[risc]: https://openid.net/specs/openid-risc-1_0-final.html
