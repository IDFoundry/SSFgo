# Changelog

## Unreleased — v1.0.0

Not yet tagged. The API has been reviewed and frozen for v1.0.0; this
entry becomes the release notes when it is. The first stable release: an
embeddable SSF Transmitter and Receiver with CAEP and RISC, verified
against the OpenID Foundation conformance suite.
See [COMPATIBILITY.md](COMPATIBILITY.md) for what v1 guarantees.

### Implemented

- OpenID Shared Signals Framework 1.0: subject identifiers (RFC 9493 and
  SSF §3, including complex subjects and matching), SET profile (§4),
  Transmitter configuration discovery (§7) and the full stream management
  API (§8), with push (RFC 8935) and poll (RFC 8936) delivery.
- OpenID CAEP 1.0: all 8 event types. OpenID RISC 1.0: all 14.
  SCIM events (RFC 9967): all 12, and the `scim` subject.
- CAEP Interoperability Profile 1.0: `caep/interop` configuration check
  and event validator.
- Receiver OAuth client credentials with `client_secret_basic`,
  `client_secret_post`, `client_secret_jwt` and `private_key_jwt`.
- Replay protection, JWKS rotation handling, SSRF-safe push delivery,
  configurable push retries, opt-in support for pre-SSF-1.0 Transmitters.

### Conformance

The full matrix runs daily in CI (`conformance/scripts/run-all.sh`):
every module of the CAEP Interop Transmitter plan passes in all four
auth × delivery variants, on both the in-memory and SQLite stores, and so
does every module of the CAEP Interop Receiver plan, as of the suite's
2026-09-30 master. See [conformance/README.md](conformance/README.md).

### Added since v0.5

- Observability: `receiver.Config.Hooks` reports every SET's outcome
  (handled, duplicate, rejected with its code, failed), every poll and
  every JWKS refetch; `transmitter.Config.Hooks` every emit (streams
  considered and queued on), push attempt (delivered, rejected, retry,
  dropped, with attempt and latency), poll served and stream change.
  Hooks run on the goroutine of the work they report, once it is done; a
  hook that panics is recovered and logged, and fields carrying the other
  party's text are cleaned, bounded and documented as untrusted.
  `Receiver.Ready` and `Transmitter.Ready` back readiness probes. No
  metrics library is imported.
- `revocation`: a `Revoker` records what session-revoked, account-disabled,
  account-purged, sessions-revoked and SCIM deactivate and delete events
  mean — a user's or one session's tokens, issued before the event, are
  revoked — and checks tokens the application validated against it, with
  `IsRevoked` or as `net/http` middleware answering 401. `New` takes
  explicit options and reports every problem with them: `Issuers` says
  which token issuer each Transmitter speaks for (`StaticTokenIssuers`,
  or `SameIssuer` for an identity provider that is its own Transmitter),
  so no Transmitter can revoke another identity provider's users;
  `Events` (`RecommendedEvents` is the usual choice); `Retention`, at
  most `MaxRetention`; and `MaxClockSkew`. Events map to users and
  sessions through iss_sub and complex subjects, to email addresses only
  with `MatchEmail` (scoped to the token issuer, ignoring ASCII case
  only), and to anything else through `KeysFor`; `OnRevoke` lets the
  application end its own sessions. New
  `storage.RevocationStore` contract, with `memstore.NewRevocationStore`
  and `storagetest.RevocationStore`, and `sqlstore.NewRevocationStore`
  for revocations that survive restarts and are shared by Receiver
  instances (a new `ssf_revocations` table, which `CreateSchema` adds to
  an existing schema).
- `ssftest`: an in-process Transmitter (`NewTransmitter`) for testing a
  Receiver — with a ready `ReceiverConfig`, `Emit`, and `SetAvailable` to
  simulate an outage — and an in-process Receiver (`NewReceiver`, then
  `Connect`) for testing a Transmitter, recording every SET it receives
  (`Received`, `WaitFor`). Both are real SSFgo implementations on TLS test
  servers, closed when the test ends.
- `Receiver.EnsureStream`: reuses the stream with the wanted delivery
  method (and push endpoint), updating its requested events, description
  or push `authorization_header` where they differ, or creates one. On a
  Transmitter that allows one stream per Receiver it replaces the only
  stream only with `StreamRequest.ReplaceOnConflict`, as that stream may
  be another application's. It retries while the Transmitter is
  unreachable, overloaded or not done processing — never on TLS or
  certificate failures — so a Receiver can call it on every start.
- Signing algorithms RS384, RS512, PS384, PS512, ES384 (P-384) and ES512
  (P-521), alongside RS256, PS256, ES256 and EdDSA — every asymmetric
  algorithm of RFC 7518 §3.1 — for signing, verification, JWKs and
  client assertions. `ssf.SignatureAlgorithms()` lists them. HMAC and
  `none` remain refused.
- Metadata discovery: when the SSF 1.0 §7.2 location does not exist, the
  Receiver looks for the issuer with `/.well-known/ssf-configuration`
  appended, where Transmitters built on OpenID Providers often publish
  it, then at RISC's `/.well-known/risc-configuration` (SSF §7.2.2). Only
  a location that is not found moves on; the metadata must still name the
  configured issuer. New `receiver.Config.MetadataURL` names the location
  outright.
- SCIM events (RFC 9967): the new `scim` package has all 12 event
  types — feed add and remove, create, patch and put in full and notice
  mode, delete, activate, deactivate and the asynchronous response — and
  `ssf.SCIMSubject` is the `scim` subject. A SET carries one event, so the
  events of one SCIM transaction are separate SETs sharing a `txn`: the
  new `Transmitter.EmitTxn` emits under a chosen `txn`, as an
  asynchronous response requires.
- Transmitter-initiated verification (SSF §8.1.4): `tx.SendVerification`
  sends a verification event without state on demand, and
  `transmitter.Config.VerifyNewStreams` sends one on every new stream.
- `inactivity_timeout` (SSF §8.1.1): `transmitter.Config.Inactivity`
  advertises the timeout and pauses, disables or deletes streams whose
  Receiver has gone quiet, with the stream-updated event SSF requires.
  Enforced by `Run`, or by calling `tx.ExpireInactiveStreams`. New
  `storage.Stream.LastActivity`. On the Receiver side, `r.KeepAlive`
  keeps a stream from reaching its timeout until its context is done.
- `storage/sqlstore`, a separate module: durable `StreamStore` and
  `ReplayStore` implementations on `database/sql` for PostgreSQL and
  SQLite, passing the `storagetest` contract on both. The core module
  still has no dependencies. The daily conformance run also exercises it:
  the Transmitter matrix runs on SQLite as well as in memory.
- Receiver-side CAEP Interoperability Profile preset:
  `interop.ApplyReceiver` checks the Receiver's configuration (RS256
  accepted, a profile event type registered) and installs
  `interop.CheckTransmitterMetadata` through the new
  `receiver.Config.CheckMetadata`, so `receiver.New` refuses a Transmitter
  whose metadata does not meet the profile (§2.3.1–§2.3.7).
  `interop.CheckReceiverConfig` and `interop.CheckTransmitterMetadata` are
  usable on their own.
- `receiver.ErrIssuerMismatch`: a stream whose `iss` is not the configured
  issuer (SSF 1.0 §8.1.1.1) is returned together with this error, as
  `ErrAudienceMismatch` already was, so the caller can delete the stream
  it refused instead of leaving it on the Transmitter.

### Testing

- CI builds `storage/sqlstore` against the core version its `go.mod`
  requires, not only the core in the same checkout, so its users never
  get a core too old for it; the requirement is raised to the current
  core.
- Continuous fuzzing: `.github/workflows/fuzz.yml` runs all ten fuzz
  targets daily for ten minutes each, carrying each target's corpus
  between runs. New targets cover the Receiver's push endpoint and poll
  responses, the Transmitter's management API, JWK parsing and the wire
  types' JSON decoders. CI fails if a fuzz target is not scheduled.

### Security

A trust-boundary review of the whole repository
([docs/security-review-2026-09.md](docs/security-review-2026-09.md)),
then an adversarial one
([docs/security-review-2026-10.md](docs/security-review-2026-10.md)),
and an adversarial review of what was added after it
([docs/security-review-2026-10-additions.md](docs/security-review-2026-10-additions.md));
each finding was reproduced by a failing test before it was fixed.

- New `transmitter.Config.PermitEvent`: the Transmitter decides which
  Receiver may receive events about which subject (SSF §9.2).
- The Receiver follows only `https` redirects, so its access token and
  client credentials can no longer be sent in cleartext after a redirect;
  `ClientCredentials.TokenURL` must be `https`.
- The Receiver rejects SETs older than `ReplayWindow`, closing replay of
  captured SETs once their replay record expired.
- New `transmitter.Config.Limits` caps streams per Receiver, subject rules
  per stream and queued SETs per stream.
- The push client's public-address check covers NAT64, IPv4-compatible,
  6to4 and Teredo addresses.
- A status the Transmitter sets with `SetStreamStatus` can no longer be
  overridden by the Receiver.
- A handler panic no longer loses its SET; push settings are validated;
  log output and pending verification state are bounded.
- A push client that hung up could cancel the JWKS refetch its SET
  triggered and use up the once-a-minute allowance. Repeated, that kept a
  Receiver from learning a rotated key — rejecting, and so losing, the
  Transmitter's SETs — or from ever dropping a retired key. Refetches now
  run on their own context, shared by concurrent callers.
- A 307/308 redirect replayed a request body — a client secret or
  assertion, or a push `authorization_header` — to another host. Requests
  carrying credentials now follow redirects only within their origin.
- The Receiver sends its access token only to the issuer's origin and the
  new `receiver.Config.TrustedOrigins`; metadata or a stream configuration
  pointing elsewhere is refused.
- `KeepAlive` bounds the Transmitter's `inactivity_timeout`, which could
  overflow into a busy loop, and stops on `ErrIssuerMismatch` or
  `ErrAudienceMismatch`. One poll response is handled up to `MaxEvents`
  (or 1000) SETs with bounded logging, `RunPoller` pauses between empty
  polls, and `APIError.Body` keeps at most 1 KiB.
- `transmitter.Config.PermitEvent` is now required; the new
  `transmitter.PermitAll` permits every event, for single-tenant
  Transmitters. Left nil, it used to permit everything silently.
- A Receiver could escape a status the Transmitter set with
  `SetStreamStatus` by deleting the stream and creating another. While
  such a status holds, both are refused with 403.
- Subject rules are at most 2 KiB, and an included complex subject needs
  one of the SSF 1.0 §3.3 members. Large rules made every `Emit` slow for
  every Receiver; a complex subject of unused members matched every
  complex subject.
- A read-only (`AccessRead`) token no longer sees a push stream's
  `authorization_header`.
- One long poll per stream waits at a time; another is answered at once.
  Per-stream state of deleted streams is no longer kept forever, and push
  delivery logs storage errors.
- The push client's public-address check also refuses IPv4-translated,
  site-local, discard-only and benchmarking IPv6 ranges, and NAT64's
  `64:ff9b::/32` beyond the well-known prefix. New
  `transmitter.PublicAddressControl` lets a custom push client keep it.
- Ed25519 public keys of small order, for which one signature verifies
  for many messages, are refused. A compact JWS must use strict
  base64url, so a signed token has a single encoding, and its header is
  read by exact member names, refusing repeated members and an empty
  `crit`.
- Storage contract: `CreateOptions.MaxStreamsPerReceiver` replaces
  `SingleStreamPerReceiver` (`ErrTooManyStreams` replaces
  `ErrReceiverHasStream`); `SetSubjectRule` and `Enqueue` take a limit
  and return `ErrTooManySubjectRules` / `ErrQueueFull`;
  `storage.Stream.StatusSetByTransmitter` is new.

### Fixed since v0.5

- Found by the new fuzz targets: an empty `ssf.Audience` encoded as
  `null`, which `Audience` itself refused to decode (it now encodes `[]`);
  `ssf.NumericDate` accepted values below one second that encoded as `0`
  and then failed to decode (it now requires at least one second).
- The Receiver now enforces SSF 1.0 §3.6: a SET whose complex subject
  carries a member the Transmitter declared critical
  (`critical_subject_members`) and the Receiver does not process is
  rejected instead of handled. New `receiver.Config.SubjectMembers` lists
  non-standard members the application does process.
- `interop.ValidateEvent` now also requires a non-empty `reason_admin` on
  device-compliance-change (CAEP Interop §3.3), and checks events passed
  by pointer, which used to skip the `reason_admin` check entirely.
- A subject re-added to a stream could stay excluded: a replaced subject
  rule kept its original position, so a later rule for a broader subject
  still decided (SSF 1.0 §8.1.3). A replaced rule is now the newest. This
  changes the `storage.StreamStore` contract for `SetSubjectRule` and
  `SubjectRules`; `memstore`, `sqlstore` and `storagetest` follow it.
- The Receiver could lose a SET redelivered while its first copy was still
  being handled: the retry was acknowledged at once, and if the handling
  then failed nothing redelivered it. A redelivery now waits for the first
  copy's outcome and reports it (RFC 8935 §2).
- A nil `receiver.StreamRequest.Delivery` now sends poll explicitly instead
  of leaving out `delivery`, which SSF 1.0 §8.1.1 makes required.
- `UpdateStream`, `ReplaceStream` and `SetStatus` return the new
  `receiver.ErrNotProcessed` when the Transmitter answers 202 "accepted,
  not processed" (SSF 1.0 §8.1.1.3, §8.1.1.4, §8.1.2.2), instead of a
  generic `*APIError`.
- Stricter parsing of what a Transmitter sends: a SET is refused before
  its `nbf` (RFC 7519 §4.1.5), and a subject that names a member twice —
  a complex subject listing `user` twice, say — is refused instead of the
  last occurrence silently winning. A proprietary subject format name
  must follow the registry's syntax, as SSF's own `catalog_item` does, or
  be an absolute URI (RFC 9493 §3).
- Push delivery retries a SET the Receiver rejects with `invalid_key`,
  `authentication_failed` or `access_denied` — often temporary, while it
  fetches a rotated key or a credential is updated — up to eight times,
  instead of dropping it at once (RFC 8935 §2.3, §4). Each SET now gets
  the full `PushRetry.MaxAttempts`: the failures of the SET before it in
  the queue used to count against it.
- Every SET the Transmitter sends now carries a `txn` (SSF 1.0 §4.1.9).
  Verification and stream-updated SETs used to omit it, which the
  conformance suite now warns about; each gets a `txn` of its own.

### Changed since v0.5

API review before the freeze — all breaking, none behavioural:

- `ssf.OAuth2AuthorizationScheme` (a mutable variable) is replaced by the
  constant `ssf.OAuth2SpecURN`.
- `interop.Events` and `interop.SubjectFormats` (mutable slices that
  `ValidateEvent` read) are now functions, `interop.EventTypes()` and
  `interop.SubjectFormats()`, returning copies.
- `memstore.Store` / `memstore.New` are renamed `memstore.StreamStore` /
  `memstore.NewStreamStore`, matching `memstore.ReplayStore`.
- `interop.Apply` is renamed `interop.ApplyTransmitter`, alongside the new
  `interop.ApplyReceiver`.
- `caep.AssuranceLevelChange.Namespace` has the new type
  `caep.AssuranceNamespace`.
- `receiver.RejectedSET` and the `receiver.ErrCode*` constants are no
  longer exported; no public API returned or accepted them.
- `transmitter.New` and `receiver.New` copy the slices in their Config,
  and `Metadata()` returns a copy, so neither can be changed from outside
  afterwards.

Since the freeze, one behavioural change: `Receiver.Streams` returns the
streams that pass its checks, reporting the others in a
`*receiver.StreamsError` the caller can use to delete them, instead of
failing the whole list for one stream.

Configuration that decides security has no implicit defaults
([docs/design-rules.md](docs/design-rules.md), rule 2):

- `receiver.Config.ReplayWindow`, `KeyMaxAge` and `MaxClockSkew` move into
  a required `receiver.Config.Limits`; `receiver.RecommendedLimits()`
  gives the former defaults (7 days, 24 hours, 1 minute). A zero
  `MaxClockSkew` now means none rather than one minute, and
  `ReplayWindow` is at most `receiver.MaxReplayWindow`.
- `transmitter.Config.Limits` is required, each field positive, and
  gains `LongPollTimeout` (formerly `Config.LongPollTimeout`);
  `transmitter.RecommendedLimits()` gives the former defaults.
- `transmitter.Config.PushRetry` is required for a Transmitter that
  delivers by push; `transmitter.RecommendedPushRetry()` gives the former
  defaults.
- `ssftest` fills in the recommended values where a test leaves them
  unset.
