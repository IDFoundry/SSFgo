# Changelog

## Unreleased — v1.0.0

Not yet tagged. The API has been reviewed and frozen for v1.0.0; this
entry becomes the release notes when it is. The first stable release: an embeddable SSF Transmitter and Receiver with
CAEP and RISC, verified against the OpenID Foundation conformance suite.
See [COMPATIBILITY.md](COMPATIBILITY.md) for what v1 guarantees.

### Implemented

- OpenID Shared Signals Framework 1.0: subject identifiers (RFC 9493 and
  SSF §3, including complex subjects and matching), SET profile (§4),
  Transmitter configuration discovery (§7) and the full stream management
  API (§8), with push (RFC 8935) and poll (RFC 8936) delivery.
- OpenID CAEP 1.0: all 8 event types. OpenID RISC 1.0: all 14.
- CAEP Interoperability Profile 1.0: `caep/interop` configuration check
  and event validator.
- Receiver OAuth client credentials with `client_secret_basic`,
  `client_secret_post`, `client_secret_jwt` and `private_key_jwt`.
- Replay protection, JWKS rotation handling, SSRF-safe push delivery,
  configurable push retries, opt-in support for pre-SSF-1.0 Transmitters.

### Conformance

The full matrix runs daily in CI (`conformance/scripts/run-all.sh`):
every module of the CAEP Interop Transmitter plan passes in all four
auth × delivery variants; the Receiver passes every module except
`openid-ssf-receiver-stream-caep-interop`, which fails because of a
conformance-suite defect (millisecond `event_timestamp`), documented in
[conformance/README.md](conformance/README.md).

### Added since v0.5

- Receiver-side CAEP Interoperability Profile preset:
  `interop.ApplyReceiver` checks the Receiver's configuration (RS256
  accepted, a profile event type registered) and installs
  `interop.CheckTransmitterMetadata` through the new
  `receiver.Config.CheckMetadata`, so `receiver.New` refuses a Transmitter
  whose metadata does not meet the profile (§2.3.1–§2.3.7).
  `interop.CheckReceiverConfig` and `interop.CheckTransmitterMetadata` are
  usable on their own.

### Testing

- Continuous fuzzing: `.github/workflows/fuzz.yml` runs all ten fuzz
  targets daily for ten minutes each, carrying each target's corpus
  between runs. New targets cover the Receiver's push endpoint and poll
  responses, the Transmitter's management API, JWK parsing and the wire
  types' JSON decoders. CI fails if a fuzz target is not scheduled.

### Security

A trust-boundary review of the whole repository
([docs/security-review-2026-09.md](docs/security-review-2026-09.md));
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
