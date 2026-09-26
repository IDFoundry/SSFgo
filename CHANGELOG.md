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

### Changed since v0.5

API review before the freeze — all breaking, none behavioural:

- `ssf.OAuth2AuthorizationScheme` (a mutable variable) is replaced by the
  constant `ssf.OAuth2SpecURN`.
- `interop.Events` and `interop.SubjectFormats` (mutable slices that
  `ValidateEvent` read) are now functions, `interop.EventTypes()` and
  `interop.SubjectFormats()`, returning copies.
- `memstore.Store` / `memstore.New` are renamed `memstore.StreamStore` /
  `memstore.NewStreamStore`, matching `memstore.ReplayStore`.
- `caep.AssuranceLevelChange.Namespace` has the new type
  `caep.AssuranceNamespace`.
- `receiver.RejectedSET` and the `receiver.ErrCode*` constants are no
  longer exported; no public API returned or accepted them.
- `transmitter.New` and `receiver.New` copy the slices in their Config,
  and `Metadata()` returns a copy, so neither can be changed from outside
  afterwards.
