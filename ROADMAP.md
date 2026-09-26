# Roadmap

Each milestone ends with an exit criterion that can be checked, mostly
against the OIDF conformance suite. See [ARCHITECTURE.md](ARCHITECTURE.md)
for the design these milestones build.

## v0.1 — Wire formats ✅

- Subject identifiers: every RFC 9493 format, SSF §3.5 formats, complex
  subjects, proprietary formats, and SSF §8.1.3.1 subject matching.
- `Event`/`Registry`, SSF's verification and stream-updated events.
- `internal/jose`: RS256, PS256, ES256, EdDSA sign/verify, JWK, JWKS.
- `internal/setcodec`: SET signing and verification per SSF §4.
- All 8 CAEP 1.0 events and all 14 RISC 1.0 events.

**Exit:** round-trip tests against every example in SSF §5, CAEP §3 and
RISC §2; fuzz targets on compact JWS, JWKS, subject and SET parsing.

## v0.2 — Transmitter control plane ✅

- Transmitter configuration metadata, including the issuer path suffix
  (SSF §7.2) and `authorization_schemes`.
- JWKS endpoint.
- Stream create/read/update/replace/delete, status, add/remove subject,
  verification endpoint with `min_verification_interval`.
- `Authorizer` hook; `storage` contracts, `memstore`, `storagetest`.
- Conformance harness: client-credentials token issuer, public deployment.

**Exit:** OIDF metadata test and all stream-control negative tests pass.
Met: every stream-management module passes in all four auth × delivery
variants — see [conformance/README.md](conformance/README.md).

## v0.3 — Transmitter delivery ✅

- Poll handler (RFC 8936) and push worker (RFC 8935) draining the
  per-stream queue v0.2 introduced, with acknowledgement.
- `Emit` routing; stream-updated and verification event emission.
- `caep/interop` preset and startup checker.

**Exit:** CAEP Interop Transmitter plan passes for poll, then push; base
SSF Transmitter plan also passes. Met: every module of the CAEP Interop
Transmitter plan passes in all four auth × delivery variants — see
[conformance/README.md](conformance/README.md).

## v0.4 — Receiver

- Discovery and issuer validation (SSF §7.2.4).
- `TokenSource`: static bearer token and client credentials.
- Stream management client; push `http.Handler`; poll client.
- SET verification, `jti` replay protection, typed dispatch
  (`caep.OnSessionRevoked(fn)`-style adapters).
- Unsolicited verification and stream-updated handling.

**Exit:** CAEP Interop Receiver plan passes for {push, poll} × {static,
dynamic}; base Receiver supported-events test passes with CAEP + RISC
registered.

## v0.5 — Hardening

- JWKS rotation and caching; push retry/backoff tuning.
- Concurrency and race tests; security review.
- Opt-in receiver leniency for legacy transmitters: event-embedded
  `subject` (SSF §3.1.1) and Google's `subject_type` (RISC §3.1).
- Documentation and a session-revocation example.

**Exit:** the full conformance matrix runs in CI and passes reliably.

## v1.0

API freeze. The matrix passes on every release. Certification is
submitted once OIDF opens the SSF certification programme.

## Not planned for v1.0

- SCIM events (RFC 9967).
- A durable storage implementation — `storagetest` lets one be written
  and verified outside this module.
