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
- `AuthorizeFunc` hook; `storage` contracts, `memstore`, `storagetest`.
- Conformance harness with a client-credentials token issuer.

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

## v0.4 — Receiver ✅

- Discovery and issuer validation (SSF §7.2.4).
- `TokenSource`: static bearer token and client credentials.
- Stream management client; push `http.Handler`; poll client.
- SET verification, `jti` replay protection, typed dispatch
  (`receiver.On(r, func(ctx, set, e caep.SessionRevoked) error)`).
- Unsolicited verification and stream-updated handling.

**Exit:** CAEP Interop Receiver plan passes for {push, poll} × {static,
dynamic}; base Receiver supported-events test passes with CAEP + RISC
registered. Met in full since 2026-10-03, when the suite fixed the
millisecond `event_timestamp` that had failed
`openid-ssf-receiver-stream-caep-interop` — see
[conformance/README.md](conformance/README.md).

## v0.5 — Hardening ✅

- JWKS rotation and caching (`KeyMaxAge`, rate-limited refetch); push
  retry policy (`PushRetry`: backoff bounds and an optional attempt cap).
- Concurrency stress test; security review (SSRF-safe default push
  client, https-only endpoints, no credentials in push URLs) and
  [SECURITY.md](SECURITY.md).
- Opt-in receiver leniency for legacy transmitters
  (`AcceptLegacySubjects`): event-embedded `subject` (SSF §3.1.1) and
  Google's `subject_type` (RISC §3.1).
- `client_secret_jwt` and `private_key_jwt` client authentication for the
  Receiver's client-credentials token source.
- README usage and a runnable session-revocation example.

**Exit:** the full conformance matrix runs in CI and passes reliably.
[`conformance/scripts/run-all.sh`](conformance/scripts/run-all.sh) runs it
and `.github/workflows/conformance.yml` runs that daily.

## v1.0 — API frozen, release pending

API freeze, after a review of every exported identifier (see
[CHANGELOG.md](CHANGELOG.md)); the compatibility promise is in
[COMPATIBILITY.md](COMPATIBILITY.md). The full matrix runs daily in CI.
Certification will be submitted once OIDF opens the SSF certification
programme. Remaining: tag and publish `v1.0.0`.

Added since the freeze: a security review
([docs/security-review-2026-09.md](docs/security-review-2026-09.md)),
whose fixes changed the storage contract before any tag (see
[CHANGELOG.md](CHANGELOG.md)), the Receiver-side `caep/interop` preset, continuous fuzzing,
Transmitter-initiated verification, `inactivity_timeout` with the
Receiver's `KeepAlive`, and `storage/sqlstore` for PostgreSQL and SQLite.

## Not planned for v1.0

- SCIM events (RFC 9967).
