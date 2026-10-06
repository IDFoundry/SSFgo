# Security review — additions since October 2026

An adversarial review of what eleven pull requests added after the
[October review](security-review-2026-10.md): SCIM events and subjects
(#34), metadata discovery fallbacks (#35), the RS/PS/ES 384 and 512
algorithms (#36), stricter JSON parsing (#37), push retries on transient
rejections (#38), `EnsureStream` (#39), `ssftest` (#40), the `revocation`
package and its stores (#41, #42), observability hooks and readiness
(#43), and the example and drift check (#44). Three reviewers each took
one surface — revocation; the Receiver's additions; the wire format,
cryptography and the Transmitter's additions — with the brief to bypass
the October fixes as well as find new issues. Every finding below was
demonstrated with a proof of concept against the code as it stood, then
fixed in [#45](https://github.com/IDFoundry/SSFgo/pull/45) (revocation) or
[#47](https://github.com/IDFoundry/SSFgo/pull/47) (Receiver and
Transmitter); regression tests guard each fix. The trust boundaries are
those of the [September review](security-review-2026-09.md).

The fixes follow one rule: configuration that decides trust is explicit
and fails closed, with permissive choices named rather than defaulted.

## Findings

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | Medium | **A session revocation could revoke nothing.** Unless a complex subject's `user` was an iss_sub identifier, its `session` was recorded under the SET's issuer, and the user's own revocation was dropped. When the Transmitter's issuer differs from the tokens' — `https://ssf.idp.example` and `https://idp.example` — the session's tokens stayed valid (reproduced with no user, an email, an opaque and an aliases user). | `revocation.Options.Issuers` says which token issuer each Transmitter speaks for; sessions are recorded under it whatever the `user` (#45). |
| 2 | Medium | **One Transmitter could revoke another identity provider's users.** The issuer a revocation was recorded under came from the subject the Transmitter wrote, and email revocations had none. With one `Revoker` registered on the Receivers of several identity providers, a compromised or malicious Transmitter revoked any user of any of them, for as long as it kept sending (reproduced). | `Issuers` is required: `StaticTokenIssuers` maps each Transmitter to its token issuer, `SameIssuer` is the named choice for an identity provider that is its own Transmitter. A SET from an unlisted Transmitter, or a subject naming another issuer, revokes nothing; email revocations are scoped to the token issuer (#45). |
| 3 | Low | **A long `Retention` disabled revocation with `sqlstore`.** An expiry after 2262 overflowed `UnixNano` into the past, so every revocation had already expired; `memstore` was unaffected (reproduced with 250 years). | `New` rejects a `Retention` above `MaxRetention` (10 years); `sqlstore` clamps times to the representable range; a storage contract case covers far-future expiries (#45). |
| 4 | Low | **Lookalike addresses revoked each other.** Email addresses were folded with `strings.ToLower`, which maps the Kelvin sign (U+212A) to `k`: revoking `Kate@example.com` spelt with it revoked `kate@example.com` (reproduced). | Only ASCII letters are folded (#45). |
| 5 | Low | **A token stamped just after its revocation escaped it.** With the identity provider's clock ahead of the Transmitter's, tokens issued just before a revocation carry a later `iat` (reproduced at 5 s). | `MaxClockSkew`, zero by default and never negative, also extends `Retention` (#45). |
| 6 | Low | **A hook bug crashed the process on demand.** `Hooks.KeysRefreshed` ran on the detached key-refresh goroutine, before waiting requests were released: anyone able to push junk naming an unknown `kid` triggered a refresh, so a panicking hook took down the process, and a slow one stalled every push waiting for keys (reproduced). | No hook runs on a goroutine of its own; `KeysRefreshed` runs after waiters are released, on the request that started the refresh; hook documentation says hooks must not block or panic, and which fields carry untrusted text (#47). |
| 7 | Low | **`EnsureStream` retried permanent TLS failures forever.** Any `net.OpError` was retryable, including a TLS alert from the Transmitter such as "certificate required"; with a background context `EnsureStream` never returned (reproduced). | TLS alerts, certificate and record-header errors are permanent (#47). |
| 8 | Low | **`EnsureStream` took over another application's stream.** On 409 with a single existing stream it replaced that stream, so two applications sharing a client credential silently redirected each other's events on every start (reproduced). | Replacing an existing stream needs `StreamRequest.ReplaceOnConflict`; otherwise the conflict is returned (#47). |
| 9 | Low | **Attacker text in errors, logs and hooks.** Header members of a junk SET — about 40 KB of `alg`, `typ` or `kid` — were logged, returned in the 400 response and passed to hooks in full; a Transmitter's error body was quoted in `APIError.Error()` (reproduced). | Errors own what they expose: descriptions are bounded and keep only printable ASCII, and response bodies stay out of `Error()` (#47). |
| 10 | Low | **A stream-updated notice was dropped unsent.** The Transmitter counted push failures per stream, so a control SET queued behind a failing one — when the operator paused or disabled the stream — inherited the count and was dropped as having used up its attempts (reproduced). | Failures count against the SET they happened to (#47). |
| 11 | Info | **Lenient identifiers.** SCIM events checked full/notice exclusivity by exact member name while decoding ignored case; SCIM subjects accepted a backslash in `uri` and reserved names in another case among `attributes`; proprietary format names accepted invisible and bidirectional Unicode; `EmitTxn` took a `txn` of any length. None crossed a trust boundary: subjects and events come from the trusted Transmitter, and matching is exact. | Tightened (#47). |

## Considered and left unchanged

- **Untrusted text in `PushInfo.Detail`.** It is the Receiver's own
  description of a rejection, already bounded to 16 KiB; documented as
  untrusted rather than filtered, since it is what an operator needs.
- **Duplicate members inside nested JSON** (`attributes`, proprietary
  members) are not detected; only the trusted Transmitter could send them,
  and Go decodes them the same way every time.
- **ssftest in production code.** It holds no secrets and disables no
  verification: its clients trust only the test server's certificate, and
  its token is accepted only by its own in-process Transmitter.

## Reviewed and found sound

- **Algorithms.** Keys of one curve are refused for another curve's
  algorithm, also when a JWK's `alg` disagrees with its `crv`; P-521
  points and ES512 signatures are validated, out-of-range values from a
  faulty signer give errors, not panics; RSA keys are sized per
  algorithm and PSS salts must equal the hash length.
- **Parsing.** Escaped and invalid-UTF-8 duplicate member names, trailing
  data and deep nesting are refused; `nbf` of the wrong type or in the
  future is refused.
- **Metadata discovery.** Fallback locations are under the issuer's own
  path or host root, tried only after 404 or 410; every endpoint is still
  held to the issuer's origin and `TrustedOrigins`.
- **`EnsureStream`.** Backoff bounds its requests; rejected streams are
  never reused; push credentials go only to the configuration endpoint.
- **Readiness.** `Ready` does no network I/O while keys are fresh, and
  shares the once-a-minute refetch limit, so a public probe cannot cause a
  JWKS fetch storm.
- **Push retries.** Transient rejections are retried at most eight times,
  per stream, so one Receiver cannot hold up another's delivery.
- **Revocation store.** Concurrent revocations keep the later times on
  PostgreSQL and SQLite; queries are parameterised; empty identifiers never
  become wildcard keys.
- **The October fixes** all hold, including under `-race`.
- **Fuzzing.** Thirty seconds on each of the JWK, JWKS, compact
  serialization, sign-verify, subject and SET decoding targets found
  nothing.
