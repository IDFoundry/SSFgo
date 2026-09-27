# Security review — September 2026

A review of the whole repository before the v1.0 release, focused on
trust boundaries: what each component accepts from whom, and whether
anything an untrusted party controls can make SSFgo misbehave. Every
finding below was first demonstrated with a failing test against the code
as it stood, then fixed; those tests now guard against regression.

## Trust boundaries

| Boundary | Untrusted party | What crosses it |
|---|---|---|
| Transmitter management API and poll endpoint | Any client that can reach them; then an **authenticated Receiver** | HTTP requests: stream configurations, push URLs and `authorization_header`, subjects, status, verification state, poll acks and `setErrs` |
| Transmitter push delivery | The **Receiver's push server** | Push responses (status, error bodies); where the Transmitter connects |
| Receiver push endpoint | **Anyone** who can reach it | SETs |
| Receiver HTTP client | The **Transmitter** (and anyone on the network path) | Metadata, JWKS, stream configurations, poll responses, redirects |
| Receiver token source | The **authorization server** | Token responses, redirects |
| Application ↔ library | Trusted | Config, `AuthorizeFunc`, handlers, emitted events |

Receivers are authenticated by the application's `AuthorizeFunc`, but an
authenticated Receiver is still an adversary with respect to the
Transmitter's resources and to other Receivers' data. A Transmitter is
trusted by its Receivers to sign SETs, but not to steer the Receiver's
credentials or network connections.

## Findings

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | High | **Cross-Receiver data exposure.** Nothing let a Transmitter decide which Receiver may see events about which subject. With `default_subjects: ALL` every Receiver got every event; with `NONE` a Receiver could add any subject and receive that user's events (SSF §9.1, §9.2). | `transmitter.Config.PermitEvent`, consulted for every stream an event is routed to. Documented as mandatory for multi-tenant Transmitters. |
| 2 | High | **Bearer token and client credentials over cleartext after a redirect.** `net/http` copies `Authorization` to a same-host redirect regardless of scheme, so an `https`→`http` redirect from the Transmitter or authorization server sent the Receiver's access token or client secret unencrypted (reproduced). | Every Receiver HTTP client, including a user-supplied one, follows only `https` redirects; `ClientCredentials.TokenURL` must be `https`. |
| 3 | High | **Replay of captured SETs after the replay window.** Replay records expired after `ReplayWindow`, but nothing rejected older SETs, so a SET captured from logs or a proxy was handled again once its record expired (reproduced). | SETs older than `ReplayWindow` are rejected, and replay records live exactly as long as a SET is acceptable. |
| 4 | Medium | **Unbounded state per Receiver.** An authenticated Receiver could create unlimited streams, subject rules and — simply by never polling — queued SETs. 120 streams made every `Emit` sign 121 SETs (151 ms each). | `transmitter.Config.Limits` (streams per Receiver, subject rules per stream, queued SETs per stream) with safe defaults and no unlimited setting, enforced atomically by the storage contract. |
| 5 | Medium | **SSRF protection bypass via addresses embedding IPv4.** NAT64 (`64:ff9b::7f00:1`), IPv4-compatible (`::7f00:1`), 6to4 and Teredo addresses reached internal IPv4 hosts past the public-address check. | NAT64 addresses are judged by their embedded IPv4 address; the other forms are refused. |
| 6 | Medium | **Receiver could override an operator.** A stream the Transmitter disabled for abuse could be re-enabled by the Receiver. | A status set by `SetStreamStatus` locks out Receiver changes (403, SSF §8.1.2.2) until the Transmitter re-enables the stream. |
| 7 | Low | **A handler panic lost the SET.** The SET was recorded as processed before the handler ran; a panic left the record, so the retry was acknowledged as a duplicate (reproduced). | The record is removed when a handler fails or panics; the panic is re-raised. |
| 8 | Low | **Invalid push settings stored.** An `authorization_header` with CR/LF or control characters, or an oversized push URL, was accepted, then failed every delivery. | Validated at stream creation: a legal header value up to 4 KiB, a URL up to 2 KiB. |
| 9 | Low | **Log flooding.** One poll request's `setErrs` produced one log line per entry. | At most 10 per request, then a count. |
| 10 | Low | **Unbounded verification state.** Receiver `state` values for verifications that never arrived were kept forever. | At most 16 outstanding per stream. |

## Reviewed and found sound

- **SET verification.** The algorithm comes from the caller's allow-list,
  never the token; `none` and HMAC are rejected; RSA keys are 2048–8192
  bits with a sane exponent; EC points are checked on-curve; `crit` is
  honoured; `typ`, `iss`, `aud`, `iat`, and the absence of `sub`/`exp`
  are enforced; exactly one event; SETs are at most 64 KiB.
- **Fuzzing.** Ten targets — including the Receiver's push endpoint and
  poll responses and the Transmitter's management API — run daily with a
  corpus that persists between runs.
- **Parsing.** Every body and response read is size-limited; subject
  nesting is bounded; JWKS entries with private key material are refused.
- **Stream isolation.** Every operation, including poll acknowledgements,
  checks the stream belongs to the authenticated Receiver; another
  Receiver's stream reads as 404.
- **Credentials.** Tokens are accepted only from the `Authorization`
  header; the push `Authorization` check is constant-time; no token,
  secret or push credential is logged.
- **JWKS refetch** is rate-limited, so forged SETs cannot make a Receiver
  hammer the Transmitter.
- **Dependencies.** None beyond the standard library; `govulncheck` runs
  in CI.

## Accepted risks and guidance

- `cmd/conformance-transmitter` and `cmd/conformance-receiver` disable TLS
  verification and use static credentials. They are test harnesses, are
  not importable, and must never be deployed.
- `storage/memstore` keeps everything in memory; production deployments
  supply durable storage.
- A Receiver push endpoint without `PushOptions.AuthorizationHeader`
  accepts pushes from anyone. SETs still need a valid signature and are
  de-duplicated, but setting the header is recommended.
- A handler that panics inside `RunPoller` crashes the poller's
  goroutine, as any panic would; handlers should not panic.
- Subject matching follows SSF §8.1.3.1 exactly: removing a simple subject
  does not exclude complex subjects that contain it. `PermitEvent` is the
  control for what a Receiver may see.
- CI pins third-party actions by commit SHA and GitHub's own by major
  version. The conformance workflow runs the OIDF suite's code with a
  read-only token.
