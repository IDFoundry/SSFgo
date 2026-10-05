# Security review — October 2026

An adversarial review of the whole library, a month after the
[September review](security-review-2026-09.md) and before the v1.0
release. Five reviewers each took one attack surface — JOSE and SET
verification; the Receiver's network surface; the Transmitter's API and
push delivery; subject matching and storage; engineering and supply chain
— with the brief to bypass the September fixes as well as find new
issues. Every finding below was demonstrated with a proof of concept
against the code as it stood, then fixed in
[#30](https://github.com/IDFoundry/SSFgo/pull/30) (Receiver),
[#31](https://github.com/IDFoundry/SSFgo/pull/31) (Transmitter) or
[#32](https://github.com/IDFoundry/SSFgo/pull/32) (JOSE); regression tests
guard each fix. The trust boundaries are those of the September review.

## Findings

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | High | **Anyone could stop a Receiver from refreshing the Transmitter's keys.** A JWKS refetch ran on the triggering request's context and used up the once-a-minute allowance before fetching. A push client that sent junk naming an unknown `kid` and hung up cancelled the fetch; repeated each minute, SETs signed with a rotated key were rejected as `invalid_key` — which the Transmitter treats as final, so they were lost — and a retired, possibly compromised, key stayed trusted past `KeyMaxAge` (reproduced, including over a real socket). | Refetches run on their own context, with a timeout, shared by concurrent callers (#30). |
| 2 | Medium | **Secrets replayed on 307/308 redirects.** The Receiver's redirect policy required only `https`; a 307/308 to another host replays the request body — a `client_secret_post` secret, a client assertion, or a push `authorization_header` (reproduced). | Requests with an `Authorization` header or a body follow redirects only within their origin (#30). |
| 3 | Medium | **Access token steerable to any host.** The Transmitter's metadata, or a stream's poll URL, could send the Receiver's bearer token to any `https` host, internal ones included. | The token goes only to the issuer's origin and `receiver.Config.TrustedOrigins` (#30). |
| 4 | Medium | **Operator lock escaped** (bypasses September #6). A Receiver whose stream the operator disabled could delete it and create a new, enabled one (reproduced). | While a status set by `SetStreamStatus` holds, deleting the stream and creating another are refused with 403 (#31). |
| 5 | Medium | **One Receiver could slow every `Emit`.** Subject rules were limited in number but not size; 64 KiB aliases rules, re-parsed for every stream on every `Emit`, added 0.76 s per stream with 150 rules, delaying every Receiver's events (measured on SQLite). | Subject rules are at most 2 KiB (#31). |
| 6 | Medium | **Read-only tokens saw push credentials.** An `AccessRead` token could read a push stream's `authorization_header`. | Omitted for `AccessRead` (#31). |
| 7 | Low | **One complex subject rule matched every complex subject.** Members an event lacks match as wildcards (SSF §8.1.3.1), so a rule made only of members the Transmitter never emits — or a lone `tenant` — matched other tenants' users' events when `PermitEvent` was unset (reproduced). | `PermitEvent` is required, with `PermitAll` an explicit choice; an included complex subject needs a §3.3 member (#31). |
| 8 | Low | **`KeepAlive` busy loop.** A huge `inactivity_timeout` from the Transmitter overflowed `time.Duration`, and `KeepAlive` sent about 6,200 requests a second (reproduced). | The interval is clamped to [1 s, 24 h]; issuer or audience mismatch ends `KeepAlive` (#30). |
| 9 | Low | **Unbounded work per poll response.** One response with 60,000 junk SETs produced 60,000 log records and `setErrs` entries (reproduced). | At most `MaxEvents` (or 1000) SETs handled per response, 10 rejection logs then a count; `RunPoller` pauses between empty polls; `APIError.Body` keeps 1 KiB (#30). |
| 10 | Low | **State kept for deleted streams.** The poll notifier and push state grew with every stream ever created (2,000 of 2,000 entries kept). | Notifier entries are reference-counted; push state is pruned on each delivery scan (#31). |
| 11 | Low | **Unlimited concurrent long polls.** Each waiting poll rechecks storage every second. | One long poll per stream waits; another is answered at once (#31). |
| 12 | Low | **SSRF address gaps.** IPv4-translated (`::ffff:0:0:0/96`, embeds an IPv4 address), site-local, discard-only, benchmarking, and NAT64's `64:ff9b::/32` beyond the well-known prefix counted as public. | Refused; `PublicAddressControl` lets a custom push client keep the check (#31). |
| 13 | Low | **Small-order Ed25519 keys accepted.** With one in a JWKS — the identity point, say — a single signature verifies for many or all messages (reproduced). | Refused, by libsodium's blocklist, ignoring the sign bit (#32). |
| 14 | Info | **Several encodings of one token; lax headers.** Non-zero base64url padding bits and CR/LF were accepted, and encoding/json matched header members case-insensitively with the last duplicate winning (`CRIT: null` cancelled `crit`). Harmless — de-duplication keys on `jti`, and the header is signed. | Strict base64url; headers read by exact name, refusing repeated members and an empty `crit` (#32). |

Two smaller fixes came with these: push delivery logs storage errors it
used to drop (#31), and `Run`'s documentation says it coordinates push
delivery within one process, so with a shared store it belongs on one
instance (#31).

## Considered and left unchanged

- **Retryable answer for an unknown `kid`.** Answering a SET whose key
  could not be refetched with 500 rather than `invalid_key` would close
  the pre-existing one-minute window after a key rotation. It fails the
  OIDF `invalid-set-rejection` module, which expects 400, and finding 1's
  fix does not need it.
- **`AccessRead` can acknowledge polls.** For poll delivery the token is
  the delivery credential; requiring `AccessManage` would make every
  polling Receiver hold a management token. Documented on `AccessRead`.
- **Spec-defined subject matching.** A `{group: X}` rule matching members
  of the group is SSF §8.1.3.1; `PermitEvent` decides what a Receiver may
  see.
- **ECDSA high-S signatures.** JWS has no low-S rule and `ecdsa.Sign`
  produces high-S half the time; the malleability is harmless since
  de-duplication keys on `jti`.
- **SET payload and JWK parsing** remain case-insensitive in encoding/json.
  The payload is signed and a JWKS comes from the trusted Transmitter;
  only they could exploit a differential, against themselves.
- **Conformance suite run from upstream master.** The daily workflow runs
  the OIDF suite's latest code, as an early warning of suite changes. It
  holds a read-only token; since this review it also keeps no Git
  credentials and no Go build cache that later jobs could restore.
- **Minor:** `memstore` returns shallow copies of stored subjects (the
  library never mutates them); `ssf` compares invalid UTF-8 in proprietary
  subject members as equal; PostgreSQL rejects a Receiver-supplied string
  containing NUL (that request only gets 500); `ClientCredentials` holds
  its lock across a token fetch.

## Reviewed and found sound

- **Algorithms and keys.** The algorithm comes from the caller's
  allow-list and must equal the header's; key type and curve are checked
  per algorithm; `none`, HMAC and their variants are rejected; ECDSA r/s
  bounds, Ed25519 non-canonical S and RSA modulus and exponent edge cases
  are refused without panics; JWKS entries with private material are
  refused.
- **Claims.** `typ` tricks, `cty` and nested JWTs; `iat` as string, NaN,
  negative or milliseconds; `sub`/`exp` present; claims injected through
  caller-supplied events or subjects — all refused.
- **Transmitter isolation.** Every endpoint authorizes the `stream_id` it
  acts on; duplicate JSON keys cannot split check from use; path tricks and
  method overrides do not reach other handlers; limits hold under
  concurrency.
- **Push delivery.** DNS rebinding is blocked by the check on the address
  dialled; no redirects, no proxy; slow or huge responses are bounded.
- **Storage.** No SQL injection; limit checks, `MarkSET` and the subject
  rule reinsertion are atomic on PostgreSQL and SQLite.
- **Receiver.** Concurrent redeliveries wait for the first copy's outcome;
  replay keys on (issuer, `jti`); verification `state` is 128 random bits,
  single-use; no secrets or subjects in logs.
- **Engineering.** No data races in repeated `-race` runs; `govulncheck`,
  `go vet` clean; CI actions pinned, permissions read-only, no
  `pull_request_target` or expression injection.
