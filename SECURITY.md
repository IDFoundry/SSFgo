# Security Policy

SSFgo carries security signals — session revocations, credential
changes, compromised accounts — between identity systems. A flaw that lets
an attacker forge, suppress, replay or redirect those signals, or reach
systems through them, is a security issue. Please report it privately
rather than opening a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the **Security** tab on
this repository and select **Report a vulnerability**. This creates a
private advisory visible only to maintainers until a fix is ready.

If private reporting isn't available, open a regular issue asking a
maintainer to open a private channel — without vulnerability details.

## Supported versions

SSFgo is pre-1.0 and has no tagged releases yet. Reports against `main`
are the ones we can act on.

## What to include

- The affected package or file and, if possible, a minimal reproduction.
- The requirement or security property you believe is violated — a
  section of SSF 1.0, CAEP 1.0, RISC 1.0, the CAEP Interoperability
  Profile or an RFC helps.
- Whether it is exploitable with a default configuration or needs a
  specific setup.

## Security model

What SSFgo enforces on its own, so reviewers know where to look:

- **SET integrity.** Receivers verify every SET's signature with keys from
  the Transmitter's JWKS, against algorithms the application lists — never
  the algorithm the token names. `none` and HMAC algorithms are rejected.
  RSA keys must be 2048–8192 bits. `iss`, `aud`, `typ` and `iat` are
  checked, and SETs carrying `sub` or `exp` are refused (SSF 1.0 §4).
- **Replay.** Processed SETs are recorded in a `storage.ReplayStore`; a
  redelivered SET is acknowledged but not handled again.
- **Verification state.** A verification event carrying `state` must match
  an outstanding request from this Receiver (SSF 1.0 §8.1.4.1).
- **Transport.** Issuers and every advertised endpoint must be `https`.
  Access tokens are accepted only in the `Authorization` header.
- **Stream isolation.** A Transmitter's streams belong to the Receiver
  identity that created them; another Receiver's stream is reported as not
  found, so stream IDs cannot be probed.
- **Server-side request forgery.** Receivers choose push endpoints. The
  Transmitter's default push client connects only to public unicast
  addresses (checked on the address actually dialled, so DNS rebinding
  does not help, and NAT64/6to4/Teredo addresses cannot smuggle an
  internal IPv4 address), follows no redirects, and uses no proxy; push
  URLs may not carry credentials. `Config.AllowPushEndpoint` can restrict
  further. A custom `Config.HTTPClient` keeps the address check by using
  `transmitter.PublicAddressControl` as its dialer's `Control`.
- **What each Receiver may see.** `transmitter.Config.PermitEvent` decides,
  per stream, whether its Receiver may receive an event about a subject
  (SSF §9.2). It is required: `transmitter.PermitAll` makes "every Receiver
  may see everything" an explicit choice, right only for a single-tenant
  Transmitter. Subject rules cannot stand in for it — one complex subject
  can match many.
- **Replay window.** A SET is accepted only within `ReplayWindow` of its
  `iat`, and remembered for exactly that long.
- **Redirects.** The Receiver follows only `https` redirects, so its
  access token and client credentials cannot be downgraded to cleartext.
- **Resource limits.** An authenticated Receiver's streams, subject rules
  and queued SETs are capped (`transmitter.Config.Limits`); request and
  response bodies, SETs and JWKS documents are size-limited; push retries
  back off exponentially; JWKS refetches are rate-limited to one a minute.
- **Operator control.** A stream status the Transmitter sets with
  `SetStreamStatus` cannot be undone by the Receiver.

The most recent review, an adversarial one, is
[docs/security-review-2026-10.md](docs/security-review-2026-10.md); the
trust boundaries are set out in
[docs/security-review-2026-09.md](docs/security-review-2026-09.md).

What stays the application's responsibility: authenticating Receivers
(`transmitter.AuthorizeFunc`), protecting signing keys (any
`crypto.Signer`, including KMS- or HSM-backed ones), TLS termination and
certificates, rate-limiting the management API, and durable storage
(`storage/sqlstore` is a reference implementation). Whatever the backend,
its database holds each push stream's `authorization_header` — a
credential for the Receiver's push endpoint — and signed SETs awaiting
delivery, so protect it as you would other credentials.
