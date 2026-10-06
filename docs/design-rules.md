# Design rules

The conventions every change to SSFgo follows for security and developer
experience. They are shared with FAPIgo, the OAuth and FAPI library from
the same authors, so an application using both finds one style. When a
change cannot follow a rule, the pull request says why.

Rules marked *adopting* are not yet followed everywhere; the
[status table](#adoption-status) lists the gaps and how they close.

## Security

### 1. Trust is explicit and fails closed

Configuration that decides whom to trust has no permissive default. The
permissive choice is a named value the caller has to write —
`transmitter.PermitAll`, `revocation.SameIssuer` — never a zero value or
a nil func. An issuer, Transmitter, origin or key nobody configured is
refused, not assumed.

- Issuers are compared exactly, as strings. Anything that needs
  normalising is normalised once, where it is parsed.
- Trust maps are keyed by who is speaking: one party never vouches for
  something outside its own scope, such as one Transmitter revoking
  another identity provider's users.
- Where a trust relationship has several shapes, offer an interface
  with a static implementation, such as `revocation.TokenIssuers` and
  `StaticTokenIssuers`.

### 2. No implicit defaults for security-relevant configuration

Constructors validate their configuration and report every problem at
once, with `errors.Join`. Each message names the field as the caller
writes it in Go, for example
`receiver: invalid config: Limits.MaxClockSkew must not be negative`.

- Security-relevant settings must be given explicitly: lifetimes,
  retention, clock skew, limits and algorithms.
- Starting values come from `Recommended*()` functions. Their docs cite
  the specification the values come from, so choosing them is a visible
  decision.
- Defaults are fine for things that don't affect security, such as
  `Now` and `Logger`.

### 3. Limits are named, bounded and overflow-safe

- Every size, count or duration cap is a named constant or a config
  field, never a bare literal.
- For durations, zero means *none* only where the field's doc says so.
  Negative values are refused.
- Ceilings are chosen so the arithmetic built on them cannot overflow,
  e.g. `revocation.MaxRetention`.
- A store converting times to integers clamps them to what it can
  represent, rather than letting a value wrap into the past.

Durations follow FAPIgo's names: `MaxClockSkew`, `Retention`, `KeyMaxAge`.

### 4. Secrets are a type, not a string *(adopting)*

A credential is held in a `Secret`:
- `String`, `GoString` and `MarshalText` all redact;
- `Reveal()` is the only way to read the value.

So a client secret, a push `authorization_header` or a bearer token
cannot reach a log, a `%v` or a JSON body by accident. The library never
logs secrets, tokens or subject identifiers.

### 5. Errors own their exposure *(adopting)*

A failure is a typed error. It carries a protocol error code, a
description that is safe to show, and a cause that is for logs only. The
error type decides what may go into a response, not the caller.

- Text from a peer, whether a Transmitter's error body, a Receiver's
  rejection or a SET header, is untrusted:
  - it is bounded in length;
  - it is reduced to printable ASCII before it reaches a log, a
    response or a hook;
  - it is quoted wherever it appears.
- A raw response body never appears in `Error()`. Say its length and
  content type instead, and offer the body through an explicit
  accessor.

### 6. Untrusted input is parsed strictly

- Wire formats are read by exact member names. Repeated members, trailing
  data and wrong types are refused.
- Every parser of untrusted input has a size cap and a fuzz target.
- Identifiers are compared exactly.
  - Where a specification makes something case-insensitive, fold ASCII
    letters only.
  - `strings.ToLower` and `strings.EqualFold` fold non-ASCII characters
    into ASCII, e.g. the Kelvin sign into `k`.
- Characters that are invisible or that change text direction are refused
  in identifiers.

### 7. Application code runs where it can do no harm

Hooks and callbacks (`Hooks`, `OnRevoke`, `PermitEvent`, `AuthorizeFunc`)
run synchronously, on the goroutine of the work they concern, after the
library's own state is consistent.

- Every call recovers and logs a panic, so a bug in a hook cannot stop
  the library's own goroutines, such as push delivery, or crash the
  process.
- Their docs say:
  - they must not block or panic;
  - which fields may carry untrusted text, to be logged and never
    returned or used as a metric label.

### 8. Retries are allow-listed and bounded

- A retry happens only for failures known to be transient: network
  errors, 429 and 5xx.
- TLS alerts, certificate errors, refused redirects and refused origins
  are permanent, and are returned at once.
- Backoff is exponential and capped.
- Attempts are counted against the item that failed, not against the
  queue it sits in.

### 9. Nothing another party owns is replaced without an explicit opt-in

An "ensure" or "upsert" that finds something it did not create (another
application's stream, say) returns the conflict instead of overwriting
it. An explicit field such as `ReplaceOnConflict` makes overwriting the
caller's decision.

### 10. Production refuses development shortcuts *(adopting)*

- An assurance setting lets production deployments refuse in-memory
  stores.
- A setting for horizontally scaled deployments requires stores that
  declare cross-instance consistency.
- Development conveniences, such as plain HTTP on loopback, are opt-in
  and refused in production.

### 11. Every finding is reproduced before it is fixed

A security fix lands with a test that failed before it. Reviews are
recorded, dated, in `docs/security-review-*.md`, together with what was
attacked and held up.

## Developer experience

### 12. One package and constructor per role

`transmitter`, `receiver`, `revocation` and `ssftest` each have their own
constructor and `Config` or `Options` struct. They are plain structs, not
functional options, so a configuration is visible, comparable and
validated in one place. `transmitter` and `receiver` never import each
other; they share protocol code through `internal/`, and packages built
on a role (`revocation`, `ssftest`) follow the
[dependency rules](../ARCHITECTURE.md#dependency-rules).

### 13. The safe path is the short path

The shortest correct program is the safe one:
- `Recommended*()` presets;
- `ensure`-style helpers;
- middleware that answers with the right status code.

An unsafe choice needs more code and a name that says what it does.

### 14. Documentation is part of the API

- Every exported symbol has a doc comment. It states the field's unit,
  what zero means, its bounds and its security consequence.
- The README shows a working configuration for each role.
- Runnable examples in `examples/` are tested in CI and use only the
  public API. *(adopting: each example becomes its own module, with a
  check that it imports nothing internal.)*
- `GETTING_STARTED.md` walks through each role, and `docs/guides/` has
  one guide per feature. *(adopting)*

### 15. Breaking changes are announced where users look *(adopting)*

- Commits follow Conventional Commits; a breaking change is `feat!:` or
  `fix!:`.
- The same pull request adds its section to `UPGRADING.md`, showing
  the old and new code.
- The CHANGELOG lists it under "⚠ BREAKING CHANGES".
- Releases are cut by release-please. [COMPATIBILITY.md](../COMPATIBILITY.md)
  says what a breaking change is.

### 16. Integrators get test kits and contracts

- `ssftest` runs the other role in-process, so an application can test
  its own side without mocks.
- `storagetest` lets any store prove it meets the storage contract.
- Both are maintained like public API.

## Adoption status

| Rule | Gap | Closes in |
|---|---|---|
| 1 | `revocation` trusted the issuer written in each subject | #45 |
| 2 | The Receiver and Transmitter silently defaulted `ReplayWindow`, `KeyMaxAge`, `MaxClockSkew` (zero became 1 minute), the Transmitter's limits, `LongPollTimeout` and `PushRetry`; there were no `Recommended*()` presets | #48 |
| 3 | `revocation.Retention` was unbounded, and `sqlstore` wrapped far-future times | #45 |
| 4 | `ClientCredentials.ClientSecret` and `Delivery.AuthorizationHeader` are plain strings | `Secret` PR |
| 5 | `APIError.Error()` quotes response bodies; SET rejection descriptions carry up to 40 KB of attacker text into logs, responses and hooks | #47 |
| 6 | SCIM full/notice exclusivity is case-sensitive; SCIM `uri` accepts `\`; proprietary format names accept invisible Unicode; `revocation` folded email with `strings.ToLower` | #45, #47 |
| 7 | `Hooks.KeysRefreshed` runs on the detached key-refresh goroutine | #47 |
| 8 | `EnsureStream` retries TLS alerts; push failures are counted per stream | #47 |
| 9 | `EnsureStream` replaces the only stream on 409 | #47 |
| 10 | No assurance levels or store capabilities | Assurance PR |
| 14 | Examples share the root module; no `GETTING_STARTED.md` or guides | Examples and guides PRs |
| 15 | No release-please, `UPGRADING.md` or `AGENTS.md` | Release tooling PR |
