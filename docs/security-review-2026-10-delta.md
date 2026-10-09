# Security and developer-experience review — changes since the additions review

A review of what pull requests #45–#63 changed after the
[review of the additions](security-review-2026-10-additions.md): that
review's fixes (#45, #47), fail-closed configuration (#50), `ssf.Secret`
(#51), assurance levels (#52), key custody (#57), sqlstore schema
versioning (#59), `revocation.Options.AllSessions` (#60),
`receiver.Config.AudiencePerStream` (#61), RISC account-disabled reasons
(#62), the Keycloak interop test (#63), and the documentation, examples
and CI added alongside (#53–#56, #58).

Three adversarial reviewers each took one surface — the Receiver;
revocation and storage; the Transmitter, the core package and CI — with
the brief to bypass the earlier fixes as well as find new issues. A
fourth built a Receiver and a Transmitter from the documentation alone,
misconfigured every constructor, and checked the code against the
[design rules](design-rules.md) and the sibling library FAPIgo. Every
security finding below was demonstrated with a proof of concept against
the code as it stood; the trust boundaries are those of the
[September review](security-review-2026-09.md). Fixes land in follow-up
pull requests, each with a test that fails without it; the table says
which.

## Security findings

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | Medium | **`KeysFor` bypassed `Issuers`.** With `KeysFor` set, a SET from a Transmitter `Issuers` does not name still reached it, and the keys it returned were recorded whatever issuer they named. The guide's SCIM example hard-coded the identity provider's issuer, so any Transmitter a shared `Revoker`'s Receivers accepted could revoke that provider's users with a SCIM deactivate — finding 2 of the additions review, by another path (reproduced). | `KeysFor` runs only for Transmitters `Issuers` trusts, is given the token issuer, and keys naming another issuer are dropped; `FuzzIssuerScope` holds the boundary for any subject (#64). |
| 2 | Medium | **One replayed SET made the Receiver call the Transmitter on every push.** Under `AudiencePerStream`, a stream lookup the Transmitter answered with 403 — or any error but 404 — was not cached, so replaying one genuine SET addressed to another Receiver's `<Audience>/<id>` caused one authenticated stream read per push, and a 401 a token refetch each time (reproduced: 50 pushes, 50 reads). | Every lookup outcome is kept — a stream refused with 403 or 404 for a minute, a failure for ten seconds — and the cache is bounded (#65). |
| 3 | Low | **Stream lookups for SETs of any age.** The lookup ran before the replay-window check, so a SET signed years ago still caused a Transmitter read (reproduced). | The replay window is checked first; only an otherwise acceptable SET can cause a lookup (#65). |
| 4 | Low | **A deleted stream came back.** A lookup in flight when `DeleteStream` returned recorded the stream as found afterwards, for the life of the process; a stream deleted by another instance was never forgotten (reproduced). | A deletion invalidates lookups under way, and a stream found is confirmed again after an hour (#65). |
| 5 | Low | **Lookups ignored their caller's deadline, and a panic stuck them.** The push that started a lookup waited for it, up to 30 s, whatever its own context; a panic in the `TokenSource` or transport left the lookup in flight for good, failing every later SET for that stream (reproduced). | Lookups run on their own goroutine, each caller waiting no longer than its context, and a panic fails the lookup (#65). |
| 6 | Low | **A custom push client dropped SSRF protection.** Setting `transmitter.Config.HTTPClient` — to add tracing, say — replaced the client that refuses non-public addresses and redirects, also under `AssuranceProduction`: a Receiver could register a loopback endpoint, or redirect a push to one (reproduced). | `PushTransport` wraps the protected client and `AllowedPrivatePushHosts` admits named private hosts, both keeping every other check; under `AssuranceProduction` an `HTTPClient` requires `UnrestrictedPushClient` (#66). |
| 7 | Low | **Secrets in logs.** `ssf.Secret` and `receiver.StaticToken` printed their value for fmt verbs other than `%v`, `%s`, `%q` and `%x`, and through unexported struct fields; JSON logging of a `Delivery` or `StreamConfiguration` revealed `authorization_header`; `%+v` of a `ClientCredentials` printed its cached access token (reproduced). | `ClientCredentials` keeps its token out of fmt's reach (#65); every verb withholds a `Secret` and a `StaticToken`, a `Secret` is held by handle so printing by reflection shows none, and `Delivery` and `StreamConfiguration` log without the header (#66). |
| 8 | Low | **An unplaced session revoked every session.** A session-revoked event whose session the default mapping could not place — another issuer's, an aliases or an email subject — fell back to the user and revoked all their sessions, as if `AllSessions` were set (reproduced). | Such an event revokes nothing (#64). |
| 9 | Low | **A huge `MaxClockSkew` disabled revocation.** It had no upper bound; above about 282 years `Retention + MaxClockSkew` overflowed and every revocation had already expired, and large values short of that revoked a user's later sign-ins (reproduced). | `MaxClockSkew` is at most `MaxClockSkewBound`, an hour (#64). |
| 10 | Low | **Wrapping the `TokenSource` skipped key custody.** The production custody check applied only to a `*receiver.ClientCredentials` itself, so a wrapper — for metrics, say — let an ephemeral `private_key_jwt` key through (reproduced). | `New` finds a `ClientCredentials` through `Unwrap() TokenSource` (#65). |
| 11 | Low | **sqlstore declared in-memory SQLite durable, and a negative schema version panicked.** A `:memory:` database passed `AssuranceProduction`; a negative `ssf_schema` version made `CreateSchema` panic (reproduced). | Pending. |
| 12 | Info | **Smaller items.** Loopback spellings the production check missed (`127.1`, `0.0.0.0`, `[::]`); a typed-nil signer panicking `transmitter.New`; a foreign `ssf_schema` table passing the version check; migrations under a non-default PostgreSQL isolation level; no size bound on `Emit`; `AllSessions` accepting surrounding white space; revocation errors naming the user, session or address they concerned. CI: the interop job kept setup-go's cache and pulled an image by tag; checkouts persisted credentials; a Sonar suppression covered all of `storage/sqlstore`. | `AllSessions` and revocation errors (#64); loopback spellings, typed nils and an `Emit` bound of `MaxSETBytes` (#66); the rest pending. |

## Developer-experience findings

| # | Severity | Finding | Fix |
|---|---|---|---|
| D1 | High | **Revoker events silently never arrived.** `Register` installed handlers for event types the Receiver's Registry could not decode, so the stream never requested them: following the getting-started guide, which registered only CAEP, account-disabled and SCIM events never revoked anything. | `Register` returns an error naming them, installing nothing; the guides register all three families (#64). |
| D2 | High | **A panicking handler crashed the process.** Handlers, `OnRevoke` and `KeysFor` ran unrecovered — under `RunPoller`, on the library's goroutine — against [rule 7](design-rules.md). | Handler panics fail the SET's handling, so it is delivered again (#65). |
| D3 | High | **The token endpoint's body reached errors and logs.** A failed token request quoted up to 64 KB of the response, against [rule 5](design-rules.md). | A failed token request returns an `*APIError`, showing only a cleaned code and description (#65). |
| D4 | Medium | `ClientCredentials` was checked only at the first token request, one problem at a time; several messages did not name the Go field; no guide covered Transmitters other than SSFgo's; the getting-started guide had no development path; `Middleware` answered 503 without logging why; `receiver.New` failed at once when the Transmitter was down; many exported identifiers lacked doc comments, and no package had runnable examples. | `ClientCredentials` is checked by `New`, every problem by field, and a stream refused for a per-stream audience says to set `AudiencePerStream` (#65); the rest pending. |
| D5 | Low | Adoption-table entries ahead of the code (rules 5, 7, 12, 14, 15); constructor shapes and `Options`/`Config` naming differ; no `RecommendedAlgorithms`; README install line; the top-level `interop` directory reads like the `caep/interop` package. | Pending. |

## Reviewed and found sound

- **Issuer scoping in the default mapping.** Identifiers naming another
  issuer — in aliases, as a complex subject's user or session — map to
  nothing; emails are scoped to the token issuer; `AllSessions` matches
  exactly, only for session-revoked, and cannot widen issuer scope.
- **Stream-lookup URLs.** Stream IDs carrying `&stream_id=`, `?`, `#`,
  encoded slashes or NULs are query-escaped, and the answer must name the
  identical stream with the matching audience; unsigned or forged pushes
  never reach a lookup; one lookup per SET however many audiences it
  names; concurrent SETs share one lookup.
- **`authorization_header`.** Never returned to read-only callers, in
  status responses, stream-updated events, hooks or errors; a `PATCH`
  replaces the whole delivery, so an old header never goes to a new
  URL; stores round-trip it once.
- **Limits and retries.** Every limit is required and positive; backoff
  is clamped to its maximum for any minimum, so the push worker cannot
  spin; `time.Time.Add` saturates for long timeouts.
- **Assurance and custody.** A store or signer wrapper that does not
  forward its declaration counts as undeclared, failing closed.
- **sqlstore.** Values are bound parameters; a failed migration leaves
  data and version unchanged; a newer schema is refused.
- **CI.** No `pull_request_target`, no untrusted input in `run:` steps,
  `contents: read` throughout, `SONAR_TOKEN` withheld from forks;
  `internal/doccheck` cannot be steered by documentation to read outside
  the repository or run what it builds.
