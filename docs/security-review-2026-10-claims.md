# Security and developer-experience review — changes since the delta review

A review of what pull requests #64–#94 changed after the
[delta review](security-review-2026-10-delta.md): that review's fixes
(#64–#70), replay claims (#84), sqlstore writes at READ COMMITTED (#89),
poll acknowledgements across restarts (#91), the scaling guidance (#93),
`Receiver.Verify` and the `ssf` command (#94), and the CI added alongside
— release-please (#73–#81), OpenSSF Scorecard and SHA-pinned actions
(#83) and the conformance job (#88).

Three adversarial reviewers each took one surface — the Receiver's
delivery path; storage; the `ssf` command and CI — with the brief to
bypass the earlier fixes as well as find new issues. A fourth built a
horizontally scaled Receiver, a v0.1 upgrade, a `Verify` endpoint and
`ssf` sessions from the documentation alone, misconfigured every
constructor, and checked the changes against the
[design rules](design-rules.md). Storage was tested on SQLite and on
PostgreSQL 17, with both the default and a SERIALIZABLE default
isolation level. Every security finding below was demonstrated with a
proof of concept against the code as it stood (v0.3.0); the trust
boundaries are those of the [September review](security-review-2026-09.md).
Each fix landed in a follow-up pull request, a code fix with a test that
fails without it; the table says which. All ship in v0.4.0.

## Security findings

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | Low | **A failed verification handler used up its state.** `dispatch` took the outstanding `state` before the handler ran, so when the handler failed — and push answered 500 for a retry — the retry was refused with 400 `invalid_state`, which the Transmitter does not retry: a verification the Receiver asked for was never handled (reproduced, push and poll). | `dispatch` checks the `state` before the handler runs and uses it up only once the handler succeeds, so a retried verification is handled (#101). |
| 2 | Low | **A store outage longer than a lease handled a SET twice at once.** When `RenewClaim` failed for a whole lease, the Receiver only logged a warning; another instance claimed the SET and handled it while the first handler still ran, and the first handler's context was never cancelled (reproduced: two concurrent handlings). The documentation described a lapsed claim only after a crash. | A renewal that finds the claim taken, or renewals failing until half a lease remains, cancel the handler's context with `receiver.ErrClaimLost`; the documentation describes a lapsed claim after an outage too (#101). |
| 3 | Low | **sqlstore wrapped expiries past 2262, so a handled SET could be handled again.** `ReplayStore` stored `time.Time.UnixNano()` unclamped, unlike `RevocationStore`; `receiver.Limits.MaxClockSkew` had no upper bound, so a very large skew made every completed record already expired, and a redelivered SET was handled once per delivery (reproduced end to end on SQLite and PostgreSQL; memstore unaffected). | `ReplayStore` clamps its times as `RevocationStore` does (sqlstore v0.2.3, #96), and `Limits.MaxClockSkew` is at most `receiver.MaxClockSkewBound`, an hour (#98, breaking, in UPGRADING.md); `storagetest` stores far-future times (#99). |
| 4 | Low | **`storagetest` did not race takeovers of an expired claim.** A store that inserts atomically but takes over an expired claim by a read and a separate write — the natural shape for a key-value store — passed every subtest yet gave one claim to 14 of 20 concurrent claimers; the storage guide said the suite checks all the atomicity the library depends on (reproduced with a test store; neither shipped store is affected). | `storagetest.ReplayStore` races fifty claimers against the old holder's renewal or release of a lapsed claim, twenty rounds, and the storage guide says a race that passes is evidence, not proof (#99, #105). |
| 5 | Low | **A rolling upgrade from v0.1 brought back lost SETs.** A v0.1 Receiver still running after another instance migrated the schema to version 2 acknowledged a SET a v0.2 instance was still handling, and its `ForgetSET` deleted that instance's live claim; UPGRADING.md did not say to stop every v0.1 Receiver before migrating (reproduced on SQLite and PostgreSQL with v0.1's statements). | UPGRADING.md says to stop every v0.1 Receiver before migrating, and why (#105). |
| 6 | Low | **Store and token-source panics crashed the process.** A panic in `RenewClaim` ran on the library's renewal goroutine; panics in `ClaimSET`, `CompleteSET`, `ReleaseClaim` and in the `TokenSource` during a poll escaped `Poll` and so `RunPoller` — application-supplied code, the class [rule 7](design-rules.md) covers and #65 fixed for handlers and stream lookups (reproduced). | Every `ReplayStore` call and `TokenSource.Token` recovers a panic as an error, and the SET is not acknowledged; [rule 7](design-rules.md) names stores and token sources (#101). |
| 7 | Low | **`ssf` wrote terminal controls from a SET.** The JSON output kept C1 controls, DEL and bidirectional overrides raw, and the `verified:` line printed the `jti` unescaped, so a signed SET — or any token given to `decode` — could send escape sequences to the terminal, against [rule 5](design-rules.md) (reproduced). | Everything `ssf` prints escapes controls, DEL, C1, formatting characters and invalid UTF-8 as `\uXXXX`, which JSON reads the same; the `verified:` line quotes the `jti` (#103). |
| 8 | Low | **The conformance job ran unpinned suite code in `main`'s cache scope.** It runs the suite's newest `release-v*` tag and its images by tag, and the suite's Python on the runner; code there could write cache entries that `ci.yml`'s jobs on `main` and on pull requests restore. Reaching it needs the suite's tags or registry compromised; no secret is in reach. Narrowed, not introduced, by #88. | The job pins the suite's release by tag and commit, failing if the tag moves, and its images, mongo included, by digest; a `newer-suite` job fails when a newer release is out (#106). |
| 9 | Info | **Smaller items.** A claim's expiry is judged by each instance's clock, so an instance more than about 40 seconds fast takes over a live claim (double handling, never loss), and nothing said clocks must agree; a `jti` or subject value carrying U+0000 is refused by PostgreSQL alone, so such a SET is redelivered until its window ends; release-please's job held write permissions its own token made unused; `ssf` follows redirects and `jwks_uri` to any https host, as the Receiver does — it only matters if the command is wrapped in a service; `cmd/conformance-receiver` listens on every interface by default. | Clocks must agree within seconds, in `ReplayStore`'s doc and the scaling guide (#105); U+0000 in any string claim or the subject is rejected with `invalid_request` (#104); release-please's job only reads (#106). `ssf` keeps following the Receiver's rules for redirects and `jwks_uri`, and `cmd/conformance-receiver` still listens on every interface, which the suite's container needs on Linux; its `-push-addr` help says so (#106). |

## Developer-experience findings

| # | Severity | Finding | Fix |
|---|---|---|---|
| D1 | Medium | **Instances starting together each made a stream.** Following "call `EnsureStream` on every start", two push instances made two streams on a Transmitter allowing several, and one event was then handled twice under two `jti`s, which no replay store can catch; four poll instances made four streams, three never polled. On a Transmitter allowing one, three of four starts failed with 409 for the stream they wanted. | Before creating a stream, an instance takes a lock in the shared `ReplayStore` and lists the streams again, so instances starting together share one stream; a 409 lists again and reuses a stream with the wanted delivery (#102). |
| D2 | Medium | **Verification failed in a scaled deployment.** The outstanding `state` lives in the instance that called `RequestVerification`; a verification event delivered to another instance was refused with `invalid_state`, while the scaling guide said any instance can take a push or poll. | `RequestVerification`'s doc and the scaling guide say only the requesting instance accepts the event, and to request it from the poller's (#105). |
| D3 | Medium | **A wrong `Audience` left a stream behind on every start.** `EnsureStream` created a stream, refused it for its audience, and kept it: five starts, five orphaned streams receiving events. The error named neither `Config.Audience` nor the fix. | `EnsureStream` deletes a stream it creates and refuses, and the audience error names `Config.Audience` (#102). |
| D4 | Medium | **The v0.2.0 upgrade notes showed no code.** UPGRADING.md mapped `MarkSET` to `ClaimSET` alone; code following it left a claim rather than a handled record, and the SET was accepted again once the lease ended. [Rule 15](design-rules.md) asks for old and new code. | The v0.2.0 notes show before and after code, `CompleteSET` included (#105). |
| D5 | Medium | **`ssf` could not reach a development Transmitter.** The getting-started guide serves one with a development certificate, and the command had no way to trust another CA. | `ssf -ca-file` trusts a PEM file of CA certificates besides the system's (#103). |
| D6 | Low | **`ssf` input and output.** A file name with two dots and no slash (`captured.2026.jwt`) was taken for a token; `decode`'s output matched `verify`'s once standard error was discarded; a flag after the token was refused with a misleading message; errors printed `ssf: ssf:`; no `-audience-per-stream`. | A file is read as a file whatever its name; the JSON has a `verified` member; flags may follow the token; errors are prefixed once; `-audience-per-stream` reads the stream with the token in `SSF_ACCESS_TOKEN` (#103). |
| D7 | Low | **`Verify` returned an untyped rejection.** A "check this SET" endpoint could get the RFC 8935 error code and the cleaned description only by parsing `Error()` ([rule 5](design-rules.md)). | `Verify` returns a `*receiver.RejectionError`, with `Code` and `Description` (#104). |
| D8 | Low | **Documentation behind the code.** The receiver package doc's example used `CreateStream`; sqlstore's doc said several Transmitter instances may each call `Run`; ROADMAP's milestone names collide with the real v0.x tags and stop before replay claims; "since v0.5" in UPGRADING and the CHANGELOG names a version no one had; the `HorizontallyScaled` error did not say which store to use; sqlstore's doc said every atomic operation runs in one transaction, which `ClaimSET` on SQLite does not need; COMPATIBILITY.md's storage promise omitted `RevocationStore`; `storage.ClaimOutcome` has no `String`; the adoption table missed the gaps in rules 5, 13 and 15 above. | All corrected; `ClaimOutcome` has a `String`; the adoption table records rules 3, 5, 13 and 15 (#104, #105). |

## Reviewed and found sound

- **Claims on one instance.** A handler error, a recovered panic and a
  rejection all release the claim, so a redelivery is handled; success
  completes it detached from the request's context; the renewal
  goroutine always stops. Push and poll copies of one SET share one
  handling and report its result, never acknowledging early.
- **Claim fencing.** Holders are 128 random bits per handling; renewing
  or releasing by a holder that lost its claim changes nothing; a
  completed record cannot be renewed or reclaimed until it expires.
- **Exclusivity at READ COMMITTED.** `INSERT … ON CONFLICT DO UPDATE …
  WHERE expires_at <= now` re-evaluates its condition on the locked row:
  thirty rounds of twenty claimers racing a renewing and releasing old
  holder, on SQLite and on PostgreSQL at either default, never gave two
  holders. Revocations racing each other or a prune keep the later
  times and are never lost.
- **Claim scope.** Claims are keyed by exact issuer and `jti`, and only a
  SET that passed every check is claimed: no one can pre-claim or hold a
  claim without a genuine SET addressed to this Receiver.
- **Poll acknowledgement.** Failed and in-progress SETs are neither
  acknowledged nor reported as errors; acknowledgements a restart loses
  are covered by the durable record; acknowledgements a failed poll did
  not send are restored.
- **Schema.** The version 2 migration runs in one transaction under a
  lock; a v0.1 database is refused until migrated, and its handled SETs
  then count as done; foreign, negative and newer schemas are refused;
  every in-memory SQLite spelling tried is declared not durable.
- **`Verify`.** It makes delivery's checks through the same code, the
  stream lookup last, bounded by its caller's context; it records
  nothing, checks size first, quotes peer text in its errors, and a
  public endpoint built on it caused no key refetches.
- **The `ssf` command.** A failed `verify` prints nothing on standard
  output and exits 1; `decode` refuses without `-unverified`; `none` and
  HMAC algorithms are refused; non-https issuers are refused even in
  development; inputs are bounded; peer text in errors is quoted.
- **CI.** Every action is pinned by SHA; no `pull_request_target`; values
  from the suite reach `run:` steps through `env:`; checkouts keep no
  credentials; `SONAR_TOKEN` and the release token are out of reach of
  pull requests; the suite's Python dependencies are installed by hash;
  release-please runs only on pushes to `main`.
- **Configuration.** Every constructor reports every problem at once,
  names the Go field and fails closed, typed-nil stores included.
