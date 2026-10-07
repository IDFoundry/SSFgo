# Agent guidance

This file is for AI coding agents working in this repo. It doesn't
replace [CONTRIBUTING.md](CONTRIBUTING.md) — read that first for the
conformance-first approach, the pre-PR checks and the commit format.
This file adds process notes and points at where knowledge already
lives.

## Workflow

- Never push to `main`. Work on a branch per change, open a pull
  request, and wait for CI — SonarCloud included — to pass.
- Don't merge a pull request yourself unless told to. Sync a local
  `main` only once the pull request is merged
  (`gh pr view <n> --json state`), then delete the branch.
- Never stash or switch branches in a working tree that a long-running
  job — a conformance matrix, say — is using; use a `git worktree`.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org).
  A breaking change is `feat!:` or `fix!:` with a `BREAKING CHANGE:`
  footer, and adds its section to [UPGRADING.md](UPGRADING.md) in the
  same pull request.
- Write commit messages and pull request descriptions as a summary of
  what changed and why. Never narrate the conversation that produced
  them ("the user asked…").
- Don't tag releases, bump versions or date the CHANGELOG unless asked.

## Design and security

- New API follows [docs/design-rules.md](docs/design-rules.md). Check a
  change against it, and keep its adoption table current when a change
  closes a gap.
- A security fix lands with a test that fails without it. Reviews are
  recorded in `docs/security-review-*.md`, with what held up.
- Justify a feature by the specifications and its own merits.
- Conformance is strict: don't relax validation to accommodate a test
  suite's quirk. Record the quirk in
  [conformance/README.md](conformance/README.md) instead.

## Checks CI runs that tests alone miss

- The benchmark smoke run, `go test -run '^$' -bench . -benchtime 1x ./...`
  — benchmarks build their own configs.
- `storage/sqlstore` built against the core version its `go.mod`
  requires, without the `replace`. When sqlstore — its tests included —
  needs something new in the core, raise the requirement as
  [CONTRIBUTING.md](CONTRIBUTING.md) describes, then check locally: copy
  the module, `go mod edit -dropreplace=github.com/idfoundry/ssfgo`,
  `GOFLAGS=-mod=mod go vet ./...`.
- `.github/workflows/fuzz.yml` lists every fuzz target.
- `go run ./internal/doccheck` builds the Go code in `GETTING_STARTED.md`
  and `docs/guides` against the checkout. A new guide's code needs a
  harness in `internal/doccheck/harness`, with stubs for what the guide
  marks as the application's own; the check fails on any code block no
  harness covers.
- Each example under `examples/` is its own module, so root `go test`
  skips it; the `examples` job builds, tests and checks it uses only the
  public API. A new example adds itself to that job's matrix. Run them
  locally from the example's directory.

## Where conformance knowledge lives

[conformance/README.md](conformance/README.md) covers both roles: how to
run each against the OpenID Foundation suite, the results, and what the
suite expects that isn't obvious from the specifications.
[`conformance/scripts/run-all.sh`](conformance/scripts/run-all.sh) runs
the full matrix; its header lists the environment it reads. The
Transmitter listens on `PORT` (default 9443) — choose another if that
port is taken, rather than stopping whatever holds it.
