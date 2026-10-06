# Contributing

SSFgo is conformance-first: its design decisions trace to specific
requirements of SSF 1.0, CAEP 1.0, RISC 1.0, the CAEP Interoperability
Profile and the RFCs they build on, and its correctness bar is the OpenID
Foundation conformance suite, not only its own tests.

**Open an issue before a pull request** for anything beyond a trivial
fix. A change that looks reasonable in isolation can conflict with a
specification requirement, a rule in [ARCHITECTURE.md](ARCHITECTURE.md),
or suite behaviour that is not obvious from the code.

New API follows the security and developer-experience conventions in
[docs/design-rules.md](docs/design-rules.md): explicit, fail-closed
configuration; named limits; secrets and errors that control what they
expose; hooks that cannot take down the process.

## Before you open a pull request

- `gofmt -l .`, `go vet ./...`, `go test -race ./...` and
  `golangci-lint run ./...` are clean — CI enforces them, along with
  `govulncheck` and `actionlint`.
- `storage/sqlstore` is its own module: run the same checks in that
  directory. Its tests use SQLite, and PostgreSQL too when
  `SSFGO_TEST_POSTGRES` holds a URL, for example
  `postgres://postgres@localhost:5432/postgres?sslmode=disable`
  (`docker run -e POSTGRES_HOST_AUTH_METHOD=trust -p 5432:5432 postgres:17-alpine`).
- `storage/sqlstore` builds against the core in the same checkout (its
  `go.mod` has a `replace`), but its users get the core version its
  `go.mod` requires. CI checks that version is enough. If a change makes
  `storage/sqlstore` use something new in the core, land the core change
  first, then raise the requirement to that commit:
  `go get github.com/idfoundry/ssfgo@<commit>` in `storage/sqlstore`.
  A breaking core change that `storage/sqlstore` must follow cannot land
  first; raise the requirement in the same pull request instead, to the
  branch's own core commit — merging with a merge commit keeps it
  reachable.
- Behaviour changes come with tests, including the rejection paths.
  Changes to a hot path (emitting, delivery, verification, storage) say
  what the benchmarks in [ARCHITECTURE.md](ARCHITECTURE.md#performance)
  show before and after.
- New parsers of untrusted input come with a fuzz target, listed in
  `.github/workflows/fuzz.yml` (CI checks). A failing input the fuzzer
  finds is committed under `testdata/fuzz/<FuzzName>/` with the fix.
- Changes to protocol behaviour are checked against the suite:
  [`conformance/scripts/run-all.sh`](conformance/scripts/run-all.sh) runs
  the full matrix against a local suite (see
  [conformance/README.md](conformance/README.md)).
- Public API changes respect [COMPATIBILITY.md](COMPATIBILITY.md).

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org): `feat:`,
`fix:`, `docs:`, `test:`, `refactor:`, `ci:`, `chore:`; `feat!:` or
`fix!:` for a breaking change, with a `BREAKING CHANGE:` footer. Describe
what changed and why.

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).
