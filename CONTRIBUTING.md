# Contributing

SSFgo is conformance-first: its design decisions trace to specific
requirements of SSF 1.0, CAEP 1.0, RISC 1.0, the CAEP Interoperability
Profile and the RFCs they build on, and its correctness bar is the OpenID
Foundation conformance suite, not only its own tests.

**Open an issue before a pull request** for anything beyond a trivial
fix. A change that looks reasonable in isolation can conflict with a
specification requirement, a rule in [ARCHITECTURE.md](ARCHITECTURE.md),
or suite behaviour that is not obvious from the code.

## Before you open a pull request

- `gofmt -l .`, `go vet ./...`, `go test -race ./...` and
  `golangci-lint run ./...` are clean — CI enforces them, along with
  `govulncheck` and `actionlint`.
- Behaviour changes come with tests, including the rejection paths.
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
