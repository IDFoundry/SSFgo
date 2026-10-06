# Compatibility

From v1.0.0 SSFgo follows [Semantic Versioning](https://semver.org): a
program that compiles and works against v1.x keeps compiling and working
against every later v1.y.

## What is covered

The public API is every exported identifier in these packages:

| Package | Contents |
|---|---|
| `github.com/idfoundry/ssfgo` | subjects, events, registry, SET, wire types |
| `.../caep`, `.../caep/interop` | CAEP events, CAEP Interop profile checks |
| `.../risc` | RISC events |
| `.../scim` | SCIM events (RFC 9967) |
| `.../transmitter`, `.../receiver` | the two roles |
| `.../storage`, `.../storage/memstore`, `.../storage/storagetest` | persistence contracts and implementations |
| `.../ssftest` | in-process Transmitter and Receiver for tests |

Not covered: `internal/...` (not importable), `cmd/...` and
`storage/sqlstore/cmd/...` (conformance harnesses), `examples/...` and
`conformance/...`.

`github.com/idfoundry/ssfgo/storage/sqlstore` is a separate module with
its own version tags (`storage/sqlstore/vX.Y.Z`), so the core module stays
free of dependencies. It follows the same rules from its own v1, and its
database schema is part of its API: a release that changes the schema says
how to migrate.

## Storage interfaces

`storage.StreamStore` and `storage.ReplayStore` are implemented by
applications, so adding a method to them would break every implementation.
Within v1 they will not gain methods. A new storage capability will arrive
as a separate, optional interface that the Transmitter or Receiver detects
with a type assertion and does without when absent.

## Protocol behaviour

SSFgo exists to be conformant, so behaviour may change in a minor release
when:

- a specification it implements publishes errata, or the OIDF conformance
  suite corrects an expectation SSFgo followed;
- validation is found to accept input a specification forbids, or to
  reject input it allows.

Such changes are called out in [CHANGELOG.md](CHANGELOG.md). Loosening
validation beyond what the specifications allow only ever happens behind
an explicit opt-in, such as `receiver.Config.AcceptLegacySubjects`.

## Go versions

SSFgo supports the two most recent Go releases. Raising the minimum Go
version in `go.mod` is not a breaking change.
