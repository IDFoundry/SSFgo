# Changelog

## [0.1.1](https://github.com/IDFoundry/SSFgo/compare/storage/sqlstore/v0.1.0...storage/sqlstore/v0.1.1) (2026-10-12)


### Bug Fixes

* **sqlstore:** require the core at v0.1.0 ([5caef1e](https://github.com/IDFoundry/SSFgo/commit/5caef1ed1668b3d8c6982cf8882440f02ffb4380))

## 0.1.0 (2026-10-12)

The first release: durable implementations of SSFgo's storage contracts
on `database/sql`, for PostgreSQL and SQLite, passing the
`storage/storagetest` contract suite on both. It imports no database
driver.

### Features

* `NewStreamStore`, `NewReplayStore` and `NewRevocationStore`: a
  Transmitter's streams and delivery queues, a Receiver's replay record,
  and revocations for the `revocation` package.
* A versioned schema: `CreateSchema` creates it or migrates an older one
  in one transaction, and the stores refuse a database at any other
  `SchemaVersion`.
* Several Transmitter instances can share a PostgreSQL database: stream
  operations lock their row, and the stores declare themselves consistent
  across instances there. On SQLite, the transactions run one at a time.
* The stores declare themselves durable, so `AssuranceProduction`
  accepts them — except on a SQLite in-memory database, which it refuses.
* The Transmitter conformance matrix runs on sqlstore with SQLite daily.
