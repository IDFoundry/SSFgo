# Changelog

## [0.2.4](https://github.com/IDFoundry/SSFgo/compare/storage/sqlstore/v0.2.3...storage/sqlstore/v0.2.4) (2026-10-15)


### Bug Fixes

* **sqlstore:** require the core at v0.4.0 ([b8a18e6](https://github.com/IDFoundry/SSFgo/commit/b8a18e67d1b5f15fbb28af175d65e22bb3f94aed))

## [0.2.3](https://github.com/IDFoundry/SSFgo/compare/storage/sqlstore/v0.2.2...storage/sqlstore/v0.2.3) (2026-10-14)


### Bug Fixes

* **sqlstore:** clamp replay leases and records past 2262, so a handled SET is not handled again ([d2a3631](https://github.com/IDFoundry/SSFgo/commit/d2a3631bbe6ca1b23b7a379152e03c915416bc5a))

## [0.2.2](https://github.com/IDFoundry/SSFgo/compare/storage/sqlstore/v0.2.1...storage/sqlstore/v0.2.2) (2026-10-14)


### Bug Fixes

* **sqlstore:** write replay claims and revocations at READ COMMITTED on PostgreSQL ([aae8fb7](https://github.com/IDFoundry/SSFgo/commit/aae8fb7a480ff8d40ff8192a10de5df4ebd651bf))

## [0.2.1](https://github.com/IDFoundry/SSFgo/compare/storage/sqlstore/v0.2.0...storage/sqlstore/v0.2.1) (2026-10-13)


### Bug Fixes

* **sqlstore:** require the core at v0.2.0 ([02c6f7a](https://github.com/IDFoundry/SSFgo/commit/02c6f7a87b15311ccd9faba9a3cb9b76372f3f45))

## [0.2.0](https://github.com/IDFoundry/SSFgo/compare/storage/sqlstore/v0.1.1...storage/sqlstore/v0.2.0) (2026-10-13)


### ⚠ BREAKING CHANGES

* storage.ReplayStore's MarkSET and ForgetSET are replaced by ClaimSET, RenewClaim, CompleteSET and ReleaseClaim, and storage/sqlstore's schema moves to version 2: call CreateSchema before building the stores. See UPGRADING.md for v0.2.0.

### Bug Fixes

* claim a SET while it is handled, so a crash or another instance cannot lose it ([3c5ac65](https://github.com/IDFoundry/SSFgo/commit/3c5ac65d2259f388d7ed8658b9b70deb538bf28f))

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
