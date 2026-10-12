# Changelog

## 0.1.0 (2026-10-12)


### ⚠ BREAKING CHANGES

* ssf.Assurance is no longer a string type, and revocation.New(store, opts) is now revocation.New(opts) with Options.Store.
* **sqlstore:** the sqlstore store constructors take a context.Context as their first argument, and refuse a database whose schema CreateSchema has not created or migrated.
* transmitter.Config, receiver.Config and revocation.Options require Assurance.
* receiver.Config's ReplayWindow, KeyMaxAge and MaxClockSkew move into Limits; transmitter.Config.LongPollTimeout moves into Limits; both roles' Limits, and PushRetry for push, must be set — use the Recommended* functions for the former defaults.
* scope revocations to the token issuer each Transmitter speaks for

### Features

* assurance levels and store capabilities ([3f48b89](https://github.com/IDFoundry/SSFgo/commit/3f48b891579449dab6a580d82431785f81953658))
* **conformance:** run the Transmitter conformance matrix on sqlstore ([ef7e524](https://github.com/IDFoundry/SSFgo/commit/ef7e524fe7893a7d3fe449183d8cf7b99a8e404b))
* make Assurance an enumeration, give the Revoker its store in Options, and name fields in every config error ([5bb43f2](https://github.com/IDFoundry/SSFgo/commit/5bb43f21d100cbfd61b02cffc39319e1c81c3040))
* no implicit defaults for security-relevant configuration ([771ceae](https://github.com/IDFoundry/SSFgo/commit/771ceaef2b434c1ddc7b54ad8e4b7fb37b30c3ae))
* **sqlstore:** RevocationStore ([94dca5f](https://github.com/IDFoundry/SSFgo/commit/94dca5f3a593eae802f20b3c7083afa46a50f2ab))
* **sqlstore:** version the schema and migrate it in CreateSchema ([29646f0](https://github.com/IDFoundry/SSFgo/commit/29646f01092164a5f5bf112382473e6a393e8155))
* **storage:** sqlstore, durable storage for PostgreSQL and SQLite ([c41bf6c](https://github.com/IDFoundry/SSFgo/commit/c41bf6c25c91d452109823a4066216aa87af7a6f))


### Bug Fixes

* benchmarks and sqlstore build against the explicit limits ([c844df2](https://github.com/IDFoundry/SSFgo/commit/c844df295cb2c6500e6e376d60db51ed5ebd8681))
* close SSF spec gaps in subject rules, redelivery and stream calls ([a3511ed](https://github.com/IDFoundry/SSFgo/commit/a3511ed5981ec45e00df7eef6069fcf00c6ea75a))
* scope revocations to the token issuer each Transmitter speaks for ([9d179b6](https://github.com/IDFoundry/SSFgo/commit/9d179b6434f25f1f594cf59eda9976dcdd90c5c0))
* **sqlstore:** raise golang.org/x/text to v0.41.0 for GO-2026-6629 ([f333906](https://github.com/IDFoundry/SSFgo/commit/f33390650e5f0082b5d4e2dd0c26d5218e0412b1))
* **sqlstore:** refuse in-memory SQLite in production, foreign schema tables, and other isolation levels ([733b3b5](https://github.com/IDFoundry/SSFgo/commit/733b3b522721aca1bb65fb477d1637268cd3b929))
* **sqlstore:** upgrade golang.org/x/text to v0.39.0 (GO-2026-5970) ([d67a29d](https://github.com/IDFoundry/SSFgo/commit/d67a29d5c684ac76af0328f6c660dab82a8b3faa))
* **transmitter:** require PermitEvent and close lock, rule and state gaps ([6fb2c13](https://github.com/IDFoundry/SSFgo/commit/6fb2c1340bb9ac4d712e37d6d4ab9a83b474edfd))
