# Storage and scaling in Go

Each role keeps state in a store it is given:

| Role | Store | Holds |
|---|---|---|
| Transmitter | `storage.StreamStore` | streams, their subject rules and queued SETs |
| Receiver | `storage.ReplayStore` | the SETs it has handled, so none is handled twice |
| `revocation` | `storage.RevocationStore` | revocations, until `Retention` passes |

`storage/memstore` keeps them in memory, for tests and development.
`storage/sqlstore`, a separate module, keeps them in PostgreSQL or
SQLite.

## Production

`ssf.AssuranceProduction` refuses a store that does not declare itself
durable: an in-memory one loses its streams and queued SETs on restart,
accepts replays of SETs it already handled, and forgets revocations.

```go
// go get github.com/idfoundry/ssfgo/storage/sqlstore
db, err := sql.Open("pgx", dsn) // any database/sql driver for PostgreSQL or SQLite
if err != nil {
	return err
}
if err := sqlstore.CreateSchema(ctx, db, sqlstore.Postgres); err != nil {
	return err // creates or migrates the schema; safe on every start
}
streams, err := sqlstore.NewStreamStore(ctx, db, sqlstore.Postgres) // transmitter.Config.Store
if err != nil {
	return err
}
replay, err := sqlstore.NewReplayStore(ctx, db, sqlstore.Postgres) // receiver.Config.ReplayStore
if err != nil {
	return err
}
revocations, err := sqlstore.NewRevocationStore(ctx, db, sqlstore.Postgres) // revocation.Options.Store
if err != nil {
	return err
}
```

Expired replay records and revocations are deleted as new ones are
added. The schema is versioned: the stores refuse a database
`CreateSchema` has not migrated to `sqlstore.SchemaVersion()`, so call it
on every start, before building them.

## Several instances

Run several instances of a role on one PostgreSQL database by declaring
it, which also requires the stores to declare themselves consistent
across instances — sqlstore does on PostgreSQL, not on SQLite:

```go
txCfg.Store = streams
txCfg.Assurance = ssf.AssuranceProduction
txCfg.HorizontallyScaled = true

rxCfg.ReplayStore = replay
rxCfg.Assurance = ssf.AssuranceProduction
rxCfg.HorizontallyScaled = true
```

- **Transmitter.** Every instance serves `Handler()` and can `Emit`:
  stream limits and queues are enforced in the database. Run `Run`, which
  delivers pushed SETs, in **one** instance only: it coordinates
  deliveries within its process, so several would push the same SETs.
- **Receiver.** Any instance can take a push or poll: the shared replay
  store keeps a SET from being handled twice.
- **Revocation.** Every instance sees every revocation, so set
  `HorizontallyScaled` in `revocation.Options` too.

## Your own store

Implement the interface, declare what it guarantees, and prove it:

```go
// Capabilities implements storage.StoreAssurance. These are your claims:
// nothing verifies durability or consistency across instances.
func (s *redisReplayStore) Capabilities() storage.Capabilities {
	return storage.Capabilities{Durable: true, CrossInstanceConsistent: true}
}

func TestRedisReplayStore(t *testing.T) {
	storagetest.ReplayStore(t, func(t *testing.T) storage.ReplayStore {
		return newRedisReplayStore(t) // yours: a fresh, empty store
	})
}
```

The `storagetest` suites — `StreamStore`, `ReplayStore`,
`RevocationStore` — check everything observable through the interface,
including the atomicity limits and de-duplication depend on.
