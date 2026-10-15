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

A durable replay store is also what makes a polling Receiver's restart
safe. A poll's acknowledgements wait in memory for the next poll, or for
`Acknowledge`, which `RunPoller` calls as it stops. A process that stops
without either loses them, and the Transmitter returns those SETs: the
replay store, which records a SET as handled for as long as it is
acceptable, has the restarted process acknowledge them without handling
them again.

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
  store keeps a SET from being handled twice. An instance that receives
  a SET another is still handling leaves it unacknowledged
  (`receiver.ErrSETInProgress`), so the Transmitter delivers it again,
  and it is handled then if that handling failed. To spread a stream's
  SETs across instances, use push delivery behind a load balancer. Run a
  poll stream's `RunPoller` in **one** instance: a poll returns every SET
  not yet acknowledged (RFC 8936 §2.4), so several pollers receive the
  same SETs — safe, but no faster than one. Verification stays with one
  instance: the `state` of a `RequestVerification` is held in memory, so
  only the instance that asked accepts the verification event; ask from
  the poller's. `EnsureStream` can run in every instance: those starting
  together take turns in the replay store and share one stream.
- **Clocks.** A replay claim's lease is judged by each instance's clock.
  Keep instances' clocks within seconds of each other (NTP does): one
  running some 40 seconds ahead takes over a claim that is still live,
  and the SET is handled twice — never lost.
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
`RevocationStore` — check the contract's behaviour through the
interface, and race concurrent callers against the atomicity that limits
and de-duplication depend on. A race that passes is evidence, not proof;
and durability and consistency across instances, which `Capabilities`
declares, are yours to ensure.
