// Package sqlstore is a reference implementation of SSFgo's storage
// contracts on database/sql, for PostgreSQL and SQLite. It passes the
// storage/storagetest contract suite on both.
//
// The package imports no database driver: open the *sql.DB with the
// driver of your choice, create or migrate the schema, and build the
// stores:
//
//	db, err := sql.Open("pgx", dsn) // github.com/jackc/pgx/v5/stdlib
//	if err := sqlstore.CreateSchema(ctx, db, sqlstore.Postgres); err != nil { ... }
//	streams, err := sqlstore.NewStreamStore(ctx, db, sqlstore.Postgres)
//	replay, err := sqlstore.NewReplayStore(ctx, db, sqlstore.Postgres)
//	revocations, err := sqlstore.NewRevocationStore(ctx, db, sqlstore.Postgres)
//
// # Schema
//
// The stores use five tables, all prefixed ssf_: ssf_streams,
// ssf_subject_rules, ssf_events, ssf_replay and ssf_revocations. Times
// are stored as Unix nanoseconds, NULL for a zero time; lists and
// delivery settings as JSON text.
//
// The schema is versioned, and ssf_schema records the version a database
// has. CreateSchema creates the schema, or migrates an older one to
// SchemaVersion, in one transaction — on PostgreSQL, instances starting
// together take turns — so call it on every start, before building the
// stores. The stores refuse, at construction, a database whose version is
// not SchemaVersion: one never migrated, or one a newer release of this
// module has migrated. A release that changes the schema adds a migration;
// it never edits one already released. An ssf_schema table holding
// anything but the one row CreateSchema writes is refused, not adopted.
//
// # Concurrency
//
// Every operation the contract requires to be atomic runs in one
// transaction. On PostgreSQL, operations on a stream lock its row
// (SELECT ... FOR UPDATE) and creating a stream under a per-Receiver
// limit takes a transaction-scoped advisory lock on the Receiver, so any
// number of Transmitter instances can share the database. On SQLite, those
// transactions begin with BEGIN IMMEDIATE and so run one at a time.
// PostgreSQL transactions run at READ COMMITTED, whatever the database's
// default, as the locks require.
//
// # Assurance
//
// The stores declare themselves durable (storage.StoreAssurance), except
// on a SQLite in-memory database, which AssuranceProduction therefore
// refuses; on PostgreSQL they also declare themselves consistent across
// instances, which a SQLite file, local to one host, is not.
//
// Several Transmitter instances may share a PostgreSQL database and each
// call Run. A pushed SET may then be delivered by more than one instance;
// RFC 8935 allows redelivery, and Receivers recognise it by its "jti"
// (SSFgo's does so through its ReplayStore).
//
// SQLite connections must wait for the database lock rather than fail at
// once: set a busy timeout on every connection, for example with
// modernc.org/sqlite's DSN parameter _pragma=busy_timeout(5000). WAL mode
// (_pragma=journal_mode(WAL)) lets reads proceed during a write.
//
// # Load
//
// transmitter.Run reads the stream list every second, and each push
// stream's queue: a query per push stream per second, per instance. That
// suits modest numbers of streams; the indexes CreateSchema makes keep
// each query cheap.
//
// # Security
//
// Every query uses placeholders for values; table and column names are
// constants. The database holds each push stream's authorization_header,
// a credential for the Receiver's push endpoint, and the signed SETs
// awaiting delivery, both in plain text: restrict access to it
// accordingly.
package sqlstore
