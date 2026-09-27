// Package sqlstore is a reference implementation of SSFgo's storage
// contracts on database/sql, for PostgreSQL and SQLite. It passes the
// storage/storagetest contract suite on both.
//
// The package imports no database driver: open the *sql.DB with the
// driver of your choice, create the schema once, and build the stores:
//
//	db, err := sql.Open("pgx", dsn) // github.com/jackc/pgx/v5/stdlib
//	if err := sqlstore.CreateSchema(ctx, db, sqlstore.Postgres); err != nil { ... }
//	streams, err := sqlstore.NewStreamStore(db, sqlstore.Postgres)
//	replay, err := sqlstore.NewReplayStore(db, sqlstore.Postgres)
//
// # Schema
//
// CreateSchema creates four tables, all prefixed ssf_, if they do not
// exist: ssf_streams, ssf_subject_rules, ssf_events and ssf_replay. Times
// are stored as Unix nanoseconds, NULL for a zero time; lists and
// delivery settings as JSON text. The schema is part of this module's
// compatibility promise: a release that changes it says how to migrate.
//
// # Concurrency
//
// Every operation the contract requires to be atomic runs in one
// transaction. On PostgreSQL, operations on a stream lock its row
// (SELECT ... FOR UPDATE) and creating a stream under a per-Receiver
// limit takes a transaction-scoped advisory lock on the Receiver, so any
// number of Transmitter instances can share the database. On SQLite, those
// transactions begin with BEGIN IMMEDIATE and so run one at a time.
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
