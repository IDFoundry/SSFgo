package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// migrations are the schema's versions, oldest first: applying
// migrations[n] takes a database from version n to n+1, and the schema's
// version is len(migrations). A release that changes the schema adds a
// migration; it never edits one already released. {serial} is replaced by
// Dialect.serial.
//
// Version 1 keeps IF NOT EXISTS, so it also adopts a database created
// before versions were recorded, leaving its data as it was.
var migrations = [][]string{{
	`CREATE TABLE IF NOT EXISTS ssf_streams (
		seq {serial},
		id TEXT NOT NULL UNIQUE,
		receiver_id TEXT NOT NULL,
		audience TEXT NOT NULL,
		delivery TEXT NOT NULL,
		events_requested TEXT NOT NULL,
		events_delivered TEXT NOT NULL,
		description TEXT NOT NULL,
		status TEXT NOT NULL,
		status_reason TEXT NOT NULL,
		status_locked BOOLEAN NOT NULL,
		last_verification_request BIGINT,
		last_activity BIGINT,
		created_at BIGINT
	)`,
	`CREATE INDEX IF NOT EXISTS ssf_streams_receiver ON ssf_streams (receiver_id, seq)`,
	`CREATE TABLE IF NOT EXISTS ssf_subject_rules (
		seq {serial},
		stream_id TEXT NOT NULL,
		subject TEXT NOT NULL,
		included BOOLEAN NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS ssf_subject_rules_stream ON ssf_subject_rules (stream_id, seq)`,
	`CREATE TABLE IF NOT EXISTS ssf_events (
		seq {serial},
		stream_id TEXT NOT NULL,
		jti TEXT NOT NULL,
		set_token TEXT NOT NULL,
		enqueued_at BIGINT,
		control BOOLEAN NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS ssf_events_stream ON ssf_events (stream_id, seq)`,
	`CREATE INDEX IF NOT EXISTS ssf_events_jti ON ssf_events (stream_id, jti)`,
	`CREATE TABLE IF NOT EXISTS ssf_replay (
		issuer TEXT NOT NULL,
		jti TEXT NOT NULL,
		expires_at BIGINT NOT NULL,
		PRIMARY KEY (issuer, jti)
	)`,
	`CREATE INDEX IF NOT EXISTS ssf_replay_expires ON ssf_replay (expires_at)`,
	`CREATE TABLE IF NOT EXISTS ssf_revocations (
		kind TEXT NOT NULL,
		issuer TEXT NOT NULL,
		value TEXT NOT NULL,
		revoked_at BIGINT NOT NULL,
		expires_at BIGINT NOT NULL,
		PRIMARY KEY (kind, issuer, value)
	)`,
	`CREATE INDEX IF NOT EXISTS ssf_revocations_expires ON ssf_revocations (expires_at)`,
}}

// schemaTable records the database's schema version, in one row.
const schemaTable = `CREATE TABLE IF NOT EXISTS ssf_schema (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	version INTEGER NOT NULL
)`

// SchemaVersion is the version of the database schema this module's stores
// use.
func SchemaVersion() int { return len(migrations) }

// CreateSchema creates the tables and indexes the stores use, or migrates
// a database whose schema is older to SchemaVersion, in one transaction;
// on PostgreSQL, instances starting together take turns. It is safe to
// call on every start. A database whose schema is newer than this module
// knows is refused: upgrade storage/sqlstore instead.
func CreateSchema(ctx context.Context, db *sql.DB, d Dialect) error {
	if err := d.check(db); err != nil {
		return err
	}
	return d.inTx(ctx, db, func(q querier) error {
		if d == Postgres {
			// Two instances starting together could otherwise both try
			// to migrate: IF NOT EXISTS is not atomic.
			if _, err := q.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1, 0)", advisoryLockClass); err != nil {
				return err
			}
		}
		if _, err := q.ExecContext(ctx, schemaTable); err != nil {
			return err
		}
		version, err := readVersion(ctx, q)
		if err != nil {
			return err
		}
		if version > len(migrations) {
			return fmt.Errorf("sqlstore: the database schema is version %d, newer than this storage/sqlstore's %d: upgrade storage/sqlstore", version, len(migrations))
		}
		for _, m := range migrations[version:] {
			for _, stmt := range m {
				if _, err := q.ExecContext(ctx, strings.ReplaceAll(stmt, "{serial}", d.serial())); err != nil {
					return fmt.Errorf("sqlstore: migrate the schema from version %d: %w", version, err)
				}
			}
		}
		_, err = q.ExecContext(ctx, d.rebind(`INSERT INTO ssf_schema (id, version) VALUES (1, ?)
			ON CONFLICT (id) DO UPDATE SET version = excluded.version`), len(migrations))
		return err
	})
}

// readVersion returns the schema version recorded in the database, or 0
// for one with none. The record must be the one row CreateSchema writes:
// a table of another shape, or a negative version, is not this module's.
func readVersion(ctx context.Context, q querier) (int, error) {
	rows, err := q.QueryContext(ctx, "SELECT id, version FROM ssf_schema")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	n, version := 0, 0
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id, &version); err != nil {
			return 0, err
		}
		if n++; n > 1 || id != 1 || version < 0 {
			return 0, errForeignSchema
		}
	}
	return version, rows.Err()
}

// errForeignSchema reports an ssf_schema table CreateSchema did not write.
var errForeignSchema = errors.New("sqlstore: the ssf_schema table is not this module's: it must hold one row, with id 1 and a version of at least 0")

// checkSchema reports whether the database's schema is the version this
// module's stores use, so a store refuses at construction, rather than at
// its first query, a database CreateSchema has not created or migrated.
func checkSchema(ctx context.Context, db *sql.DB) error {
	version, err := readVersion(ctx, db)
	switch {
	case errors.Is(err, errForeignSchema):
		return err
	case err != nil:
		return fmt.Errorf("sqlstore: read the schema version (has CreateSchema run?): %w", err)
	case version < len(migrations):
		return fmt.Errorf("sqlstore: the database schema is version %d, older than this storage/sqlstore's %d: run CreateSchema to migrate it", version, len(migrations))
	case version > len(migrations):
		return fmt.Errorf("sqlstore: the database schema is version %d, newer than this storage/sqlstore's %d: upgrade storage/sqlstore", version, len(migrations))
	}
	return nil
}
