package sqlstore

import (
	"context"
	"database/sql"
	"strings"
)

// schema is the DDL for both dialects; {serial} is replaced by
// Dialect.serial.
var schema = []string{
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
}

// CreateSchema creates the tables and indexes the stores use, skipping any
// that already exist. It is safe to call on every start.
func CreateSchema(ctx context.Context, db *sql.DB, d Dialect) error {
	if err := d.check(db); err != nil {
		return err
	}
	return d.inTx(ctx, db, func(q querier) error {
		if d == Postgres {
			// Two instances starting together could otherwise both try
			// to create the same table: IF NOT EXISTS is not atomic.
			if _, err := q.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1, 0)", advisoryLockClass); err != nil {
				return err
			}
		}
		for _, stmt := range schema {
			if _, err := q.ExecContext(ctx, strings.ReplaceAll(stmt, "{serial}", d.serial())); err != nil {
				return err
			}
		}
		return nil
	})
}
