package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Dialect selects the SQL a store generates.
type Dialect int

const (
	// Postgres is PostgreSQL 12 or later.
	Postgres Dialect = iota + 1
	// SQLite is SQLite 3.35 or later.
	SQLite
)

func (d Dialect) String() string {
	switch d {
	case Postgres:
		return "postgres"
	case SQLite:
		return "sqlite"
	}
	return "Dialect(" + strconv.Itoa(int(d)) + ")"
}

func (d Dialect) check(db *sql.DB) error {
	if db == nil {
		return errors.New("sqlstore: nil *sql.DB")
	}
	if d != Postgres && d != SQLite {
		return fmt.Errorf("sqlstore: unknown dialect %v", d)
	}
	return nil
}

// serial is the column type of an insertion-ordered primary key.
func (d Dialect) serial() string {
	if d == Postgres {
		return "BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY"
	}
	// An alias for the rowid, which SQLite assigns in increasing order.
	return "INTEGER PRIMARY KEY"
}

// forUpdate is the suffix that locks the rows a SELECT reads. SQLite has
// none: its write transactions already hold the database lock.
func (d Dialect) forUpdate() string {
	if d == Postgres {
		return " FOR UPDATE"
	}
	return ""
}

// rebind rewrites ? placeholders as $1, $2, ... for PostgreSQL. The
// package's queries contain no ? other than placeholders.
func (d Dialect) rebind(query string) string {
	if d != Postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// advisoryLockClass namespaces this package's PostgreSQL advisory locks
// ("SSFg").
const advisoryLockClass = 0x53534667

// lockReceiver serializes, until the transaction ends, the transactions
// that create streams for one Receiver.
func (d Dialect) lockReceiver(ctx context.Context, q querier, receiverID string) error {
	if d != Postgres {
		return nil
	}
	_, err := q.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1, hashtext($2))", advisoryLockClass, receiverID)
	return err
}

// querier is what a transaction offers: *sql.Tx and *sql.Conn both
// satisfy it.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// inTx runs fn in a write transaction and commits if it returns nil. fn's
// error is returned unchanged.
func (d Dialect) inTx(ctx context.Context, db *sql.DB, fn func(querier) error) error {
	if d == Postgres {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			_ = tx.Rollback()
			return err
		}
		return tx.Commit()
	}

	// database/sql cannot begin an IMMEDIATE transaction, which takes
	// SQLite's write lock up front. A deferred one would take it at its
	// first write, and fail at once rather than wait if another
	// transaction had read in the meantime.
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	// End the transaction even if ctx is done, so the connection never
	// returns to the pool inside one.
	end := context.WithoutCancel(ctx)
	if err := fn(conn); err != nil {
		if _, rbErr := conn.ExecContext(end, "ROLLBACK"); rbErr != nil {
			discard(conn)
		}
		return err
	}
	if _, err := conn.ExecContext(end, "COMMIT"); err != nil {
		if _, rbErr := conn.ExecContext(end, "ROLLBACK"); rbErr != nil {
			discard(conn)
		}
		return err
	}
	return nil
}

// discard closes a connection instead of returning it to the pool.
func discard(conn *sql.Conn) {
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
}
