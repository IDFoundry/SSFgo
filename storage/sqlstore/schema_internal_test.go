package sqlstore

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/idfoundry/ssfgo/storage"
	_ "modernc.org/sqlite"
)

// Migrations apply in order, each once: a database at an older version
// gets only the ones it lacks, in one transaction with the new version.
func TestMigrationsApplyInOrder(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := CreateSchema(ctx, db, SQLite); err != nil {
		t.Fatal(err)
	}

	released := migrations
	t.Cleanup(func() { migrations = released })
	migrations = append(released[:len(released):len(released)],
		[]string{`CREATE TABLE ssf_test_v2 (n INTEGER)`, `INSERT INTO ssf_test_v2 (n) VALUES (2)`},
		[]string{`INSERT INTO ssf_test_v2 (n) VALUES (3)`},
	)
	if err := checkSchema(ctx, db); err == nil {
		t.Fatal("the stores accepted a database two versions behind")
	}
	if err := CreateSchema(ctx, db, SQLite); err != nil {
		t.Fatal(err)
	}
	if err := CreateSchema(ctx, db, SQLite); err != nil { // nothing left to apply
		t.Fatal(err)
	}
	var count, sum int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*), SUM(n) FROM ssf_test_v2").Scan(&count, &sum); err != nil {
		t.Fatal(err)
	}
	if count != 2 || sum != 5 {
		t.Errorf("migrations applied %d rows summing %d, want each once (2 rows, 5)", count, sum)
	}
	if err := checkSchema(ctx, db); err != nil {
		t.Error(err)
	}

	// A migration that fails leaves the database as it was.
	migrations = append(migrations, []string{`INSERT INTO ssf_test_v2 (n) VALUES (4)`, `NOT SQL`})
	if err := CreateSchema(ctx, db, SQLite); err == nil {
		t.Fatal("a failing migration succeeded")
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ssf_test_v2").Scan(&count); err != nil || count != 2 {
		t.Errorf("a failed migration left %d rows, %v", count, err)
	}
	if v, _ := readVersion(ctx, db); v != len(released)+2 {
		t.Errorf("a failed migration recorded version %d", v)
	}
}

// A replay record from before version 2 recorded a SET handled, and still
// does once migrated: its redelivery is acknowledged, not handled again.
func TestReplayRecordsSurviveVersion2(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "v1.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	released := migrations
	t.Cleanup(func() { migrations = released })
	migrations = released[:1]
	if err := CreateSchema(ctx, db, SQLite); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour).UnixNano()
	if _, err := db.ExecContext(ctx, `INSERT INTO ssf_replay (issuer, jti, expires_at) VALUES ('https://iss', 'old', ?)`, until); err != nil {
		t.Fatal(err)
	}

	migrations = released
	if err := CreateSchema(ctx, db, SQLite); err != nil {
		t.Fatal(err)
	}
	replay, err := NewReplayStore(ctx, db, SQLite)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := replay.ClaimSET(ctx, "https://iss", "old", "h", time.Now().Add(time.Minute)); err != nil || got != storage.ClaimDone {
		t.Errorf("a SET recorded before the migration = %v, %v; want done", got, err)
	}
}
