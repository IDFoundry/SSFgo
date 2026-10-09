package sqlstore_test

import (
	"database/sql"
	"strings"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/storage/sqlstore"
)

func schemaVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRowContext(ctx, "SELECT version FROM ssf_schema WHERE id = 1").Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// newStores builds every store on db, returning the first error.
func newStores(db *sql.DB, d sqlstore.Dialect) error {
	if _, err := sqlstore.NewStreamStore(ctx, db, d); err != nil {
		return err
	}
	if _, err := sqlstore.NewReplayStore(ctx, db, d); err != nil {
		return err
	}
	_, err := sqlstore.NewRevocationStore(ctx, db, d)
	return err
}

// A store refuses, at construction, a database CreateSchema has not
// created, so a missing schema is found at startup, not at the first
// query; CreateSchema records the version the stores then accept.
func TestSchemaVersion(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) {
			db := d.raw(t)
			if err := newStores(db, d.dialect); err == nil || !strings.Contains(err.Error(), "CreateSchema") {
				t.Errorf("stores on an empty database: %v, want a pointer to CreateSchema", err)
			}
			if err := sqlstore.CreateSchema(ctx, db, d.dialect); err != nil {
				t.Fatal(err)
			}
			if v := schemaVersion(t, db); v != sqlstore.SchemaVersion() {
				t.Errorf("version %d, want %d", v, sqlstore.SchemaVersion())
			}
			if err := newStores(db, d.dialect); err != nil {
				t.Error(err)
			}
		})
	}
}

// A database created before schema versions were recorded — its tables,
// with data, but no ssf_schema — is adopted by CreateSchema without losing
// anything; until then the stores refuse it as older.
func TestSchemaAdoptsUnversioned(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) {
			db := d.open(t)
			st, err := sqlstore.NewStreamStore(ctx, db, d.dialect)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.CreateStream(ctx, storage.Stream{ID: "s1", ReceiverID: "rx", Delivery: ssf.Delivery{Method: ssf.DeliveryPoll}}, storage.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, "DROP TABLE ssf_schema"); err != nil {
				t.Fatal(err)
			}
			if err := newStores(db, d.dialect); err == nil || !strings.Contains(err.Error(), "CreateSchema") {
				t.Errorf("stores on an unversioned database: %v", err)
			}
			if err := sqlstore.CreateSchema(ctx, db, d.dialect); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Stream(ctx, "s1"); err != nil {
				t.Errorf("the stream did not survive adoption: %v", err)
			}
			if err := newStores(db, d.dialect); err != nil {
				t.Error(err)
			}
		})
	}
}

// A database migrated by a newer storage/sqlstore is refused — by
// CreateSchema, which would otherwise downgrade nothing and record an older
// version, and by the stores — rather than used with a schema they do not
// know.
func TestSchemaNewerRefused(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) {
			db := d.open(t)
			if _, err := db.ExecContext(ctx, "UPDATE ssf_schema SET version = version + 1"); err != nil {
				t.Fatal(err)
			}
			if err := sqlstore.CreateSchema(ctx, db, d.dialect); err == nil || !strings.Contains(err.Error(), "upgrade storage/sqlstore") {
				t.Errorf("CreateSchema on a newer schema: %v", err)
			}
			if err := newStores(db, d.dialect); err == nil || !strings.Contains(err.Error(), "upgrade storage/sqlstore") {
				t.Errorf("stores on a newer schema: %v", err)
			}
			if v := schemaVersion(t, db); v != sqlstore.SchemaVersion()+1 {
				t.Errorf("CreateSchema changed a newer version to %d", v)
			}
		})
	}
}

// A store on a SQLite in-memory database does not declare itself durable,
// so AssuranceProduction refuses what forgets everything on restart.
func TestInMemorySQLiteNotDurable(t *testing.T) {
	for _, dsn := range []string{":memory:", "file::memory:?cache=shared", "file:ssf?mode=memory&cache=shared", ""} {
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		db.SetMaxOpenConns(1) // each connection to :memory: is a database of its own
		if err := sqlstore.CreateSchema(ctx, db, sqlstore.SQLite); err != nil {
			t.Fatal(err)
		}
		for _, c := range capabilities(t, db, sqlstore.SQLite) {
			if c.Durable {
				t.Errorf("a store on %q declares itself durable", dsn)
			}
		}
	}
	for _, c := range capabilities(t, openSQLite(t), sqlstore.SQLite) {
		if !c.Durable || c.CrossInstanceConsistent {
			t.Errorf("a store on a SQLite file declares %+v, want durable only", c)
		}
	}
}

// capabilities returns what each store on db declares.
func capabilities(t *testing.T, db *sql.DB, d sqlstore.Dialect) []storage.Capabilities {
	t.Helper()
	streams, err := sqlstore.NewStreamStore(ctx, db, d)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := sqlstore.NewReplayStore(ctx, db, d)
	if err != nil {
		t.Fatal(err)
	}
	revocations, err := sqlstore.NewRevocationStore(ctx, db, d)
	if err != nil {
		t.Fatal(err)
	}
	return []storage.Capabilities{streams.Capabilities(), replay.Capabilities(), revocations.Capabilities()}
}

// An ssf_schema table CreateSchema did not write — more than one row,
// another id, a negative version — is refused, not adopted or migrated.
func TestForeignSchemaTableRefused(t *testing.T) {
	for name, stmts := range map[string][]string{
		"negative version": {"UPDATE ssf_schema SET version = -1"},
		"two rows": {
			"DROP TABLE ssf_schema",
			"CREATE TABLE ssf_schema (id INTEGER, version INTEGER)",
			"INSERT INTO ssf_schema VALUES (1, 1), (1, 0)",
		},
		"another id": {
			"DROP TABLE ssf_schema",
			"CREATE TABLE ssf_schema (id INTEGER, version INTEGER)",
			"INSERT INTO ssf_schema VALUES (2, 1)",
		},
	} {
		for _, d := range dialects {
			t.Run(d.name+"/"+name, func(t *testing.T) {
				db := d.open(t)
				for _, s := range stmts {
					if _, err := db.ExecContext(ctx, s); err != nil {
						t.Fatal(err)
					}
				}
				if err := sqlstore.CreateSchema(ctx, db, d.dialect); err == nil || !strings.Contains(err.Error(), "not this module's") {
					t.Errorf("CreateSchema = %v", err)
				}
				if err := newStores(db, d.dialect); err == nil || !strings.Contains(err.Error(), "not this module's") {
					t.Errorf("stores = %v", err)
				}
			})
		}
	}
}
