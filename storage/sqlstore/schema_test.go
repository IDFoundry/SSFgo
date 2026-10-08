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
