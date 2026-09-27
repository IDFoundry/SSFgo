package sqlstore_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/storage/sqlstore"
	"github.com/idfoundry/ssfgo/storage/storagetest"
)

// postgresEnv names the variable holding a PostgreSQL URL
// (postgres://user:pass@host/db?sslmode=disable) to run the tests against.
// Without it only SQLite is tested.
const postgresEnv = "SSFGO_TEST_POSTGRES"

var ctx = context.Background()

// openSQLite opens a new, empty SQLite database with its schema.
func openSQLite(t *testing.T) *sql.DB {
	t.Helper()
	return openSQLiteAt(t, filepath.Join(t.TempDir(), "ssf.db"))
}

func openSQLiteAt(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := sqlstore.CreateSchema(ctx, db, sqlstore.SQLite); err != nil {
		t.Fatal(err)
	}
	return db
}

// openPostgres opens a connection to a new, empty PostgreSQL schema with
// the tables created in it, and drops the schema when the test ends.
func openPostgres(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv(postgresEnv)
	if dsn == "" {
		t.Skip(postgresEnv + " is not set")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	schema := "ssfgo_test_" + hex.EncodeToString(b)
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE") })

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("%s must be a URL: %v", postgresEnv, err)
	}
	q := u.Query()
	q.Set("search_path", schema) // pgx sends unknown parameters as run-time settings
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := sqlstore.CreateSchema(ctx, db, sqlstore.Postgres); err != nil {
		t.Fatal(err)
	}
	return db
}

var dialects = []struct {
	name    string
	dialect sqlstore.Dialect
	open    func(*testing.T) *sql.DB
}{
	{"SQLite", sqlstore.SQLite, openSQLite},
	{"Postgres", sqlstore.Postgres, openPostgres},
}

func TestContract(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) {
			storagetest.StreamStore(t, func(t *testing.T) storage.StreamStore {
				st, err := sqlstore.NewStreamStore(d.open(t), d.dialect)
				if err != nil {
					t.Fatal(err)
				}
				return st
			})
		})
	}
}

func TestReplayContract(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) {
			storagetest.ReplayStore(t, func(t *testing.T) storage.ReplayStore {
				st, err := sqlstore.NewReplayStore(d.open(t), d.dialect)
				if err != nil {
					t.Fatal(err)
				}
				return st
			})
		})
	}
}

// TestDurable reopens a database and finds everything that was stored.
func TestDurable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssf.db")
	created := time.Unix(1700000000, 123456789).UTC()
	want := storage.Stream{
		ID: "s1", ReceiverID: "r1", Audience: []string{"https://rx.example"},
		Delivery:        ssf.Delivery{Method: ssf.DeliveryPoll, EndpointURL: "https://tx.example/poll/s1"},
		EventsRequested: []ssf.EventType{"https://example.com/a"},
		Status:          ssf.StreamPaused, StatusReason: "inactivity timeout",
		LastActivity: created.Add(time.Minute), CreatedAt: created,
	}
	subject := ssf.ComplexSubject{User: ssf.EmailSubject{Email: "alice@example.com"}, Tenant: ssf.OpaqueSubject{ID: "t1"}}

	db := openSQLiteAt(t, path)
	st, _ := sqlstore.NewStreamStore(db, sqlstore.SQLite)
	replay, _ := sqlstore.NewReplayStore(db, sqlstore.SQLite)
	if err := st.CreateStream(ctx, want, storage.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSubjectRule(ctx, "s1", storage.SubjectRule{Subject: subject, Included: true}, 0); err != nil {
		t.Fatal(err)
	}
	if err := st.Enqueue(ctx, "s1", storage.QueuedEvent{JTI: "j1", SET: "a.b.c", EnqueuedAt: created, Control: true}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := replay.MarkSET(ctx, "https://iss", "j9", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db = openSQLiteAt(t, path)
	st, _ = sqlstore.NewStreamStore(db, sqlstore.SQLite)
	replay, _ = sqlstore.NewReplayStore(db, sqlstore.SQLite)
	got, err := st.Stream(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reopened stream = %+v\nwant %+v", got, want)
	}
	rules, _ := st.SubjectRules(ctx, "s1")
	if len(rules) != 1 || !ssf.SubjectsEqual(rules[0].Subject, subject) || !rules[0].Included {
		t.Errorf("reopened rules = %+v", rules)
	}
	q, _ := st.PendingEvents(ctx, "s1", 0, false)
	if len(q) != 1 || q[0] != (storage.QueuedEvent{JTI: "j1", SET: "a.b.c", EnqueuedAt: created, Control: true}) {
		t.Errorf("reopened queue = %+v", q)
	}
	if fresh, _ := replay.MarkSET(ctx, "https://iss", "j9", time.Now().Add(time.Hour)); fresh {
		t.Error("a SET recorded before reopening was accepted again")
	}
}

// TestStreamFields fails when storage.Stream gains a field, which the
// ssf_streams table would not store until it is added.
func TestStreamFields(t *testing.T) {
	if n := reflect.TypeFor[storage.Stream]().NumField(); n != 13 {
		t.Errorf("storage.Stream has %d fields; sqlstore stores 13 — add the new one to the schema", n)
	}
}

func TestSchemaIdempotent(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) {
			db := d.open(t)
			if err := sqlstore.CreateSchema(ctx, db, d.dialect); err != nil {
				t.Errorf("second CreateSchema: %v", err)
			}
		})
	}
}

func TestInvalidArguments(t *testing.T) {
	if _, err := sqlstore.NewStreamStore(nil, sqlstore.SQLite); err == nil {
		t.Error("NewStreamStore(nil db) succeeded")
	}
	db := openSQLite(t)
	if _, err := sqlstore.NewReplayStore(db, sqlstore.Dialect(0)); err == nil {
		t.Error("NewReplayStore(zero Dialect) succeeded")
	}
	if err := sqlstore.CreateSchema(ctx, db, sqlstore.Dialect(9)); err == nil {
		t.Error("CreateSchema(unknown Dialect) succeeded")
	}
}

// TestConcurrentLimits checks that the per-Receiver stream limit and the
// queue limit hold under concurrent writers, as they must when several
// Transmitter instances share a database.
func TestConcurrentLimits(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) {
			st, err := sqlstore.NewStreamStore(d.open(t), d.dialect)
			if err != nil {
				t.Fatal(err)
			}
			const writers, limit = 20, 3
			var (
				wg              sync.WaitGroup
				created, queued atomic.Int32
			)
			for i := range writers {
				wg.Go(func() {
					s := storage.Stream{ID: fmt.Sprint("s", i), ReceiverID: "r1", Status: ssf.StreamEnabled}
					err := st.CreateStream(ctx, s, storage.CreateOptions{MaxStreamsPerReceiver: limit})
					switch {
					case err == nil:
						created.Add(1)
					case !errors.Is(err, storage.ErrTooManyStreams):
						t.Error(err)
					}
				})
			}
			wg.Wait()
			if n := created.Load(); n != limit {
				t.Errorf("%d streams created concurrently under a limit of %d", n, limit)
			}

			all, _ := st.AllStreams(ctx)
			id := all[0].ID
			for i := range writers {
				wg.Go(func() {
					err := st.Enqueue(ctx, id, storage.QueuedEvent{JTI: fmt.Sprint(i), SET: "x"}, limit)
					switch {
					case err == nil:
						queued.Add(1)
					case !errors.Is(err, storage.ErrQueueFull):
						t.Error(err)
					}
				})
			}
			wg.Wait()
			if n := queued.Load(); n != limit {
				t.Errorf("%d SETs queued concurrently under a limit of %d", n, limit)
			}
		})
	}
}
