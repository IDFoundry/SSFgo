// Command conformance-transmitter runs the SSFgo conformance Transmitter
// (github.com/idfoundry/ssfgo/internal/conformance/txharness) on
// storage/sqlstore instead of in-memory storage, so the OIDF conformance
// suite exercises the durable backend.
//
// By default it uses a new SQLite database in a temporary directory;
// -sqlite names a database file and -postgres a PostgreSQL URL instead.
// Every other flag is the in-memory harness's.
//
//	go run ./cmd/conformance-transmitter -issuer https://host.docker.internal:9443/ssfgo
package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"log/slog"
	"os"
	"path/filepath"

	// The database/sql drivers: "pgx" and "sqlite".
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/idfoundry/ssfgo/internal/conformance/txharness"
	"github.com/idfoundry/ssfgo/storage/sqlstore"
)

func main() {
	opts := txharness.RegisterFlags(flag.CommandLine)
	sqlitePath := flag.String("sqlite", "", "SQLite database file (default: a new one in a temporary directory)")
	postgres := flag.String("postgres", "", "PostgreSQL URL; overrides -sqlite")
	flag.Parse()

	db, dialect, err := open(*sqlitePath, *postgres)
	if err != nil {
		log.Fatal(err)
	}
	if err := sqlstore.CreateSchema(context.Background(), db, dialect); err != nil {
		log.Fatal(err)
	}
	store, err := sqlstore.NewStreamStore(db, dialect)
	if err != nil {
		log.Fatal(err)
	}
	err = txharness.Run(opts, store)
	_ = db.Close()
	log.Fatal(err)
}

func open(sqlitePath, postgres string) (*sql.DB, sqlstore.Dialect, error) {
	if postgres != "" {
		slog.Info("storage: PostgreSQL")
		db, err := sql.Open("pgx", postgres)
		return db, sqlstore.Postgres, err
	}
	if sqlitePath == "" {
		dir, err := os.MkdirTemp("", "ssfgo-conformance-")
		if err != nil {
			return nil, 0, err
		}
		sqlitePath = filepath.Join(dir, "ssf.db")
	}
	slog.Info("storage: SQLite", "path", sqlitePath)
	db, err := sql.Open("sqlite", "file:"+sqlitePath+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
	return db, sqlstore.SQLite, err
}
