package sqlstore

import (
	"context"
	"database/sql"
	"sync/atomic"
	"time"

	"github.com/idfoundry/ssfgo/storage"
)

// ReplayStore implements storage.ReplayStore. Expired records are deleted
// as new ones are added.
type ReplayStore struct {
	db      *sql.DB
	d       Dialect
	caps    storage.Capabilities
	now     func() time.Time
	inserts atomic.Uint64
}

var _ storage.ReplayStore = (*ReplayStore)(nil)

// NewReplayStore returns a ReplayStore on db, whose schema CreateSchema has
// created or migrated. It fails if the database's schema version is not
// SchemaVersion, so a database left unmigrated is found at startup rather
// than at the first query that needs what changed.
func NewReplayStore(ctx context.Context, db *sql.DB, d Dialect) (*ReplayStore, error) {
	caps, err := d.open(ctx, db)
	if err != nil {
		return nil, err
	}
	return &ReplayStore{db: db, d: d, caps: caps, now: time.Now}, nil
}

// pruneEvery is how many marks pass between deletions of expired records.
const pruneEvery = 1024

// MarkSET implements storage.ReplayStore.
func (s *ReplayStore) MarkSET(ctx context.Context, issuer, jti string, until time.Time) (bool, error) {
	now := s.now().UnixNano()
	// One statement, so the check and the record are atomic: the insert
	// takes a new SET, and the conditional update takes an expired record
	// of one. A live record makes both no-ops.
	res, err := s.db.ExecContext(ctx, s.d.rebind(`INSERT INTO ssf_replay (issuer, jti, expires_at) VALUES (?, ?, ?)
		ON CONFLICT (issuer, jti) DO UPDATE SET expires_at = excluded.expires_at
		WHERE ssf_replay.expires_at <= ?`), issuer, jti, until.UnixNano(), now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if s.inserts.Add(1)%pruneEvery == 0 {
		// Best effort: a record left behind only takes space.
		_, _ = s.db.ExecContext(ctx, s.d.rebind(`DELETE FROM ssf_replay WHERE expires_at <= ?`), now)
	}
	return n == 1, nil
}

// ForgetSET implements storage.ReplayStore.
func (s *ReplayStore) ForgetSET(ctx context.Context, issuer, jti string) error {
	_, err := s.db.ExecContext(ctx, s.d.rebind(`DELETE FROM ssf_replay WHERE issuer = ? AND jti = ?`), issuer, jti)
	return err
}
