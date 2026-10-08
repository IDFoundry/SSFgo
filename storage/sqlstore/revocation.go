package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"sync/atomic"
	"time"

	"github.com/idfoundry/ssfgo/storage"
)

// RevocationStore implements storage.RevocationStore. Expired records are
// deleted as new ones are added.
type RevocationStore struct {
	db      *sql.DB
	d       Dialect
	inserts atomic.Uint64
}

var _ storage.RevocationStore = (*RevocationStore)(nil)

// NewRevocationStore returns a RevocationStore on db, whose schema CreateSchema has
// created or migrated. It fails if the database's schema version is not
// SchemaVersion, so a database left unmigrated is found at startup rather
// than at the first query that needs what changed.
func NewRevocationStore(ctx context.Context, db *sql.DB, d Dialect) (*RevocationStore, error) {
	if err := d.check(db); err != nil {
		return nil, err
	}
	if err := checkSchema(ctx, db); err != nil {
		return nil, err
	}
	return &RevocationStore{db: db, d: d}, nil
}

// Revoke implements storage.RevocationStore. One statement records a new
// revocation or, for a key already revoked, keeps the later of each time,
// so concurrent Revokes cannot lose the latest.
func (s *RevocationStore) Revoke(ctx context.Context, key storage.RevocationKey, at, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, s.d.rebind(`INSERT INTO ssf_revocations (kind, issuer, value, revoked_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (kind, issuer, value) DO UPDATE SET
			revoked_at = CASE WHEN excluded.revoked_at > ssf_revocations.revoked_at
				THEN excluded.revoked_at ELSE ssf_revocations.revoked_at END,
			expires_at = CASE WHEN excluded.expires_at > ssf_revocations.expires_at
				THEN excluded.expires_at ELSE ssf_revocations.expires_at END`),
		string(key.Kind), key.Issuer, key.Value, unixNano(at), unixNano(expires))
	if err != nil {
		return err
	}
	if s.inserts.Add(1)%pruneEvery == 0 {
		// Best effort: a record left behind only takes space.
		_, _ = s.db.ExecContext(ctx, s.d.rebind(`DELETE FROM ssf_revocations WHERE expires_at <= ?`), time.Now().UnixNano())
	}
	return nil
}

// RevokedAt implements storage.RevocationStore.
func (s *RevocationStore) RevokedAt(ctx context.Context, key storage.RevocationKey, now time.Time) (time.Time, bool, error) {
	var at int64
	err := s.db.QueryRowContext(ctx, s.d.rebind(`SELECT revoked_at FROM ssf_revocations
		WHERE kind = ? AND issuer = ? AND value = ? AND expires_at > ?`),
		string(key.Kind), key.Issuer, key.Value, unixNano(now)).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return time.Unix(0, at), true, nil
}

// unixNano is t.UnixNano clamped to the int64 range, which UnixNano
// leaves undefined beyond: an expiry after 2262 would otherwise wrap into
// the past, and the revocation would never be in force.
func unixNano(t time.Time) int64 {
	switch {
	case t.After(maxTime):
		return math.MaxInt64
	case t.Before(minTime):
		return math.MinInt64
	}
	return t.UnixNano()
}

var (
	maxTime = time.Unix(0, math.MaxInt64)
	minTime = time.Unix(0, math.MinInt64)
)
