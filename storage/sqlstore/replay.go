package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"time"

	"github.com/idfoundry/ssfgo/storage"
)

// ReplayStore implements storage.ReplayStore. Expired records are deleted
// as new ones are added. Its writes run at READ COMMITTED on PostgreSQL,
// so that concurrent claims on one SET wait for each other rather than
// fail with a serialization error on a database whose default isolation
// level is higher.
type ReplayStore struct {
	db      *sql.DB
	d       Dialect
	caps    storage.Capabilities
	now     func() time.Time
	inserts atomic.Uint64
}

var _ storage.ReplayStore = (*ReplayStore)(nil)

// errNoHolder refuses an empty holder, which would read as a SET handled.
var errNoHolder = errors.New("sqlstore: a replay claim needs a holder")

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

// pruneEvery is how many claims pass between deletions of expired records.
const pruneEvery = 1024

// ClaimSET implements storage.ReplayStore. A record with an empty holder
// is a SET handled; any other, a claim.
func (s *ReplayStore) ClaimSET(ctx context.Context, issuer, jti, holder string, leaseUntil time.Time) (storage.ClaimOutcome, error) {
	if holder == "" {
		return 0, errNoHolder
	}
	now := s.now().UnixNano()
	var outcome storage.ClaimOutcome
	err := s.d.readCommitted(ctx, s.db, func(q querier) error {
		// One statement, so the check and the claim are atomic: the
		// insert takes a new SET, and the conditional update takes an
		// expired record of one. A live record makes both no-ops.
		res, err := q.ExecContext(ctx, s.d.rebind(`INSERT INTO ssf_replay (issuer, jti, holder, expires_at) VALUES (?, ?, ?, ?)
			ON CONFLICT (issuer, jti) DO UPDATE SET holder = excluded.holder, expires_at = excluded.expires_at
			WHERE ssf_replay.expires_at <= ?`), issuer, jti, holder, leaseUntil.UnixNano(), now)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 1 {
			outcome = storage.ClaimAcquired
			return nil
		}
		// The live record that blocked the claim. If it has gone since —
		// its claim released — the SET is reported held, so it is
		// delivered and claimed again rather than taken as handled.
		var current string
		err = q.QueryRowContext(ctx, s.d.rebind(`SELECT holder FROM ssf_replay WHERE issuer = ? AND jti = ? AND expires_at > ?`),
			issuer, jti, now).Scan(&current)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			outcome = storage.ClaimHeld
		case err != nil:
			return err
		case current == "":
			outcome = storage.ClaimDone
		default:
			outcome = storage.ClaimHeld
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if s.inserts.Add(1)%pruneEvery == 0 {
		// Best effort: a record left behind only takes space.
		_, _ = s.db.ExecContext(ctx, s.d.rebind(`DELETE FROM ssf_replay WHERE expires_at <= ?`), now)
	}
	return outcome, nil
}

// RenewClaim implements storage.ReplayStore.
func (s *ReplayStore) RenewClaim(ctx context.Context, issuer, jti, holder string, leaseUntil time.Time) (bool, error) {
	if holder == "" {
		return false, errNoHolder
	}
	var held bool
	err := s.d.readCommitted(ctx, s.db, func(q querier) error {
		res, err := q.ExecContext(ctx, s.d.rebind(`UPDATE ssf_replay SET expires_at = ? WHERE issuer = ? AND jti = ? AND holder = ?`),
			leaseUntil.UnixNano(), issuer, jti, holder)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		held = n == 1
		return err
	})
	return held, err
}

// CompleteSET implements storage.ReplayStore.
func (s *ReplayStore) CompleteSET(ctx context.Context, issuer, jti string, until time.Time) error {
	return s.d.readCommitted(ctx, s.db, func(q querier) error {
		_, err := q.ExecContext(ctx, s.d.rebind(`INSERT INTO ssf_replay (issuer, jti, holder, expires_at) VALUES (?, ?, '', ?)
			ON CONFLICT (issuer, jti) DO UPDATE SET holder = '', expires_at = excluded.expires_at`), issuer, jti, until.UnixNano())
		return err
	})
}

// ReleaseClaim implements storage.ReplayStore.
func (s *ReplayStore) ReleaseClaim(ctx context.Context, issuer, jti, holder string) error {
	if holder == "" {
		return errNoHolder
	}
	return s.d.readCommitted(ctx, s.db, func(q querier) error {
		_, err := q.ExecContext(ctx, s.d.rebind(`DELETE FROM ssf_replay WHERE issuer = ? AND jti = ? AND holder = ?`), issuer, jti, holder)
		return err
	})
}
