package memstore

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/idfoundry/ssfgo/storage"
)

// ReplayStore implements storage.ReplayStore in memory. Expired records
// are dropped as new ones are added.
type ReplayStore struct {
	mu      sync.Mutex
	seen    map[replayKey]replayRecord
	now     func() time.Time
	inserts int
}

type replayKey struct{ issuer, jti string }

// replayRecord is a claim, held by holder, or — with no holder — a SET
// handled. Either lasts until expires.
type replayRecord struct {
	holder  string
	expires time.Time
}

var _ storage.ReplayStore = (*ReplayStore)(nil)

// errNoHolder refuses an empty holder, which would read as a SET handled.
var errNoHolder = errors.New("memstore: a replay claim needs a holder")

// NewReplayStore returns an empty ReplayStore.
func NewReplayStore() *ReplayStore {
	return &ReplayStore{seen: make(map[replayKey]replayRecord), now: time.Now}
}

// ClaimSET implements storage.ReplayStore.
func (s *ReplayStore) ClaimSET(_ context.Context, issuer, jti, holder string, leaseUntil time.Time) (storage.ClaimOutcome, error) {
	if holder == "" {
		return 0, errNoHolder
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	k := replayKey{issuer, jti}
	if r, ok := s.seen[k]; ok && now.Before(r.expires) {
		if r.holder == "" {
			return storage.ClaimDone, nil
		}
		return storage.ClaimHeld, nil
	}
	s.seen[k] = replayRecord{holder: holder, expires: leaseUntil}
	if s.inserts++; s.inserts%1024 == 0 {
		for key, r := range s.seen {
			if !now.Before(r.expires) {
				delete(s.seen, key)
			}
		}
	}
	return storage.ClaimAcquired, nil
}

// RenewClaim implements storage.ReplayStore.
func (s *ReplayStore) RenewClaim(_ context.Context, issuer, jti, holder string, leaseUntil time.Time) (bool, error) {
	if holder == "" {
		return false, errNoHolder
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := replayKey{issuer, jti}
	if r, ok := s.seen[k]; !ok || r.holder != holder {
		return false, nil
	}
	s.seen[k] = replayRecord{holder: holder, expires: leaseUntil}
	return true, nil
}

// CompleteSET implements storage.ReplayStore.
func (s *ReplayStore) CompleteSET(_ context.Context, issuer, jti string, until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[replayKey{issuer, jti}] = replayRecord{expires: until}
	return nil
}

// ReleaseClaim implements storage.ReplayStore.
func (s *ReplayStore) ReleaseClaim(_ context.Context, issuer, jti, holder string) error {
	if holder == "" {
		return errNoHolder
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := replayKey{issuer, jti}
	if r, ok := s.seen[k]; ok && r.holder == holder {
		delete(s.seen, k)
	}
	return nil
}
