package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/idfoundry/ssfgo/storage"
)

// ReplayStore implements storage.ReplayStore in memory. Expired records
// are dropped as new ones are added.
type ReplayStore struct {
	mu      sync.Mutex
	seen    map[replayKey]time.Time
	now     func() time.Time
	inserts int
}

type replayKey struct{ issuer, jti string }

var _ storage.ReplayStore = (*ReplayStore)(nil)

// NewReplayStore returns an empty ReplayStore.
func NewReplayStore() *ReplayStore {
	return &ReplayStore{seen: make(map[replayKey]time.Time), now: time.Now}
}

// MarkSET implements storage.ReplayStore.
func (s *ReplayStore) MarkSET(_ context.Context, issuer, jti string, until time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	k := replayKey{issuer, jti}
	if exp, ok := s.seen[k]; ok && now.Before(exp) {
		return false, nil
	}
	s.seen[k] = until
	if s.inserts++; s.inserts%1024 == 0 {
		for key, exp := range s.seen {
			if !now.Before(exp) {
				delete(s.seen, key)
			}
		}
	}
	return true, nil
}

// ForgetSET implements storage.ReplayStore.
func (s *ReplayStore) ForgetSET(_ context.Context, issuer, jti string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.seen, replayKey{issuer, jti})
	return nil
}
