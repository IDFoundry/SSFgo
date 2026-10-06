package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/idfoundry/ssfgo/storage"
)

// RevocationStore implements storage.RevocationStore in memory. Expired
// records are dropped as new ones are added.
type RevocationStore struct {
	mu      sync.Mutex
	revoked map[storage.RevocationKey]revocation
	inserts int
}

type revocation struct{ at, expires time.Time }

var _ storage.RevocationStore = (*RevocationStore)(nil)

// NewRevocationStore returns an empty RevocationStore.
func NewRevocationStore() *RevocationStore {
	return &RevocationStore{revoked: make(map[storage.RevocationKey]revocation)}
}

// Revoke implements storage.RevocationStore.
func (s *RevocationStore) Revoke(_ context.Context, key storage.RevocationKey, at, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.revoked[key]; ok {
		at, expires = latest(at, r.at), latest(expires, r.expires)
	}
	s.revoked[key] = revocation{at, expires}
	if s.inserts++; s.inserts%1024 == 0 {
		now := time.Now()
		for k, r := range s.revoked {
			if !now.Before(r.expires) {
				delete(s.revoked, k)
			}
		}
	}
	return nil
}

// RevokedAt implements storage.RevocationStore.
func (s *RevocationStore) RevokedAt(_ context.Context, key storage.RevocationKey, now time.Time) (time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.revoked[key]
	if !ok || !now.Before(r.expires) {
		return time.Time{}, false, nil
	}
	return r.at, true, nil
}

func latest(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
