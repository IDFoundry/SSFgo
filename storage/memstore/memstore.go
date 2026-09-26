// Package memstore is an in-memory implementation of SSFgo's storage
// contracts, for tests, examples and conformance runs. Its state is lost
// when the process exits.
package memstore

import (
	"context"
	"slices"
	"sync"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
)

// Store implements storage.StreamStore.
type Store struct {
	mu       sync.Mutex
	streams  map[string]*entry
	sequence int
}

type entry struct {
	stream   storage.Stream
	order    int
	subjects []ssf.Subject
	queue    []storage.QueuedEvent
}

var _ storage.StreamStore = (*Store)(nil)

// New returns an empty Store.
func New() *Store {
	return &Store{streams: make(map[string]*entry)}
}

func clone(s storage.Stream) storage.Stream {
	s.Audience = slices.Clone(s.Audience)
	s.EventsRequested = slices.Clone(s.EventsRequested)
	s.EventsDelivered = slices.Clone(s.EventsDelivered)
	return s
}

// CreateStream implements storage.StreamStore.
func (m *Store) CreateStream(_ context.Context, s storage.Stream, opts storage.CreateOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.streams[s.ID]; ok {
		return storage.ErrExists
	}
	if opts.SingleStreamPerReceiver {
		for _, e := range m.streams {
			if e.stream.ReceiverID == s.ReceiverID {
				return storage.ErrReceiverHasStream
			}
		}
	}
	m.sequence++
	m.streams[s.ID] = &entry{stream: clone(s), order: m.sequence}
	return nil
}

// Stream implements storage.StreamStore.
func (m *Store) Stream(_ context.Context, id string) (storage.Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.streams[id]
	if !ok {
		return storage.Stream{}, storage.ErrNotFound
	}
	return clone(e.stream), nil
}

// StreamsForReceiver implements storage.StreamStore.
func (m *Store) StreamsForReceiver(_ context.Context, receiverID string) ([]storage.Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var owned []*entry
	for _, e := range m.streams {
		if e.stream.ReceiverID == receiverID {
			owned = append(owned, e)
		}
	}
	slices.SortFunc(owned, func(a, b *entry) int { return a.order - b.order })
	out := make([]storage.Stream, 0, len(owned))
	for _, e := range owned {
		out = append(out, clone(e.stream))
	}
	return out, nil
}

// UpdateStream implements storage.StreamStore.
func (m *Store) UpdateStream(_ context.Context, id string, update func(*storage.Stream) error) (storage.Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.streams[id]
	if !ok {
		return storage.Stream{}, storage.ErrNotFound
	}
	s := clone(e.stream)
	if err := update(&s); err != nil {
		return storage.Stream{}, err
	}
	s.ID = id
	e.stream = clone(s)
	return s, nil
}

// DeleteStream implements storage.StreamStore.
func (m *Store) DeleteStream(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.streams[id]; !ok {
		return storage.ErrNotFound
	}
	delete(m.streams, id)
	return nil
}

// AddSubject implements storage.StreamStore.
func (m *Store) AddSubject(_ context.Context, streamID string, s ssf.Subject) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.streams[streamID]
	if !ok {
		return storage.ErrNotFound
	}
	for _, have := range e.subjects {
		if ssf.SubjectsEqual(have, s) {
			return nil
		}
	}
	e.subjects = append(e.subjects, s)
	return nil
}

// RemoveSubject implements storage.StreamStore.
func (m *Store) RemoveSubject(_ context.Context, streamID string, s ssf.Subject) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.streams[streamID]
	if !ok {
		return storage.ErrNotFound
	}
	e.subjects = slices.DeleteFunc(e.subjects, func(have ssf.Subject) bool { return ssf.SubjectsEqual(have, s) })
	return nil
}

// Subjects implements storage.StreamStore.
func (m *Store) Subjects(_ context.Context, streamID string) ([]ssf.Subject, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.streams[streamID]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return slices.Clone(e.subjects), nil
}

// Enqueue implements storage.StreamStore.
func (m *Store) Enqueue(_ context.Context, streamID string, q storage.QueuedEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.streams[streamID]
	if !ok {
		return storage.ErrNotFound
	}
	e.queue = append(e.queue, q)
	return nil
}

// PendingEvents implements storage.StreamStore.
func (m *Store) PendingEvents(_ context.Context, streamID string, max int) ([]storage.QueuedEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.streams[streamID]
	if !ok {
		return nil, storage.ErrNotFound
	}
	n := len(e.queue)
	if max > 0 && max < n {
		n = max
	}
	return slices.Clone(e.queue[:n]), nil
}
