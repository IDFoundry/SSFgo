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

// StreamStore implements storage.StreamStore.
type StreamStore struct {
	mu       sync.Mutex
	streams  map[string]*entry
	sequence int
}

type entry struct {
	stream storage.Stream
	order  int
	rules  []storage.SubjectRule
	queue  []storage.QueuedEvent
}

var _ storage.StreamStore = (*StreamStore)(nil)

// NewStreamStore returns an empty StreamStore.
func NewStreamStore() *StreamStore {
	return &StreamStore{streams: make(map[string]*entry)}
}

func clone(s storage.Stream) storage.Stream {
	s.Audience = slices.Clone(s.Audience)
	s.EventsRequested = slices.Clone(s.EventsRequested)
	s.EventsDelivered = slices.Clone(s.EventsDelivered)
	return s
}

// CreateStream implements storage.StreamStore.
func (m *StreamStore) CreateStream(_ context.Context, s storage.Stream, opts storage.CreateOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.streams[s.ID]; ok {
		return storage.ErrExists
	}
	if opts.MaxStreamsPerReceiver > 0 {
		owned := 0
		for _, e := range m.streams {
			if e.stream.ReceiverID == s.ReceiverID {
				owned++
			}
		}
		if owned >= opts.MaxStreamsPerReceiver {
			return storage.ErrTooManyStreams
		}
	}
	m.sequence++
	m.streams[s.ID] = &entry{stream: clone(s), order: m.sequence}
	return nil
}

// Stream implements storage.StreamStore.
func (m *StreamStore) Stream(_ context.Context, id string) (storage.Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.streams[id]
	if !ok {
		return storage.Stream{}, storage.ErrNotFound
	}
	return clone(e.stream), nil
}

// StreamsForReceiver implements storage.StreamStore.
func (m *StreamStore) StreamsForReceiver(_ context.Context, receiverID string) ([]storage.Stream, error) {
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

// AllStreams implements storage.StreamStore.
func (m *StreamStore) AllStreams(_ context.Context) ([]storage.Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := make([]*entry, 0, len(m.streams))
	for _, e := range m.streams {
		all = append(all, e)
	}
	slices.SortFunc(all, func(a, b *entry) int { return a.order - b.order })
	out := make([]storage.Stream, 0, len(all))
	for _, e := range all {
		out = append(out, clone(e.stream))
	}
	return out, nil
}

// UpdateStream implements storage.StreamStore.
func (m *StreamStore) UpdateStream(_ context.Context, id string, update func(*storage.Stream) error) (storage.Stream, error) {
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
func (m *StreamStore) DeleteStream(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.streams[id]; !ok {
		return storage.ErrNotFound
	}
	delete(m.streams, id)
	return nil
}

// SetSubjectRule implements storage.StreamStore.
func (m *StreamStore) SetSubjectRule(_ context.Context, streamID string, rule storage.SubjectRule, maxRules int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.streams[streamID]
	if !ok {
		return storage.ErrNotFound
	}
	for i, have := range e.rules {
		if ssf.SubjectsEqual(have.Subject, rule.Subject) {
			e.rules = append(slices.Delete(e.rules, i, i+1), rule)
			return nil
		}
	}
	if maxRules > 0 && len(e.rules) >= maxRules {
		return storage.ErrTooManySubjectRules
	}
	e.rules = append(e.rules, rule)
	return nil
}

// SubjectRules implements storage.StreamStore.
func (m *StreamStore) SubjectRules(_ context.Context, streamID string) ([]storage.SubjectRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.streams[streamID]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return slices.Clone(e.rules), nil
}

// Enqueue implements storage.StreamStore.
func (m *StreamStore) Enqueue(_ context.Context, streamID string, q storage.QueuedEvent, maxQueued int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.streams[streamID]
	if !ok {
		return storage.ErrNotFound
	}
	if maxQueued > 0 && len(e.queue) >= maxQueued {
		return storage.ErrQueueFull
	}
	e.queue = append(e.queue, q)
	return nil
}

// PendingEvents implements storage.StreamStore.
func (m *StreamStore) PendingEvents(_ context.Context, streamID string, limit int, controlOnly bool) ([]storage.QueuedEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.streams[streamID]
	if !ok {
		return nil, storage.ErrNotFound
	}
	var out []storage.QueuedEvent
	for _, q := range e.queue {
		if limit > 0 && len(out) == limit {
			break
		}
		if !controlOnly || q.Control {
			out = append(out, q)
		}
	}
	return out, nil
}

// AckEvents implements storage.StreamStore.
func (m *StreamStore) AckEvents(_ context.Context, streamID string, jtis []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.streams[streamID]
	if !ok {
		return storage.ErrNotFound
	}
	acked := make(map[string]bool, len(jtis))
	for _, j := range jtis {
		acked[j] = true
	}
	e.queue = slices.DeleteFunc(e.queue, func(q storage.QueuedEvent) bool { return acked[q.JTI] })
	return nil
}

// PurgeEvents implements storage.StreamStore.
func (m *StreamStore) PurgeEvents(_ context.Context, streamID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.streams[streamID]
	if !ok {
		return storage.ErrNotFound
	}
	e.queue = nil
	return nil
}
