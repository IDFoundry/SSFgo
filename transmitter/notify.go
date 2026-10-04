package transmitter

import "sync"

// notifier wakes goroutines waiting for SETs: long-polling Receivers wait
// on their stream's key, the push loop on anyStream. It only shortens
// waits — every waiter also re-checks storage on a timer, so SETs queued
// by another process sharing the store are still delivered.
//
// An entry exists only while someone waits on its key, so streams that come
// and go — created, polled once, deleted — leave nothing behind.
type notifier struct {
	mu      sync.Mutex
	waiting map[string]*waiters
}

// waiters is the channel for one key and how many are waiting on it.
type waiters struct {
	ch chan struct{}
	n  int
}

const anyStream = ""

func newNotifier() *notifier {
	return &notifier{waiting: make(map[string]*waiters)}
}

// wait returns a channel closed at the next notify for key, and a done
// function to call once the caller stops waiting on it.
func (n *notifier) wait(key string) (<-chan struct{}, func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	w, ok := n.waiting[key]
	if !ok {
		w = &waiters{ch: make(chan struct{})}
		n.waiting[key] = w
	}
	w.n++
	return w.ch, func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		// After a notify, key may already have a new entry, which is not
		// this caller's to count down.
		if w.n--; w.n == 0 && n.waiting[key] == w {
			delete(n.waiting, key)
		}
	}
}

// notify wakes everything waiting on streamID and on anyStream.
func (n *notifier) notify(streamID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, key := range []string{streamID, anyStream} {
		if w, ok := n.waiting[key]; ok {
			close(w.ch)
			delete(n.waiting, key)
		}
	}
}
