package transmitter

import "sync"

// notifier wakes goroutines waiting for SETs: long-polling Receivers wait
// on their stream's key, the push loop on anyStream. It only shortens
// waits — every waiter also re-checks storage on a timer, so SETs queued
// by another process sharing the store are still delivered.
type notifier struct {
	mu      sync.Mutex
	waiting map[string]chan struct{}
}

const anyStream = ""

func newNotifier() *notifier {
	return &notifier{waiting: make(map[string]chan struct{})}
}

// wait returns a channel closed at the next notify for key.
func (n *notifier) wait(key string) <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	ch, ok := n.waiting[key]
	if !ok {
		ch = make(chan struct{})
		n.waiting[key] = ch
	}
	return ch
}

// notify wakes everything waiting on streamID and on anyStream.
func (n *notifier) notify(streamID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, key := range []string{streamID, anyStream} {
		if ch, ok := n.waiting[key]; ok {
			close(ch)
			delete(n.waiting, key)
		}
	}
}
