package receiver

import (
	"testing"
	"time"
)

// SetKeepAliveUnknownInterval shortens KeepAlive's interval before a
// stream's timeout is known, for the rest of the test.
func SetKeepAliveUnknownInterval(t *testing.T, d time.Duration) {
	old := keepAliveUnknownInterval
	keepAliveUnknownInterval = d
	t.Cleanup(func() { keepAliveUnknownInterval = old })
}

// SetEnsureRetry shortens EnsureStream's backoff for the rest of the test.
func SetEnsureRetry(t *testing.T, d time.Duration) {
	oldMin, oldMax := ensureRetryMin, ensureRetryMax
	ensureRetryMin, ensureRetryMax = d, d
	t.Cleanup(func() { ensureRetryMin, ensureRetryMax = oldMin, oldMax })
}
