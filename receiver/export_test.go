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
