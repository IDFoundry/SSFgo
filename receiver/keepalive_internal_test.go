package receiver

import (
	"testing"
	"time"
)

// A Transmitter-supplied inactivity_timeout cannot overflow the interval
// or make KeepAlive spin.
func TestKeepAliveIntervalBounds(t *testing.T) {
	for _, c := range []struct {
		timeout int64
		want    time.Duration
	}{
		{1, keepAliveMinInterval},
		{2, keepAliveMinInterval},
		{600, 5 * time.Minute},
		{9223372037, keepAliveMaxInterval},  // overflows time.Duration
		{18446744074, keepAliveMaxInterval}, // wraps to a small positive one
		{1<<63 - 1, keepAliveMaxInterval},
	} {
		if got := keepAliveInterval(c.timeout); got != c.want {
			t.Errorf("keepAliveInterval(%d) = %v, want %v", c.timeout, got, c.want)
		}
	}
}
