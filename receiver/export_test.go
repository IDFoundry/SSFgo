package receiver

import (
	"context"
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

// ProcessPolled handles sets as if a poll on streamID had returned them,
// and returns the acknowledgements and error codes the next poll would
// send.
func ProcessPolled(r *Receiver, streamID string, sets map[string]string) (ack []string, errs map[string]string) {
	r.handlePolled(context.Background(), streamID, sets, len(sets))
	p := r.takeAcks(streamID)
	errs = map[string]string{}
	for jti, e := range p.errs {
		errs[jti] = e.Err
	}
	return p.ack, errs
}

// SetClaimLease shortens how long a claim on a SET lasts unrenewed, for
// the rest of the test.
func SetClaimLease(t *testing.T, d time.Duration) {
	old := claimLease
	claimLease = d
	t.Cleanup(func() { claimLease = old })
}
