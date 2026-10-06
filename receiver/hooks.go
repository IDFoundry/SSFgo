package receiver

import (
	"context"
	"errors"
	"fmt"
	"time"

	ssf "github.com/idfoundry/ssfgo"
)

// Hooks are callbacks that observe a Receiver, to feed metrics or traces.
// Each is optional. They run synchronously on the Receiver's goroutines —
// a push request's, a poller's — so they should return quickly.
type Hooks struct {
	// SET is called once for every SET pushed or polled, with its outcome.
	SET func(ctx context.Context, info SETInfo)
	// Poll is called after every poll request, successful or not.
	Poll func(ctx context.Context, info PollInfo)
	// KeysRefreshed is called after every refetch of the Transmitter's
	// JWKS, with nil or the reason it failed.
	KeysRefreshed func(ctx context.Context, err error)
}

// SETOutcome is what became of a SET.
type SETOutcome int

const (
	// SETHandled: verified and handled, and acknowledged.
	SETHandled SETOutcome = iota + 1
	// SETDuplicate: a redelivery of a SET already handled, acknowledged
	// again without handling it twice.
	SETDuplicate
	// SETRejected: refused with an RFC 8935 error code, never handled.
	SETRejected
	// SETFailed: verified, but its handling failed or could not be
	// recorded; the Transmitter will deliver it again.
	SETFailed
)

// String returns the outcome's name, such as "handled".
func (o SETOutcome) String() string {
	switch o {
	case SETHandled:
		return "handled"
	case SETDuplicate:
		return "duplicate"
	case SETRejected:
		return "rejected"
	case SETFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// SETInfo describes one SET the Receiver processed.
type SETInfo struct {
	// Delivery is how the SET arrived: ssf.DeliveryPush or
	// ssf.DeliveryPoll.
	Delivery ssf.DeliveryMethod
	// JTI and EventType are empty for a SET that could not be decoded.
	JTI       string
	EventType ssf.EventType
	Outcome   SETOutcome
	// ErrorCode is the RFC 8935 error code of a rejected SET.
	ErrorCode string
	// Err is why a SET was rejected or failed.
	Err error
	// Duration is how long verifying and handling took.
	Duration time.Duration
}

// PollInfo describes one poll request.
type PollInfo struct {
	StreamID string
	// Received is how many SETs the Transmitter returned.
	Received int
	// Duration includes any time the Transmitter held the request.
	Duration time.Duration
	// Err is why the request failed.
	Err error
}

// Ready reports whether the Receiver can verify SETs: it holds signing keys
// from the Transmitter, fetched within KeyMaxAge. Keys older than that are
// refetched first, as receiving a SET would refetch them. For a readiness
// probe.
func (r *Receiver) Ready(ctx context.Context) error {
	if _, fetched := r.currentKeys(); r.cfg.Now().Sub(fetched) > r.cfg.KeyMaxAge {
		r.maybeRefreshKeys(ctx)
	}
	keys, fetched := r.currentKeys()
	if len(keys) == 0 {
		return errors.New("receiver: no usable signing keys from the Transmitter")
	}
	if age := r.cfg.Now().Sub(fetched); age > r.cfg.KeyMaxAge {
		return fmt.Errorf("receiver: the Transmitter's signing keys are %v old, and refetching them fails", age.Round(time.Second))
	}
	return nil
}
