package receiver

import (
	"context"
	"errors"
	"time"
)

// keepAliveUnknownInterval stands in for the keep-alive interval until
// the stream's timeout is known; a variable so tests can shorten it.
var keepAliveUnknownInterval = 10 * time.Second

// KeepAlive keeps a stream from reaching its inactivity_timeout
// (SSF 1.0 §8.1.1) until ctx is done, then returns ctx.Err().
//
// It reads the stream's configuration every half of the timeout the
// Transmitter advertises, and follows the timeout if it changes. That is a
// stream management request referencing the stream, which every
// Transmitter must count as Receiver activity. It returns nil once
// the stream has no inactivity_timeout (at once if it never had one), and
// an error matching ErrNotFound if the stream no longer exists. Other
// failures are logged and retried sooner.
//
// A stream that the Transmitter has already paused or disabled stays so:
// KeepAlive only prevents the timeout, it does not re-enable the stream.
// A stream that is polled continuously, as RunPoller does, does not need
// it.
func (r *Receiver) KeepAlive(ctx context.Context, streamID string) error {
	var interval time.Duration
	for {
		c, err := r.Stream(ctx, streamID)
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case err == nil:
			if c.InactivityTimeout <= 0 {
				return nil
			}
			// Half the timeout leaves room for a Transmitter that records
			// activity coarsely and for a failed attempt to be retried.
			interval = time.Duration(c.InactivityTimeout) * time.Second / 2
		case errors.Is(err, ErrNotFound):
			return err
		default:
			r.cfg.Logger.WarnContext(ctx, "ssf receiver: keep-alive failed", "stream_id", streamID, "error", err)
			if interval == 0 {
				// The timeout is not yet known.
				interval = keepAliveUnknownInterval
			}
		}
		wait := interval
		if err != nil {
			wait = min(interval/4, 30*time.Second)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}
