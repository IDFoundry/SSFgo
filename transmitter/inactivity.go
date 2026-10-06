package transmitter

import (
	"context"
	"errors"
	"fmt"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
)

// inactivityCheckInterval is how often Run looks for inactive streams.
const inactivityCheckInterval = 30 * time.Second

// touch records eligible Receiver activity on s, restarting its
// inactivity timeout (SSF 1.0 §8.1.1). To keep a busy poll stream from
// writing to storage on every request, it writes at most once per tenth
// of the timeout.
func (t *Transmitter) touch(ctx context.Context, s storage.Stream) {
	timeout := t.cfg.Inactivity.Timeout
	if timeout == 0 {
		return
	}
	now := t.now()
	if now.Sub(lastActivity(s)) < timeout/10 {
		return
	}
	_, err := t.cfg.Store.UpdateStream(ctx, s.ID, func(s *storage.Stream) error {
		s.LastActivity = now
		return nil
	})
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		t.log.WarnContext(ctx, "ssf transmitter: record stream activity", "stream_id", s.ID, "error", err)
	}
}

func lastActivity(s storage.Stream) time.Time {
	if s.LastActivity.After(s.CreatedAt) {
		return s.LastActivity
	}
	return s.CreatedAt
}

// ExpireInactiveStreams applies Config.Inactivity to every stream whose
// Receiver has been inactive for longer than the timeout. Run calls it
// periodically; call it directly if Run is not in use. A stream already
// in the state the action would put it in is left alone.
func (t *Transmitter) ExpireInactiveStreams(ctx context.Context) error {
	policy := t.cfg.Inactivity
	if policy.Timeout == 0 {
		return nil
	}
	streams, err := t.cfg.Store.AllStreams(ctx)
	if err != nil {
		return fmt.Errorf("transmitter: expire inactive streams: %w", err)
	}
	now := t.now()
	var errs []error
	for _, s := range streams {
		if now.Sub(lastActivity(s)) <= policy.Timeout {
			continue
		}
		const reason = "inactivity timeout"
		switch policy.Action {
		case InactivityDelete:
			if err = t.cfg.Store.DeleteStream(ctx, s.ID); err == nil {
				t.streamChanged(ctx, s, StreamDeleted, true)
			}
		case InactivityDisable:
			if s.Status != ssf.StreamDisabled {
				err = t.setStatus(ctx, s.ID, ssf.StreamDisabled, reason, false)
			}
		case InactivityPause:
			if s.Status == ssf.StreamEnabled {
				err = t.setStatus(ctx, s.ID, ssf.StreamPaused, reason, false)
			}
		}
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			errs = append(errs, fmt.Errorf("stream %s: %w", s.ID, err))
		}
		err = nil
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("transmitter: expire inactive streams: %w", err)
	}
	return nil
}
