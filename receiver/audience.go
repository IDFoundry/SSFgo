package receiver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/setcodec"
)

// Config.AudiencePerStream accepts SETs addressed to "<Audience>/<id>",
// but only for an id the Transmitter confirms is a stream of this
// Receiver's with that audience. The form alone proves nothing: another
// Receiver whose own audience is "<Audience>/app" is indistinguishable
// from a stream "app".
//
// Every lookup's outcome is kept for a while, so SETs replayed from
// another Receiver cannot make this one call the Transmitter more than
// once per stream ID per streamNotFoundFor, nor while the Transmitter is
// failing, more than once per streamLookupFailedFor.

const (
	// maxStreamLookups bounds the stream IDs remembered. When it is
	// reached and no entry has expired, an unknown stream is not looked
	// up: its SET fails, to be delivered again.
	maxStreamLookups = 1024
	// streamLookupTimeout bounds one lookup.
	streamLookupTimeout = 30 * time.Second
	// streamFoundFor is how long a stream is known to be this
	// Receiver's before the Transmitter is asked again, so a stream
	// deleted elsewhere — by another instance, or by the Transmitter —
	// stops being accepted.
	streamFoundFor = time.Hour
	// streamNotFoundFor is how long a stream that is not this Receiver's
	// is not asked about again.
	streamNotFoundFor = time.Minute
	// streamLookupFailedFor is how long a failed lookup is not retried;
	// SETs naming the stream meanwhile fail, to be delivered again.
	streamLookupFailedFor = 10 * time.Second
)

// streamAudiences holds what AudiencePerStream has learned.
type streamAudiences struct {
	mu      sync.Mutex
	lookups map[string]*streamLookup
	// deletions counts the deletions of each stream ID, so a lookup that
	// started before one cannot record the stream as found after it.
	deletions map[string]uint64
}

// streamLookup is one stream's known state, or the lookup finding it.
type streamLookup struct {
	done  chan struct{} // closed once found, err and until are set
	found bool
	err   error     // the lookup failed
	until time.Time // when the outcome expires
}

func newStreamAudiences() streamAudiences {
	return streamAudiences{lookups: map[string]*streamLookup{}, deletions: map[string]uint64{}}
}

// perStreamAudience reports whether, under AudiencePerStream, c's "aud"
// is "<Audience>/<stream_id>".
func (r *Receiver) perStreamAudience(c ssf.StreamConfiguration) bool {
	return r.cfg.AudiencePerStream && !strings.Contains(c.StreamID, "/") &&
		slices.Contains(c.Audience, r.cfg.Audience+"/"+c.StreamID)
}

// rememberStream records the stream as this Receiver's, unless it has
// been deleted since deletions was deletionsBefore.
func (r *Receiver) rememberStream(id string, deletionsBefore uint64) {
	a := &r.streamAud
	done := make(chan struct{})
	close(done)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.deletions[id] != deletionsBefore {
		return
	}
	a.lookups[id] = &streamLookup{done: done, found: true, until: r.cfg.Now().Add(streamFoundFor)}
}

func (r *Receiver) deletionsOf(id string) uint64 {
	r.streamAud.mu.Lock()
	defer r.streamAud.mu.Unlock()
	return r.streamAud.deletions[id]
}

// forgetStreamAudience forgets a stream the Receiver deleted, and makes
// any lookup of it already under way discard what it finds.
func (r *Receiver) forgetStreamAudience(id string) {
	r.streamAud.mu.Lock()
	defer r.streamAud.mu.Unlock()
	delete(r.streamAud.lookups, id)
	r.streamAud.deletions[id]++
}

// streamIDOf returns the stream ID in an audience "<Audience>/<id>".
func (r *Receiver) streamIDOf(aud string) (string, bool) {
	id, ok := strings.CutPrefix(aud, r.cfg.Audience+"/")
	return id, ok && id != "" && !strings.Contains(id, "/")
}

// checkSETAudience applies AudiencePerStream to a SET Decode accepted:
// unless it is addressed to Audience itself, one of its audiences must
// name a stream of this Receiver's. It looks up at most one unknown
// stream per SET. A failed lookup returns an error that is not a
// rejection, so the Transmitter delivers the SET again.
func (r *Receiver) checkSETAudience(ctx context.Context, set ssf.SET) error {
	if !r.cfg.AudiencePerStream || slices.Contains(set.Audience, r.cfg.Audience) {
		return nil
	}
	for _, aud := range set.Audience {
		id, ok := r.streamIDOf(aud)
		if !ok {
			continue
		}
		found, err := r.lookUpStream(ctx, id)
		if err != nil {
			return err
		}
		if found {
			return nil
		}
		break // one lookup per SET
	}
	return &rejectedSET{code: setcodec.CodeInvalidAudience, description: "aud names no stream of this Receiver"}
}

// lookUpStream reports whether id is a stream of this Receiver's with the
// audience "<Audience>/<id>", asking the Transmitter unless an outcome
// that has not expired is known. Concurrent callers share one lookup;
// each waits for it no longer than its own context allows.
func (r *Receiver) lookUpStream(ctx context.Context, id string) (bool, error) {
	a := &r.streamAud
	now := r.cfg.Now()
	a.mu.Lock()
	l := a.lookups[id]
	if l != nil {
		select {
		case <-l.done:
			if now.Before(l.until) {
				a.mu.Unlock()
				return l.found, l.err
			}
			l = nil
		default: // under way
		}
	}
	if l == nil {
		if len(a.lookups) >= maxStreamLookups && !a.pruneLocked(now) {
			a.mu.Unlock()
			return false, errors.New("receiver: too many unknown streams to look up")
		}
		l = &streamLookup{done: make(chan struct{})}
		a.lookups[id] = l
		go r.runStreamLookup(context.WithoutCancel(ctx), id, l, a.deletions[id])
	}
	a.mu.Unlock()
	select {
	case <-l.done:
		return l.found, l.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// runStreamLookup asks the Transmitter for stream id on its own
// goroutine and context, so no caller giving up cancels it. A panic — in
// the TokenSource, say — fails the lookup like any other error.
func (r *Receiver) runStreamLookup(ctx context.Context, id string, l *streamLookup, deletionsBefore uint64) {
	found, err := false, error(nil)
	defer func() {
		if v := recover(); v != nil {
			r.cfg.Logger.ErrorContext(ctx, "ssf receiver: stream lookup panicked", "panic", v, "stack", string(debug.Stack()))
			found, err = false, fmt.Errorf("receiver: stream lookup panicked: %v", v)
		}
		r.finishStreamLookup(id, l, found, err, deletionsBefore)
	}()
	ctx, cancel := context.WithTimeout(ctx, streamLookupTimeout)
	defer cancel()
	found, err = r.readStreamAudience(ctx, id)
}

// readStreamAudience reads stream id from the Transmitter and reports
// whether it is this Receiver's with the audience "<Audience>/<id>". A
// stream the Transmitter does not have, refuses to show this Receiver,
// or that fails its checks, is not; any other failure is an error.
func (r *Receiver) readStreamAudience(ctx context.Context, id string) (bool, error) {
	var c ssf.StreamConfiguration
	err := r.call(ctx, http.MethodGet, withStreamID(r.metadata.ConfigurationEndpoint, id), nil, &c, http.StatusOK)
	var apiErr *APIError
	switch {
	case errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusForbidden):
		return false, nil
	case err != nil:
		return false, err
	}
	return c.StreamID == id && r.validateStream(c) == nil && r.perStreamAudience(c), nil
}

// finishStreamLookup records l's outcome and releases its waiters.
func (r *Receiver) finishStreamLookup(id string, l *streamLookup, found bool, err error, deletionsBefore uint64) {
	a := &r.streamAud
	now := r.cfg.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	deleted := a.deletions[id] != deletionsBefore
	switch {
	case deleted:
		found, err = false, nil
	case err != nil:
		l.until = now.Add(streamLookupFailedFor)
	case found:
		l.until = now.Add(streamFoundFor)
	default:
		l.until = now.Add(streamNotFoundFor)
	}
	l.found, l.err = found, err
	if deleted && a.lookups[id] == l {
		delete(a.lookups, id)
	}
	close(l.done)
}

// pruneLocked drops the finished outcomes that have expired, and reports
// whether there is now room for another.
func (a *streamAudiences) pruneLocked(now time.Time) bool {
	for id, l := range a.lookups {
		select {
		case <-l.done:
			if !now.Before(l.until) {
				delete(a.lookups, id)
			}
		default:
		}
	}
	return len(a.lookups) < maxStreamLookups
}
