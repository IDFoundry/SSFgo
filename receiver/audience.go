package receiver

import (
	"context"
	"errors"
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

// maxStreamLookups bounds the stream IDs remembered as not this
// Receiver's.
const maxStreamLookups = 1024

// streamLookupTimeout bounds one lookup of an unknown stream.
const streamLookupTimeout = 30 * time.Second

// streamAudiences holds what AudiencePerStream has learned: a stream ID
// maps to a lookup, which is done and found for a stream known to be this
// Receiver's.
type streamAudiences struct {
	mu      sync.Mutex
	lookups map[string]*streamLookup
}

type streamLookup struct {
	done  chan struct{}
	found bool
	err   error     // the lookup failed and may be tried again
	at    time.Time // when the lookup finished
}

// acceptStreamAudience reports whether, under AudiencePerStream, c's
// "aud" is "<Audience>/<stream_id>"; if so, the stream is remembered as
// this Receiver's.
func (r *Receiver) acceptStreamAudience(c ssf.StreamConfiguration) bool {
	if !r.cfg.AudiencePerStream || strings.Contains(c.StreamID, "/") ||
		!slices.Contains(c.Audience, r.cfg.Audience+"/"+c.StreamID) {
		return false
	}
	done := make(chan struct{})
	close(done)
	r.streamAud.mu.Lock()
	r.streamAud.lookups[c.StreamID] = &streamLookup{done: done, found: true}
	r.streamAud.mu.Unlock()
	return true
}

// forgetStreamAudience forgets a stream the Receiver deleted.
func (r *Receiver) forgetStreamAudience(streamID string) {
	r.streamAud.mu.Lock()
	delete(r.streamAud.lookups, streamID)
	r.streamAud.mu.Unlock()
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
	var unknown string
	for _, aud := range set.Audience {
		id, ok := r.streamIDOf(aud)
		if !ok {
			continue
		}
		if r.knownStream(id) {
			return nil
		}
		if unknown == "" {
			unknown = id
		}
	}
	if unknown != "" {
		found, err := r.lookUpStream(ctx, unknown)
		if err != nil {
			return err
		}
		if found {
			return nil
		}
	}
	return &rejectedSET{code: setcodec.CodeInvalidAudience, description: "aud names no stream of this Receiver"}
}

func (r *Receiver) knownStream(id string) bool {
	r.streamAud.mu.Lock()
	defer r.streamAud.mu.Unlock()
	l := r.streamAud.lookups[id]
	if l == nil {
		return false
	}
	select {
	case <-l.done:
		return l.found
	default:
		return false
	}
}

// lookUpStream asks the Transmitter whether id is a stream of this
// Receiver's with the audience "<Audience>/<id>". Concurrent callers
// share one lookup, and a stream not found is not asked about again for
// a minute, so SETs replayed from another Receiver cannot make this one
// hammer the Transmitter.
func (r *Receiver) lookUpStream(ctx context.Context, id string) (bool, error) {
	a := &r.streamAud
	a.mu.Lock()
	l := a.lookups[id]
	if l != nil {
		select {
		case <-l.done:
			if l.found || r.cfg.Now().Sub(l.at) < keyRefetchInterval {
				a.mu.Unlock()
				return l.found, nil
			}
			l = nil
		default:
		}
	}
	started := l == nil
	if started {
		if len(a.lookups) >= maxStreamLookups {
			a.pruneLocked()
		}
		l = &streamLookup{done: make(chan struct{})}
		a.lookups[id] = l
	}
	a.mu.Unlock()
	if started {
		r.runStreamLookup(context.WithoutCancel(ctx), id, l)
	}
	select {
	case <-l.done:
		return l.found, l.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// runStreamLookup runs l on its own context, so a caller that gives up
// neither cancels it nor leaves the stream marked as not found.
func (r *Receiver) runStreamLookup(ctx context.Context, id string, l *streamLookup) {
	ctx, cancel := context.WithTimeout(ctx, streamLookupTimeout)
	defer cancel()
	// Stream remembers the stream through acceptStreamAudience if it is
	// this Receiver's with that audience.
	_, err := r.Stream(ctx, id)
	found := err == nil && r.knownStreamAfterLookup(id, l)
	if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrIssuerMismatch) && !errors.Is(err, ErrAudienceMismatch) {
		l.err = err
	}
	a := &r.streamAud
	a.mu.Lock()
	l.found, l.at = found, r.cfg.Now()
	// Found, acceptStreamAudience has replaced the entry; not found, it
	// stays, so the stream is not asked about again for a while — unless
	// the lookup failed, when the next SET tries again.
	if l.err != nil && a.lookups[id] == l {
		delete(a.lookups, id)
	}
	a.mu.Unlock()
	close(l.done)
}

// knownStreamAfterLookup reports whether the lookup l found id: Stream
// replaced l with a found entry.
func (r *Receiver) knownStreamAfterLookup(id string, l *streamLookup) bool {
	r.streamAud.mu.Lock()
	defer r.streamAud.mu.Unlock()
	cur := r.streamAud.lookups[id]
	return cur != nil && cur != l && cur.found
}

// pruneLocked drops the finished lookups of streams not found, keeping
// the streams known to be this Receiver's.
func (a *streamAudiences) pruneLocked() {
	for id, l := range a.lookups {
		select {
		case <-l.done:
			if !l.found {
				delete(a.lookups, id)
			}
		default:
		}
	}
}
