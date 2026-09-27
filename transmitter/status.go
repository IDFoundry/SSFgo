package transmitter

import (
	"net/http"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
)

var errStatusLocked = &apiError{http.StatusForbidden, "status_locked", "the Transmitter has set this stream's status and it cannot be changed by the Receiver"}

func stateOf(s storage.Stream) ssf.StreamState {
	return ssf.StreamState{StreamID: s.ID, Status: s.Status, Reason: s.StatusReason}
}

// readStatus implements SSF 1.0 §8.1.2.1.
func (t *Transmitter) readStatus(w http.ResponseWriter, r *http.Request, rx Receiver) {
	id := r.URL.Query().Get("stream_id")
	if id == "" {
		t.writeAPIError(w, r, "read status", badRequest("the stream_id query parameter is required"))
		return
	}
	s, err := t.ownedStream(r, id, rx)
	if err != nil {
		t.writeAPIError(w, r, "read status", err)
		return
	}
	t.touch(r.Context(), s)
	writeJSON(w, http.StatusOK, stateOf(s))
}

// updateStatus implements SSF 1.0 §8.1.2.2. A change the Receiver asks for
// is not announced with a stream-updated event: §8.1.2 requires that only
// for changes the Transmitter makes on its own.
func (t *Transmitter) updateStatus(w http.ResponseWriter, r *http.Request, rx Receiver) {
	obj, err := readObject(w, r)
	if err != nil {
		t.writeAPIError(w, r, "update status", err)
		return
	}
	id, _, err := member[string](obj, "stream_id")
	if err == nil && id == "" {
		err = badRequest("stream_id is required")
	}
	if err != nil {
		t.writeAPIError(w, r, "update status", err)
		return
	}
	status, _, err := member[ssf.StreamStatus](obj, "status")
	if err == nil && !status.IsValid() {
		err = badRequest("status must be enabled, paused or disabled")
	}
	if err != nil {
		t.writeAPIError(w, r, "update status", err)
		return
	}
	reason, _, err := member[string](obj, "reason")
	if err != nil {
		t.writeAPIError(w, r, "update status", err)
		return
	}
	s, err := t.updateOwned(r, id, rx, func(s *storage.Stream) error {
		if s.StatusSetByTransmitter {
			return errStatusLocked
		}
		s.Status, s.StatusReason = status, reason
		return nil
	})
	if err != nil {
		t.writeAPIError(w, r, "update status", err)
		return
	}
	if status == ssf.StreamDisabled {
		// A disabled stream holds no events (SSF 1.0 §8.1.2.1).
		if err := t.cfg.Store.PurgeEvents(r.Context(), id); err != nil {
			t.writeAPIError(w, r, "update status", t.notFoundOr(err))
			return
		}
	}
	t.notify.notify(id)
	t.touch(r.Context(), s)
	writeJSON(w, http.StatusOK, stateOf(s))
}
