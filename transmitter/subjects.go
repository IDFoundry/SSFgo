package transmitter

import (
	"encoding/json"
	"io"
	"net/http"

	ssf "github.com/idfoundry/ssfgo"
)

// readBody reads a JSON request body into v.
func readBody(w http.ResponseWriter, r *http.Request, v json.Unmarshaler) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	if err != nil {
		return badRequest("the request body could not be read: %v", err)
	}
	if err := v.UnmarshalJSON(body); err != nil {
		return badRequest("%v", err)
	}
	return nil
}

// addSubject implements SSF 1.0 §8.1.3.2. The "verified" flag is accepted
// but not acted on: SSFgo records every subject a Receiver adds.
func (t *Transmitter) addSubject(w http.ResponseWriter, r *http.Request, rx Receiver) {
	var req ssf.AddSubjectRequest
	if err := readBody(w, r, &req); err != nil {
		t.writeAPIError(w, r, "add subject", err)
		return
	}
	if _, err := t.ownedStream(r, req.StreamID, rx); err != nil {
		t.writeAPIError(w, r, "add subject", err)
		return
	}
	if err := t.cfg.Store.AddSubject(r.Context(), req.StreamID, req.Subject); err != nil {
		t.writeAPIError(w, r, "add subject", t.notFoundOr(err))
		return
	}
	w.WriteHeader(http.StatusOK)
}

// removeSubject implements SSF 1.0 §8.1.3.3.
func (t *Transmitter) removeSubject(w http.ResponseWriter, r *http.Request, rx Receiver) {
	var req ssf.RemoveSubjectRequest
	if err := readBody(w, r, &req); err != nil {
		t.writeAPIError(w, r, "remove subject", err)
		return
	}
	if _, err := t.ownedStream(r, req.StreamID, rx); err != nil {
		t.writeAPIError(w, r, "remove subject", err)
		return
	}
	if err := t.cfg.Store.RemoveSubject(r.Context(), req.StreamID, req.Subject); err != nil {
		t.writeAPIError(w, r, "remove subject", t.notFoundOr(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
