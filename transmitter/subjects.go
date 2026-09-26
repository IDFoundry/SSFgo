package transmitter

import (
	"encoding/json"
	"io"
	"net/http"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
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

// addSubject implements SSF 1.0 §8.1.3.2 by recording an include rule.
// The "verified" flag is accepted but not acted on.
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
	rule := storage.SubjectRule{Subject: req.Subject, Included: true}
	if err := t.cfg.Store.SetSubjectRule(r.Context(), req.StreamID, rule); err != nil {
		t.writeAPIError(w, r, "add subject", t.notFoundOr(err))
		return
	}
	w.WriteHeader(http.StatusOK)
}

// removeSubject implements SSF 1.0 §8.1.3.3 by recording an exclude rule,
// which also overrides default_subjects "ALL" for that subject.
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
	rule := storage.SubjectRule{Subject: req.Subject, Included: false}
	if err := t.cfg.Store.SetSubjectRule(r.Context(), req.StreamID, rule); err != nil {
		t.writeAPIError(w, r, "remove subject", t.notFoundOr(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
