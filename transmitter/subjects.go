package transmitter

import (
	"encoding/json"
	"errors"
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
	const op = "add subject"
	var req ssf.AddSubjectRequest
	if err := readBody(w, r, &req); err != nil {
		t.writeAPIError(w, r, op, err)
		return
	}
	s, err := t.ownedStream(r, req.StreamID, rx)
	if err != nil {
		t.writeAPIError(w, r, op, err)
		return
	}
	t.touch(r.Context(), s)
	if err := checkRuleSubject(req.Subject, true); err != nil {
		t.writeAPIError(w, r, op, err)
		return
	}
	rule := storage.SubjectRule{Subject: req.Subject, Included: true}
	if err := t.cfg.Store.SetSubjectRule(r.Context(), req.StreamID, rule, t.cfg.Limits.SubjectRulesPerStream); err != nil {
		t.writeAPIError(w, r, op, t.subjectError(err))
		return
	}
	w.WriteHeader(http.StatusOK)
}

// removeSubject implements SSF 1.0 §8.1.3.3 by recording an exclude rule,
// which also overrides default_subjects "ALL" for that subject.
func (t *Transmitter) removeSubject(w http.ResponseWriter, r *http.Request, rx Receiver) {
	const op = "remove subject"
	var req ssf.RemoveSubjectRequest
	if err := readBody(w, r, &req); err != nil {
		t.writeAPIError(w, r, op, err)
		return
	}
	s, err := t.ownedStream(r, req.StreamID, rx)
	if err != nil {
		t.writeAPIError(w, r, op, err)
		return
	}
	t.touch(r.Context(), s)
	if err := checkRuleSubject(req.Subject, false); err != nil {
		t.writeAPIError(w, r, op, err)
		return
	}
	rule := storage.SubjectRule{Subject: req.Subject, Included: false}
	if err := t.cfg.Store.SetSubjectRule(r.Context(), req.StreamID, rule, t.cfg.Limits.SubjectRulesPerStream); err != nil {
		t.writeAPIError(w, r, op, t.subjectError(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// maxRuleSubjectBytes bounds one subject rule's encoded size. Every Emit
// matches every rule of every stream, so a few rules of the request size
// limit — an aliases subject with thousands of identifiers, say — would
// slow event delivery for every Receiver.
const maxRuleSubjectBytes = 2048

// checkRuleSubject refuses a subject a Receiver may not add or remove: one
// larger than maxRuleSubjectBytes, or, to include, a complex subject with
// none of the SSF 1.0 §3.3 members. Members a Transmitter never emits act
// as wildcards in matching (§8.1.3.1), so such a rule would match every
// complex subject. PermitEvent remains what decides what a Receiver may
// see.
func checkRuleSubject(subject ssf.Subject, include bool) error {
	encoded, err := json.Marshal(subject)
	if err != nil {
		return badRequest("the subject could not be encoded: %v", err)
	}
	if len(encoded) > maxRuleSubjectBytes {
		return badRequest("the subject is %d bytes; at most %d are accepted", len(encoded), maxRuleSubjectBytes)
	}
	if c, ok := subject.(ssf.ComplexSubject); ok && include &&
		c.User == nil && c.Device == nil && c.Session == nil && c.Application == nil &&
		c.Tenant == nil && c.OrgUnit == nil && c.Group == nil {
		return badRequest("a complex subject must have at least one of the members user, device, session, application, tenant, org_unit or group")
	}
	return nil
}

var errTooManySubjects = &apiError{http.StatusForbidden, "subject_limit", "this stream has the maximum number of subject rules"}

func (t *Transmitter) subjectError(err error) error {
	if errors.Is(err, storage.ErrTooManySubjectRules) {
		return errTooManySubjects
	}
	return t.notFoundOr(err)
}
