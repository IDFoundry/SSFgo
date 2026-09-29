package txharness

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/caep/interop"
	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/transmitter"
)

// emitAfterVerification stands in for the operator the OIDF CAEP Interop
// test expects to "trigger these events on the transmitter" once stream
// verification succeeds. After each successful verification request it
// waits delay — so the events queue behind the verification SET — then
// emits every CAEP Interop event type the stream delivers.
func emitAfterVerification(tx *transmitter.Transmitter, store storage.StreamStore, issuer string, delay time.Duration, next http.Handler) http.Handler {
	verificationPath := pathOf(tx.Metadata().VerificationEndpoint)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != verificationPath {
			next.ServeHTTP(w, r)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		r.Body = io.NopCloser(bytes.NewReader(body))
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if rec.status != http.StatusNoContent {
			return
		}
		var req ssf.VerificationRequest
		if json.Unmarshal(body, &req) != nil {
			return
		}
		time.AfterFunc(delay, func() { emitInteropEvents(tx, store, issuer, req.StreamID) })
	})
}

func emitInteropEvents(tx *transmitter.Transmitter, store storage.StreamStore, issuer, streamID string) {
	ctx := context.Background()
	s, err := store.Stream(ctx, streamID)
	if err != nil {
		return
	}
	reason := caep.Common{
		EventTimestamp:   ssf.NewNumericDate(time.Now()),
		InitiatingEntity: caep.InitiatedByAdmin,
		ReasonAdmin:      ssf.LocalizedText{"en": "SSFgo conformance harness"},
	}
	// Both subject formats the profile allows (§2.5) are demonstrated.
	user := ssf.IssSubSubject{Issuer: issuer, Subject: "conformance-user"}
	email := ssf.EmailSubject{Email: "conformance-user@example.com"}
	events := map[ssf.EventType]struct {
		subject ssf.Subject
		event   ssf.Event
	}{
		caep.SessionRevokedEventType: {user, caep.SessionRevoked{Common: reason}},
		caep.CredentialChangeEventType: {email, caep.CredentialChange{
			Common: reason, CredentialType: caep.CredentialPassword, ChangeType: caep.ChangeUpdate,
		}},
		caep.DeviceComplianceChangeEventType: {user, caep.DeviceComplianceChange{
			Common: reason, PreviousStatus: caep.Compliant, CurrentStatus: caep.NotCompliant,
		}},
	}
	for _, typ := range interop.EventTypes() {
		if !slices.Contains(s.EventsDelivered, typ) {
			continue
		}
		e := events[typ]
		if err := tx.Emit(ctx, e.subject, e.event); err != nil {
			slog.Error("emit interop event", "type", typ, "error", err)
		}
	}
}

func pathOf(endpoint string) string {
	if i := strings.Index(endpoint, "://"); i >= 0 {
		if j := strings.IndexByte(endpoint[i+3:], '/'); j >= 0 {
			return endpoint[i+3+j:]
		}
	}
	return "/"
}
