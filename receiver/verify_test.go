package receiver_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

func TestVerifyNeitherHandlesNorRecords(t *testing.T) {
	replay := memstore.NewReplayStore()
	e := newEnv(t, func(c *receiver.Config) { c.ReplayStore = replay })
	var calls atomic.Int32
	receiver.On(e.rx, func(context.Context, ssf.SET, caep.SessionRevoked) error {
		calls.Add(1)
		return nil
	})
	token := sign(t, e, func(s *ssf.SET) { s.JWTID = "inspected" })

	set, err := e.rx.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if set.JWTID != "inspected" || set.Event.EventType() != caep.SessionRevokedEventType {
		t.Errorf("Verify = %s %s, want the SET", set.JWTID, set.Event.EventType())
	}
	if calls.Load() != 0 {
		t.Errorf("Verify ran a handler")
	}
	// Nothing was recorded, so delivery still handles it.
	if got := push(t, e.rx.PushHandler(receiver.PushOptions{}), "", token); got.status != 202 || calls.Load() != 1 {
		t.Errorf("delivered after Verify: %d after %d handler calls, want 202 after 1", got.status, calls.Load())
	}
}

// Verify's rejection carries the error code delivery would report and a
// description safe to show, so a caller need not parse Error().
func TestVerifyRejectsWhatDeliveryRejects(t *testing.T) {
	e := newEnv(t)
	for name, tc := range map[string]struct {
		mutate func(*ssf.SET)
		code   string
		want   string
	}{
		"another audience": {func(s *ssf.SET) { s.Audience = []string{"https://someone-else.example"} }, "invalid_audience", "aud"},
		"another issuer":   {func(s *ssf.SET) { s.Issuer = "https://elsewhere.example" }, "invalid_issuer", "iss"},
		"too old":          {func(s *ssf.SET) { s.IssuedAt = time.Now().Add(-30 * 24 * time.Hour) }, "invalid_request", "replay window"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := e.rx.Verify(context.Background(), sign(t, e, tc.mutate))
			var rej *receiver.RejectionError
			if !errors.As(err, &rej) || rej.Code != tc.code || !strings.Contains(rej.Description, tc.want) {
				t.Errorf("Verify = %#v, want a *RejectionError with code %s about %s", err, tc.code, tc.want)
			}
		})
	}
	var rej *receiver.RejectionError
	if _, err := e.rx.Verify(context.Background(), "not.a.set"); !errors.As(err, &rej) || rej.Code != "invalid_request" {
		t.Errorf("Verify of a malformed token = %v, want a *RejectionError with code invalid_request", err)
	}
}
