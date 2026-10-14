package receiver_test

import (
	"context"
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

func TestVerifyRejectsWhatDeliveryRejects(t *testing.T) {
	e := newEnv(t)
	for name, tc := range map[string]struct {
		mutate func(*ssf.SET)
		want   string
	}{
		"another audience": {func(s *ssf.SET) { s.Audience = []string{"https://someone-else.example"} }, "aud"},
		"another issuer":   {func(s *ssf.SET) { s.Issuer = "https://elsewhere.example" }, "iss"},
		"too old":          {func(s *ssf.SET) { s.IssuedAt = time.Now().Add(-30 * 24 * time.Hour) }, "replay window"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := e.rx.Verify(context.Background(), sign(t, e, tc.mutate))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Verify = %v, want an error about %s", err, tc.want)
			}
		})
	}
	if _, err := e.rx.Verify(context.Background(), "not.a.set"); err == nil {
		t.Error("Verify accepted a malformed token")
	}
}
