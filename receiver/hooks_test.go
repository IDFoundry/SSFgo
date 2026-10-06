package receiver_test

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/receiver"
)

// hookLog records what the Receiver's hooks report.
type hookLog struct {
	mu    sync.Mutex
	sets  []receiver.SETInfo
	polls []receiver.PollInfo
	keys  []error
}

func (h *hookLog) hooks() receiver.Hooks {
	return receiver.Hooks{
		SET:           func(_ context.Context, i receiver.SETInfo) { h.mu.Lock(); h.sets = append(h.sets, i); h.mu.Unlock() },
		Poll:          func(_ context.Context, i receiver.PollInfo) { h.mu.Lock(); h.polls = append(h.polls, i); h.mu.Unlock() },
		KeysRefreshed: func(_ context.Context, err error) { h.mu.Lock(); h.keys = append(h.keys, err); h.mu.Unlock() },
	}
}

func TestHooksReportSETOutcomes(t *testing.T) {
	var log hookLog
	e := newEnv(t, func(c *receiver.Config) { c.Hooks = log.hooks() })
	var rec recorder
	rec.install(e.rx)
	h := e.rx.PushHandler(receiver.PushOptions{})
	tok := sign(t, e, nil)
	push(t, h, "", tok)                                                     // handled
	push(t, h, "", tok)                                                     // duplicate
	push(t, h, "", sign(t, e, func(s *ssf.SET) { s.Issuer = "https://x" })) // rejected
	rec.fail.Store(1)
	push(t, h, "", sign(t, e, func(s *ssf.SET) { s.JWTID = "fails" })) // failed

	want := []receiver.SETOutcome{receiver.SETHandled, receiver.SETDuplicate, receiver.SETRejected, receiver.SETFailed}
	if len(log.sets) != len(want) {
		t.Fatalf("%d SET reports, want %d", len(log.sets), len(want))
	}
	for i, w := range want {
		got := log.sets[i]
		if got.Outcome != w || got.Delivery != ssf.DeliveryPush {
			t.Errorf("report %d: %v via %s, want %v via push", i, got.Outcome, got.Delivery, w)
		}
	}
	if log.sets[0].JTI == "" || log.sets[0].EventType == "" {
		t.Errorf("handled SET reported without jti or type: %+v", log.sets[0])
	}
	if log.sets[2].ErrorCode != "invalid_issuer" || log.sets[2].Err == nil {
		t.Errorf("rejection reported as %q, %v", log.sets[2].ErrorCode, log.sets[2].Err)
	}
}

func TestHooksReportPollsAndKeys(t *testing.T) {
	var log hookLog
	now := time.Now()
	e := newEnv(t, func(c *receiver.Config) {
		c.Hooks = log.hooks()
		c.Now = func() time.Time { return now }
		c.KeyMaxAge = time.Hour
	})
	ctx := context.Background()
	stream, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.rx.Poll(ctx, stream, receiver.PollOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(log.polls) != 1 || log.polls[0].StreamID != stream.StreamID || log.polls[0].Err != nil {
		t.Errorf("poll reports: %+v", log.polls)
	}

	// Ready refetches keys that are overdue, reporting it; with the JWKS
	// endpoint down, the Receiver is not ready.
	if err := e.rx.Ready(ctx); err != nil {
		t.Errorf("Ready with fresh keys: %v", err)
	}
	now = now.Add(2 * time.Hour)
	if err := e.rx.Ready(ctx); err != nil || len(log.keys) != 1 || log.keys[0] != nil {
		t.Errorf("Ready with overdue keys = %v; key reports %v", err, log.keys)
	}
	e.txSrv.Config.Handler = http.NotFoundHandler()
	now = now.Add(2 * time.Hour)
	if err := e.rx.Ready(ctx); err == nil {
		t.Error("Ready while the JWKS cannot be refetched")
	}
	if len(log.keys) != 2 || log.keys[1] == nil {
		t.Errorf("failed refetch reports: %v", log.keys)
	}
}
