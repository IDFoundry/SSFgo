package transmitter_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/storage/memstore"
	"github.com/idfoundry/ssfgo/transmitter"
)

func TestSendVerification(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := pollStream(f, "alice")
	if err := f.tx.SendVerification(ctx, c.StreamID); err != nil {
		t.Fatal(err)
	}
	q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, false)
	if len(q) != 1 {
		t.Fatalf("queued %d SETs, want 1", len(q))
	}
	set := f.decodeSET(q[0].SET, "https://alice.example")
	if v, ok := set.Event.(ssf.Verification); !ok || v.State != "" {
		t.Errorf("event = %#v, want a verification without state (SSF §8.1.4.2)", set.Event)
	}
	if !ssf.SubjectsEqual(set.Subject, ssf.OpaqueSubject{ID: c.StreamID}) {
		t.Errorf("sub_id = %v", set.Subject)
	}
	if set.TransactionID == "" {
		t.Error("verification SET has no txn")
	}
	// Not limited by min_verification_interval, which applies to Receivers.
	if err := f.tx.SendVerification(ctx, c.StreamID); err != nil {
		t.Errorf("second SendVerification: %v", err)
	}
	if err := f.tx.SendVerification(ctx, "unknown"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("unknown stream: %v", err)
	}
	expect(t, f.do("POST", f.metadata().StatusEndpoint, "alice", map[string]any{"stream_id": c.StreamID, "status": "disabled"}), http.StatusOK)
	_ = f.tx.SendVerification(ctx, c.StreamID)
	if q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, false); len(q) != 0 {
		t.Errorf("a disabled stream queued %d SETs", len(q))
	}
}

func TestVerifyNewStreams(t *testing.T) {
	f := newFixture(t, func(c *transmitter.Config) { c.VerifyNewStreams = true })
	c := pollStream(f, "alice")
	got := f.poll(c, "alice", nil)
	if len(got.Sets) != 1 {
		t.Fatalf("a new stream delivered %d SETs, want one verification", len(got.Sets))
	}
	for _, tok := range got.Sets {
		if v, ok := f.decodeSET(tok, "https://alice.example").Event.(ssf.Verification); !ok || v.State != "" {
			t.Errorf("event = %#v", v)
		}
	}
}

func inactivityFixture(t *testing.T, action transmitter.InactivityAction) *fixture {
	return newFixture(t, func(c *transmitter.Config) {
		c.Inactivity = transmitter.InactivityPolicy{Timeout: time.Hour, Action: action}
	})
}

func TestInactivityTimeoutAdvertised(t *testing.T) {
	f := inactivityFixture(t, transmitter.InactivityPause)
	c := pollStream(f, "alice")
	if c.InactivityTimeout != 3600 {
		t.Errorf("inactivity_timeout = %d, want 3600", c.InactivityTimeout)
	}
	// A Receiver sending the configuration back unchanged must succeed
	// (SSF §8.1.1.4 read-modify-replace).
	expect(t, f.do("PUT", f.metadata().ConfigurationEndpoint, "alice", c), http.StatusOK)
}

func TestInactivityPause(t *testing.T) {
	f := inactivityFixture(t, transmitter.InactivityPause)
	ctx := context.Background()
	c := pollStream(f, "alice")

	f.now = f.now.Add(59 * time.Minute)
	if err := f.tx.ExpireInactiveStreams(ctx); err != nil {
		t.Fatal(err)
	}
	if s, _ := f.store.Stream(ctx, c.StreamID); s.Status != ssf.StreamEnabled {
		t.Fatalf("paused before the timeout: %s", s.Status)
	}

	f.now = f.now.Add(2 * time.Minute)
	if err := f.tx.ExpireInactiveStreams(ctx); err != nil {
		t.Fatal(err)
	}
	s, _ := f.store.Stream(ctx, c.StreamID)
	if s.Status != ssf.StreamPaused || s.StatusReason != "inactivity timeout" {
		t.Fatalf("after the timeout: %s (%s)", s.Status, s.StatusReason)
	}
	// The Receiver is told (SSF §8.1.2), and may re-enable the stream:
	// an inactivity pause is not an operator lock.
	got := f.poll(c, "alice", nil)
	if len(got.Sets) != 1 {
		t.Fatalf("paused stream delivered %d SETs, want the stream-updated notice", len(got.Sets))
	}
	for _, tok := range got.Sets {
		if ev, ok := f.decodeSET(tok, "https://alice.example").Event.(ssf.StreamUpdated); !ok || ev.Status != ssf.StreamPaused {
			t.Errorf("event = %#v", ev)
		}
	}
	expect(t, f.do("POST", f.metadata().StatusEndpoint, "alice", map[string]any{"stream_id": c.StreamID, "status": "enabled"}), http.StatusOK)
}

// Management calls that reference the stream, and polls on a poll stream,
// restart the timeout; a stream with a Receiver that keeps polling is
// never paused.
func TestInactivityRefreshedByActivity(t *testing.T) {
	f := inactivityFixture(t, transmitter.InactivityPause)
	ctx := context.Background()
	c := pollStream(f, "alice")
	md := f.metadata()
	activities := []func(){
		func() { f.poll(c, "alice", nil) },
		func() { f.do("GET", md.StatusEndpoint+"?stream_id="+c.StreamID, "alice", nil) },
		func() { f.do("GET", md.ConfigurationEndpoint+"?stream_id="+c.StreamID, "alice", nil) },
		func() {
			f.do("POST", md.AddSubjectEndpoint, "alice", map[string]any{"stream_id": c.StreamID, "subject": map[string]any{"format": "opaque", "id": "x"}})
		},
	}
	for i := range 8 {
		f.now = f.now.Add(40 * time.Minute)
		activities[i%len(activities)]()
		if err := f.tx.ExpireInactiveStreams(ctx); err != nil {
			t.Fatal(err)
		}
		if s, _ := f.store.Stream(ctx, c.StreamID); s.Status != ssf.StreamEnabled {
			t.Fatalf("after activity %d the stream was %s", i, s.Status)
		}
	}
	// Listing all streams does not reference this one.
	f.now = f.now.Add(40 * time.Minute)
	f.do("GET", md.ConfigurationEndpoint, "alice", nil)
	f.now = f.now.Add(40 * time.Minute)
	_ = f.tx.ExpireInactiveStreams(ctx)
	if s, _ := f.store.Stream(ctx, c.StreamID); s.Status != ssf.StreamPaused {
		t.Errorf("a list request should not count as activity: %s", s.Status)
	}
}

func TestInactivityDisableAndDelete(t *testing.T) {
	ctx := context.Background()

	f := inactivityFixture(t, transmitter.InactivityDisable)
	c := pollStream(f, "alice")
	_ = f.tx.SendVerification(ctx, c.StreamID)
	f.now = f.now.Add(2 * time.Hour)
	if err := f.tx.ExpireInactiveStreams(ctx); err != nil {
		t.Fatal(err)
	}
	s, _ := f.store.Stream(ctx, c.StreamID)
	q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, false)
	if s.Status != ssf.StreamDisabled || len(q) != 1 || !q[0].Control {
		t.Errorf("disable: status %s, %d queued (want only the stream-updated notice)", s.Status, len(q))
	}
	// Running again changes nothing.
	_ = f.tx.ExpireInactiveStreams(ctx)
	if q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, true); len(q) != 1 {
		t.Errorf("a second expiry queued another notice: %d", len(q))
	}

	f = inactivityFixture(t, transmitter.InactivityDelete)
	c = pollStream(f, "alice")
	f.now = f.now.Add(2 * time.Hour)
	if err := f.tx.ExpireInactiveStreams(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Stream(ctx, c.StreamID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("delete: the stream still exists (%v)", err)
	}
}

func TestInactivityConfigValidation(t *testing.T) {
	cfg := func(p transmitter.InactivityPolicy) transmitter.Config {
		return transmitter.Config{
			PermitEvent:     transmitter.PermitAll,
			Issuer:          "https://tx.example",
			SigningKeys:     []transmitter.SigningKey{{Signer: signingKey(t), Algorithm: ssf.RS256, KeyID: "k"}},
			EventsSupported: interopEvents,
			DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPoll},
			DefaultSubjects: ssf.DefaultSubjectsAll,
			Store:           memstore.NewStreamStore(),
			Authorize:       func(context.Context, string) (transmitter.Receiver, error) { return transmitter.Receiver{}, nil },
			Inactivity:      p,
		}
	}
	for _, ok := range []transmitter.InactivityPolicy{{}, {Timeout: time.Hour, Action: transmitter.InactivityDelete}} {
		if _, err := transmitter.New(cfg(ok)); err != nil {
			t.Errorf("valid policy %+v rejected: %v", ok, err)
		}
	}
	for name, p := range map[string]transmitter.InactivityPolicy{
		"no action":        {Timeout: time.Hour},
		"unknown action":   {Timeout: time.Hour, Action: "archive"},
		"fractional":       {Timeout: 1500 * time.Millisecond, Action: transmitter.InactivityPause},
		"negative timeout": {Timeout: -time.Second, Action: transmitter.InactivityPause},
	} {
		if _, err := transmitter.New(cfg(p)); err == nil || !strings.Contains(err.Error(), "Inactivity") {
			t.Errorf("%s: New = %v, want an Inactivity error", name, err)
		}
	}
}

// Run applies inactivity timeouts without being asked.
func TestRunExpiresInactiveStreams(t *testing.T) {
	f := inactivityFixture(t, transmitter.InactivityPause)
	c := pollStream(f, "alice")
	f.now = f.now.Add(2 * time.Hour)
	runTransmitter(t, f)
	waitFor(t, func() bool {
		s, _ := f.store.Stream(context.Background(), c.StreamID)
		return s.Status == ssf.StreamPaused
	})
}
