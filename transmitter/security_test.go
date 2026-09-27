package transmitter_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/transmitter"
)

// An authenticated Receiver cannot grow Transmitter state without bound.
func TestLimits(t *testing.T) {
	f := newFixture(t, func(c *transmitter.Config) {
		c.Limits = transmitter.Limits{StreamsPerReceiver: 3, SubjectRulesPerStream: 5, QueuedSETsPerStream: 4}
	})
	md := f.metadata()
	for range 3 {
		pollStream(f, "alice")
	}
	expect(t, f.do("POST", md.ConfigurationEndpoint, "alice", map[string]any{}), http.StatusForbidden)

	c := pollStream(f, "bob")
	subject := func(i int) map[string]any {
		return map[string]any{"format": "email", "email": fmt.Sprintf("u%d@example.com", i)}
	}
	for i := range 5 {
		expect(t, f.do("POST", md.RemoveSubjectEndpoint, "bob", map[string]any{"stream_id": c.StreamID, "subject": subject(i)}), http.StatusNoContent)
	}
	expect(t, f.do("POST", md.RemoveSubjectEndpoint, "bob", map[string]any{"stream_id": c.StreamID, "subject": subject(99)}), http.StatusForbidden)
	expect(t, f.do("POST", md.AddSubjectEndpoint, "bob", map[string]any{"stream_id": c.StreamID, "subject": subject(0)}), http.StatusOK) // replacing is fine

	for range 10 {
		if err := f.tx.Emit(context.Background(), ssf.EmailSubject{Email: "someone@example.com"}, revoked()); err != nil {
			t.Fatalf("Emit must not fail because one stream's queue is full: %v", err)
		}
	}
	if q, _ := f.store.PendingEvents(context.Background(), c.StreamID, 0, false); len(q) != 4 {
		t.Errorf("queue holds %d SETs, want the limit of 4", len(q))
	}
	// A stream-updated notice still gets through a full queue.
	if err := f.tx.SetStreamStatus(context.Background(), c.StreamID, ssf.StreamPaused, "maintenance"); err != nil {
		t.Fatal(err)
	}
	if q, _ := f.store.PendingEvents(context.Background(), c.StreamID, 0, true); len(q) != 1 {
		t.Errorf("control events queued: %d, want the stream-updated notice", len(q))
	}
}

func TestSingleStreamStill409(t *testing.T) {
	f := newFixture(t, func(c *transmitter.Config) { c.MultipleStreamsPerReceiver = false })
	pollStream(f, "alice")
	expect(t, f.do("POST", f.metadata().ConfigurationEndpoint, "alice", map[string]any{}), http.StatusConflict)
}

// PermitEvent keeps a Receiver from obtaining events about subjects it may
// not see, however it subscribes (SSF 1.0 §9.1, §9.2).
func TestPermitEvent(t *testing.T) {
	for _, defaults := range []ssf.DefaultSubjects{ssf.DefaultSubjectsAll, ssf.DefaultSubjectsNone} {
		t.Run(string(defaults), func(t *testing.T) {
			var asked []string
			f := newFixture(t, func(c *transmitter.Config) {
				c.DefaultSubjects = defaults
				c.PermitEvent = func(_ context.Context, receiverID string, s ssf.Subject, _ ssf.Event) bool {
					asked = append(asked, receiverID)
					return s.(ssf.EmailSubject).Email != "victim@other-tenant.example"
				}
			})
			c := pollStream(f, "bob")
			for _, email := range []string{"victim@other-tenant.example", "own@tenant.example"} {
				expect(t, f.do("POST", f.metadata().AddSubjectEndpoint, "bob", map[string]any{
					"stream_id": c.StreamID, "subject": map[string]any{"format": "email", "email": email},
				}), http.StatusOK)
				if err := f.tx.Emit(context.Background(), ssf.EmailSubject{Email: email}, revoked()); err != nil {
					t.Fatal(err)
				}
			}
			if q, _ := f.store.PendingEvents(context.Background(), c.StreamID, 0, false); len(q) != 1 {
				t.Errorf("queued %d SETs, want only the permitted one", len(q))
			}
			if len(asked) != 2 || asked[0] != "bob" {
				t.Errorf("PermitEvent asked about %v, want bob twice", asked)
			}
		})
	}
}

// A status the operator imposed with SetStreamStatus cannot be undone by
// the Receiver until the Transmitter lifts it.
func TestOperatorStatusLock(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := pollStream(f, "bob")
	status := func(s ssf.StreamStatus) response {
		return f.do("POST", f.metadata().StatusEndpoint, "bob", map[string]any{"stream_id": c.StreamID, "status": s})
	}
	expect(t, status(ssf.StreamPaused), http.StatusOK) // the Receiver's own change
	expect(t, status(ssf.StreamEnabled), http.StatusOK)

	if err := f.tx.SetStreamStatus(ctx, c.StreamID, ssf.StreamDisabled, "abuse"); err != nil {
		t.Fatal(err)
	}
	expect(t, status(ssf.StreamEnabled), http.StatusForbidden)
	if err := f.tx.SetStreamStatus(ctx, c.StreamID, ssf.StreamEnabled, ""); err != nil {
		t.Fatal(err)
	}
	expect(t, status(ssf.StreamPaused), http.StatusOK)
}

func TestPushSettingsValidated(t *testing.T) {
	f := newFixture(t)
	url := f.metadata().ConfigurationEndpoint
	long := "https://rx.example/" + string(make([]byte, 3000))
	for name, delivery := range map[string]map[string]any{
		"header injection": {"method": ssf.DeliveryPush, "endpoint_url": "https://rx.example", "authorization_header": "Bearer x\r\nX-Injected: 1"},
		"URL too long":     {"method": ssf.DeliveryPush, "endpoint_url": long},
	} {
		if r := f.do("POST", url, "alice", map[string]any{"delivery": delivery}); r.status != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, r.status)
		}
	}
}
