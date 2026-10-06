package transmitter_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/transmitter"
)

// An authenticated Receiver cannot grow Transmitter state without bound.
func TestLimits(t *testing.T) {
	f := newFixture(t, func(c *transmitter.Config) {
		c.Limits = transmitter.Limits{StreamsPerReceiver: 3, SubjectRulesPerStream: 5, QueuedSETsPerStream: 4, LongPollTimeout: time.Second}
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

// A Receiver cannot escape a status the Transmitter set by deleting the
// stream and creating another.
func TestOperatorStatusLockSurvivesRecreate(t *testing.T) {
	for _, multiple := range []bool{false, true} {
		f := newFixture(t, func(c *transmitter.Config) { c.MultipleStreamsPerReceiver = multiple })
		ctx := context.Background()
		c := pollStream(f, "bob")
		if err := f.tx.SetStreamStatus(ctx, c.StreamID, ssf.StreamDisabled, "abuse"); err != nil {
			t.Fatal(err)
		}
		md := f.metadata()
		expect(t, f.do("DELETE", md.ConfigurationEndpoint+"?stream_id="+c.StreamID, "bob", nil), http.StatusForbidden)
		expect(t, f.do("POST", md.ConfigurationEndpoint, "bob", map[string]any{"delivery": map[string]any{"method": ssf.DeliveryPoll}}), http.StatusForbidden)

		// Once the Transmitter re-enables the stream, both are allowed.
		if err := f.tx.SetStreamStatus(ctx, c.StreamID, ssf.StreamEnabled, ""); err != nil {
			t.Fatal(err)
		}
		expect(t, f.do("DELETE", md.ConfigurationEndpoint+"?stream_id="+c.StreamID, "bob", nil), http.StatusNoContent)
		pollStream(f, "bob")
	}
}

// Subject rules are bounded in size, and an include rule cannot be a
// complex subject made only of members no event carries, which would
// match every complex subject.
func TestSubjectRuleChecks(t *testing.T) {
	f := newFixture(t, func(c *transmitter.Config) { c.DefaultSubjects = ssf.DefaultSubjectsNone })
	c := pollStream(f, "alice")
	md := f.metadata()
	rule := func(endpoint string, subject any, status int) {
		t.Helper()
		expect(t, f.do("POST", endpoint, "alice", map[string]any{"stream_id": c.StreamID, "subject": subject}), status)
	}
	var ids []any
	for i := range 200 {
		ids = append(ids, map[string]any{"format": "email", "email": fmt.Sprintf("user-%03d@example.com", i)})
	}
	huge := map[string]any{"format": "aliases", "identifiers": ids}
	rule(md.AddSubjectEndpoint, huge, http.StatusBadRequest)
	rule(md.RemoveSubjectEndpoint, huge, http.StatusBadRequest)

	opaque := map[string]any{"format": "opaque", "id": "x"}
	rule(md.AddSubjectEndpoint, map[string]any{"format": "complex", "zz": opaque}, http.StatusBadRequest)
	rule(md.AddSubjectEndpoint, map[string]any{"format": "complex", "tenant": opaque, "zz": opaque}, http.StatusOK)
	// Excluding is always allowed: it can only narrow what is delivered.
	rule(md.RemoveSubjectEndpoint, map[string]any{"format": "complex", "zz": opaque}, http.StatusNoContent)
}

// A read-only token does not see the push endpoint's credential.
func TestReadOnlyTokenCannotReadPushCredential(t *testing.T) {
	f := newFixture(t)
	c := f.create("alice", pushBody())
	url := f.metadata().ConfigurationEndpoint
	var one ssf.StreamConfiguration
	f.do("GET", url+"?stream_id="+c.StreamID, "alice-readonly", nil).json(t, &one)
	var all []ssf.StreamConfiguration
	f.do("GET", url, "alice-readonly", nil).json(t, &all)
	if one.Delivery.AuthorizationHeader != "" || len(all) != 1 || all[0].Delivery.AuthorizationHeader != "" {
		t.Errorf("read-only token read authorization_header %q / %v", one.Delivery.AuthorizationHeader, all)
	}
	var managed ssf.StreamConfiguration
	f.do("GET", url+"?stream_id="+c.StreamID, "alice", nil).json(t, &managed)
	if managed.Delivery.AuthorizationHeader != "Bearer push-token" {
		t.Errorf("manage token read authorization_header %q", managed.Delivery.AuthorizationHeader)
	}
}

// Only one long poll per stream waits at a time; another is answered at
// once, so a Receiver cannot tie up any number of waiting requests.
func TestOneLongPollPerStream(t *testing.T) {
	f := newFixture(t, func(c *transmitter.Config) { c.Limits.LongPollTimeout = 2 * time.Second })
	c := pollStream(f, "alice")
	first := make(chan struct{})
	go func() {
		defer close(first)
		f.do("POST", c.Delivery.EndpointURL, "alice", map[string]any{"returnImmediately": false})
	}()
	time.Sleep(200 * time.Millisecond) // the first poll is waiting
	start := time.Now()
	f.poll(c, "alice", map[string]any{"returnImmediately": false})
	if took := time.Since(start); took > time.Second {
		t.Errorf("a second long poll on the stream waited %v", took)
	}
	<-first
	// With the first done, the next long poll waits again.
	start = time.Now()
	f.poll(c, "alice", map[string]any{"returnImmediately": false})
	if took := time.Since(start); took < time.Second {
		t.Errorf("a long poll with none other waiting returned after %v", took)
	}
}

// Push endpoints are checked for length and against AllowPushEndpoint.
func TestPushEndpointChecks(t *testing.T) {
	f := newFixture(t, func(c *transmitter.Config) {
		c.AllowPushEndpoint = func(_ transmitter.Receiver, u *url.URL) error {
			if u.Host != "rx.example" {
				return errors.New("unknown host")
			}
			return nil
		}
	})
	endpoint := f.metadata().ConfigurationEndpoint
	push := func(url string) map[string]any {
		return map[string]any{"delivery": map[string]any{"method": ssf.DeliveryPush, "endpoint_url": url}}
	}
	expect(t, f.do("POST", endpoint, "alice", push("https://rx.example/"+strings.Repeat("a", 3000))), http.StatusBadRequest)
	expect(t, f.do("POST", endpoint, "alice", push("https://elsewhere.example/push")), http.StatusBadRequest)
	expect(t, f.do("POST", endpoint, "alice", push("https://rx.example/push")), http.StatusCreated)
}
