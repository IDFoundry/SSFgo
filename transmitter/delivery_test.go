package transmitter_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/internal/jose"
	"github.com/idfoundry/ssfgo/internal/setcodec"
	"github.com/idfoundry/ssfgo/transmitter"
)

var (
	alice = ssf.EmailSubject{Email: "alice@example.com"}
	bob   = ssf.IssSubSubject{Issuer: "https://idp.example", Subject: "bob"}
)

func revoked() caep.SessionRevoked {
	return caep.SessionRevoked{Common: caep.Common{ReasonAdmin: ssf.LocalizedText{"en": "revoked"}}}
}

// decodeSET verifies a delivered SET as a Receiver with audience aud would.
func (f *fixture) decodeSET(token, aud string) ssf.SET {
	f.t.Helper()
	r := ssf.NewRegistry()
	if err := caep.Register(r); err != nil {
		f.t.Fatal(err)
	}
	set, err := setcodec.Decode(token, setcodec.VerifyOptions{
		Issuer:     f.issuer,
		Audience:   aud,
		Algorithms: []ssf.SignatureAlgorithm{ssf.RS256},
		Keys:       []jose.SetKey{{KeyID: "k1", PublicKey: signingKey(f.t).Public()}},
		Registry:   r,
		Now:        func() time.Time { return f.now.Add(time.Hour) },
	})
	if err != nil {
		f.t.Fatalf("delivered SET does not verify: %v", err)
	}
	return set
}

type pollResult struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable"`
}

func (f *fixture) poll(c ssf.StreamConfiguration, token string, body map[string]any) pollResult {
	f.t.Helper()
	if body == nil {
		body = map[string]any{"returnImmediately": true}
	}
	r := f.do("POST", c.Delivery.EndpointURL, token, body)
	expect(f.t, r, http.StatusOK)
	var p pollResult
	r.json(f.t, &p)
	if p.Sets == nil {
		f.t.Fatalf("poll response has no sets object: %s", r.body)
	}
	return p
}

func pollStream(f *fixture, token string) ssf.StreamConfiguration {
	return f.create(token, map[string]any{"events_requested": interopEvents})
}

func TestPoll(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := pollStream(f, "alice")

	if got := f.poll(c, "alice", nil); len(got.Sets) != 0 || got.MoreAvailable {
		t.Fatalf("empty stream: %+v", got)
	}
	for range 3 {
		if err := f.tx.Emit(ctx, alice, revoked()); err != nil {
			t.Fatal(err)
		}
	}

	// maxEvents limits the batch and reports moreAvailable.
	first := f.poll(c, "alice", map[string]any{"maxEvents": 2, "returnImmediately": true})
	if len(first.Sets) != 2 || !first.MoreAvailable {
		t.Fatalf("maxEvents 2: %d sets, moreAvailable %v", len(first.Sets), first.MoreAvailable)
	}
	for jti, token := range first.Sets {
		set := f.decodeSET(token, "https://alice.example")
		if set.JWTID != jti || !ssf.SubjectsEqual(set.Subject, alice) {
			t.Errorf("SET %s: jti %s, subject %v", jti, set.JWTID, set.Subject)
		}
		if _, ok := set.Event.(caep.SessionRevoked); !ok {
			t.Errorf("event = %T", set.Event)
		}
	}

	// Unacknowledged SETs are returned again.
	again := f.poll(c, "alice", nil)
	if len(again.Sets) != 3 {
		t.Fatalf("second poll returned %d sets, want all 3 unacknowledged", len(again.Sets))
	}

	// Acknowledge-only (RFC 8936 §2.4.2): acknowledges, returns nothing.
	var acks []string
	for jti := range first.Sets {
		acks = append(acks, jti)
	}
	if got := f.poll(c, "alice", map[string]any{"ack": acks, "maxEvents": 0, "returnImmediately": true}); len(got.Sets) != 0 {
		t.Fatalf("ack-only returned %d sets", len(got.Sets))
	}
	// Poll with acknowledgement and errors: setErrs also removes the SET.
	rest := f.poll(c, "alice", nil)
	if len(rest.Sets) != 1 {
		t.Fatalf("after acking 2 of 3: %d sets", len(rest.Sets))
	}
	var last string
	for jti := range rest.Sets {
		last = jti
	}
	got := f.poll(c, "alice", map[string]any{
		"setErrs":           map[string]any{last: map[string]any{"err": "invalid_key", "description": "test"}},
		"returnImmediately": true,
	})
	if len(got.Sets) != 0 {
		t.Errorf("after setErrs: %d sets", len(got.Sets))
	}
	if q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, false); len(q) != 0 {
		t.Errorf("queue still holds %d SETs", len(q))
	}
}

func TestPollRejects(t *testing.T) {
	f := newFixture(t)
	c := pollStream(f, "alice")
	push := f.create("alice", pushBody())
	pollURL := c.Delivery.EndpointURL

	expect(t, f.do("POST", pollURL, "", map[string]any{}), http.StatusUnauthorized)
	expect(t, f.do("POST", pollURL, "bob", map[string]any{}), http.StatusNotFound)
	expect(t, f.do("POST", pollURL, "alice", ";{ broken"), http.StatusBadRequest)
	expect(t, f.do("POST", pollURL, "alice", map[string]any{"maxEvents": -1}), http.StatusBadRequest)
	expect(t, f.do("POST", pollURL, "alice", map[string]any{"maxEvents": "ten"}), http.StatusBadRequest)
	expect(t, f.do("POST", strings.Replace(pollURL, c.StreamID, push.StreamID, 1), "alice", map[string]any{}), http.StatusBadRequest)
	// A read-only token may poll (RFC 8936 delivery is how it reads events).
	expect(t, f.do("POST", pollURL, "alice-readonly", map[string]any{"returnImmediately": true}), http.StatusOK)
	// An empty body is a default poll (RFC 8936 §2.4.1 Figure 2).
	f.tx.Emit(context.Background(), alice, revoked())
	expect(t, f.do("POST", pollURL, "alice", nil), http.StatusOK)
}

func TestLongPoll(t *testing.T) {
	f := newFixture(t, func(c *transmitter.Config) { c.Limits.LongPollTimeout = 5 * time.Second })
	c := pollStream(f, "alice")

	go func() {
		time.Sleep(200 * time.Millisecond)
		if err := f.tx.Emit(context.Background(), alice, revoked()); err != nil {
			t.Error(err)
		}
	}()
	start := time.Now()
	got := f.poll(c, "alice", map[string]any{"returnImmediately": false})
	if len(got.Sets) != 1 {
		t.Fatalf("long poll returned %d sets", len(got.Sets))
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("long poll took %v; it should wake when the SET is queued", elapsed)
	}
}

func TestLongPollTimesOut(t *testing.T) {
	f := newFixture(t, func(c *transmitter.Config) { c.Limits.LongPollTimeout = 300 * time.Millisecond })
	c := pollStream(f, "alice")
	start := time.Now()
	if got := f.poll(c, "alice", map[string]any{}); len(got.Sets) != 0 {
		t.Fatalf("got %d sets", len(got.Sets))
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Errorf("returned after %v, before the long poll timeout", elapsed)
	}
}

func TestEmitRouting(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	all := pollStream(f, "alice")
	onlyCredential := f.create("alice", map[string]any{"events_requested": []ssf.EventType{caep.CredentialChangeEventType}})
	bobStream := pollStream(f, "bob")
	disabled := pollStream(f, "alice")
	expect(t, f.do("POST", f.metadata().StatusEndpoint, "alice", map[string]any{"stream_id": disabled.StreamID, "status": "disabled"}), http.StatusOK)

	// Exclude alice from the first stream (default_subjects is ALL).
	expect(t, f.do("POST", f.metadata().RemoveSubjectEndpoint, "alice", map[string]any{
		"stream_id": all.StreamID, "subject": map[string]any{"format": "email", "email": "alice@example.com"},
	}), http.StatusNoContent)

	if err := f.tx.Emit(ctx, alice, revoked()); err != nil {
		t.Fatal(err)
	}
	if err := f.tx.Emit(ctx, bob, revoked()); err != nil {
		t.Fatal(err)
	}

	count := func(c ssf.StreamConfiguration) int {
		q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, false)
		return len(q)
	}
	if n := count(all); n != 1 {
		t.Errorf("stream excluding alice got %d SETs, want only bob's", n)
	}
	if n := count(onlyCredential); n != 0 {
		t.Errorf("stream without session-revoked in events_delivered got %d SETs", n)
	}
	if n := count(bobStream); n != 2 {
		t.Errorf("bob's receiver got %d SETs, want 2", n)
	}
	if n := count(disabled); n != 0 {
		t.Errorf("disabled stream got %d SETs", n)
	}

	// One Emit gives each stream its own SET — own aud and jti — with a
	// shared txn.
	q1, _ := f.store.PendingEvents(ctx, all.StreamID, 0, false)
	q2, _ := f.store.PendingEvents(ctx, bobStream.StreamID, 0, false)
	s1 := f.decodeSET(q1[0].SET, "https://alice.example")
	s2 := f.decodeSET(q2[1].SET, "https://bob.example")
	if s1.JWTID == s2.JWTID || s1.TransactionID == "" || s1.TransactionID != s2.TransactionID {
		t.Errorf("jti %s/%s, txn %q/%q", s1.JWTID, s2.JWTID, s1.TransactionID, s2.TransactionID)
	}
}

func TestEmitWithDefaultSubjectsNone(t *testing.T) {
	f := newFixture(t, func(c *transmitter.Config) { c.DefaultSubjects = ssf.DefaultSubjectsNone })
	ctx := context.Background()
	c := pollStream(f, "alice")
	// A complex subject added by the Receiver matches a more specific
	// event subject (SSF 1.0 §8.1.3.1).
	tenant := ssf.OpaqueSubject{ID: "tenant-1"}
	expect(t, f.do("POST", f.metadata().AddSubjectEndpoint, "alice", map[string]any{
		"stream_id": c.StreamID, "subject": map[string]any{"format": "complex", "tenant": map[string]any{"format": "opaque", "id": "tenant-1"}},
	}), http.StatusOK)

	if err := f.tx.Emit(ctx, alice, revoked()); err != nil {
		t.Fatal(err)
	}
	if err := f.tx.Emit(ctx, ssf.ComplexSubject{Tenant: tenant, User: alice}, revoked()); err != nil {
		t.Fatal(err)
	}
	if err := f.tx.Emit(ctx, ssf.ComplexSubject{Tenant: ssf.OpaqueSubject{ID: "tenant-2"}, User: alice}, revoked()); err != nil {
		t.Fatal(err)
	}
	q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, false)
	if len(q) != 1 {
		t.Fatalf("got %d SETs, want only the tenant-1 event", len(q))
	}
}

func TestReaddedSubjectAfterBroaderRemoval(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := pollStream(f, "alice")
	email := map[string]any{"format": "email", "email": "alice@example.com"}
	narrow := map[string]any{"format": "complex", "user": email, "tenant": map[string]any{"format": "opaque", "id": "tenant-1"}}
	subject := func(endpoint string, s map[string]any, status int) {
		t.Helper()
		expect(t, f.do("POST", endpoint, "alice", map[string]any{"stream_id": c.StreamID, "subject": s}), status)
	}
	// Add the narrow subject, remove a broader one that covers it, then
	// add the narrow one again: the newest matching rule decides, so its
	// events are delivered (SSF 1.0 §8.1.3.1, §8.1.3.2).
	subject(f.metadata().AddSubjectEndpoint, narrow, http.StatusOK)
	subject(f.metadata().RemoveSubjectEndpoint, map[string]any{"format": "complex", "user": email}, http.StatusNoContent)
	subject(f.metadata().AddSubjectEndpoint, narrow, http.StatusOK)

	if err := f.tx.Emit(ctx, ssf.ComplexSubject{User: alice, Tenant: ssf.OpaqueSubject{ID: "tenant-1"}}, revoked()); err != nil {
		t.Fatal(err)
	}
	if err := f.tx.Emit(ctx, ssf.ComplexSubject{User: alice, Tenant: ssf.OpaqueSubject{ID: "tenant-2"}}, revoked()); err != nil {
		t.Fatal(err)
	}
	q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, false)
	if len(q) != 1 {
		t.Fatalf("got %d SETs, want only the re-added tenant-1 event", len(q))
	}
}

func TestEmitRejects(t *testing.T) {
	sentinel := errors.New("profile says no")
	f := newFixture(t, func(c *transmitter.Config) {
		c.EventValidator = func(s ssf.Subject, _ ssf.Event) error {
			if _, ok := s.(ssf.PhoneNumberSubject); ok {
				return sentinel
			}
			return nil
		}
	})
	ctx := context.Background()
	stream := pollStream(f, "alice")
	huge := caep.SessionRevoked{Common: caep.Common{ReasonAdmin: ssf.LocalizedText{"en": strings.Repeat("x", transmitter.MaxSETBytes)}}}
	for name, c := range map[string]struct {
		subject ssf.Subject
		event   ssf.Event
		is      error
	}{
		"nil subject":        {nil, revoked(), nil},
		"nil event":          {alice, nil, nil},
		"invalid subject":    {ssf.EmailSubject{}, revoked(), ssf.ErrInvalidSubject},
		"invalid event":      {alice, caep.CredentialChange{}, ssf.ErrInvalidEvent},
		"unsupported type":   {alice, caep.RiskLevelChange{Principal: "USER", CurrentLevel: caep.RiskLow}, transmitter.ErrUnsupportedEvent},
		"subject constraint": {alice, ssf.Verification{}, ssf.ErrInvalidEvent},
		"validator":          {ssf.PhoneNumberSubject{PhoneNumber: "+15550100"}, revoked(), sentinel},
		"too large":          {alice, huge, transmitter.ErrSETTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			err := f.tx.Emit(ctx, c.subject, c.event)
			if err == nil || (c.is != nil && !errors.Is(err, c.is)) {
				t.Fatalf("Emit = %v, want %v", err, c.is)
			}
		})
	}
	if got := f.poll(stream, "alice", nil); len(got.Sets) != 0 {
		t.Errorf("a refused event queued %d SETs", len(got.Sets))
	}
}

func TestSetStreamStatus(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := pollStream(f, "alice")
	if err := f.tx.Emit(ctx, alice, revoked()); err != nil {
		t.Fatal(err)
	}

	// Pausing sends a stream-updated event that is delivered while every
	// other SET is held.
	if err := f.tx.SetStreamStatus(ctx, c.StreamID, ssf.StreamPaused, "maintenance"); err != nil {
		t.Fatal(err)
	}
	got := f.poll(c, "alice", nil)
	if len(got.Sets) != 1 {
		t.Fatalf("paused stream delivered %d SETs, want only stream-updated", len(got.Sets))
	}
	for _, token := range got.Sets {
		set := f.decodeSET(token, "https://alice.example")
		if ev, ok := set.Event.(ssf.StreamUpdated); !ok || ev.Status != ssf.StreamPaused || ev.Reason != "maintenance" {
			t.Errorf("event = %#v", set.Event)
		}
		if !ssf.SubjectsEqual(set.Subject, ssf.OpaqueSubject{ID: c.StreamID}) {
			t.Errorf("sub_id = %v", set.Subject)
		}
		if set.TransactionID == "" {
			t.Error("stream-updated SET has no txn")
		}
	}
	r := f.do("GET", f.metadata().StatusEndpoint+"?stream_id="+c.StreamID, "alice", nil)
	var st ssf.StreamState
	r.json(t, &st)
	if st.Status != ssf.StreamPaused || st.Reason != "maintenance" {
		t.Errorf("status = %+v", st)
	}

	// Setting the same status again sends nothing.
	if err := f.tx.SetStreamStatus(ctx, c.StreamID, ssf.StreamPaused, "again"); err != nil {
		t.Fatal(err)
	}
	if q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, true); len(q) != 1 {
		t.Errorf("repeating the status queued another event: %d control events", len(q))
	}

	// Re-enabling announces itself and releases the held SET.
	if err := f.tx.SetStreamStatus(ctx, c.StreamID, ssf.StreamEnabled, ""); err != nil {
		t.Fatal(err)
	}
	if got := f.poll(c, "alice", nil); len(got.Sets) != 3 {
		t.Errorf("after re-enabling: %d SETs, want held event + two stream-updated", len(got.Sets))
	}

	// Disabling discards held SETs but still announces the change.
	if err := f.tx.SetStreamStatus(ctx, c.StreamID, ssf.StreamDisabled, "gone"); err != nil {
		t.Fatal(err)
	}
	q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, false)
	if len(q) != 1 || !q[0].Control {
		t.Errorf("after disabling: %d queued, want only the new stream-updated", len(q))
	}

	if err := f.tx.SetStreamStatus(ctx, "unknown", ssf.StreamPaused, ""); err == nil {
		t.Error("unknown stream accepted")
	}
	if err := f.tx.SetStreamStatus(ctx, c.StreamID, "stopped", ""); err == nil {
		t.Error("invalid status accepted")
	}
}

// pushReceiver is a push endpoint recording what it receives.
type pushReceiver struct {
	mu       sync.Mutex
	srv      *httptest.Server
	requests []*http.Request
	bodies   []string
	respond  func(n int) (int, string)
	got      chan struct{}
}

func newPushReceiver(t *testing.T) *pushReceiver {
	p := &pushReceiver{got: make(chan struct{}, 100), respond: func(int) (int, string) { return http.StatusAccepted, "" }}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.requests = append(p.requests, r)
		p.bodies = append(p.bodies, string(body))
		status, resp := p.respond(len(p.requests))
		p.mu.Unlock()
		if resp != "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(resp))
		p.got <- struct{}{}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *pushReceiver) wait(t *testing.T, n int) {
	t.Helper()
	for range n {
		select {
		case <-p.got:
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for push %d", n)
		}
	}
}

func runTransmitter(t *testing.T, f *fixture) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- f.tx.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Run = %v", err)
		}
	})
}

func pushStream(f *fixture, rx *pushReceiver, authHeader string) ssf.StreamConfiguration {
	delivery := map[string]any{"method": ssf.DeliveryPush, "endpoint_url": rx.srv.URL + "/events"}
	if authHeader != "" {
		delivery["authorization_header"] = authHeader
	}
	return f.create("bob", map[string]any{"events_requested": interopEvents, "delivery": delivery})
}

func TestPush(t *testing.T) {
	rx := newPushReceiver(t)
	f := newFixture(t, func(c *transmitter.Config) { c.HTTPClient = rx.srv.Client() })
	c := pushStream(f, rx, "Bearer push-secret")
	runTransmitter(t, f)
	ctx := context.Background()

	if err := f.tx.Emit(ctx, bob, revoked()); err != nil {
		t.Fatal(err)
	}
	cc := caep.CredentialChange{CredentialType: caep.CredentialPassword, ChangeType: caep.ChangeUpdate, Common: caep.Common{ReasonAdmin: ssf.LocalizedText{"en": "reset"}}}
	if err := f.tx.Emit(ctx, bob, cc); err != nil {
		t.Fatal(err)
	}
	rx.wait(t, 2)

	rx.mu.Lock()
	defer rx.mu.Unlock()
	req := rx.requests[0]
	if req.Method != "POST" || req.URL.Path != "/events" ||
		req.Header.Get("Content-Type") != "application/secevent+jwt" ||
		req.Header.Get("Accept") != "application/json" ||
		req.Header.Get("Authorization") != "Bearer push-secret" {
		t.Errorf("push request: %s %s %v", req.Method, req.URL.Path, req.Header)
	}
	// Delivered in the order emitted.
	if _, ok := f.decodeSET(rx.bodies[0], "https://bob.example").Event.(caep.SessionRevoked); !ok {
		t.Error("first push is not the first event emitted")
	}
	if _, ok := f.decodeSET(rx.bodies[1], "https://bob.example").Event.(caep.CredentialChange); !ok {
		t.Error("second push is not the second event emitted")
	}
	waitFor(t, func() bool {
		q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, false)
		return len(q) == 0
	})
}

func TestPushWithoutAuthorizationHeader(t *testing.T) {
	rx := newPushReceiver(t)
	f := newFixture(t, func(c *transmitter.Config) { c.HTTPClient = rx.srv.Client() })
	c := pushStream(f, rx, "")
	runTransmitter(t, f)
	expect(t, f.do("POST", f.metadata().VerificationEndpoint, "bob", map[string]any{"stream_id": c.StreamID, "state": "s"}), http.StatusNoContent)
	rx.wait(t, 1)
	rx.mu.Lock()
	defer rx.mu.Unlock()
	if h, ok := rx.requests[0].Header["Authorization"]; ok {
		t.Errorf("Authorization header sent without one configured: %v", h)
	}
}

func TestPushRetriesAndRejections(t *testing.T) {
	rx := newPushReceiver(t)
	rx.respond = func(n int) (int, string) {
		switch n {
		case 1:
			return http.StatusServiceUnavailable, "" // recoverable: retried
		case 2:
			return http.StatusAccepted, ""
		default:
			return http.StatusBadRequest, `{"err":"invalid_audience","description":"not me"}` // permanent: dropped
		}
	}
	f := newFixture(t, func(c *transmitter.Config) { c.HTTPClient = rx.srv.Client() })
	c := pushStream(f, rx, "")
	runTransmitter(t, f)
	ctx := context.Background()

	if err := f.tx.Emit(ctx, bob, revoked()); err != nil {
		t.Fatal(err)
	}
	rx.wait(t, 2) // the failure, then the retry after backoff
	rx.mu.Lock()
	if rx.bodies[0] != rx.bodies[1] {
		t.Error("the retry did not resend the same SET")
	}
	rx.mu.Unlock()

	if err := f.tx.Emit(ctx, bob, revoked()); err != nil {
		t.Fatal(err)
	}
	rx.wait(t, 1)
	waitFor(t, func() bool {
		q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, false)
		return len(q) == 0
	})
}

func TestPushMaxAttempts(t *testing.T) {
	rx := newPushReceiver(t)
	rx.respond = func(n int) (int, string) {
		if n <= 2 {
			return http.StatusBadGateway, ""
		}
		return http.StatusAccepted, ""
	}
	f := newFixture(t, func(c *transmitter.Config) {
		c.HTTPClient = rx.srv.Client()
		c.PushRetry = transmitter.PushRetryPolicy{MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond, MaxAttempts: 2}
	})
	c := pushStream(f, rx, "")
	runTransmitter(t, f)
	ctx := context.Background()
	if err := f.tx.Emit(ctx, bob, revoked()); err != nil {
		t.Fatal(err)
	}
	rx.wait(t, 2) // two failed attempts, then the SET is dropped
	cc := caep.CredentialChange{CredentialType: caep.CredentialPIN, ChangeType: caep.ChangeCreate, Common: caep.Common{ReasonAdmin: ssf.LocalizedText{"en": "x"}}}
	if err := f.tx.Emit(ctx, bob, cc); err != nil {
		t.Fatal(err)
	}
	rx.wait(t, 1)
	rx.mu.Lock()
	third := rx.bodies[2]
	rx.mu.Unlock()
	if _, ok := f.decodeSET(third, "https://bob.example").Event.(caep.CredentialChange); !ok {
		t.Error("after the dropped SET, the next one should be delivered")
	}
	waitFor(t, func() bool {
		q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, false)
		return len(q) == 0
	})
}

// A rejection that may clear on its own — the Receiver has yet to fetch a
// rotated key, say — is retried rather than taken as final.
func TestPushRetriesTransientRejection(t *testing.T) {
	rx := newPushReceiver(t)
	rx.respond = func(n int) (int, string) {
		if n <= 2 {
			return http.StatusBadRequest, `{"err":"invalid_key","description":"no key matches kid"}`
		}
		return http.StatusAccepted, ""
	}
	f := newFixture(t, func(c *transmitter.Config) {
		c.HTTPClient = rx.srv.Client()
		c.PushRetry = transmitter.PushRetryPolicy{MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond}
	})
	c := pushStream(f, rx, "")
	runTransmitter(t, f)
	ctx := context.Background()
	if err := f.tx.Emit(ctx, bob, revoked()); err != nil {
		t.Fatal(err)
	}
	rx.wait(t, 3)
	rx.mu.Lock()
	if rx.bodies[0] != rx.bodies[2] {
		t.Error("the retry did not resend the same SET")
	}
	rx.mu.Unlock()
	waitFor(t, func() bool {
		q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, false)
		return len(q) == 0
	})
}

// A rejection that does not clear is retried a bounded number of times,
// then the SET is dropped so the stream is not held up for good.
func TestPushGivesUpOnPersistentTransientRejection(t *testing.T) {
	const attempts = 8
	rx := newPushReceiver(t)
	rx.respond = func(n int) (int, string) {
		if n <= attempts {
			return http.StatusBadRequest, `{"err":"authentication_failed","description":"no"}`
		}
		return http.StatusAccepted, ""
	}
	f := newFixture(t, func(c *transmitter.Config) {
		c.HTTPClient = rx.srv.Client()
		c.PushRetry = transmitter.PushRetryPolicy{MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}
	})
	c := pushStream(f, rx, "")
	runTransmitter(t, f)
	ctx := context.Background()
	if err := f.tx.Emit(ctx, bob, revoked()); err != nil {
		t.Fatal(err)
	}
	rx.wait(t, attempts)
	cc := caep.CredentialChange{CredentialType: caep.CredentialPIN, ChangeType: caep.ChangeCreate, Common: caep.Common{ReasonAdmin: ssf.LocalizedText{"en": "x"}}}
	if err := f.tx.Emit(ctx, bob, cc); err != nil {
		t.Fatal(err)
	}
	rx.wait(t, 1)
	rx.mu.Lock()
	next := rx.bodies[attempts]
	rx.mu.Unlock()
	if _, ok := f.decodeSET(next, "https://bob.example").Event.(caep.CredentialChange); !ok {
		t.Error("after the dropped SET, the next one should be delivered")
	}
	waitFor(t, func() bool {
		q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, false)
		return len(q) == 0
	})
}

// Each SET gets its full MaxAttempts: failures of the SET before it do not
// count against it.
func TestPushAttemptsCountPerSET(t *testing.T) {
	rx := newPushReceiver(t)
	rx.respond = func(n int) (int, string) {
		switch n {
		case 1, 2, 4: // the first SET fails twice; the second fails once
			return http.StatusBadGateway, ""
		}
		return http.StatusAccepted, ""
	}
	f := newFixture(t, func(c *transmitter.Config) {
		c.HTTPClient = rx.srv.Client()
		c.PushRetry = transmitter.PushRetryPolicy{MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond, MaxAttempts: 3}
	})
	c := pushStream(f, rx, "")
	ctx := context.Background()
	if err := f.tx.Emit(ctx, bob, revoked()); err != nil {
		t.Fatal(err)
	}
	cc := caep.CredentialChange{CredentialType: caep.CredentialPIN, ChangeType: caep.ChangeCreate, Common: caep.Common{ReasonAdmin: ssf.LocalizedText{"en": "x"}}}
	if err := f.tx.Emit(ctx, bob, cc); err != nil {
		t.Fatal(err)
	}
	runTransmitter(t, f)
	rx.wait(t, 5)
	rx.mu.Lock()
	fourth, fifth := rx.bodies[3], rx.bodies[4]
	rx.mu.Unlock()
	if fourth != fifth {
		t.Error("the second SET was dropped after one attempt instead of retried")
	}
	waitFor(t, func() bool {
		q, _ := f.store.PendingEvents(ctx, c.StreamID, 0, false)
		return len(q) == 0
	})
}

// With the default client, a push to a Receiver on a private address is
// refused and retried rather than sent.
func TestDefaultClientRefusesPrivatePushEndpoints(t *testing.T) {
	rx := newPushReceiver(t)
	f := newFixture(t) // no HTTPClient: the SSRF-safe default
	pushStream(f, rx, "")
	runTransmitter(t, f)
	if err := f.tx.Emit(context.Background(), bob, revoked()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-rx.got:
		t.Fatal("the default client pushed to a loopback address")
	case <-time.After(1500 * time.Millisecond):
	}
}

func TestPushHoldsEventsWhilePaused(t *testing.T) {
	rx := newPushReceiver(t)
	f := newFixture(t, func(c *transmitter.Config) { c.HTTPClient = rx.srv.Client() })
	c := pushStream(f, rx, "")
	ctx := context.Background()
	expect(t, f.do("POST", f.metadata().StatusEndpoint, "bob", map[string]any{"stream_id": c.StreamID, "status": "paused"}), http.StatusOK)
	if err := f.tx.Emit(ctx, bob, revoked()); err != nil {
		t.Fatal(err)
	}
	runTransmitter(t, f)
	select {
	case <-rx.got:
		t.Fatal("a paused stream pushed an event")
	case <-time.After(1500 * time.Millisecond):
	}
	expect(t, f.do("POST", f.metadata().StatusEndpoint, "bob", map[string]any{"stream_id": c.StreamID, "status": "enabled"}), http.StatusOK)
	rx.wait(t, 1)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
