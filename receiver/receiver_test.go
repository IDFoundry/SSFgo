package receiver_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/internal/jose"
	"github.com/idfoundry/ssfgo/internal/setcodec"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/storage/memstore"
	"github.com/idfoundry/ssfgo/transmitter"
)

const audience = "https://rx.example"

var (
	keyOnce sync.Once
	txKey   *rsa.PrivateKey
)

func signingKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		if txKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return txKey
}

var quiet = slog.New(slog.DiscardHandler)

// env is an SSFgo Transmitter and a Receiver configured against it.
type env struct {
	t     testing.TB
	txSrv *httptest.Server
	tx    *transmitter.Transmitter
	store *memstore.StreamStore
	rx    *receiver.Receiver
	cfg   receiver.Config
}

func newEnv(t testing.TB, mutate ...func(*receiver.Config)) *env {
	t.Helper()
	return newEnvTx(t, nil, mutate...)
}

// newEnvTx is newEnv with the Transmitter's configuration adjusted by
// txMutate, if it is not nil.
func newEnvTx(t testing.TB, txMutate func(*transmitter.Config), mutate ...func(*receiver.Config)) *env {
	t.Helper()
	e := &env{t: t, store: memstore.NewStreamStore()}
	e.txSrv = httptest.NewUnstartedServer(nil)
	e.txSrv.StartTLS()
	t.Cleanup(e.txSrv.Close)
	issuer := e.txSrv.URL + "/tx"

	txLimits := transmitter.RecommendedLimits()
	txLimits.LongPollTimeout = 2 * time.Second
	txCfg := transmitter.Config{
		Limits:          txLimits,
		PushRetry:       transmitter.RecommendedPushRetry(),
		PermitEvent:     transmitter.PermitAll,
		Issuer:          issuer,
		SigningKeys:     []transmitter.SigningKey{{Signer: signingKey(t), Algorithm: ssf.RS256, KeyID: "k1"}},
		EventsSupported: []ssf.EventType{caep.SessionRevokedEventType, caep.CredentialChangeEventType, risc.AccountDisabledEventType},
		DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPush, ssf.DeliveryPoll},
		DefaultSubjects: ssf.DefaultSubjectsAll,
		Store:           e.store,
		Authorize: func(_ context.Context, token string) (transmitter.Receiver, error) {
			if token != "rx-token" {
				return transmitter.Receiver{}, transmitter.ErrInvalidToken
			}
			return transmitter.Receiver{ID: "rx", Audience: []string{audience}, Access: transmitter.AccessManage}, nil
		},
		HTTPClient: e.txSrv.Client(),
		Logger:     quiet,
	}
	if txMutate != nil {
		txMutate(&txCfg)
	}
	tx, err := transmitter.New(txCfg)
	if err != nil {
		t.Fatal(err)
	}
	e.tx = tx
	e.txSrv.Config.Handler = tx.Handler()

	registry := ssf.NewRegistry()
	if err := caep.Register(registry); err != nil {
		t.Fatal(err)
	}
	if err := risc.Register(registry); err != nil {
		t.Fatal(err)
	}
	e.cfg = receiver.Config{
		Limits:      receiver.RecommendedLimits(),
		Issuer:      issuer,
		Audience:    audience,
		Registry:    registry,
		Algorithms:  []ssf.SignatureAlgorithm{ssf.RS256},
		TokenSource: receiver.StaticToken("rx-token"),
		ReplayStore: memstore.NewReplayStore(),
		HTTPClient:  e.txSrv.Client(),
		Logger:      quiet,
	}
	for _, m := range mutate {
		m(&e.cfg)
	}
	rx, err := receiver.New(context.Background(), e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.rx = rx
	return e
}

func revoked() caep.SessionRevoked {
	return caep.SessionRevoked{Common: caep.Common{ReasonAdmin: ssf.LocalizedText{"en": "revoked"}}}
}

var alice = ssf.EmailSubject{Email: "alice@example.com"}

// recorder collects handled events.
type recorder struct {
	mu      sync.Mutex
	revoked []ssf.SET
	states  []string
	fail    atomic.Int32 // fail this many calls first
}

func (rec *recorder) install(rx *receiver.Receiver) {
	receiver.On(rx, func(_ context.Context, set ssf.SET, _ caep.SessionRevoked) error {
		if rec.fail.Load() > 0 {
			rec.fail.Add(-1)
			return errors.New("handler failed")
		}
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.revoked = append(rec.revoked, set)
		return nil
	})
	receiver.On(rx, func(_ context.Context, _ ssf.SET, v ssf.Verification) error {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.states = append(rec.states, v.State)
		return nil
	})
}

func (rec *recorder) counts() (int, int) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return len(rec.revoked), len(rec.states)
}

func TestDiscovery(t *testing.T) {
	e := newEnv(t)
	if md := e.rx.Metadata(); md.Issuer != e.cfg.Issuer || md.ConfigurationEndpoint == "" {
		t.Errorf("metadata = %+v", md)
	}

	// The metadata must name the issuer it was fetched for (SSF 1.0 §7.2.4).
	bad := e.cfg
	bad.Issuer = e.txSrv.URL + "/other"
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/ssf-configuration/other", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": e.cfg.Issuer, "jwks_uri": e.rx.Metadata().JWKSURI})
	})
	mux.Handle("/", e.tx.Handler())
	e.txSrv.Config.Handler = mux
	if _, err := receiver.New(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "names issuer") {
		t.Errorf("issuer mismatch: %v", err)
	}

	// Every advertised endpoint must use TLS (SSF 1.0 §7.1).
	plain := e.cfg
	plain.Issuer = e.txSrv.URL + "/plain"
	mux.HandleFunc("/.well-known/ssf-configuration/plain", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": plain.Issuer, "jwks_uri": e.rx.Metadata().JWKSURI,
			"configuration_endpoint": "http://tx.example/ssf/stream",
		})
	})
	if _, err := receiver.New(context.Background(), plain); err == nil || !strings.Contains(err.Error(), "not an https URL") {
		t.Errorf("plain-HTTP endpoint: %v", err)
	}

	for name, mutate := range map[string]func(*receiver.Config){
		"http issuer":  func(c *receiver.Config) { c.Issuer = "http://tx.example" },
		"no audience":  func(c *receiver.Config) { c.Audience = "" },
		"no registry":  func(c *receiver.Config) { c.Registry = nil },
		"no algorithm": func(c *receiver.Config) { c.Algorithms = nil },
		"no token":     func(c *receiver.Config) { c.TokenSource = nil },
		"no replay":    func(c *receiver.Config) { c.ReplayStore = nil },
		// No implicit defaults for what decides how much is trusted.
		"no limits":           func(c *receiver.Config) { c.Limits = receiver.Limits{} },
		"no replay window":    func(c *receiver.Config) { c.Limits.ReplayWindow = 0 },
		"huge replay window":  func(c *receiver.Config) { c.Limits.ReplayWindow = receiver.MaxReplayWindow + 1 },
		"no key max age":      func(c *receiver.Config) { c.Limits.KeyMaxAge = 0 },
		"negative clock skew": func(c *receiver.Config) { c.Limits.MaxClockSkew = -1 },
	} {
		c := e.cfg
		mutate(&c)
		if _, err := receiver.New(context.Background(), c); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
}

func TestPollEndToEnd(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var rec recorder
	rec.install(e.rx)

	stream, err := e.rx.CreateStream(ctx, receiver.StreamRequest{Description: "poll"})
	if err != nil {
		t.Fatal(err)
	}
	if stream.Delivery.Method != ssf.DeliveryPoll || len(stream.EventsDelivered) != 3 {
		t.Fatalf("stream = %+v", stream)
	}
	if got, err := e.rx.Stream(ctx, stream.StreamID); err != nil || got.StreamID != stream.StreamID {
		t.Fatalf("Stream = %+v, %v", got, err)
	}
	if all, err := e.rx.Streams(ctx); err != nil || len(all) != 1 {
		t.Fatalf("Streams = %v, %v", all, err)
	}
	if st, err := e.rx.Status(ctx, stream.StreamID); err != nil || st.Status != ssf.StreamEnabled {
		t.Fatalf("Status = %+v, %v", st, err)
	}

	state, err := e.rx.RequestVerification(ctx, stream.StreamID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.tx.Emit(ctx, alice, revoked()); err != nil {
		t.Fatal(err)
	}
	res, err := e.rx.Poll(ctx, stream, receiver.PollOptions{})
	if err != nil || res.Received != 2 {
		t.Fatalf("Poll = %+v, %v", res, err)
	}
	if n, v := rec.counts(); n != 1 || v != 1 || rec.states[0] != state {
		t.Fatalf("handled %d events, %d verifications (states %v, want %s)", n, v, rec.states, state)
	}
	if !ssf.SubjectsEqual(rec.revoked[0].Subject, alice) {
		t.Errorf("subject = %v", rec.revoked[0].Subject)
	}

	// The next poll acknowledges both; nothing is redelivered.
	if res, err := e.rx.Poll(ctx, stream, receiver.PollOptions{}); err != nil || res.Received != 0 {
		t.Fatalf("second poll = %+v, %v", res, err)
	}
	if q, _ := e.store.PendingEvents(ctx, stream.StreamID, 0, false); len(q) != 0 {
		t.Errorf("transmitter still holds %d SETs", len(q))
	}

	if err := e.rx.DeleteStream(ctx, stream.StreamID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.rx.Stream(ctx, stream.StreamID); !errors.Is(err, receiver.ErrNotFound) {
		t.Errorf("Stream after delete: %v", err)
	}
}

func TestPollRedeliversAfterHandlerFailure(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var rec recorder
	rec.install(e.rx)
	rec.fail.Store(1)
	stream, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.tx.Emit(ctx, alice, revoked()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.rx.Poll(ctx, stream, receiver.PollOptions{}); err != nil {
		t.Fatal(err)
	}
	if n, _ := rec.counts(); n != 0 {
		t.Fatal("a failing handler's event was recorded")
	}
	// Not acknowledged, so the Transmitter returns it again.
	if res, err := e.rx.Poll(ctx, stream, receiver.PollOptions{}); err != nil || res.Received != 1 {
		t.Fatalf("redelivery poll = %+v, %v", res, err)
	}
	if n, _ := rec.counts(); n != 1 {
		t.Fatalf("handled %d times after redelivery, want 1", n)
	}
	if err := e.rx.Acknowledge(ctx, stream); err != nil {
		t.Fatal(err)
	}
	if q, _ := e.store.PendingEvents(ctx, stream.StreamID, 0, false); len(q) != 0 {
		t.Errorf("Acknowledge left %d SETs queued", len(q))
	}
}

func TestRunPoller(t *testing.T) {
	e := newEnv(t)
	var rec recorder
	rec.install(e.rx)
	stream, err := e.rx.CreateStream(context.Background(), receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- e.rx.RunPoller(ctx, stream) }()
	if err := e.tx.Emit(context.Background(), alice, revoked()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { n, _ := rec.counts(); return n == 1 })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("RunPoller = %v", err)
	}
	if q, _ := e.store.PendingEvents(context.Background(), stream.StreamID, 0, false); len(q) != 0 {
		t.Errorf("RunPoller left %d SETs unacknowledged", len(q))
	}
}

func TestPushEndToEnd(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var rec recorder
	rec.install(e.rx)

	pushSrv := httptest.NewTLSServer(e.rx.PushHandler(receiver.PushOptions{AuthorizationHeader: ssf.NewSecret("Bearer push-secret")}))
	defer pushSrv.Close()
	// The Transmitter must trust the push server's test certificate.
	e.setTransmitterClient(pushSrv.Client())

	stream, err := e.rx.CreateStream(ctx, receiver.StreamRequest{Delivery: &ssf.Delivery{
		Method: ssf.DeliveryPush, EndpointURL: pushSrv.URL + "/events", AuthorizationHeader: ssf.NewSecret("Bearer push-secret"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = e.tx.Run(runCtx) }()

	if _, err := e.rx.RequestVerification(ctx, stream.StreamID); err != nil {
		t.Fatal(err)
	}
	if err := e.tx.Emit(ctx, alice, revoked()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { n, v := rec.counts(); return n == 1 && v == 1 })
	waitFor(t, func() bool {
		q, _ := e.store.PendingEvents(ctx, stream.StreamID, 0, false)
		return len(q) == 0
	})
}

// setTransmitterClient rebuilds the Transmitter with an HTTP client that
// trusts the push server, keeping its store and handler.
func (e *env) setTransmitterClient(c *http.Client) {
	e.t.Helper()
	tx, err := transmitter.New(transmitter.Config{
		Limits:          transmitter.RecommendedLimits(),
		PushRetry:       transmitter.RecommendedPushRetry(),
		PermitEvent:     transmitter.PermitAll,
		Issuer:          e.cfg.Issuer,
		SigningKeys:     []transmitter.SigningKey{{Signer: signingKey(e.t), Algorithm: ssf.RS256, KeyID: "k1"}},
		EventsSupported: []ssf.EventType{caep.SessionRevokedEventType, caep.CredentialChangeEventType, risc.AccountDisabledEventType},
		DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPush, ssf.DeliveryPoll},
		DefaultSubjects: ssf.DefaultSubjectsAll,
		Store:           e.store,
		Authorize: func(_ context.Context, token string) (transmitter.Receiver, error) {
			if token != "rx-token" {
				return transmitter.Receiver{}, transmitter.ErrInvalidToken
			}
			return transmitter.Receiver{ID: "rx", Audience: []string{audience}, Access: transmitter.AccessManage}, nil
		},
		HTTPClient: c,
		Logger:     quiet,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.tx = tx
	e.txSrv.Config.Handler = tx.Handler()
}

// sign builds a SET the way the test Transmitter would, with overrides.
func sign(t testing.TB, e *env, mutate func(*ssf.SET)) string {
	t.Helper()
	set := ssf.SET{
		Issuer:   e.cfg.Issuer,
		Audience: []string{audience},
		JWTID:    "jti-" + time.Now().Format(time.RFC3339Nano),
		IssuedAt: time.Now(),
		Subject:  alice,
		Event:    revoked(),
	}
	if mutate != nil {
		mutate(&set)
	}
	tok, err := setcodec.Encode(setcodec.Signer{Key: signingKey(t), Algorithm: ssf.RS256, KeyID: "k1"}, set)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type pushResult struct {
	status int
	err    string
	lang   string
}

func push(t *testing.T, h http.Handler, auth, body string) pushResult {
	t.Helper()
	req := httptest.NewRequest("POST", "/events", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/secevent+jwt")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var e struct {
		Err string `json:"err"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	return pushResult{rec.Code, e.Err, rec.Header().Get("Content-Language")}
}

func TestPushHandlerRejections(t *testing.T) {
	e := newEnv(t)
	var rec recorder
	rec.install(e.rx)
	h := e.rx.PushHandler(receiver.PushOptions{AuthorizationHeader: ssf.NewSecret("Bearer push-secret")})
	const auth = "Bearer push-secret"

	for name, c := range map[string]struct {
		auth, body string
		status     int
		err        string
	}{
		"no authorization":    {"", sign(t, e, nil), 401, "authentication_failed"},
		"wrong authorization": {"Bearer nope", sign(t, e, nil), 401, "authentication_failed"},
		"not a JWT":           {auth, "hello", 400, "invalid_request"},
		"wrong audience":      {auth, sign(t, e, func(s *ssf.SET) { s.Audience = []string{"https://other.example"} }), 400, "invalid_audience"},
		"wrong issuer":        {auth, sign(t, e, func(s *ssf.SET) { s.Issuer = "https://evil.example" }), 400, "invalid_issuer"},
		"unregistered event": {auth, sign(t, e, func(s *ssf.SET) {
			s.Event = caep.RiskLevelChange{Principal: caep.PrincipalUser, CurrentLevel: caep.RiskLow}
			s.Subject = ssf.IssSubSubject{Issuer: "https://i", Subject: "s"}
		}), 202, ""}, // registered in the Registry, just no handler: acknowledged
		"verification with unknown state": {auth, sign(t, e, func(s *ssf.SET) {
			s.Subject = ssf.OpaqueSubject{ID: "stream-1"}
			s.Event = ssf.Verification{State: "never-requested"}
		}), 400, "invalid_state"},
		"unsolicited verification": {auth, sign(t, e, func(s *ssf.SET) {
			s.Subject = ssf.OpaqueSubject{ID: "stream-1"}
			s.Event = ssf.Verification{}
		}), 202, ""},
	} {
		t.Run(name, func(t *testing.T) {
			got := push(t, h, c.auth, c.body)
			if got.status != c.status || got.err != c.err {
				t.Fatalf("got %d %q, want %d %q", got.status, got.err, c.status, c.err)
			}
			if c.status == 400 && got.lang != "en" {
				t.Errorf("Content-Language = %q", got.lang)
			}
		})
	}
	if n, _ := rec.counts(); n != 0 {
		t.Errorf("a rejected SET reached the handler")
	}

	req := httptest.NewRequest("GET", "/events", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d", w.Code)
	}
}

func TestPushReplayAndRetry(t *testing.T) {
	e := newEnv(t)
	var rec recorder
	rec.install(e.rx)
	h := e.rx.PushHandler(receiver.PushOptions{})
	token := sign(t, e, nil)

	rec.fail.Store(1)
	if got := push(t, h, "", token); got.status != 500 {
		t.Fatalf("failing handler: %d, want 500 so the Transmitter retries", got.status)
	}
	if got := push(t, h, "", token); got.status != 202 {
		t.Fatalf("retry: %d", got.status)
	}
	if got := push(t, h, "", token); got.status != 202 {
		t.Fatalf("duplicate: %d, want 202 (RFC 8935 §2)", got.status)
	}
	if n, _ := rec.counts(); n != 1 {
		t.Errorf("handled %d times, want exactly once", n)
	}
}

func TestPushRedeliveryDuringHandling(t *testing.T) {
	e := newEnv(t)
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	receiver.On(e.rx, func(context.Context, ssf.SET, caep.SessionRevoked) error {
		if calls.Add(1) == 1 {
			close(started)
			<-release
			return errors.New("handler failed")
		}
		return nil
	})
	h := e.rx.PushHandler(receiver.PushOptions{})
	token := sign(t, e, nil)

	// The Transmitter gives up on a slow first delivery and retries while
	// it is still being handled. The retry must not be acknowledged before
	// the first copy's outcome is known (RFC 8935 §2).
	first := make(chan pushResult, 1)
	go func() { first <- push(t, h, "", token) }()
	<-started
	retry := make(chan pushResult, 1)
	go func() { retry <- push(t, h, "", token) }()
	select {
	case got := <-retry:
		t.Fatalf("retry answered %d while the first copy was being handled", got.status)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if got := <-first; got.status != 500 {
		t.Errorf("first delivery: %d, want 500", got.status)
	}
	if got := <-retry; got.status != 500 {
		t.Errorf("retry during the failed handling: %d, want 500 so the Transmitter retries again", got.status)
	}
	// The next retry is handled afresh.
	if got := push(t, h, "", token); got.status != 202 || calls.Load() != 2 {
		t.Errorf("later retry: %d after %d handler calls, want 202 after 2", got.status, calls.Load())
	}
}

func TestKeyRotation(t *testing.T) {
	now := time.Now()
	e := newEnv(t, func(c *receiver.Config) { c.Now = func() time.Time { return now } })
	h := e.rx.PushHandler(receiver.PushOptions{})
	var rec recorder
	rec.install(e.rx)

	// The Transmitter rotates to a new key, published alongside the old.
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e.rotate(newKey)
	set := ssf.SET{Issuer: e.cfg.Issuer, Audience: []string{audience}, JWTID: "rotated", IssuedAt: now, Subject: alice, Event: revoked()}
	tok, err := setcodec.Encode(setcodec.Signer{Key: newKey, Algorithm: ssf.RS256, KeyID: "k2"}, set)
	if err != nil {
		t.Fatal(err)
	}
	// Within a minute of the last fetch the Receiver will not refetch.
	if got := push(t, h, "", tok); got.status != 400 || got.err != "invalid_key" {
		t.Fatalf("before the refetch interval: %d %q", got.status, got.err)
	}
	now = now.Add(2 * time.Minute)
	if got := push(t, h, "", tok); got.status != 202 {
		t.Fatalf("after rotation: %d %q", got.status, got.err)
	}
}

func (e *env) rotate(newKey *rsa.PrivateKey) {
	e.t.Helper()
	tx, err := transmitter.New(transmitter.Config{
		Limits:      transmitter.RecommendedLimits(),
		PushRetry:   transmitter.RecommendedPushRetry(),
		PermitEvent: transmitter.PermitAll,
		Issuer:      e.cfg.Issuer,
		SigningKeys: []transmitter.SigningKey{
			{Signer: newKey, Algorithm: ssf.RS256, KeyID: "k2"},
			{Signer: signingKey(e.t), Algorithm: ssf.RS256, KeyID: "k1"},
		},
		EventsSupported: []ssf.EventType{caep.SessionRevokedEventType},
		DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPoll},
		DefaultSubjects: ssf.DefaultSubjectsAll,
		Store:           e.store,
		Authorize:       func(context.Context, string) (transmitter.Receiver, error) { return transmitter.Receiver{}, nil },
		Logger:          quiet,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.txSrv.Config.Handler = tx.Handler()
}

func TestKeyMaxAge(t *testing.T) {
	now := time.Now()
	e := newEnv(t, func(c *receiver.Config) {
		c.Now = func() time.Time { return now }
		c.Limits.KeyMaxAge = time.Hour
	})
	h := e.rx.PushHandler(receiver.PushOptions{})
	// The Transmitter retires k1 entirely: only k2 is published.
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := transmitter.New(transmitter.Config{
		Limits:          transmitter.RecommendedLimits(),
		PushRetry:       transmitter.RecommendedPushRetry(),
		PermitEvent:     transmitter.PermitAll,
		Issuer:          e.cfg.Issuer,
		SigningKeys:     []transmitter.SigningKey{{Signer: newKey, Algorithm: ssf.RS256, KeyID: "k2"}},
		EventsSupported: []ssf.EventType{caep.SessionRevokedEventType},
		DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPoll},
		DefaultSubjects: ssf.DefaultSubjectsAll,
		Store:           e.store,
		Authorize:       func(context.Context, string) (transmitter.Receiver, error) { return transmitter.Receiver{}, nil },
		Logger:          quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.txSrv.Config.Handler = tx.Handler()

	oldSigned := sign(t, e, func(s *ssf.SET) { s.IssuedAt = now; s.JWTID = "old" })
	if got := push(t, h, "", oldSigned); got.status != 202 {
		t.Fatalf("within KeyMaxAge the cached k1 is still trusted: %d %q", got.status, got.err)
	}
	now = now.Add(2 * time.Hour)
	oldSigned = sign(t, e, func(s *ssf.SET) { s.IssuedAt = now; s.JWTID = "old-2" })
	if got := push(t, h, "", oldSigned); got.status != 400 || got.err != "invalid_key" {
		t.Fatalf("after KeyMaxAge the retired k1 must no longer verify: %d %q", got.status, got.err)
	}

	// With the JWKS endpoint down, the keys already held stay in use.
	e.txSrv.Config.Handler = http.NotFoundHandler()
	now = now.Add(2 * time.Hour)
	set := ssf.SET{Issuer: e.cfg.Issuer, Audience: []string{audience}, JWTID: "new", IssuedAt: now, Subject: alice, Event: revoked()}
	tok, _ := setcodec.Encode(setcodec.Signer{Key: newKey, Algorithm: ssf.RS256, KeyID: "k2"}, set)
	if got := push(t, h, "", tok); got.status != 202 {
		t.Fatalf("an unavailable JWKS endpoint must not drop the cached keys: %d %q", got.status, got.err)
	}
}

// TestCriticalSubjectMembers checks SSF 1.0 §3.6: an event whose subject
// has a member the Transmitter declares critical and the Receiver does not
// process is discarded.
func TestCriticalSubjectMembers(t *testing.T) {
	e := newEnv(t)
	tx, err := transmitter.New(transmitter.Config{
		Limits:                 transmitter.RecommendedLimits(),
		PushRetry:              transmitter.RecommendedPushRetry(),
		PermitEvent:            transmitter.PermitAll,
		Issuer:                 e.cfg.Issuer,
		SigningKeys:            []transmitter.SigningKey{{Signer: signingKey(t), Algorithm: ssf.RS256, KeyID: "k1"}},
		EventsSupported:        []ssf.EventType{caep.SessionRevokedEventType},
		DeliveryMethods:        []ssf.DeliveryMethod{ssf.DeliveryPoll},
		DefaultSubjects:        ssf.DefaultSubjectsAll,
		CriticalSubjectMembers: []string{"tenant", "x_region"},
		Store:                  e.store,
		Authorize:              func(context.Context, string) (transmitter.Receiver, error) { return transmitter.Receiver{}, nil },
		Logger:                 quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.txSrv.Config.Handler = tx.Handler()

	complexWith := func(extra string) ssf.Subject {
		s := ssf.ComplexSubject{User: alice, Tenant: ssf.OpaqueSubject{ID: "t1"}}
		if extra != "" {
			s.Additional = map[string]ssf.Subject{extra: ssf.OpaqueSubject{ID: "v"}}
		}
		return s
	}
	for _, c := range []struct {
		name    string
		members []string
		subject ssf.Subject
		status  int
	}{
		{"simple subject", nil, alice, 202},
		{"critical standard member", nil, complexWith(""), 202},
		{"non-critical unknown member", nil, complexWith("x_other"), 202},
		{"critical unknown member", nil, complexWith("x_region"), 400},
		{"critical member the application processes", []string{"x_region"}, complexWith("x_region"), 202},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := e.cfg
			cfg.SubjectMembers = c.members
			cfg.ReplayStore = memstore.NewReplayStore()
			rx, err := receiver.New(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			var handled atomic.Bool
			receiver.On(rx, func(context.Context, ssf.SET, caep.SessionRevoked) error { handled.Store(true); return nil })
			got := push(t, rx.PushHandler(receiver.PushOptions{}), "", sign(t, e, func(s *ssf.SET) { s.Subject = c.subject }))
			if got.status != c.status {
				t.Fatalf("status = %d %q, want %d", got.status, got.err, c.status)
			}
			if handled.Load() != (c.status == 202) {
				t.Errorf("handler called = %v", handled.Load())
			}
		})
	}
}

func TestAudienceMismatch(t *testing.T) {
	e := newEnv(t, func(c *receiver.Config) { c.Audience = "https://not-what-the-transmitter-assigns.example" })
	c, err := e.rx.CreateStream(context.Background(), receiver.StreamRequest{})
	if !errors.Is(err, receiver.ErrAudienceMismatch) || c.StreamID == "" {
		t.Fatalf("CreateStream = %+v, %v; want the stream and ErrAudienceMismatch", c, err)
	}
}

func TestIssuerMismatch(t *testing.T) {
	e := newEnv(t)
	// The Transmitter answers stream creation with a foreign "iss".
	endpoint, err := url.Parse(e.rx.Metadata().ConfigurationEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	tx := e.txSrv.Config.Handler
	e.txSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != endpoint.Path {
			tx.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		tx.ServeHTTP(rec, r)
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Errorf("create response: %v", err)
		}
		body["iss"] = "https://elsewhere.example"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rec.Code)
		_ = json.NewEncoder(w).Encode(body)
	})
	ctx := context.Background()
	c, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if !errors.Is(err, receiver.ErrIssuerMismatch) || c.StreamID == "" {
		t.Fatalf("CreateStream = %+v, %v; want the stream and ErrIssuerMismatch", c, err)
	}
	// The caller can still remove the stream it refused.
	if err := e.rx.DeleteStream(ctx, c.StreamID); err != nil {
		t.Errorf("DeleteStream: %v", err)
	}
}

func TestNilDeliveryRequestsPoll(t *testing.T) {
	e := newEnv(t)
	var bodies []map[string]any
	tx := e.txSrv.Config.Handler
	e.txSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			raw, _ := io.ReadAll(r.Body)
			var body map[string]any
			if json.Unmarshal(raw, &body) == nil {
				bodies = append(bodies, body)
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
		}
		tx.ServeHTTP(w, r)
	})
	ctx := context.Background()
	c, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.rx.ReplaceStream(ctx, c.StreamID, receiver.StreamRequest{}); err != nil {
		t.Fatal(err)
	}
	// "delivery" is required (SSF 1.0 §8.1.1): a nil Delivery is sent as
	// poll, not left for the Transmitter to default.
	if len(bodies) != 2 {
		t.Fatalf("saw %d create/replace requests, want 2", len(bodies))
	}
	for i, body := range bodies {
		d, _ := body["delivery"].(map[string]any)
		if d["method"] != string(ssf.DeliveryPoll) {
			t.Errorf("request %d delivery = %v, want poll", i, body["delivery"])
		}
	}
}

func TestNotProcessed(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	// The Transmitter accepts every change but cannot decide yet
	// (SSF 1.0 §8.1.1.3, §8.1.1.4, §8.1.2.2).
	tx := e.txSrv.Config.Handler
	e.txSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			tx.ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	desc := "changed"
	if _, err := e.rx.UpdateStream(ctx, c.StreamID, receiver.StreamUpdate{Description: &desc}); !errors.Is(err, receiver.ErrNotProcessed) {
		t.Errorf("UpdateStream = %v, want ErrNotProcessed", err)
	}
	if _, err := e.rx.ReplaceStream(ctx, c.StreamID, receiver.StreamRequest{}); !errors.Is(err, receiver.ErrNotProcessed) {
		t.Errorf("ReplaceStream = %v, want ErrNotProcessed", err)
	}
	if s, err := e.rx.SetStatus(ctx, c.StreamID, ssf.StreamPaused, ""); !errors.Is(err, receiver.ErrNotProcessed) || s.Status != "" {
		t.Errorf("SetStatus = %+v, %v; want an empty state and ErrNotProcessed", s, err)
	}
}

func TestManagementErrors(t *testing.T) {
	e := newEnv(t, func(c *receiver.Config) { c.TokenSource = receiver.StaticToken("wrong") })
	_, err := e.rx.CreateStream(context.Background(), receiver.StreamRequest{})
	var apiErr *receiver.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("CreateStream with a bad token = %v", err)
	}
	if _, err := receiver.StaticToken("").Token(context.Background()); err == nil {
		t.Error("empty static token accepted")
	}
}

func TestSubjectsAndStatus(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	stream, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.rx.RemoveSubject(ctx, stream.StreamID, alice); err != nil {
		t.Fatal(err)
	}
	verified := true
	if err := e.rx.AddSubject(ctx, stream.StreamID, alice, &verified); err != nil {
		t.Fatal(err)
	}
	if st, err := e.rx.SetStatus(ctx, stream.StreamID, ssf.StreamPaused, "maintenance"); err != nil || st.Status != ssf.StreamPaused {
		t.Fatalf("SetStatus = %+v, %v", st, err)
	}
	desc := "renamed"
	if c, err := e.rx.UpdateStream(ctx, stream.StreamID, receiver.StreamUpdate{Description: &desc}); err != nil || c.Description != desc {
		t.Fatalf("UpdateStream = %+v, %v", c, err)
	}
	if c, err := e.rx.ReplaceStream(ctx, stream.StreamID, receiver.StreamRequest{Description: "replaced"}); err != nil || c.Description != "replaced" {
		t.Fatalf("ReplaceStream = %+v, %v", c, err)
	}
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

// tokenServer is a client-credentials token endpoint for ClientCredentials.
func TestClientCredentials(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = r.ParseForm()
		id, secret, basic := r.BasicAuth()
		if !basic {
			id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		if id != "client" || secret != "s3cret" || r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("scope") != "ssf.read ssf.manage" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"tok-`+string(rune('0'+calls.Load()))+`","token_type":"Bearer","expires_in":3600}`)
	}))
	defer srv.Close()

	for _, method := range []receiver.ClientAuthMethod{receiver.ClientSecretBasic, receiver.ClientSecretPost} {
		calls.Store(0)
		cc := &receiver.ClientCredentials{
			TokenURL: srv.URL, ClientID: "client", ClientSecret: ssf.NewSecret("s3cret"),
			Scopes: []string{"ssf.read", "ssf.manage"}, AuthMethod: method, HTTPClient: srv.Client(),
		}
		first, err := cc.Token(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		if again, _ := cc.Token(context.Background()); again != first || calls.Load() != 1 {
			t.Errorf("%s: token not cached (%d calls)", method, calls.Load())
		}
		cc.Invalidate()
		if next, _ := cc.Token(context.Background()); next == first {
			t.Errorf("%s: Invalidate did not force a new token", method)
		}
	}
	bad := &receiver.ClientCredentials{TokenURL: srv.URL, ClientID: "client", ClientSecret: ssf.NewSecret("wrong"), AuthMethod: receiver.ClientSecretBasic, HTTPClient: srv.Client()}
	if _, err := bad.Token(context.Background()); err == nil {
		t.Error("wrong secret accepted")
	}
	unknown := &receiver.ClientCredentials{TokenURL: srv.URL, ClientID: "c", ClientSecret: ssf.NewSecret("s"), AuthMethod: "tls_client_auth"}
	if _, err := unknown.Token(context.Background()); err == nil {
		t.Error("unsupported auth method accepted")
	}
	noKey := &receiver.ClientCredentials{TokenURL: srv.URL, ClientID: "c", AuthMethod: receiver.PrivateKeyJWT}
	if _, err := noKey.Token(context.Background()); err == nil {
		t.Error("private_key_jwt without a key accepted")
	}
}

// validAssertion checks a token request's client assertion as an
// authorization server would (RFC 7523 §3): HS256 against the shared
// secret, PS256 against the client's public key.
func validAssertion(r *http.Request, tokenURL, secret string, key *rsa.PrivateKey) bool {
	_ = r.ParseForm()
	if r.PostForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" || r.PostForm.Get("client_id") != "client" {
		return false
	}
	assertion := r.PostForm.Get("client_assertion")
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return false
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	if claims["iss"] != "client" || claims["sub"] != "client" || claims["aud"] != tokenURL {
		return false
	}
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if strings.Contains(string(header), "HS256") {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(parts[0] + "." + parts[1]))
		return parts[2] == base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	c, err := jose.ParseCompact(assertion)
	return err == nil && c.Verify(&key.PublicKey, ssf.PS256) == nil
}

// TestClientAssertions checks the assertions ClientCredentials sends for
// client_secret_jwt and private_key_jwt verify as an authorization server
// would check them (RFC 7523 §3).
func TestClientAssertions(t *testing.T) {
	secret := strings.Repeat("s", 32)
	key := signingKey(t)
	var tokenURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validAssertion(r, tokenURL, secret, key) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"t","token_type":"Bearer","expires_in":60}`)
	}))
	defer srv.Close()
	tokenURL = srv.URL + "/token"

	for _, cc := range []*receiver.ClientCredentials{
		{TokenURL: tokenURL, ClientID: "client", ClientSecret: ssf.NewSecret(secret), AuthMethod: receiver.ClientSecretJWT, HTTPClient: srv.Client()},
		{TokenURL: tokenURL, ClientID: "client", AuthMethod: receiver.PrivateKeyJWT, SigningKey: key, SigningAlgorithm: ssf.PS256, KeyID: "k", HTTPClient: srv.Client()},
	} {
		if tok, err := cc.Token(context.Background()); err != nil || tok != "t" {
			t.Errorf("%s: %q, %v", cc.AuthMethod, tok, err)
		}
	}
}

// The Receiver finds metadata published at the SSF location, appended to
// the issuer, at RISC's location, or at an explicit MetadataURL — but
// moves on only from a location that does not exist.
func TestMetadataLocations(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tx := e.txSrv.Config.Handler
	ssfPath := "/.well-known/ssf-configuration/tx"
	// publish serves the Transmitter's metadata at path only; status, if
	// set, answers the SSF location instead of 404.
	publish := func(path string, status int) {
		e.txSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == path:
				r.URL.Path = ssfPath
				tx.ServeHTTP(w, r)
			case r.URL.Path == ssfPath && status != 0:
				w.WriteHeader(status)
			case strings.Contains(r.URL.Path, "/.well-known/"), r.URL.Path == "/custom/metadata":
				http.NotFound(w, r)
			default:
				tx.ServeHTTP(w, r)
			}
		})
	}
	for name, c := range map[string]struct {
		path, metadataURL string
		status            int
		ok                bool
	}{
		"SSF location":                         {path: ssfPath, ok: true},
		"appended to the issuer":               {path: "/tx/.well-known/ssf-configuration", ok: true},
		"RISC location":                        {path: "/.well-known/risc-configuration/tx", ok: true},
		"MetadataURL":                          {path: "/custom/metadata", metadataURL: "/custom/metadata", ok: true},
		"elsewhere without MetadataURL":        {path: "/custom/metadata"},
		"MetadataURL replaces the search":      {path: ssfPath, metadataURL: "/custom/metadata"},
		"no fallback past a server error":      {path: "/tx/.well-known/ssf-configuration", status: http.StatusInternalServerError},
		"fallback past a resource that's gone": {path: "/tx/.well-known/ssf-configuration", status: http.StatusGone, ok: true},
	} {
		t.Run(name, func(t *testing.T) {
			publish(c.path, c.status)
			cfg := e.cfg
			if c.metadataURL != "" {
				cfg.MetadataURL = e.txSrv.URL + c.metadataURL
			}
			_, err := receiver.New(ctx, cfg)
			if c.ok && err != nil {
				t.Errorf("New: %v", err)
			}
			if !c.ok && err == nil {
				t.Error("New succeeded")
			}
		})
	}
	cfg := e.cfg
	cfg.MetadataURL = "http://tx.example/metadata"
	if _, err := receiver.New(ctx, cfg); err == nil || !strings.Contains(err.Error(), "MetadataURL") {
		t.Errorf("an http MetadataURL: %v", err)
	}
}

// One stream failing its checks does not hide the others: Streams returns
// those that pass and reports the rest, so the caller can delete them.
func TestStreamsReportsRejectedStreams(t *testing.T) {
	e := newEnvTx(t, func(c *transmitter.Config) { c.MultipleStreamsPerReceiver = true })
	ctx := context.Background()
	good, err := e.rx.CreateStream(ctx, receiver.StreamRequest{Description: "good"})
	if err != nil {
		t.Fatal(err)
	}
	bad, err := e.rx.CreateStream(ctx, receiver.StreamRequest{Description: "bad"})
	if err != nil {
		t.Fatal(err)
	}
	// The Transmitter's list names another issuer on one stream.
	endpoint, err := url.Parse(e.rx.Metadata().ConfigurationEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	tx := e.txSrv.Config.Handler
	e.txSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != endpoint.Path || r.URL.RawQuery != "" {
			tx.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		tx.ServeHTTP(rec, r)
		var list []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Errorf("list response: %v", err)
		}
		for _, c := range list {
			if c["stream_id"] == bad.StreamID {
				c["iss"] = "https://elsewhere.example"
			}
		}
		_ = json.NewEncoder(w).Encode(list)
	})

	streams, err := e.rx.Streams(ctx)
	if len(streams) != 1 || streams[0].StreamID != good.StreamID {
		t.Errorf("Streams returned %v, want only the good stream", streams)
	}
	var se *receiver.StreamsError
	if !errors.As(err, &se) || len(se.Rejected) != 1 || se.Rejected[0].Stream.StreamID != bad.StreamID {
		t.Fatalf("Streams error = %v, want a StreamsError naming the bad stream", err)
	}
	if !errors.Is(err, receiver.ErrIssuerMismatch) {
		t.Errorf("errors.Is(%v, ErrIssuerMismatch) = false", err)
	}
	if err := e.rx.DeleteStream(ctx, se.Rejected[0].Stream.StreamID); err != nil {
		t.Errorf("deleting the rejected stream: %v", err)
	}
}
