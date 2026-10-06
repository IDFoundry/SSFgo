package receiver_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/internal/setcodec"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

// A SET older than ReplayWindow is rejected, so a captured SET cannot be
// replayed once its replay record has expired.
func TestStaleSETRejected(t *testing.T) {
	e := newEnv(t, func(c *receiver.Config) { c.Limits.ReplayWindow = 2 * time.Second })
	var handled atomic.Int32
	receiver.On(e.rx, func(context.Context, ssf.SET, caep.SessionRevoked) error { handled.Add(1); return nil })
	h := e.rx.PushHandler(receiver.PushOptions{})
	tok := sign(t, e, func(s *ssf.SET) { s.IssuedAt = time.Now(); s.JWTID = "captured" })
	push(t, h, "", tok)
	time.Sleep(2200 * time.Millisecond) // past the window: "iat" has whole-second precision
	got := push(t, h, "", tok)
	if got.status != 400 || got.err != "invalid_request" || handled.Load() != 1 {
		t.Errorf("replay after the window: %d %q, handled %d times; want 400 invalid_request, handled once", got.status, got.err, handled.Load())
	}
}

// A same-host https->http redirect is refused rather than followed with
// the bearer token (net/http would copy Authorization to it).
func TestRedirectToHTTPRefused(t *testing.T) {
	var leaked atomic.Value
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNotFound)
	}))
	defer plain.Close()
	e := newEnv(t)
	// The Transmitter's configuration endpoint now redirects to plain HTTP
	// on the same host (httptest servers share 127.0.0.1).
	e.txSrv.Config.Handler = http.RedirectHandler(plain.URL+"/steal", http.StatusFound)
	_, err := e.rx.CreateStream(context.Background(), receiver.StreamRequest{})
	if err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Errorf("CreateStream = %v, want the redirect refused", err)
	}
	if v, _ := leaked.Load().(string); v != "" {
		t.Errorf("bearer token sent over plain HTTP after a redirect: %q", v)
	}
}

// After a handler panic the SET is forgotten, so the Transmitter's retry
// is handled instead of being acknowledged as a duplicate.
func TestHandlerPanicAllowsRedelivery(t *testing.T) {
	e := newEnv(t, func(c *receiver.Config) { c.ReplayStore = memstore.NewReplayStore() })
	var calls atomic.Int32
	receiver.On(e.rx, func(context.Context, ssf.SET, caep.SessionRevoked) error {
		if calls.Add(1) == 1 {
			panic("handler bug")
		}
		return nil
	})
	srv := httptest.NewServer(e.rx.PushHandler(receiver.PushOptions{}))
	defer srv.Close()
	tok := sign(t, e, func(s *ssf.SET) { s.JWTID = "panics-once" })
	for range 2 {
		res, err := http.Post(srv.URL, "application/secevent+jwt", strings.NewReader(tok))
		if err == nil {
			res.Body.Close()
		}
	}
	if calls.Load() < 2 {
		t.Errorf("after a handler panic the retry was treated as a duplicate; handler ran %d time(s)", calls.Load())
	}
}

func TestTokenURLMustBeHTTPS(t *testing.T) {
	cc := &receiver.ClientCredentials{TokenURL: "http://as.example/token", ClientID: "c", ClientSecret: ssf.NewSecret("s"), AuthMethod: receiver.ClientSecretBasic}
	if _, err := cc.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("Token with an http TokenURL = %v", err)
	}
}

// forgedUnknownKid is a junk SET naming a key the Transmitter never
// published: anyone who can reach a push endpoint can send it.
func forgedUnknownKid() string {
	b := base64.RawURLEncoding.EncodeToString
	return b([]byte(`{"alg":"RS256","typ":"secevent+jwt","kid":"attacker"}`)) + "." + b([]byte(`{}`)) + "." + b([]byte("sig"))
}

// pushAndHangUp pushes body on a request whose client has already gone.
func pushAndHangUp(h http.Handler, body string) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)).WithContext(ctx))
}

// A push client that hangs up must not cancel the JWKS refetch its SET
// triggered, nor use up the refetch allowance: otherwise anyone who can
// reach the push endpoint could, once a minute, keep the Receiver from
// ever learning the Transmitter's rotated key.
func TestKeyRefreshSurvivesHungUpPusher(t *testing.T) {
	now := time.Now()
	e := newEnv(t, func(c *receiver.Config) { c.Now = func() time.Time { return now } })
	h := e.rx.PushHandler(receiver.PushOptions{})
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e.rotate(newKey)
	for i := range 3 {
		now = now.Add(2 * time.Minute)
		pushAndHangUp(h, forgedUnknownKid())
		set := ssf.SET{Issuer: e.cfg.Issuer, Audience: []string{audience}, JWTID: fmt.Sprint("rotated-", i), IssuedAt: now, Subject: alice, Event: revoked()}
		tok, err := setcodec.Encode(setcodec.Signer{Key: newKey, Algorithm: ssf.RS256, KeyID: "k2"}, set)
		if err != nil {
			t.Fatal(err)
		}
		if got := push(t, h, "", tok); got.status != 202 {
			t.Fatalf("minute %d: a SET signed with the rotated key got %d %q after a hung-up push", i, got.status, got.err)
		}
	}
}

// Likewise a hung-up push must not keep a retired key trusted past
// KeyMaxAge.
func TestKeyMaxAgeSurvivesHungUpPusher(t *testing.T) {
	now := time.Now()
	e := newEnv(t, func(c *receiver.Config) {
		c.Now = func() time.Time { return now }
		c.Limits.KeyMaxAge = time.Hour
	})
	h := e.rx.PushHandler(receiver.PushOptions{})
	// The Transmitter retires k1, publishing no keys at all.
	e.txSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	now = now.Add(2 * time.Hour)
	pushAndHangUp(h, "junk")
	retired := sign(t, e, func(s *ssf.SET) { s.IssuedAt = now; s.JWTID = "retired" })
	if got := push(t, h, "", retired); got.status == 202 {
		t.Error("a SET signed with the retired key was accepted after KeyMaxAge")
	}
}

// The Receiver sends its access token only to the issuer's origin unless
// told otherwise, so neither the Transmitter's metadata nor a stream
// configuration can steer it to another host.
func TestAccessTokenStaysOnTrustedOrigins(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// The metadata points the stream management API elsewhere.
	tx := e.txSrv.Config.Handler
	e.txSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/.well-known/") {
			tx.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		tx.ServeHTTP(rec, r)
		var md map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &md); err != nil {
			t.Fatal(err)
		}
		md["configuration_endpoint"] = "https://elsewhere.example/streams"
		_ = json.NewEncoder(w).Encode(md)
	})
	if _, err := receiver.New(ctx, e.cfg); err == nil || !strings.Contains(err.Error(), "TrustedOrigins") {
		t.Errorf("New with an off-origin configuration_endpoint = %v, want an error naming TrustedOrigins", err)
	}
	trusting := e.cfg
	trusting.TrustedOrigins = []string{"https://elsewhere.example"}
	if _, err := receiver.New(ctx, trusting); err != nil {
		t.Errorf("New trusting that origin: %v", err)
	}
	for _, bad := range []string{"http://elsewhere.example", "https://elsewhere.example/path", "https://user@elsewhere.example", "elsewhere.example"} {
		cfg := e.cfg
		cfg.TrustedOrigins = []string{bad}
		if _, err := receiver.New(ctx, cfg); err == nil {
			t.Errorf("TrustedOrigins %q accepted", bad)
		}
	}

	// A stream configuration cannot steer the token either.
	e.txSrv.Config.Handler = tx
	stream := ssf.StreamConfiguration{StreamID: "s", Delivery: ssf.Delivery{Method: ssf.DeliveryPoll, EndpointURL: "https://elsewhere.example/poll"}}
	if _, err := e.rx.Poll(ctx, stream, receiver.PollOptions{}); err == nil || !strings.Contains(err.Error(), "TrustedOrigins") {
		t.Errorf("Poll at an off-origin endpoint = %v, want a refusal", err)
	}
}

// countingHandler counts log records.
type countingHandler struct{ n atomic.Int64 }

func (h *countingHandler) Enabled(context.Context, slog.Level) bool  { return true }
func (h *countingHandler) Handle(context.Context, slog.Record) error { h.n.Add(1); return nil }
func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler        { return h }
func (h *countingHandler) WithGroup(string) slog.Handler             { return h }

// One poll response cannot make the Receiver handle, or log, without
// bound: a Transmitter that ignores maxEvents gets the rest delivered
// again later.
func TestPollResponseBounded(t *testing.T) {
	logs := &countingHandler{}
	e := newEnv(t, func(c *receiver.Config) { c.Logger = slog.New(logs) })
	ctx := context.Background()
	stream, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	const junk = 5000
	tx := e.txSrv.Config.Handler
	e.txSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != strings.TrimPrefix(stream.Delivery.EndpointURL, e.txSrv.URL) {
			tx.ServeHTTP(w, r)
			return
		}
		sets := make(map[string]string, junk)
		for i := range junk {
			sets[fmt.Sprint(i)] = "x"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sets": sets})
	})
	logs.n.Store(0)
	res, err := e.rx.Poll(ctx, stream, receiver.PollOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.MoreAvailable {
		t.Error("MoreAvailable not set although SETs were left for redelivery")
	}
	if n := logs.n.Load(); n > 11 {
		t.Errorf("one poll response produced %d log records", n)
	}

	// The SETs left over are not acknowledged or reported.
	var reported int
	e.txSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Ack     []string       `json:"ack"`
			SetErrs map[string]any `json:"setErrs"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		reported = len(req.Ack) + len(req.SetErrs)
		_, _ = w.Write([]byte(`{"sets":{}}`))
	})
	if err := e.rx.Acknowledge(ctx, stream); err != nil {
		t.Fatal(err)
	}
	if reported != 1000 {
		t.Errorf("reported %d SETs back, want the 1000 handled", reported)
	}
}

// A Transmitter's error response is kept only in part.
func TestAPIErrorBodyTruncated(t *testing.T) {
	e := newEnv(t)
	e.txSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(strings.Repeat("x", 100_000)))
	})
	_, err := e.rx.CreateStream(context.Background(), receiver.StreamRequest{})
	var apiErr *receiver.APIError
	if !errors.As(err, &apiErr) || len(apiErr.Body) > 1100 {
		t.Errorf("APIError body kept %d bytes", len(apiErr.Body))
	}
}

// A Transmitter that answers long polls at once with nothing does not get
// polled in a busy loop.
func TestRunPollerPausesOnEmptyPolls(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	stream, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var polls atomic.Int64
	e.txSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		polls.Add(1)
		_, _ = w.Write([]byte(`{"sets":{}}`))
	})
	runCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	_ = e.rx.RunPoller(runCtx, stream)
	if n := polls.Load(); n > 3 {
		t.Errorf("%d polls in 1.5s against a Transmitter that ignores long polling", n)
	}
}

// A panicking hook is recovered and logged: KeysRefreshed — whose refetch
// anyone able to push can trigger — and SET alike leave the Receiver
// answering, rather than taking down the process.
func TestHookPanicRecovered(t *testing.T) {
	now := time.Now()
	var logs countingHandler
	e := newEnv(t, func(c *receiver.Config) {
		c.Now = func() time.Time { return now }
		c.Logger = slog.New(&logs)
		// A typical bug: err is nil after a successful refetch.
		c.Hooks.KeysRefreshed = func(_ context.Context, err error) { _ = err.Error() }
		c.Hooks.SET = func(context.Context, receiver.SETInfo) { panic("hook bug") }
	})
	h := e.rx.PushHandler(receiver.PushOptions{})
	now = now.Add(2 * time.Minute)
	if got := push(t, h, "", forgedUnknownKid()); got.status != http.StatusBadRequest {
		t.Errorf("junk push = %d, want 400", got.status)
	}
	if got := push(t, h, "", sign(t, e, nil)); got.status != http.StatusAccepted {
		t.Errorf("valid push after hook panics = %d %q, want 202", got.status, got.err)
	}
	if logs.n.Load() == 0 {
		t.Error("hook panics were not logged")
	}
}

// A TLS alert — the Transmitter requiring a client certificate the
// Receiver does not have — will not clear by waiting, so EnsureStream
// returns it at once instead of retrying until its context ends.
func TestEnsureStreamTLSAlertNotRetried(t *testing.T) {
	receiver.SetEnsureRetry(t, 10*time.Millisecond)
	e := newEnv(t)
	e.txSrv.TLS.ClientAuth = tls.RequireAnyClientCert
	e.txSrv.CloseClientConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	_, err := e.rx.EnsureStream(ctx, receiver.StreamRequest{})
	if err == nil || errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Errorf("EnsureStream = %v after %v, want the TLS failure at once", err, time.Since(start))
	}
}

// An APIError's message shows a JSON error's code and description,
// cleaned, and never the raw body: a Transmitter cannot forge log lines
// or flood a log through it.
func TestAPIErrorMessageCleaned(t *testing.T) {
	for body, want := range map[string]string{
		`{"error":"invalid_request","error_description":"bad\nforged: line"}`: ": HTTP 400: invalid_request: bad?forged: line",
		"<html>\nforged: line</html>":                                         ": HTTP 400 (26-byte body)",
		"":                                                                    ": HTTP 400",
	} {
		e := newEnv(t)
		e.txSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(body))
		})
		_, err := e.rx.CreateStream(context.Background(), receiver.StreamRequest{})
		if err == nil || !strings.HasSuffix(err.Error(), want) || strings.Contains(err.Error(), "\n") {
			t.Errorf("body %q: error %q, want it to end %q", body, err, want)
		}
	}
}

// A SET's header is written by whoever pushes it, so a rejection quotes
// it only cleaned and bounded — in the log, the response and the hook.
func TestRejectionDescriptionBounded(t *testing.T) {
	var info receiver.SETInfo
	e := newEnv(t, func(c *receiver.Config) {
		c.Hooks.SET = func(_ context.Context, i receiver.SETInfo) { info = i }
	})
	b := base64.RawURLEncoding.EncodeToString
	header := `{"alg":"RS256","typ":"secevent+jwt","kid":"` + strings.Repeat("X", 40_000) + `\n"}`
	got := push(t, e.rx.PushHandler(receiver.PushOptions{}), "", b([]byte(header))+"."+b([]byte(`{}`))+"."+b([]byte("sig")))
	if got.status != http.StatusBadRequest || len(got.err) > 64 {
		t.Fatalf("push = %d %q", got.status, got.err)
	}
	if info.Err == nil || len(info.Err.Error()) > 512 || strings.ContainsAny(info.Err.Error(), "\n") {
		t.Errorf("hook error kept %d bytes: %.80q", len(fmt.Sprint(info.Err)), info.Err)
	}
}

// A Receiver's credentials are withheld when its configuration is printed
// or logged: a static access token, a client secret, a push
// Authorization header.
func TestCredentialsWithheld(t *testing.T) {
	cfg := receiver.Config{TokenSource: receiver.StaticToken("tok3n-value")}
	cc := &receiver.ClientCredentials{ClientID: "c", ClientSecret: ssf.NewSecret("s3cret-value")}
	opts := receiver.PushOptions{AuthorizationHeader: ssf.NewSecret("Bearer h3ader-value")}
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "token", cfg.TokenSource, "cc", cc, "opts", opts)
	for _, out := range []string{fmt.Sprintf("%v %+v %#v", cfg, cc, opts), fmt.Sprintf("%#v %+v", cfg, cc), buf.String()} {
		if strings.Contains(out, "-value") {
			t.Errorf("a credential was printed: %s", out)
		}
	}
}
