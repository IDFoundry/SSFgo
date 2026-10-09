package receiver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/setcodec"
	"github.com/idfoundry/ssfgo/receiver"
)

// perStreamTransmitter makes the test Transmitter give each stream the
// audience "<audience>/<stream_id>", as some Transmitters do. It returns
// the number of single-stream reads, and a switch that makes them fail.
func perStreamTransmitter(t testing.TB, e *env) (reads *atomic.Int32, failReads *atomic.Bool) {
	t.Helper()
	reads, failReads = new(atomic.Int32), new(atomic.Bool)
	tx := e.txSrv.Config.Handler
	e.txSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Has("stream_id") {
			reads.Add(1)
			if failReads.Load() {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		rec := httptest.NewRecorder()
		tx.ServeHTTP(rec, r)
		body := rec.Body.Bytes()
		var stream map[string]any
		if json.Unmarshal(body, &stream) == nil && stream["stream_id"] != nil {
			stream["aud"] = audience + "/" + stream["stream_id"].(string)
			body, _ = json.Marshal(stream)
		}
		for k, v := range rec.Header() {
			if k != "Content-Length" {
				w.Header()[k] = v
			}
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(body)
	})
	return reads, failReads
}

func perStream(c *receiver.Config) { c.AudiencePerStream = true }

func TestAudiencePerStreamOffByDefault(t *testing.T) {
	e := newEnv(t)
	perStreamTransmitter(t, e)
	c, err := e.rx.CreateStream(context.Background(), receiver.StreamRequest{})
	if !errors.Is(err, receiver.ErrAudienceMismatch) {
		t.Fatalf("CreateStream = %v; want ErrAudienceMismatch", err)
	}
	got := push(t, e.rx.PushHandler(receiver.PushOptions{}), "", sign(t, e, func(s *ssf.SET) {
		s.Audience = []string{audience + "/" + c.StreamID}
	}))
	if got.status != http.StatusBadRequest || got.err != setcodec.CodeInvalidAudience {
		t.Errorf("push = %+v; want 400 %s", got, setcodec.CodeInvalidAudience)
	}
}

func TestAudiencePerStream(t *testing.T) {
	e := newEnv(t, perStream)
	reads, _ := perStreamTransmitter(t, e)
	ctx := context.Background()
	c, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	var rec recorder
	rec.install(e.rx)
	h := e.rx.PushHandler(receiver.PushOptions{})
	for name, aud := range map[string][]string{
		"the stream's audience":  {audience + "/" + c.StreamID},
		"the Receiver's own too": {audience},
		"among others":           {"https://other.example", audience + "/" + c.StreamID},
	} {
		if got := push(t, h, "", sign(t, e, func(s *ssf.SET) { s.Audience = aud })); got.status != http.StatusAccepted {
			t.Errorf("%s: push = %+v; want 202", name, got)
		}
	}
	if n := reads.Load(); n != 0 {
		t.Errorf("the Transmitter was asked about a stream the Receiver created %d times", n)
	}

	for name, aud := range map[string]string{
		"a nested path":        audience + "/" + c.StreamID + "/x",
		"an empty stream ID":   audience + "/",
		"another prefix":       "https://rx.example.org/" + c.StreamID,
		"a stream not its own": audience + "/app",
	} {
		got := push(t, h, "", sign(t, e, func(s *ssf.SET) { s.Audience = []string{aud} }))
		if got.status != http.StatusBadRequest || got.err != setcodec.CodeInvalidAudience {
			t.Errorf("%s: push = %+v; want 400 %s", name, got, setcodec.CodeInvalidAudience)
		}
	}

	// A deleted stream's audience is no longer accepted.
	if err := e.rx.DeleteStream(ctx, c.StreamID); err != nil {
		t.Fatal(err)
	}
	got := push(t, h, "", sign(t, e, func(s *ssf.SET) { s.Audience = []string{audience + "/" + c.StreamID} }))
	if got.status != http.StatusBadRequest || got.err != setcodec.CodeInvalidAudience {
		t.Errorf("deleted stream: push = %+v; want 400 %s", got, setcodec.CodeInvalidAudience)
	}
}

// Another Receiver instance, which has not seen the stream, asks the
// Transmitter about it once, and accepts its SETs.
func TestAudiencePerStreamLooksUpUnknownStream(t *testing.T) {
	e := newEnv(t, perStream)
	reads, failReads := perStreamTransmitter(t, e)
	ctx := context.Background()
	c, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var skew atomic.Int64
	cfg := e.cfg
	cfg.Now = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	other, err := receiver.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := other.PushHandler(receiver.PushOptions{})
	signed := func() string {
		return sign(t, e, func(s *ssf.SET) { s.Audience = []string{audience + "/" + c.StreamID} })
	}

	// The Transmitter cannot answer: the SET is to be delivered again,
	// not rejected, and the Transmitter is not asked again at once.
	failReads.Store(true)
	for range 3 {
		if got := push(t, h, "", signed()); got.status != http.StatusInternalServerError {
			t.Errorf("lookup failing: push = %+v; want 500", got)
		}
	}
	if n := reads.Load(); n != 1 {
		t.Errorf("a failing Transmitter was asked %d times; want once", n)
	}
	failReads.Store(false)
	reads.Store(0)
	skew.Store(int64(11 * time.Second)) // past the wait after a failure
	for range 3 {
		if got := push(t, h, "", signed()); got.status != http.StatusAccepted {
			t.Errorf("push = %+v; want 202", got)
		}
	}
	if n := reads.Load(); n != 1 {
		t.Errorf("the Transmitter was asked %d times; want once", n)
	}
}

// SETs naming a stream that is not the Receiver's are rejected, and the
// Transmitter is asked about that stream at most once a minute.
func TestAudiencePerStreamLookupRateLimited(t *testing.T) {
	e := newEnv(t, perStream)
	reads, _ := perStreamTransmitter(t, e)
	h := e.rx.PushHandler(receiver.PushOptions{})
	for range 5 {
		got := push(t, h, "", sign(t, e, func(s *ssf.SET) { s.Audience = []string{audience + "/app"} }))
		if got.status != http.StatusBadRequest || got.err != setcodec.CodeInvalidAudience {
			t.Errorf("push = %+v; want 400 %s", got, setcodec.CodeInvalidAudience)
		}
	}
	if n := reads.Load(); n != 1 {
		t.Errorf("the Transmitter was asked %d times; want once", n)
	}
}

func TestAudiencePerStreamConfig(t *testing.T) {
	cfg := newEnv(t).cfg
	cfg.Audience = "rp/"
	cfg.AudiencePerStream = true
	_, err := receiver.New(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "AudiencePerStream") {
		t.Errorf("New = %v; want an error naming AudiencePerStream", err)
	}
}

// SETs arriving together for a stream the Receiver has not seen share one
// lookup, and none is rejected while it runs.
func TestAudiencePerStreamConcurrentLookup(t *testing.T) {
	e := newEnv(t, perStream)
	reads, _ := perStreamTransmitter(t, e)
	ctx := context.Background()
	c, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := receiver.New(ctx, e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := other.PushHandler(receiver.PushOptions{})
	tokens := make([]string, 8)
	for i := range tokens {
		tokens[i] = sign(t, e, func(s *ssf.SET) {
			s.Audience = []string{audience + "/" + c.StreamID}
			s.JWTID = fmt.Sprintf("concurrent-%d", i)
		})
	}
	var wg sync.WaitGroup
	for _, tok := range tokens {
		wg.Go(func() {
			if got := push(t, h, "", tok); got.status != http.StatusAccepted {
				t.Errorf("push = %+v; want 202", got)
			}
		})
	}
	wg.Wait()
	if n := reads.Load(); n != 1 {
		t.Errorf("the Transmitter was asked %d times; want once", n)
	}
}

// wrapTx puts a middleware in front of the test Transmitter.
func wrapTx(e *env, mw func(next http.Handler) http.Handler) {
	e.txSrv.Config.Handler = mw(e.txSrv.Config.Handler)
}

// A Transmitter refusing to show another client's stream with 403, not
// 404, is "not this Receiver's" too, and asked about only once: a
// replayed SET cannot make the Receiver read the stream on every push.
func TestAudiencePerStreamForbiddenCached(t *testing.T) {
	e := newEnv(t, perStream)
	reads, _ := perStreamTransmitter(t, e)
	wrapTx(e, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Query().Get("stream_id") == "app" {
				reads.Add(1)
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	h := e.rx.PushHandler(receiver.PushOptions{})
	tok := sign(t, e, func(s *ssf.SET) { s.Audience = []string{audience + "/app"} })
	for range 20 {
		if got := push(t, h, "", tok); got.status != http.StatusBadRequest || got.err != setcodec.CodeInvalidAudience {
			t.Fatalf("push = %+v; want 400 %s", got, setcodec.CodeInvalidAudience)
		}
	}
	if n := reads.Load(); n != 1 {
		t.Errorf("20 pushes of one SET made %d stream reads; want 1", n)
	}
}

// A SET outside the replay window is rejected before any lookup.
func TestAudiencePerStreamOldSETNoLookup(t *testing.T) {
	e := newEnv(t, perStream)
	reads, _ := perStreamTransmitter(t, e)
	tok := sign(t, e, func(s *ssf.SET) {
		s.Audience = []string{audience + "/app"}
		s.IssuedAt = time.Now().Add(-2 * 365 * 24 * time.Hour)
	})
	if got := push(t, e.rx.PushHandler(receiver.PushOptions{}), "", tok); got.status != http.StatusBadRequest {
		t.Errorf("push = %+v; want 400", got)
	}
	if n := reads.Load(); n != 0 {
		t.Errorf("an expired SET made %d stream reads", n)
	}
}

// A lookup under way when DeleteStream returns cannot bring the deleted
// stream back.
func TestAudiencePerStreamDeleteDuringLookup(t *testing.T) {
	e := newEnv(t, perStream)
	perStreamTransmitter(t, e)
	ctx := context.Background()
	c, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := receiver.New(ctx, e.cfg) // has not seen the stream
	if err != nil {
		t.Fatal(err)
	}
	inGet, release := make(chan struct{}), make(chan struct{})
	var gated atomic.Bool
	gated.Store(true)
	wrapTx(e, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Query().Get("stream_id") == c.StreamID && gated.CompareAndSwap(true, false) {
				rec := httptest.NewRecorder()
				next.ServeHTTP(rec, r) // the stream still exists now...
				close(inGet)
				<-release // ...but the answer arrives after the delete
				for k, v := range rec.Header() {
					w.Header()[k] = v
				}
				w.WriteHeader(rec.Code)
				_, _ = w.Write(rec.Body.Bytes())
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	h := other.PushHandler(receiver.PushOptions{})
	aud := func(jti string) func(*ssf.SET) {
		return func(s *ssf.SET) { s.Audience = []string{audience + "/" + c.StreamID}; s.JWTID = jti }
	}
	first := make(chan pushResult)
	tok := sign(t, e, aud("during"))
	go func() { first <- push(t, h, "", tok) }()
	<-inGet
	if err := other.DeleteStream(ctx, c.StreamID); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-first
	if got := push(t, h, "", sign(t, e, aud("after"))); got.status == http.StatusAccepted {
		t.Errorf("after DeleteStream: push = %+v; want refused", got)
	}
}

// A stream known to be this Receiver's is confirmed again after a while,
// so one deleted by another instance stops being accepted.
func TestAudiencePerStreamFoundExpires(t *testing.T) {
	e := newEnv(t, perStream)
	perStreamTransmitter(t, e)
	ctx := context.Background()
	c, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var skew atomic.Int64
	cfg := e.cfg
	cfg.Now = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	other, err := receiver.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := other.PushHandler(receiver.PushOptions{})
	aud := func(jti string) func(*ssf.SET) {
		return func(s *ssf.SET) {
			s.Audience = []string{audience + "/" + c.StreamID}
			s.JWTID = jti
			s.IssuedAt = cfg.Now()
		}
	}
	if got := push(t, h, "", sign(t, e, aud("a"))); got.status != http.StatusAccepted {
		t.Fatalf("push = %+v", got)
	}
	if err := e.rx.DeleteStream(ctx, c.StreamID); err != nil { // another instance
		t.Fatal(err)
	}
	skew.Store(int64(61 * time.Minute))
	if got := push(t, h, "", sign(t, e, aud("b"))); got.status != http.StatusBadRequest {
		t.Errorf("an hour after another instance deleted it: push = %+v; want 400", got)
	}
}

// The push that starts a lookup waits for it no longer than its own
// context allows.
func TestAudiencePerStreamLookupHonoursCaller(t *testing.T) {
	e := newEnv(t, perStream)
	perStreamTransmitter(t, e)
	unblock := make(chan struct{})
	t.Cleanup(func() { close(unblock) })
	wrapTx(e, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Query().Get("stream_id") == "slow" {
				<-unblock
			}
			next.ServeHTTP(w, r)
		})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(sign(t, e, func(s *ssf.SET) {
		s.Audience = []string{audience + "/slow"}
	}))).WithContext(ctx)
	start := time.Now()
	rec := httptest.NewRecorder()
	e.rx.PushHandler(receiver.PushOptions{}).ServeHTTP(rec, req)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("push with a 100ms context returned after %v", d)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("push = %d; want 500, to be delivered again", rec.Code)
	}
}

type panickyTokens struct{ armed atomic.Bool }

func (p *panickyTokens) Token(context.Context) (string, error) {
	if p.armed.Load() {
		panic("token source bug")
	}
	return "rx-token", nil
}

// A panic during a lookup fails it like any other error — the process
// survives, and the stream is looked up again once the wait after a
// failure has passed.
func TestAudiencePerStreamLookupPanic(t *testing.T) {
	tokens := &panickyTokens{}
	var skew atomic.Int64
	e := newEnv(t, perStream, func(c *receiver.Config) {
		c.TokenSource = tokens
		c.Now = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	})
	perStreamTransmitter(t, e)
	ctx := context.Background()
	c, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := receiver.New(ctx, e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := other.PushHandler(receiver.PushOptions{})
	signed := func(jti string) string {
		return sign(t, e, func(s *ssf.SET) {
			s.Audience = []string{audience + "/" + c.StreamID}
			s.JWTID = jti
		})
	}
	tokens.armed.Store(true)
	if got := push(t, h, "", signed("p1")); got.status != http.StatusInternalServerError {
		t.Errorf("lookup panicking: push = %+v; want 500", got)
	}
	tokens.armed.Store(false)
	skew.Store(int64(11 * time.Second))
	if got := push(t, h, "", signed("p2")); got.status != http.StatusAccepted {
		t.Errorf("after the panic: push = %+v; want 202", got)
	}
}
