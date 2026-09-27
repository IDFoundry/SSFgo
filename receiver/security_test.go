package receiver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

// A SET older than ReplayWindow is rejected, so a captured SET cannot be
// replayed once its replay record has expired.
func TestStaleSETRejected(t *testing.T) {
	e := newEnv(t, func(c *receiver.Config) { c.ReplayWindow = 2 * time.Second })
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
	cc := &receiver.ClientCredentials{TokenURL: "http://as.example/token", ClientID: "c", ClientSecret: "s", AuthMethod: receiver.ClientSecretBasic}
	if _, err := cc.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("Token with an http TokenURL = %v", err)
	}
}
