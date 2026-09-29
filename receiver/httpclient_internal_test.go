package receiver

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func redirectTo(t *testing.T, target string) *http.Request {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Request{URL: u}
}

func TestHTTPSOnlyRedirects(t *testing.T) {
	via := func(n int) []*http.Request { return make([]*http.Request, n) }
	stop := errors.New("application policy")

	t.Run("https redirect followed", func(t *testing.T) {
		c := httpsOnlyRedirects(&http.Client{})
		if err := c.CheckRedirect(redirectTo(t, "https://tx.example/next"), via(1)); err != nil {
			t.Errorf("CheckRedirect = %v, want nil", err)
		}
	})
	t.Run("non-https redirect refused", func(t *testing.T) {
		c := httpsOnlyRedirects(&http.Client{})
		for _, target := range []string{"http://tx.example/next", "ftp://tx.example/next", "//tx.example/next"} {
			if err := c.CheckRedirect(redirectTo(t, target), via(1)); err == nil {
				t.Errorf("redirect to %s followed", target)
			}
		}
	})
	t.Run("redirect credentials not logged", func(t *testing.T) {
		c := httpsOnlyRedirects(&http.Client{})
		err := c.CheckRedirect(redirectTo(t, "http://user:secret@tx.example/next"), via(1))
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Errorf("CheckRedirect = %v, want an error without the password", err)
		}
	})
	t.Run("too many redirects", func(t *testing.T) {
		c := httpsOnlyRedirects(&http.Client{})
		if err := c.CheckRedirect(redirectTo(t, "https://tx.example/next"), via(maxRedirects-1)); err != nil {
			t.Errorf("redirect %d refused: %v", maxRedirects, err)
		}
		if err := c.CheckRedirect(redirectTo(t, "https://tx.example/next"), via(maxRedirects)); err == nil {
			t.Errorf("redirect %d followed", maxRedirects+1)
		}
	})
	t.Run("application policy applied to https redirects", func(t *testing.T) {
		calls := 0
		app := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { calls++; return stop }}
		c := httpsOnlyRedirects(app)
		if err := c.CheckRedirect(redirectTo(t, "https://tx.example/next"), via(1)); !errors.Is(err, stop) {
			t.Errorf("CheckRedirect = %v, want the application's error", err)
		}
		// The https check comes first: the application's policy cannot
		// allow a downgrade.
		allowAll := httpsOnlyRedirects(&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }})
		if err := allowAll.CheckRedirect(redirectTo(t, "http://tx.example/next"), via(1)); err == nil {
			t.Error("an application policy allowing everything let an http redirect through")
		}
		if calls != 1 {
			t.Errorf("application policy called %d times, want 1", calls)
		}
		if c == app {
			t.Error("httpsOnlyRedirects returned the client it was given rather than a copy")
		}
	})
}
