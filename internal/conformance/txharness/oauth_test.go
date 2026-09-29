package txharness

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/ssfgo/transmitter"
)

func tokenRequest(t *testing.T, h http.Handler, form url.Values, basic [2]string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic[0] != "" {
		req.SetBasicAuth(basic[0], basic[1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestAuthServer(t *testing.T) {
	as := newAuthServer("https://as.example", "client", "secret", time.Minute)
	mux := http.NewServeMux()
	as.register(mux)
	creds := [2]string{"client", "secret"}
	cc := url.Values{"grant_type": {"client_credentials"}}

	status, body := tokenRequest(t, mux, cc, creds)
	if status != 200 || body["token_type"] != "Bearer" || body["scope"] != "ssf.read ssf.manage" {
		t.Fatalf("basic auth: %d %v", status, body)
	}
	rx, err := as.authorize(context.Background(), body["access_token"].(string))
	if err != nil || rx.ID != "client" || rx.Access != transmitter.AccessManage {
		t.Errorf("authorize = %+v, %v", rx, err)
	}

	post := url.Values{"grant_type": {"client_credentials"}, "client_id": {"client"}, "client_secret": {"secret"}, "scope": {"ssf.read"}}
	status, body = tokenRequest(t, mux, post, [2]string{})
	if status != 200 {
		t.Fatalf("post auth: %d %v", status, body)
	}
	if rx, _ := as.authorize(context.Background(), body["access_token"].(string)); rx.Access != transmitter.AccessRead {
		t.Errorf("ssf.read token has access %v", rx.Access)
	}

	for name, c := range map[string]struct {
		form   url.Values
		creds  [2]string
		status int
		code   string
	}{
		"wrong secret":   {cc, [2]string{"client", "nope"}, 401, "invalid_client"},
		"no credentials": {cc, [2]string{}, 401, "invalid_client"},
		"wrong grant":    {url.Values{"grant_type": {"password"}}, creds, 400, "unsupported_grant_type"},
		"unknown scope":  {url.Values{"grant_type": {"client_credentials"}, "scope": {"admin"}}, creds, 400, "invalid_scope"},
	} {
		status, body := tokenRequest(t, mux, c.form, c.creds)
		if status != c.status || body["error"] != c.code {
			t.Errorf("%s: %d %v", name, status, body)
		}
	}

	if _, err := as.authorize(context.Background(), "unknown"); !errors.Is(err, transmitter.ErrInvalidToken) {
		t.Errorf("unknown token: %v", err)
	}
	as.tokens["expired"] = grant{scopes: knownScopes, expires: time.Now().Add(-time.Second)}
	if _, err := as.authorize(context.Background(), "expired"); !errors.Is(err, transmitter.ErrInvalidToken) {
		t.Errorf("expired token: %v", err)
	}
	as.addStaticToken("static")
	if rx, err := as.authorize(context.Background(), "static"); err != nil || rx.Access != transmitter.AccessManage {
		t.Errorf("static token: %+v, %v", rx, err)
	}
}

func TestSupportedEventsExcludeDeprecatedAndSSFEvents(t *testing.T) {
	events, err := supportedEvents()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 8+13 {
		t.Errorf("%d events, want 21 (8 CAEP + 13 non-deprecated RISC)", len(events))
	}
	for _, e := range events {
		if strings.Contains(string(e), "/ssf/") || strings.HasSuffix(string(e), "sessions-revoked") {
			t.Errorf("unexpected event %s", e)
		}
	}
}
