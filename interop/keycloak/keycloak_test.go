// Package keycloak_test runs an SSFgo Receiver against Keycloak's SSF
// Transmitter. It needs a running Keycloak with the ssf feature enabled,
// and is skipped unless SSFGO_INTEROP_KEYCLOAK names it; see
// interop/README.md.
package keycloak_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/revocation"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/scim"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

const (
	realm          = "ssfgo-interop"
	receiverClient = "ssf-receiver"
	receiverSecret = "receiver-secret"
	loginClient    = "ssf-login"
	loginSecret    = "login-secret"
	username       = "alice"
	password       = "alice-password-1"
)

// waitFor bounds how long each step waits for its SET.
const waitFor = 30 * time.Second

func TestKeycloak(t *testing.T) {
	base := os.Getenv("SSFGO_INTEROP_KEYCLOAK")
	if base == "" {
		t.Skip("SSFGO_INTEROP_KEYCLOAK is not set")
	}
	ctx := context.Background()
	kc := &keycloak{t: t, base: strings.TrimSuffix(base, "/"), client: httpClient(t)}
	kc.setUp()
	issuer := kc.base + "/realms/" + realm

	// Every SET's outcome, so a rejection fails the test with its reason.
	var mu sync.Mutex
	outcomes := map[ssf.EventType]int{}
	var rejections []string
	registry := ssf.NewRegistry()
	for _, register := range []func(*ssf.Registry) error{caep.Register, risc.Register, scim.Register} {
		if err := register(registry); err != nil {
			t.Fatal(err)
		}
	}
	rx, err := receiver.New(ctx, receiver.Config{
		Assurance: ssf.AssuranceDevelopment,
		Limits:    receiver.RecommendedLimits(),
		Issuer:    issuer,
		// Keycloak gives each stream the audience "<client_id>/<stream_id>".
		Audience:          receiverClient,
		AudiencePerStream: true,
		Registry:          registry,
		Algorithms:        []ssf.SignatureAlgorithm{ssf.RS256},
		TokenSource: &receiver.ClientCredentials{
			TokenURL:     issuer + "/protocol/openid-connect/token",
			ClientID:     receiverClient,
			ClientSecret: ssf.NewSecret(receiverSecret),
			AuthMethod:   receiver.ClientSecretBasic,
			Scopes:       []string{"ssf.read", "ssf.manage"},
			HTTPClient:   kc.client,
		},
		ReplayStore: memstore.NewReplayStore(),
		HTTPClient:  kc.client,
		Hooks: receiver.Hooks{SET: func(_ context.Context, info receiver.SETInfo) {
			mu.Lock()
			defer mu.Unlock()
			switch info.Outcome {
			case receiver.SETHandled:
				outcomes[info.EventType]++
			case receiver.SETRejected, receiver.SETFailed:
				rejections = append(rejections, fmt.Sprintf("%s %s: %s %v", info.EventType, info.JTI, info.ErrorCode, info.Err))
			}
		}},
	})
	if err != nil {
		t.Fatalf("receiver.New: %v", err)
	}

	// Keycloak sends session-revoked for every session of a user with the
	// placeholder session "ALL".
	rev, err := revocation.New(memstore.NewRevocationStore(), revocation.Options{
		Issuers:     revocation.SameIssuer,
		Events:      revocation.RecommendedEvents(),
		Retention:   time.Hour,
		Assurance:   ssf.AssuranceDevelopment,
		AllSessions: "ALL",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rev.Register(rx); err != nil {
		t.Fatal(err)
	}
	receiver.On(rx, func(context.Context, ssf.SET, caep.CredentialChange) error { return nil })

	stream, err := rx.CreateStream(ctx, receiver.StreamRequest{
		EventsRequested: []ssf.EventType{caep.SessionRevokedEventType, caep.CredentialChangeEventType, risc.AccountDisabledEventType},
		Description:     "SSFgo interop test",
	})
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	t.Logf("stream %s, aud %v", stream.StreamID, []string(stream.Audience))
	t.Cleanup(func() {
		if err := rx.DeleteStream(context.WithoutCancel(ctx), stream.StreamID); err != nil {
			t.Errorf("DeleteStream: %v", err)
		}
	})

	// poll polls until want SETs of typ have been handled.
	poll := func(step string, typ ssf.EventType, want int) {
		t.Helper()
		deadline := time.Now().Add(waitFor)
		for {
			if _, err := rx.Poll(ctx, stream, receiver.PollOptions{}); err != nil {
				t.Fatalf("%s: Poll: %v", step, err)
			}
			mu.Lock()
			got, rejected := outcomes[typ], rejections
			mu.Unlock()
			if len(rejected) > 0 {
				t.Fatalf("%s: SETs rejected or failed: %v", step, rejected)
			}
			if got >= want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: %d of %d %s SETs after %v", step, got, want, typ, waitFor)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}

	t.Run("verification", func(t *testing.T) {
		if _, err := rx.RequestVerification(ctx, stream.StreamID); err != nil {
			t.Fatalf("RequestVerification: %v", err)
		}
		poll("verification", ssf.VerificationEventType, 1)
	})

	userID := kc.createUser()
	sessionA, sessionB := kc.login(), kc.login()

	t.Run("one session revoked", func(t *testing.T) {
		kc.logout(sessionA)
		poll("logout", caep.SessionRevokedEventType, 1)
		if !isRevoked(t, rev, issuer, sessionA) {
			t.Error("the logged-out session's token is not revoked")
		}
		if isRevoked(t, rev, issuer, sessionB) {
			t.Error("another session's token is revoked")
		}
	})

	t.Run("every session revoked", func(t *testing.T) {
		kc.admin(http.MethodPost, "/users/"+userID+"/logout", nil, nil)
		poll("logout all", caep.SessionRevokedEventType, 2)
		if !isRevoked(t, rev, issuer, sessionB) {
			t.Error(`session-revoked for session "ALL" did not revoke the user's other session`)
		}
	})

	t.Run("credential change", func(t *testing.T) {
		kc.admin(http.MethodPut, "/users/"+userID+"/reset-password",
			map[string]any{"type": "password", "value": password + "-new", "temporary": false}, nil)
		poll("reset password", caep.CredentialChangeEventType, 1)
	})

	t.Run("account disabled", func(t *testing.T) {
		var user map[string]any
		kc.admin(http.MethodGet, "/users/"+userID, nil, &user)
		user["enabled"] = false
		kc.admin(http.MethodPut, "/users/"+userID, user, nil)
		poll("disable user", risc.AccountDisabledEventType, 1)
	})
}

func isRevoked(t *testing.T, rev *revocation.Revoker, issuer string, tok accessToken) bool {
	t.Helper()
	if tok.Issuer != issuer {
		t.Fatalf("access token iss %q, want %q", tok.Issuer, issuer)
	}
	revoked, err := rev.IsRevoked(context.Background(), revocation.Token{
		Issuer: tok.Issuer, Subject: tok.Subject, SessionID: tok.SessionID, IssuedAt: time.Unix(tok.IssuedAt, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return revoked
}

// httpClient trusts the CA in SSFGO_INTEROP_KEYCLOAK_CA, if set.
func httpClient(t *testing.T) *http.Client {
	t.Helper()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if file := os.Getenv("SSFGO_INTEROP_KEYCLOAK_CA"); file != "" {
		pem, err := os.ReadFile(file) //nolint:gosec // G304: the test's own configuration
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			t.Fatalf("no certificates in %s", file)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

// keycloak drives Keycloak's admin and OpenID Connect APIs.
type keycloak struct {
	t      *testing.T
	base   string
	client *http.Client
	token  string
}

// setUp creates the realm, with the SSF Transmitter enabled, a receiver
// client using Keycloak's default per-stream audience and every user as
// a default subject, and a client to log users in with.
func (kc *keycloak) setUp() {
	t := kc.t
	t.Helper()
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"},
		"username": {env("SSFGO_INTEROP_KEYCLOAK_ADMIN", "admin")}, "password": {env("SSFGO_INTEROP_KEYCLOAK_ADMIN_PASSWORD", "admin")}}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	kc.form(kc.base+"/realms/master/protocol/openid-connect/token", form, &tok)
	kc.token = tok.AccessToken

	kc.do(http.MethodDelete, kc.base+"/admin/realms/"+realm, nil, nil, http.StatusNoContent, http.StatusNotFound)
	kc.do(http.MethodPost, kc.base+"/admin/realms", map[string]any{
		"realm": realm, "enabled": true,
		"attributes": map[string]string{"ssf.transmitterEnabled": "true"},
	}, nil, http.StatusCreated)
	t.Cleanup(func() {
		kc.do(http.MethodDelete, kc.base+"/admin/realms/"+realm, nil, nil, http.StatusNoContent)
	})

	kc.admin(http.MethodPost, "/clients", map[string]any{
		"clientId": receiverClient, "enabled": true, "publicClient": false, "secret": receiverSecret,
		"serviceAccountsEnabled": true, "standardFlowEnabled": false, "directAccessGrantsEnabled": false,
		// ssf.streamAudience is left unset: Keycloak then gives the stream
		// the audience "<client_id>/<stream_id>".
		"attributes": map[string]string{"ssf.enabled": "true", "ssf.defaultSubjects": "ALL", "ssf.allowedDeliveryMethods": "poll"},
	}, nil)
	var clients []struct {
		ID string `json:"id"`
	}
	kc.admin(http.MethodGet, "/clients?clientId="+receiverClient, nil, &clients)
	if len(clients) != 1 {
		t.Fatalf("found %d clients named %s", len(clients), receiverClient)
	}
	var scopes []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	kc.admin(http.MethodGet, "/client-scopes", nil, &scopes)
	assigned := 0
	for _, s := range scopes {
		if s.Name == "ssf.read" || s.Name == "ssf.manage" {
			kc.admin(http.MethodPut, "/clients/"+clients[0].ID+"/optional-client-scopes/"+s.ID, nil, nil)
			assigned++
		}
	}
	if assigned != 2 {
		t.Fatalf("found %d of the client scopes ssf.read and ssf.manage", assigned)
	}

	kc.admin(http.MethodPost, "/clients", map[string]any{
		"clientId": loginClient, "enabled": true, "publicClient": false, "secret": loginSecret,
		"standardFlowEnabled": false, "directAccessGrantsEnabled": true,
	}, nil)
}

func (kc *keycloak) createUser() string {
	kc.admin(http.MethodPost, "/users", map[string]any{
		"username": username, "enabled": true, "email": username + "@example.com", "emailVerified": true,
		"firstName": "Alice", "lastName": "Example",
		"credentials": []map[string]any{{"type": "password", "value": password, "temporary": false}},
	}, nil)
	var users []struct {
		ID string `json:"id"`
	}
	kc.admin(http.MethodGet, "/users?exact=true&username="+username, nil, &users)
	if len(users) != 1 {
		kc.t.Fatalf("found %d users named %s", len(users), username)
	}
	return users[0].ID
}

// accessToken is what the test reads from an access token: Keycloak
// issued it, so it is not verified.
type accessToken struct {
	Issuer       string `json:"iss"`
	Subject      string `json:"sub"`
	SessionID    string `json:"sid"`
	IssuedAt     int64  `json:"iat"`
	refreshToken string
}

// login starts a session for the test user.
func (kc *keycloak) login() accessToken {
	t := kc.t
	t.Helper()
	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	kc.form(kc.base+"/realms/"+realm+"/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {loginClient}, "client_secret": {loginSecret},
		"username": {username}, "password": {password}, "scope": {"openid"},
	}, &resp)
	parts := strings.Split(resp.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatal("the access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var tok accessToken
	if err := json.Unmarshal(payload, &tok); err != nil {
		t.Fatal(err)
	}
	if tok.SessionID == "" {
		t.Fatal(`the access token has no "sid"`)
	}
	tok.refreshToken = resp.RefreshToken
	return tok
}

// logout ends one session.
func (kc *keycloak) logout(tok accessToken) {
	kc.t.Helper()
	kc.form(kc.base+"/realms/"+realm+"/protocol/openid-connect/logout", url.Values{
		"client_id": {loginClient}, "client_secret": {loginSecret}, "refresh_token": {tok.refreshToken},
	}, nil)
}

// admin calls the realm's admin API.
func (kc *keycloak) admin(method, path string, in, out any) {
	kc.t.Helper()
	kc.do(method, kc.base+"/admin/realms/"+realm+path, in, out, http.StatusOK, http.StatusCreated, http.StatusNoContent)
}

func (kc *keycloak) do(method, u string, in, out any, want ...int) {
	t := kc.t
	t.Helper()
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+kc.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	kc.send(req, out, want...)
}

func (kc *keycloak) form(u string, form url.Values, out any) {
	kc.t.Helper()
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		kc.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	kc.send(req, out, http.StatusOK, http.StatusNoContent)
}

func (kc *keycloak) send(req *http.Request, out any, want ...int) {
	t := kc.t
	t.Helper()
	resp, err := kc.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	ok := false
	for _, w := range want {
		ok = ok || resp.StatusCode == w
	}
	if !ok {
		t.Fatalf("%s %s: %s: %s", req.Method, req.URL, resp.Status, b)
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s %s: %v", req.Method, req.URL, err)
		}
	}
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
