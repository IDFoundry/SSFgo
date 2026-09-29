package txharness

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/idfoundry/ssfgo/transmitter"
)

// authServer is a minimal OAuth 2.0 authorization server issuing opaque
// access tokens with the client credentials grant (RFC 6749 §4.4), with
// client_secret_basic and client_secret_post authentication. It exists only
// so the conformance suite can obtain Transmitter access tokens.
type authServer struct {
	issuer           string
	clientID, secret string
	lifetime         time.Duration
	mu               sync.Mutex
	tokens           map[string]grant
}

type grant struct {
	scopes  []string
	expires time.Time // zero: never
}

var knownScopes = []string{"ssf.read", "ssf.manage"}

func newAuthServer(issuer, clientID, secret string, lifetime time.Duration) *authServer {
	return &authServer{issuer: issuer, clientID: clientID, secret: secret, lifetime: lifetime, tokens: map[string]grant{}}
}

func (a *authServer) addStaticToken(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tokens[token] = grant{scopes: knownScopes}
}

func (a *authServer) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", a.metadata)
	mux.HandleFunc("GET /.well-known/openid-configuration", a.metadata)
	mux.HandleFunc("POST /oauth/token", a.token)
}

func (a *authServer) metadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                a.issuer,
		"token_endpoint":                        a.issuer + "/oauth/token",
		"grant_types_supported":                 []string{"client_credentials"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                      knownScopes,
	})
}

func (a *authServer) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	id, secret, basic := r.BasicAuth()
	if !basic {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if subtle.ConstantTimeCompare([]byte(id), []byte(a.clientID)) != 1 ||
		subtle.ConstantTimeCompare([]byte(secret), []byte(a.secret)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="ssfgo"`)
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if r.PostForm.Get("grant_type") != "client_credentials" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	scopes := knownScopes
	if requested := strings.Fields(r.PostForm.Get("scope")); len(requested) > 0 {
		scopes = nil
		for _, s := range requested {
			if !slices.Contains(knownScopes, s) {
				oauthError(w, http.StatusBadRequest, "invalid_scope")
				return
			}
			scopes = append(scopes, s)
		}
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	a.mu.Lock()
	a.tokens[token] = grant{scopes: scopes, expires: time.Now().Add(a.lifetime)}
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(a.lifetime.Seconds()),
		"scope":        strings.Join(scopes, " "),
	})
}

// authorize is the Transmitter's AuthorizeFunc. Every token belongs to the
// single configured client, whose client ID is also the stream audience.
func (a *authServer) authorize(_ context.Context, token string) (transmitter.Receiver, error) {
	a.mu.Lock()
	g, ok := a.tokens[token]
	a.mu.Unlock()
	if !ok || (!g.expires.IsZero() && time.Now().After(g.expires)) {
		return transmitter.Receiver{}, transmitter.ErrInvalidToken
	}
	return transmitter.Receiver{
		ID:       a.clientID,
		Audience: []string{a.clientID},
		Access:   transmitter.AccessFromScopes(g.scopes),
	}, nil
}

func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
