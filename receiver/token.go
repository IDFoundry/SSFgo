package receiver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TokenSource supplies the OAuth 2.0 access token the Receiver presents to
// the Transmitter's stream management API and poll endpoints (CAEP
// Interoperability Profile §2.4.3).
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// tokenInvalidator is implemented by token sources that cache: after a
// 401 the Receiver asks for a fresh token once.
type tokenInvalidator interface {
	Invalidate()
}

// StaticToken is a TokenSource that always returns the same token, for
// access tokens issued out of band.
type StaticToken string

// Token implements TokenSource.
func (t StaticToken) Token(context.Context) (string, error) {
	if t == "" {
		return "", errors.New("receiver: static access token is empty")
	}
	return string(t), nil
}

// ClientAuthMethod is how ClientCredentials authenticates to the token
// endpoint (RFC 6749 §2.3.1).
type ClientAuthMethod string

const (
	ClientSecretBasic ClientAuthMethod = "client_secret_basic"
	ClientSecretPost  ClientAuthMethod = "client_secret_post"
)

// ClientCredentials is a TokenSource that obtains tokens with the OAuth 2.0
// client credentials grant (RFC 6749 §4.4) and caches each until shortly
// before it expires.
type ClientCredentials struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	// Scopes to request, e.g. "ssf.read" and "ssf.manage" (CAEP Interop
	// §2.7.3). Optional.
	Scopes     []string
	AuthMethod ClientAuthMethod
	// HTTPClient defaults to a client with a 10-second timeout.
	HTTPClient *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// tokenRefreshMargin is how long before expiry a cached token is replaced.
const tokenRefreshMargin = 30 * time.Second

// Token implements TokenSource.
func (c *ClientCredentials) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	token, lifetime, err := c.fetch(ctx)
	if err != nil {
		return "", err
	}
	c.token = token
	c.expires = time.Now().Add(lifetime - tokenRefreshMargin)
	return token, nil
}

// Invalidate drops the cached token.
func (c *ClientCredentials) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = ""
}

func (c *ClientCredentials) fetch(ctx context.Context) (string, time.Duration, error) {
	if c.TokenURL == "" || c.ClientID == "" || c.ClientSecret == "" {
		return "", 0, errors.New("receiver: ClientCredentials needs TokenURL, ClientID and ClientSecret")
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if len(c.Scopes) > 0 {
		form.Set("scope", strings.Join(c.Scopes, " "))
	}
	switch c.AuthMethod {
	case ClientSecretPost:
		form.Set("client_id", c.ClientID)
		form.Set("client_secret", c.ClientSecret)
	case ClientSecretBasic:
	default:
		return "", 0, fmt.Errorf("receiver: unsupported client authentication method %q", c.AuthMethod)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.AuthMethod == ClientSecretBasic {
		// RFC 6749 §2.3.1: the credentials are form-encoded before being
		// used as the Basic user name and password.
		req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	res, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("receiver: token request: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 64*1024))
	if res.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("receiver: token endpoint returned %d: %s", res.StatusCode, body)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", 0, errors.New("receiver: token endpoint returned no access_token")
	}
	if !strings.EqualFold(tr.TokenType, "Bearer") {
		return "", 0, fmt.Errorf("receiver: unsupported token_type %q", tr.TokenType)
	}
	lifetime := time.Duration(tr.ExpiresIn) * time.Second
	if lifetime <= tokenRefreshMargin {
		// No or very short expires_in: use the token once, then refresh.
		lifetime = tokenRefreshMargin + time.Second
	}
	return tr.AccessToken, lifetime, nil
}
