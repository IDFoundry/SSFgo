package receiver

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/clientassertion"
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
	// ClientSecretBasic sends the secret with HTTP Basic authentication.
	ClientSecretBasic ClientAuthMethod = "client_secret_basic"
	// ClientSecretPost sends the secret in the request body.
	ClientSecretPost ClientAuthMethod = "client_secret_post"
	// ClientSecretJWT sends a client assertion MACed with the secret
	// using HS256 (OpenID Connect Core §9, RFC 7523). The secret must be
	// at least 32 bytes.
	ClientSecretJWT ClientAuthMethod = "client_secret_jwt"
	// PrivateKeyJWT sends a client assertion signed with SigningKey
	// (OpenID Connect Core §9, RFC 7523).
	PrivateKeyJWT ClientAuthMethod = "private_key_jwt"
)

// ClientCredentials is a TokenSource that obtains tokens with the OAuth 2.0
// client credentials grant (RFC 6749 §4.4) and caches each until shortly
// before it expires.
type ClientCredentials struct {
	TokenURL string
	ClientID string
	// ClientSecret is used by every AuthMethod except PrivateKeyJWT.
	ClientSecret string
	// Scopes to request, e.g. "ssf.read" and "ssf.manage" (CAEP Interop
	// §2.7.3). Optional.
	Scopes     []string
	AuthMethod ClientAuthMethod

	// SigningKey, SigningAlgorithm and KeyID sign PrivateKeyJWT
	// assertions; KeyID should match the key's entry in the JWKS
	// registered with the authorization server.
	SigningKey       crypto.Signer
	SigningAlgorithm ssf.SignatureAlgorithm
	KeyID            string
	// AssertionAudience is the "aud" of client assertions. Defaults to
	// TokenURL (RFC 7523 §3).
	AssertionAudience string

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
	form, err := c.tokenForm()
	if err != nil {
		return "", 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", contentTypeJSON)
	if c.AuthMethod == ClientSecretBasic {
		// RFC 6749 §2.3.1: the credentials are form-encoded before being
		// used as the Basic user name and password.
		req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	res, err := httpsOnlyRedirects(client).Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("receiver: token request: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 64*1024))
	if res.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("receiver: token endpoint returned %d: %s", res.StatusCode, body)
	}
	return parseTokenResponse(body)
}

// tokenForm builds the client credentials request body, including the
// client's credentials for every method but client_secret_basic.
func (c *ClientCredentials) tokenForm() (url.Values, error) {
	if c.TokenURL == "" || c.ClientID == "" {
		return nil, errors.New("receiver: ClientCredentials needs TokenURL and ClientID")
	}
	if u, err := url.Parse(c.TokenURL); err != nil || u.Scheme != "https" || u.Host == "" {
		// The request carries the client's credentials.
		return nil, fmt.Errorf("receiver: TokenURL %q must be an https URL", c.TokenURL)
	}
	if c.AuthMethod != PrivateKeyJWT && c.ClientSecret == "" {
		return nil, fmt.Errorf("receiver: %s needs a ClientSecret", c.AuthMethod)
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if len(c.Scopes) > 0 {
		form.Set("scope", strings.Join(c.Scopes, " "))
	}
	switch c.AuthMethod {
	case ClientSecretBasic:
	case ClientSecretPost:
		form.Set("client_id", c.ClientID)
		form.Set("client_secret", c.ClientSecret)
	case ClientSecretJWT, PrivateKeyJWT:
		assertion, err := c.assertion()
		if err != nil {
			return nil, err
		}
		form.Set("client_id", c.ClientID)
		form.Set("client_assertion_type", clientassertion.Type)
		form.Set("client_assertion", assertion)
	default:
		return nil, fmt.Errorf("receiver: unsupported client authentication method %q", c.AuthMethod)
	}
	return form, nil
}

func (c *ClientCredentials) assertion() (string, error) {
	o := clientassertion.Options{ClientID: c.ClientID, Audience: c.AssertionAudience, Now: time.Now()}
	if o.Audience == "" {
		o.Audience = c.TokenURL
	}
	if c.AuthMethod == ClientSecretJWT {
		o.Secret = []byte(c.ClientSecret)
	} else {
		o.Signer, o.Algorithm, o.KeyID = c.SigningKey, c.SigningAlgorithm, c.KeyID
	}
	assertion, err := clientassertion.Build(o)
	if err != nil {
		return "", fmt.Errorf("receiver: %w", err)
	}
	return assertion, nil
}

// parseTokenResponse reads an RFC 6749 §5.1 token response.
func parseTokenResponse(body []byte) (string, time.Duration, error) {
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
