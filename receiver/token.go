package receiver

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/clientassertion"
	"github.com/idfoundry/ssfgo/internal/jose"
)

// TokenSource supplies the OAuth 2.0 access token the Receiver presents to
// the Transmitter's stream management API and poll endpoints (CAEP
// Interoperability Profile §2.4.3).
//
// A TokenSource that wraps another — to add metrics, say — should
// implement Unwrap() TokenSource, so New still checks what it wraps: a
// ClientCredentials' settings, and under ssf.AssuranceProduction its
// signing key's custody.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// clientCredentialsOf finds the ClientCredentials ts is or wraps, through
// Unwrap() TokenSource.
func clientCredentialsOf(ts TokenSource) *ClientCredentials {
	for range 16 {
		switch t := ts.(type) {
		case *ClientCredentials:
			return t
		case interface{ Unwrap() TokenSource }:
			ts = t.Unwrap()
		default:
			return nil
		}
	}
	return nil
}

// tokenInvalidator is implemented by token sources that cache: after a
// 401 the Receiver asks for a fresh token once.
type tokenInvalidator interface {
	Invalidate()
}

// StaticToken is a TokenSource that always returns the same token, for
// access tokens issued out of band. Printed or logged, it is withheld,
// like an ssf.Secret.
type StaticToken string

// String returns a fixed placeholder, never the token.
func (t StaticToken) String() string { return "[REDACTED]" }

// GoString implements fmt.GoStringer, so %#v withholds the token too.
func (t StaticToken) GoString() string { return "receiver.StaticToken([REDACTED])" }

// LogValue implements slog.LogValuer, so a logged StaticToken is
// withheld.
func (t StaticToken) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

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
//
// Its access token is cached out of reach of fmt and slog: a
// ClientCredentials printed with %+v shows only where the cache is.
type ClientCredentials struct {
	// TokenURL is the authorization server's token endpoint. It must be
	// https: the request carries the client's credentials.
	TokenURL string
	// ClientID is the Receiver's OAuth client identifier.
	ClientID string
	// ClientSecret is used by every AuthMethod except PrivateKeyJWT.
	ClientSecret ssf.Secret
	// Scopes to request, e.g. "ssf.read" and "ssf.manage" (CAEP Interop
	// §2.7.3). Optional.
	Scopes []string
	// AuthMethod is how the client authenticates to the token endpoint.
	AuthMethod ClientAuthMethod

	// SigningKey, SigningAlgorithm and KeyID sign PrivateKeyJWT
	// assertions; KeyID should match the key's entry in the JWKS
	// registered with the authorization server.
	SigningKey       crypto.Signer
	SigningAlgorithm ssf.SignatureAlgorithm
	KeyID            string
	// SigningKeyCustody declares how SigningKey is held, for a key that
	// does not declare it itself (ssf.KeyCustodyAssurance). It is your own
	// assertion: under ssf.AssuranceProduction a PrivateKeyJWT key must be
	// declared durable, and with HorizontallyScaled shared by every
	// instance.
	SigningKeyCustody ssf.KeyCustody
	// AssertionAudience is the "aud" of client assertions. Defaults to
	// TokenURL (RFC 7523 §3).
	AssertionAudience string

	// HTTPClient defaults to a client with a 10-second timeout.
	HTTPClient *http.Client

	mu    sync.Mutex
	cache *cachedToken
}

// cachedToken is held by pointer, so fmt prints its address, not the
// token.
type cachedToken struct {
	token   string
	expires time.Time
}

// errors reports every problem with c, naming each field under prefix.
func (c *ClientCredentials) errors(prefix string) []error {
	var errs []error
	if u, err := url.Parse(c.TokenURL); c.TokenURL == "" || err != nil || u.Scheme != "https" || u.Host == "" {
		errs = append(errs, fmt.Errorf("%sTokenURL must be an https URL: the request carries the client's credentials", prefix))
	}
	if c.ClientID == "" {
		errs = append(errs, fmt.Errorf("%sClientID is required", prefix))
	}
	switch c.AuthMethod {
	case ClientSecretBasic, ClientSecretPost:
		if c.ClientSecret.IsZero() {
			errs = append(errs, fmt.Errorf("%sClientSecret is required with %s", prefix, c.AuthMethod))
		}
	case ClientSecretJWT:
		if len(c.ClientSecret.Reveal()) < 32 {
			errs = append(errs, fmt.Errorf("%sClientSecret must be at least 32 bytes with %s", prefix, c.AuthMethod))
		}
	case PrivateKeyJWT:
		switch {
		case c.SigningKey == nil:
			errs = append(errs, fmt.Errorf("%sSigningKey is required with %s", prefix, c.AuthMethod))
		case c.SigningAlgorithm == 0:
			errs = append(errs, fmt.Errorf("%sSigningAlgorithm is required with %s", prefix, c.AuthMethod))
		default:
			if err := jose.ValidateKeyForAlgorithm(c.SigningKey.Public(), c.SigningAlgorithm); err != nil {
				errs = append(errs, fmt.Errorf("%sSigningKey: %w", prefix, err))
			}
		}
	default:
		errs = append(errs, fmt.Errorf("%sAuthMethod must be %s, %s, %s or %s, not %q", prefix,
			ClientSecretBasic, ClientSecretPost, ClientSecretJWT, PrivateKeyJWT, c.AuthMethod))
	}
	return errs
}

// tokenRefreshMargin is how long before expiry a cached token is replaced.
const tokenRefreshMargin = 30 * time.Second

// Token implements TokenSource.
func (c *ClientCredentials) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache != nil && time.Now().Before(c.cache.expires) {
		return c.cache.token, nil
	}
	token, lifetime, err := c.fetch(ctx)
	if err != nil {
		return "", err
	}
	c.cache = &cachedToken{token: token, expires: time.Now().Add(lifetime - tokenRefreshMargin)}
	return token, nil
}

// Invalidate drops the cached token.
func (c *ClientCredentials) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = nil
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
		req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret.Reveal()))
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
		// The body is the authorization server's text: APIError shows only
		// a cleaned error code and description from it.
		return "", 0, &APIError{Method: http.MethodPost, URL: c.TokenURL, StatusCode: res.StatusCode, Body: truncate(body, maxAPIErrorBody)}
	}
	return parseTokenResponse(body)
}

// tokenForm builds the client credentials request body, including the
// client's credentials for every method but client_secret_basic.
func (c *ClientCredentials) tokenForm() (url.Values, error) {
	if errs := c.errors("ClientCredentials."); len(errs) > 0 {
		return nil, fmt.Errorf("receiver: invalid ClientCredentials: %w", errors.Join(errs...))
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if len(c.Scopes) > 0 {
		form.Set("scope", strings.Join(c.Scopes, " "))
	}
	switch c.AuthMethod {
	case ClientSecretBasic:
	case ClientSecretPost:
		form.Set("client_id", c.ClientID)
		form.Set("client_secret", c.ClientSecret.Reveal())
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
		o.Secret = []byte(c.ClientSecret.Reveal())
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
