package receiver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/jose"
)

// Receiver is an SSF Receiver bound to one Transmitter. Create one with New.
type Receiver struct {
	cfg      Config
	metadata ssf.TransmitterMetadata

	keysMu      sync.Mutex
	keys        []jose.SetKey
	keysFetched time.Time

	handlersMu sync.RWMutex
	handlers   map[ssf.EventType]HandlerFunc

	stateMu sync.Mutex
	states  map[string]map[string]bool // stream ID -> outstanding verification states

	pollMu sync.Mutex
	acks   map[string]*pendingAcks // stream ID -> acknowledgements for the next poll
}

// maxResponseBytes bounds every response read from the Transmitter.
const maxResponseBytes = 1 << 20

// New validates cfg, fetches the Transmitter Configuration Metadata and
// checks it names cfg.Issuer (SSF 1.0 §7.2.4), then fetches the
// Transmitter's signing keys.
func New(ctx context.Context, cfg Config) (*Receiver, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	r := &Receiver{
		cfg:      cfg,
		handlers: map[ssf.EventType]HandlerFunc{},
		states:   map[string]map[string]bool{},
		acks:     map[string]*pendingAcks{},
	}
	wellKnown, err := ssf.WellKnownURL(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	body, err := r.get(ctx, wellKnown)
	if err != nil {
		return nil, fmt.Errorf("receiver: fetch transmitter metadata: %w", err)
	}
	if err := json.Unmarshal(body, &r.metadata); err != nil {
		return nil, fmt.Errorf("receiver: parse transmitter metadata: %w", err)
	}
	if r.metadata.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("receiver: transmitter metadata names issuer %q, not %q", r.metadata.Issuer, cfg.Issuer)
	}
	if err := r.refreshKeys(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// Metadata returns the Transmitter Configuration Metadata fetched by New.
func (r *Receiver) Metadata() ssf.TransmitterMetadata { return r.metadata }

// keyRefetchInterval rate-limits JWKS refetches triggered by SETs signed
// with an unknown key, so a stream of forged SETs cannot make the Receiver
// hammer the Transmitter.
const keyRefetchInterval = time.Minute

func (r *Receiver) refreshKeys(ctx context.Context) error {
	u, err := url.Parse(r.metadata.JWKSURI)
	if err != nil || u.Scheme != "https" {
		return fmt.Errorf("receiver: transmitter metadata needs an https jwks_uri, got %q", r.metadata.JWKSURI)
	}
	body, err := r.get(ctx, r.metadata.JWKSURI)
	if err != nil {
		return fmt.Errorf("receiver: fetch transmitter JWKS: %w", err)
	}
	keys, err := jose.ParseJWKSet(body)
	if err != nil {
		return fmt.Errorf("receiver: parse transmitter JWKS: %w", err)
	}
	r.keysMu.Lock()
	r.keys, r.keysFetched = keys, r.cfg.Now()
	r.keysMu.Unlock()
	return nil
}

func (r *Receiver) currentKeys() ([]jose.SetKey, time.Time) {
	r.keysMu.Lock()
	defer r.keysMu.Unlock()
	return r.keys, r.keysFetched
}

// get fetches an unauthenticated JSON document.
func (r *Receiver) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, &APIError{Method: http.MethodGet, URL: u, StatusCode: res.StatusCode, Body: string(body)}
	}
	return body, nil
}

// APIError is a Transmitter response with an unexpected status code.
type APIError struct {
	Method     string
	URL        string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("receiver: %s %s: HTTP %d: %s", e.Method, e.URL, e.StatusCode, e.Body)
}

// ErrNotFound is matched by an *APIError with status 404, so callers can
// write errors.Is(err, receiver.ErrNotFound).
var ErrNotFound = errors.New("receiver: not found")

// Is reports whether e matches target.
func (e *APIError) Is(target error) bool {
	return target == ErrNotFound && e.StatusCode == http.StatusNotFound
}

// ErrUnsupported is returned when the Transmitter's metadata does not
// advertise the endpoint an operation needs.
var ErrUnsupported = errors.New("receiver: the transmitter does not support this operation")

// call makes an authorized JSON request to a Transmitter endpoint and
// decodes the response into out if out is non-nil. want lists acceptable
// status codes. A 401 makes it fetch a fresh token and retry once.
func (r *Receiver) call(ctx context.Context, method, endpoint string, in, out any, want ...int) error {
	if endpoint == "" {
		return ErrUnsupported
	}
	var payload []byte
	if in != nil {
		var err error
		if payload, err = json.Marshal(in); err != nil {
			return fmt.Errorf("receiver: encode request: %w", err)
		}
	}
	for attempt := 0; ; attempt++ {
		token, err := r.cfg.TokenSource.Token(ctx)
		if err != nil {
			return fmt.Errorf("receiver: access token: %w", err)
		}
		var body io.Reader
		if payload != nil {
			body = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := r.cfg.HTTPClient.Do(req)
		if err != nil {
			return fmt.Errorf("receiver: %s %s: %w", method, endpoint, err)
		}
		respBody, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
		_ = res.Body.Close()
		if err != nil {
			return fmt.Errorf("receiver: %s %s: read response: %w", method, endpoint, err)
		}
		if res.StatusCode == http.StatusUnauthorized && attempt == 0 {
			if inv, ok := r.cfg.TokenSource.(tokenInvalidator); ok {
				inv.Invalidate()
				continue
			}
		}
		for _, w := range want {
			if res.StatusCode == w {
				if out == nil || len(respBody) == 0 {
					return nil
				}
				if err := json.Unmarshal(respBody, out); err != nil {
					return fmt.Errorf("receiver: %s %s: decode response: %w", method, endpoint, err)
				}
				return nil
			}
		}
		return &APIError{Method: method, URL: endpoint, StatusCode: res.StatusCode, Body: string(respBody)}
	}
}
