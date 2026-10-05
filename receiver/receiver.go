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
	"slices"
	"strings"
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
	keysFetched time.Time // last successful fetch
	keysTried   time.Time // last attempt, successful or not
	keyFetch    *keyFetch // the JWKS fetch in progress, if any

	handlersMu sync.RWMutex
	handlers   map[ssf.EventType]HandlerFunc

	stateMu sync.Mutex
	states  map[string][]string // stream ID -> outstanding verification states, oldest first

	pollMu sync.Mutex
	acks   map[string]*pendingAcks // stream ID -> acknowledgements for the next poll

	// origins are those the Receiver may send its access token to: the
	// issuer's and Config.TrustedOrigins.
	origins map[string]bool

	inflightMu sync.Mutex
	inflight   map[setKey]*handling // SETs being handled right now
}

// maxResponseBytes bounds every response read from the Transmitter.
const maxResponseBytes = 1 << 20

// contentTypeJSON is the media type of the JSON bodies the Receiver sends
// and accepts.
const contentTypeJSON = "application/json"

// New validates cfg, fetches the Transmitter Configuration Metadata and
// checks it names cfg.Issuer (SSF 1.0 §7.2.4), then fetches the
// Transmitter's signing keys.
func New(ctx context.Context, cfg Config) (*Receiver, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.Algorithms = slices.Clone(cfg.Algorithms)
	cfg.SubjectMembers = slices.Clone(cfg.SubjectMembers)
	r := &Receiver{
		cfg:      cfg,
		handlers: map[ssf.EventType]HandlerFunc{},
		states:   map[string][]string{},
		acks:     map[string]*pendingAcks{},
		inflight: map[setKey]*handling{},
	}
	locations, err := metadataLocations(cfg)
	if err != nil {
		return nil, err
	}
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	r.origins = map[string]bool{origin(issuer): true}
	for _, o := range cfg.TrustedOrigins {
		u, _ := url.Parse(o) // validated by cfg.validate
		r.origins[origin(u)] = true
	}
	body, err := r.fetchMetadata(ctx, locations)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &r.metadata); err != nil {
		return nil, fmt.Errorf("receiver: parse transmitter metadata: %w", err)
	}
	if r.metadata.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("receiver: transmitter metadata names issuer %q, not %q", r.metadata.Issuer, cfg.Issuer)
	}
	if err := r.checkEndpoints(); err != nil {
		return nil, err
	}
	if cfg.CheckMetadata != nil {
		if err := cfg.CheckMetadata(r.Metadata()); err != nil {
			return nil, fmt.Errorf("receiver: transmitter metadata: %w", err)
		}
	}
	if err := r.refreshKeys(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// metadataLocations returns where to look for the Transmitter's metadata,
// in order: Config.MetadataURL alone if set; otherwise the SSF 1.0 §7.2
// location, the issuer with the well-known path appended, and RISC's
// location (SSF 1.0 §7.2.2).
func metadataLocations(cfg Config) ([]string, error) {
	if cfg.MetadataURL != "" {
		return []string{cfg.MetadataURL}, nil
	}
	ssfLocation, err := ssf.WellKnownURL(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	issuer, _ := url.Parse(cfg.Issuer) // validated by ssf.WellKnownURL
	path := strings.TrimSuffix(issuer.Path, "/")
	appended, risc := *issuer, *issuer
	appended.Path, appended.RawPath = path+ssf.WellKnownPath, ""
	risc.Path, risc.RawPath = riscWellKnownPath+path, ""
	locations := []string{ssfLocation}
	for _, l := range []string{appended.String(), risc.String()} {
		if !slices.Contains(locations, l) {
			locations = append(locations, l)
		}
	}
	return locations, nil
}

// riscWellKnownPath is where RISC Transmitters may still publish their
// metadata (SSF 1.0 §7.2.2).
const riscWellKnownPath = "/.well-known/risc-configuration"

// fetchMetadata returns the metadata document from the first location
// that has one. Only a location that does not exist (404 or 410) moves on
// to the next: any other failure — an outage, say — is returned rather
// than settling for a document published somewhere else.
func (r *Receiver) fetchMetadata(ctx context.Context, locations []string) ([]byte, error) {
	for _, l := range locations {
		body, err := r.get(ctx, l)
		var apiErr *APIError
		if errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusGone) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("receiver: fetch transmitter metadata: %w", err)
		}
		return body, nil
	}
	return nil, fmt.Errorf("receiver: fetch transmitter metadata: none found at %s", strings.Join(locations, ", "))
}

// checkEndpoints enforces SSF 1.0 §7.1: every endpoint the metadata
// advertises uses HTTP over TLS. Those the Receiver sends its access token
// to must also be on an origin it trusts (see Config.TrustedOrigins).
func (r *Receiver) checkEndpoints() error {
	md := r.metadata
	if u, err := url.Parse(md.JWKSURI); md.JWKSURI != "" && (err != nil || u.Scheme != "https" || u.Host == "") {
		return fmt.Errorf("receiver: transmitter metadata jwks_uri %q is not an https URL", md.JWKSURI)
	}
	for name, endpoint := range map[string]string{
		"configuration_endpoint":  md.ConfigurationEndpoint,
		"status_endpoint":         md.StatusEndpoint,
		"add_subject_endpoint":    md.AddSubjectEndpoint,
		"remove_subject_endpoint": md.RemoveSubjectEndpoint,
		"verification_endpoint":   md.VerificationEndpoint,
	} {
		if endpoint == "" {
			continue
		}
		if err := r.checkAuthenticatedEndpoint(endpoint); err != nil {
			return fmt.Errorf("receiver: transmitter metadata %s: %w", name, err)
		}
	}
	return nil
}

// checkAuthenticatedEndpoint reports whether the Receiver may send its
// access token to endpoint: an https URL on a trusted origin.
func (r *Receiver) checkAuthenticatedEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%q is not an https URL", endpoint)
	}
	if !r.origins[origin(u)] {
		return fmt.Errorf("%q is not on the issuer's origin; add %s to Config.TrustedOrigins if the Transmitter serves it there", endpoint, origin(u))
	}
	return nil
}

// Metadata returns a copy of the Transmitter Configuration Metadata
// fetched by New.
func (r *Receiver) Metadata() ssf.TransmitterMetadata {
	md := r.metadata
	md.DeliveryMethodsSupported = slices.Clone(md.DeliveryMethodsSupported)
	md.CriticalSubjectMembers = slices.Clone(md.CriticalSubjectMembers)
	md.AuthorizationSchemes = slices.Clone(md.AuthorizationSchemes)
	return md
}

// keyRefetchInterval rate-limits JWKS refetches — whether triggered by a
// SET naming an unknown key or by KeyMaxAge — so neither a stream of forged
// SETs nor an unavailable JWKS endpoint makes the Receiver hammer the
// Transmitter.
const keyRefetchInterval = time.Minute

// keyFetchTimeout bounds one JWKS refetch.
const keyFetchTimeout = 30 * time.Second

// keyFetch is one JWKS refetch; done is closed once ok is final.
type keyFetch struct {
	done chan struct{}
	ok   bool
}

// maybeRefreshKeys refetches the JWKS, or joins a refetch already running,
// unless an attempt was made within keyRefetchInterval. It reports whether
// fresh keys were fetched.
//
// The fetch runs on its own context, not the caller's: a caller that gives
// up — a push client that disconnects, say — neither cancels it nor uses up
// the attempt, so nobody who can reach the push endpoint can keep the
// Receiver from ever learning a rotated key or forgetting a retired one.
func (r *Receiver) maybeRefreshKeys(ctx context.Context) bool {
	r.keysMu.Lock()
	f := r.keyFetch
	if f == nil {
		if r.cfg.Now().Sub(r.keysTried) < keyRefetchInterval {
			r.keysMu.Unlock()
			return false
		}
		r.keysTried = r.cfg.Now()
		f = &keyFetch{done: make(chan struct{})}
		r.keyFetch = f
		go r.fetchKeys(context.WithoutCancel(ctx), f)
	}
	r.keysMu.Unlock()
	select {
	case <-f.done:
		return f.ok
	case <-ctx.Done():
		return false
	}
}

func (r *Receiver) fetchKeys(ctx context.Context, f *keyFetch) {
	ctx, cancel := context.WithTimeout(ctx, keyFetchTimeout)
	defer cancel()
	err := r.refreshKeys(ctx)
	if err != nil {
		r.cfg.Logger.WarnContext(ctx, "ssf receiver: refresh transmitter JWKS", "error", err)
	}
	r.keysMu.Lock()
	f.ok = err == nil
	r.keyFetch = nil
	r.keysMu.Unlock()
	close(f.done)
}

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
	now := r.cfg.Now()
	r.keys, r.keysFetched, r.keysTried = keys, now, now
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
	req.Header.Set("Accept", contentTypeJSON)
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
	// Body is the response body, cut to its first 1 KiB.
	Body string
}

// maxAPIErrorBody is how much of an error response an APIError keeps: it
// ends up in logs, and the Transmitter decides how large it is.
const maxAPIErrorBody = 1024

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
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

// ErrNotProcessed is returned by UpdateStream, ReplaceStream and SetStatus
// when the Transmitter answers 202: it accepted the request but has not
// processed it yet (SSF 1.0 §8.1.1.3, §8.1.1.4, §8.1.2.2). The returned
// configuration or state is empty; the caller may repeat the request later
// to learn the outcome.
var ErrNotProcessed = errors.New("receiver: the transmitter accepted the request but has not processed it yet")

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
	status, respBody, err := r.send(ctx, method, endpoint, payload)
	if err != nil {
		return err
	}
	if status == http.StatusUnauthorized {
		if inv, ok := r.cfg.TokenSource.(tokenInvalidator); ok {
			inv.Invalidate()
			if status, respBody, err = r.send(ctx, method, endpoint, payload); err != nil {
				return err
			}
		}
	}
	if !slices.Contains(want, status) {
		return &APIError{Method: method, URL: endpoint, StatusCode: status, Body: truncate(respBody, maxAPIErrorBody)}
	}
	if status == http.StatusAccepted {
		return ErrNotProcessed
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("receiver: %s %s: decode response: %w", method, endpoint, err)
	}
	return nil
}

// send makes one authorized request and returns the response status and
// (size-limited) body.
func (r *Receiver) send(ctx context.Context, method, endpoint string, payload []byte) (int, []byte, error) {
	if err := r.checkAuthenticatedEndpoint(endpoint); err != nil {
		return 0, nil, fmt.Errorf("receiver: refusing to send the access token: %w", err)
	}
	token, err := r.cfg.TokenSource.Token(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("receiver: access token: %w", err)
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", contentTypeJSON)
	if payload != nil {
		req.Header.Set("Content-Type", contentTypeJSON)
	}
	res, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("receiver: %s %s: %w", method, endpoint, err)
	}
	respBody, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	_ = res.Body.Close()
	if err != nil {
		return 0, nil, fmt.Errorf("receiver: %s %s: read response: %w", method, endpoint, err)
	}
	return res.StatusCode, respBody, nil
}
