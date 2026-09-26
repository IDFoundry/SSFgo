package transmitter

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/jose"
	"github.com/idfoundry/ssfgo/internal/setcodec"
)

// Transmitter serves the SSF Transmitter endpoints. Create one with New.
type Transmitter struct {
	cfg      Config
	signer   setcodec.Signer
	metadata ssf.TransmitterMetadata
	jwks     []byte
	paths    paths
	now      func() time.Time
	log      *slog.Logger
	origin   string // scheme://host of the issuer
}

// paths are the request paths the Transmitter serves, all derived from
// the issuer so several Transmitters can share a host.
type paths struct {
	wellKnown, jwks, configuration, status, addSubject, removeSubject, verification, pollPrefix string
}

// New validates cfg and returns a Transmitter.
func New(cfg Config) (*Transmitter, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	u, _ := url.Parse(cfg.Issuer)
	// The issuer path becomes part of http.ServeMux patterns, so it must
	// need no escaping and must not contain pattern wildcards.
	if u.Path != u.EscapedPath() || strings.ContainsAny(u.Path, "{}") {
		return nil, fmt.Errorf("transmitter: invalid config: issuer path %q must use only unreserved URL characters", u.Path)
	}
	base := strings.TrimSuffix(u.Path, "/")
	t := &Transmitter{
		cfg:    cfg,
		now:    cfg.Now,
		origin: u.Scheme + "://" + u.Host,
		paths: paths{
			wellKnown:     ssf.WellKnownPath + base,
			jwks:          base + "/ssf/jwks.json",
			configuration: base + "/ssf/stream",
			status:        base + "/ssf/status",
			addSubject:    base + "/ssf/subjects:add",
			removeSubject: base + "/ssf/subjects:remove",
			verification:  base + "/ssf/verify",
			pollPrefix:    base + "/ssf/poll/",
		},
	}
	if t.now == nil {
		t.now = time.Now
	}
	t.log = cfg.Logger
	if t.log == nil {
		t.log = slog.Default()
	}
	active := cfg.SigningKeys[0]
	t.signer = setcodec.Signer{Key: active.Signer, Algorithm: active.Algorithm, KeyID: active.KeyID}

	keys := make([]jose.JWK, 0, len(cfg.SigningKeys))
	for _, k := range cfg.SigningKeys {
		jwk, err := jose.NewJWK(k.Signer.Public(), k.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("transmitter: signing key %q: %w", k.KeyID, err)
		}
		keys = append(keys, jwk.WithKeyID(k.KeyID))
	}
	jwks, err := jose.MarshalJWKSet(keys...)
	if err != nil {
		return nil, fmt.Errorf("transmitter: encode JWKS: %w", err)
	}
	t.jwks = jwks

	t.metadata = ssf.TransmitterMetadata{
		SpecVersion:              ssf.SpecVersion,
		Issuer:                   cfg.Issuer,
		JWKSURI:                  t.url(t.paths.jwks),
		DeliveryMethodsSupported: cfg.DeliveryMethods,
		ConfigurationEndpoint:    t.url(t.paths.configuration),
		StatusEndpoint:           t.url(t.paths.status),
		AddSubjectEndpoint:       t.url(t.paths.addSubject),
		RemoveSubjectEndpoint:    t.url(t.paths.removeSubject),
		VerificationEndpoint:     t.url(t.paths.verification),
		CriticalSubjectMembers:   cfg.CriticalSubjectMembers,
		// The stream management API accepts only OAuth 2.0 bearer tokens.
		AuthorizationSchemes: []ssf.AuthorizationScheme{ssf.OAuth2AuthorizationScheme},
		DefaultSubjects:      cfg.DefaultSubjects,
	}
	return t, nil
}

func (t *Transmitter) url(path string) string { return t.origin + path }

// Metadata returns the Transmitter Configuration Metadata the Transmitter
// publishes.
func (t *Transmitter) Metadata() ssf.TransmitterMetadata { return t.metadata }

// Handler returns the http.Handler serving every Transmitter endpoint.
// Mount it at the root of the issuer's host.
func (t *Transmitter) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+t.paths.wellKnown, t.serveMetadata)
	mux.HandleFunc("GET "+t.paths.jwks, t.serveJWKS)

	mux.Handle("POST "+t.paths.configuration, t.authorized(AccessManage, t.createStream))
	mux.Handle("GET "+t.paths.configuration, t.authorized(AccessRead, t.readStreams))
	mux.Handle("PATCH "+t.paths.configuration, t.authorized(AccessManage, t.updateStream))
	mux.Handle("PUT "+t.paths.configuration, t.authorized(AccessManage, t.replaceStream))
	mux.Handle("DELETE "+t.paths.configuration, t.authorized(AccessManage, t.deleteStream))

	mux.Handle("GET "+t.paths.status, t.authorized(AccessRead, t.readStatus))
	mux.Handle("POST "+t.paths.status, t.authorized(AccessManage, t.updateStatus))

	mux.Handle("POST "+t.paths.addSubject, t.authorized(AccessManage, t.addSubject))
	mux.Handle("POST "+t.paths.removeSubject, t.authorized(AccessManage, t.removeSubject))

	mux.Handle("POST "+t.paths.verification, t.authorized(AccessManage, t.requestVerification))
	return mux
}

func (t *Transmitter) serveMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, t.metadata)
}

func (t *Transmitter) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(t.jwks)
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, rx Receiver)

// authorized authenticates the request's bearer token and checks the
// Receiver has at least the required access (RFC 6750 §3.1 error codes).
func (t *Transmitter) authorized(required Access, h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		token := bearerToken(r)
		if token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer`)
			writeError(w, http.StatusUnauthorized, "invalid_request", "a bearer access token is required in the Authorization header")
			return
		}
		rx, err := t.cfg.Authorize(r.Context(), token)
		if errors.Is(err, ErrInvalidToken) {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid_token", "the access token is invalid")
			return
		}
		if err != nil {
			t.serverError(w, r, "authorize", err)
			return
		}
		if rx.ID == "" || len(rx.Audience) == 0 {
			t.serverError(w, r, "authorize", errors.New("AuthorizeFunc returned a Receiver without ID or Audience"))
			return
		}
		if rx.Access < required {
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
			writeError(w, http.StatusForbidden, "insufficient_scope", "the access token does not permit this operation")
			return
		}
		h(w, r, rx)
	})
}

func (t *Transmitter) serverError(w http.ResponseWriter, r *http.Request, op string, err error) {
	t.log.ErrorContext(r.Context(), "ssf transmitter: "+op, "method", r.Method, "path", r.URL.Path, "error", err)
	writeError(w, http.StatusInternalServerError, "server_error", "internal error")
}

// apiError is an error with the HTTP status the stream management API
// reports it as.
type apiError struct {
	status      int
	code        string
	description string
}

func (e *apiError) Error() string { return e.description }

func badRequest(format string, args ...any) *apiError {
	return &apiError{http.StatusBadRequest, "invalid_request", fmt.Sprintf(format, args...)}
}

var errStreamNotFound = &apiError{http.StatusNotFound, "not_found", "no stream with this stream_id exists for this Receiver"}

// writeAPIError writes err as its HTTP status, or 500 if it is not an
// *apiError.
func (t *Transmitter) writeAPIError(w http.ResponseWriter, r *http.Request, op string, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		writeError(w, ae.status, ae.code, ae.description)
		return
	}
	t.serverError(w, r, op, err)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

// randomID returns 128 random bits as hex: unreserved characters only, as
// SSF 1.0 §8.1.1 recommends for stream IDs.
func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
