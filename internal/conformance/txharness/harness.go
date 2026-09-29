// Package txharness runs an SSFgo Transmitter configured for the OpenID
// Foundation SSF conformance suite's CAEP Interoperability Profile
// Transmitter plan. cmd/conformance-transmitter runs it on in-memory
// storage, and storage/sqlstore/cmd/conformance-transmitter on
// storage/sqlstore; the store is the only difference.
//
// Besides the Transmitter it serves a minimal OAuth 2.0 authorization
// server — client credentials only, the one grant the suite uses to obtain
// Transmitter access tokens (CAEP Interop §2.7.1). That server exists for
// conformance runs; it is not part of the SSFgo library.
//
// Every key is generated at startup.
package txharness

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/caep/interop"
	"github.com/idfoundry/ssfgo/internal/testcert"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/transmitter"
)

// Options are the harness's command-line settings.
type Options struct {
	Addr, Issuer, CertFile, KeyFile      string
	ClientID, ClientSecret, StaticToken  string
	SingleStream, InsecurePush           bool
	TokenLifetime, EmitAfterVerification time.Duration
}

// RegisterFlags defines the harness's flags on fs and returns the Options
// they fill in once fs is parsed.
func RegisterFlags(fs *flag.FlagSet) *Options {
	o := &Options{}
	fs.StringVar(&o.Addr, "addr", ":9443", "listen address")
	fs.StringVar(&o.Issuer, "issuer", "https://host.docker.internal:9443/ssfgo", "Transmitter issuer; its origin also serves the OAuth endpoints")
	fs.StringVar(&o.CertFile, "tls-cert", "", "TLS certificate (PEM); a self-signed one is generated if empty")
	fs.StringVar(&o.KeyFile, "tls-key", "", "TLS private key (PEM)")
	fs.StringVar(&o.ClientID, "client-id", "ssf-test-client", "OAuth client ID the suite authenticates as")
	fs.StringVar(&o.ClientSecret, "client-secret", "ssf-test-secret", "OAuth client secret")
	fs.StringVar(&o.StaticToken, "static-token", "", "an access token that is always valid, for the suite's static auth mode")
	fs.BoolVar(&o.SingleStream, "single-stream", false, "allow one stream per Receiver (409 on a second create)")
	fs.DurationVar(&o.TokenLifetime, "token-lifetime", 10*time.Minute, "access token lifetime; CAEP Interop §2.7.1 caps it at 60 minutes")
	fs.BoolVar(&o.InsecurePush, "insecure-push-tls", false, "skip TLS verification when pushing to Receivers (the local suite's certificate is self-signed)")
	fs.DurationVar(&o.EmitAfterVerification, "emit-after-verification", 2*time.Second, "after a verification request, emit the CAEP Interop events the stream delivers; 0 disables")
	return o
}

// Run serves the harness on store until the server fails.
func Run(o *Options, store storage.StreamStore) error {
	iss, err := url.Parse(o.Issuer)
	if err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	origin := iss.Scheme + "://" + iss.Host

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	as := newAuthServer(origin, o.ClientID, o.ClientSecret, o.TokenLifetime)
	if o.StaticToken != "" {
		as.addStaticToken(o.StaticToken)
	}

	pushClient := &http.Client{Timeout: 10 * time.Second}
	if o.InsecurePush {
		pushClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // test harness flag
	}
	events, err := supportedEvents()
	if err != nil {
		return err
	}
	cfg := transmitter.Config{
		Issuer:                     o.Issuer,
		SigningKeys:                []transmitter.SigningKey{{Signer: key, Algorithm: ssf.RS256, KeyID: "ssfgo-conformance-1"}},
		EventsSupported:            events,
		DeliveryMethods:            []ssf.DeliveryMethod{ssf.DeliveryPush, ssf.DeliveryPoll},
		DefaultSubjects:            ssf.DefaultSubjectsAll,
		Store:                      store,
		Authorize:                  as.authorize,
		MultipleStreamsPerReceiver: !o.SingleStream,
		// The suite does not always delete the streams its modules
		// create, so allow many more than the default.
		Limits: transmitter.Limits{StreamsPerReceiver: 1000},
		// Exercise both optional SSF features against the suite: a
		// Transmitter-initiated verification on every new stream (the
		// suite accepts these, SSF §8.1.4), and an inactivity timeout
		// long enough never to fire during a run.
		VerifyNewStreams:        true,
		Inactivity:              transmitter.InactivityPolicy{Timeout: time.Hour, Action: transmitter.InactivityPause},
		MinVerificationInterval: 0,
		HTTPClient:              pushClient,
		Logger:                  slog.Default(),
	}
	if err := interop.ApplyTransmitter(&cfg); err != nil {
		return err
	}
	tx, err := transmitter.New(cfg)
	if err != nil {
		return err
	}
	runErr := make(chan error, 1)
	go func() { runErr <- tx.Run(context.Background()) }()

	mux := http.NewServeMux()
	as.register(mux)
	handler := tx.Handler()
	if o.EmitAfterVerification > 0 {
		handler = emitAfterVerification(tx, store, o.Issuer, o.EmitAfterVerification, handler)
	}
	mux.Handle("/", handler)

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.CertFile == "" {
		cert, err := testcert.SelfSigned(iss.Hostname())
		if err != nil {
			return err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	srv := &http.Server{
		Addr:              o.Addr,
		Handler:           logRequests(mux),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}
	wellKnown, _ := ssf.WellKnownURL(o.Issuer)
	slog.Info("conformance transmitter listening", "addr", o.Addr, "issuer", o.Issuer, "metadata", wellKnown,
		"oauth_metadata", origin+"/.well-known/oauth-authorization-server")
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServeTLS(o.CertFile, o.KeyFile) }()
	select {
	case err := <-serveErr:
		return err
	case err := <-runErr:
		return errors.Join(errors.New("push delivery stopped"), err)
	}
}

// supportedEvents is every CAEP and RISC event type a new Transmitter may
// emit: RISC's sessions-revoked is excluded, since RISC 1.0 §2.11 requires
// new implementations to use CAEP's session-revoked instead.
func supportedEvents() ([]ssf.EventType, error) {
	r := ssf.NewRegistry()
	if err := caep.Register(r); err != nil {
		return nil, err
	}
	if err := risc.Register(r); err != nil {
		return nil, err
	}
	var out []ssf.EventType
	deprecated := risc.SessionsRevokedEventType //nolint:staticcheck // SA1019: referenced to exclude it
	for _, t := range r.Types() {
		if !strings.HasPrefix(string(t), "https://schemas.openid.net/secevent/ssf/") && t != deprecated {
			out = append(out, t)
		}
	}
	return out, nil
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Info("request", "method", r.Method, "path", r.URL.Path, "query", r.URL.RawQuery, "status", rec.status)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}
