// Command conformance-transmitter runs an SSFgo Transmitter configured for
// the OpenID Foundation SSF conformance suite's CAEP Interoperability
// Profile Transmitter plan.
//
// Besides the Transmitter it serves a minimal OAuth 2.0 authorization
// server — client credentials only, the one grant the suite uses to obtain
// Transmitter access tokens (CAEP Interop §2.7.1). That server exists for
// conformance runs; it is not part of the SSFgo library.
//
// All state is in memory and every key is generated at startup.
//
//	go run ./cmd/conformance-transmitter -issuer https://host.docker.internal:9443/ssfgo
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"flag"
	"log"
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
	"github.com/idfoundry/ssfgo/storage/memstore"
	"github.com/idfoundry/ssfgo/transmitter"
)

func main() {
	var (
		addr          = flag.String("addr", ":9443", "listen address")
		issuer        = flag.String("issuer", "https://host.docker.internal:9443/ssfgo", "Transmitter issuer; its origin also serves the OAuth endpoints")
		certFile      = flag.String("tls-cert", "", "TLS certificate (PEM); a self-signed one is generated if empty")
		keyFile       = flag.String("tls-key", "", "TLS private key (PEM)")
		clientID      = flag.String("client-id", "ssf-test-client", "OAuth client ID the suite authenticates as")
		clientSecret  = flag.String("client-secret", "ssf-test-secret", "OAuth client secret")
		staticToken   = flag.String("static-token", "", "an access token that is always valid, for the suite's static auth mode")
		singleStream  = flag.Bool("single-stream", false, "allow one stream per Receiver (409 on a second create)")
		tokenLifetime = flag.Duration("token-lifetime", 10*time.Minute, "access token lifetime; CAEP Interop §2.7.1 caps it at 60 minutes")
		insecurePush  = flag.Bool("insecure-push-tls", false, "skip TLS verification when pushing to Receivers (the local suite's certificate is self-signed)")
		emitDelay     = flag.Duration("emit-after-verification", 2*time.Second, "after a verification request, emit the CAEP Interop events the stream delivers; 0 disables")
	)
	flag.Parse()

	iss, err := url.Parse(*issuer)
	if err != nil {
		log.Fatalf("issuer: %v", err)
	}
	origin := iss.Scheme + "://" + iss.Host

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	as := newAuthServer(origin, *clientID, *clientSecret, *tokenLifetime)
	if *staticToken != "" {
		as.addStaticToken(*staticToken)
	}

	store := memstore.NewStreamStore()
	pushClient := &http.Client{Timeout: 10 * time.Second}
	if *insecurePush {
		pushClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // test harness flag
	}
	cfg := transmitter.Config{
		Issuer:                     *issuer,
		SigningKeys:                []transmitter.SigningKey{{Signer: key, Algorithm: ssf.RS256, KeyID: "ssfgo-conformance-1"}},
		EventsSupported:            supportedEvents(),
		DeliveryMethods:            []ssf.DeliveryMethod{ssf.DeliveryPush, ssf.DeliveryPoll},
		DefaultSubjects:            ssf.DefaultSubjectsAll,
		Store:                      store,
		Authorize:                  as.authorize,
		MultipleStreamsPerReceiver: !*singleStream,
		MinVerificationInterval:    0,
		HTTPClient:                 pushClient,
		Logger:                     slog.Default(),
	}
	if err := interop.Apply(&cfg); err != nil {
		log.Fatal(err)
	}
	tx, err := transmitter.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		if err := tx.Run(context.Background()); err != nil {
			log.Fatal(err)
		}
	}()

	mux := http.NewServeMux()
	as.register(mux)
	handler := tx.Handler()
	if *emitDelay > 0 {
		handler = emitAfterVerification(tx, store, *issuer, *emitDelay, handler)
	}
	mux.Handle("/", handler)

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if *certFile == "" {
		cert, err := testcert.SelfSigned(iss.Hostname())
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           logRequests(mux),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}
	wellKnown, _ := ssf.WellKnownURL(*issuer)
	slog.Info("conformance transmitter listening", "addr", *addr, "issuer", *issuer, "metadata", wellKnown,
		"oauth_metadata", origin+"/.well-known/oauth-authorization-server")
	log.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))
}

// supportedEvents is every CAEP and RISC event type a new Transmitter may
// emit: RISC's sessions-revoked is excluded, since RISC 1.0 §2.11 requires
// new implementations to use CAEP's session-revoked instead.
func supportedEvents() []ssf.EventType {
	r := ssf.NewRegistry()
	if err := caep.Register(r); err != nil {
		log.Fatal(err)
	}
	if err := risc.Register(r); err != nil {
		log.Fatal(err)
	}
	var out []ssf.EventType
	deprecated := risc.SessionsRevokedEventType //nolint:staticcheck // SA1019: referenced to exclude it
	for _, t := range r.Types() {
		if !strings.HasPrefix(string(t), "https://schemas.openid.net/secevent/ssf/") && t != deprecated {
			out = append(out, t)
		}
	}
	return out
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
