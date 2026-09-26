// Command conformance-receiver drives SSFgo's Receiver through an OIDF SSF
// Receiver test plan against a running conformance suite.
//
// In a Receiver plan the suite emulates a Transmitter per test module and
// waits for the Receiver to act. For every module this driver creates the
// module, reads the emulated Transmitter's issuer and credentials from the
// suite's API, and runs one Receiver session against it: discover the
// Transmitter, create a stream, read it and its status, request
// verification, take delivery of events (push or poll) until they stop
// arriving, then delete the stream.
//
//	go run ./cmd/conformance-receiver -delivery push -auth dynamic
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/jose"
	"github.com/idfoundry/ssfgo/internal/testcert"
)

type options struct {
	suite, plan, delivery, auth, clientAuth, variant string
	pushAddr, pushBase, audience, subjects, modules  string
	expectedFailures                                 string
	idle, moduleTimeout                              time.Duration

	// assertionKey signs private_key_jwt client assertions; its public
	// half is registered in the plan configuration.
	assertionKey *rsa.PrivateKey
}

func main() {
	var o options
	flag.StringVar(&o.suite, "suite", "https://localhost.emobix.co.uk:8443/", "conformance suite base URL")
	flag.StringVar(&o.plan, "plan", "openid-ssf-receiver-caep-test-plan", "test plan")
	flag.StringVar(&o.delivery, "delivery", "poll", "delivery method variant: push or poll")
	flag.StringVar(&o.auth, "auth", "static", "auth mode variant: static or dynamic")
	flag.StringVar(&o.clientAuth, "client-auth", "client_secret_basic", "client authentication for dynamic auth: client_secret_basic, client_secret_post, client_secret_jwt or private_key_jwt")
	flag.StringVar(&o.variant, "variant", "", "extra plan variants, e.g. ssf_profile=default (comma-separated key=value)")
	flag.StringVar(&o.pushAddr, "push-addr", ":9444", "listen address for the push endpoint")
	flag.StringVar(&o.pushBase, "push-base", "https://host.docker.internal:9444", "push endpoint base URL as the suite reaches it")
	flag.StringVar(&o.audience, "audience", "https://ssfgo-receiver.example", "the Receiver's audience (ssf.stream.audience)")
	flag.StringVar(&o.subjects, "subjects", "caep", "subjects the suite sends events about: caep (email + iss_sub) or email")
	flag.StringVar(&o.modules, "modules", "", "comma-separated modules to run (default: all in the plan)")
	flag.StringVar(&o.expectedFailures, "expected-failures", "", "comma-separated modules whose failure is a known conformance-suite defect: reported, but not counted as a failure")
	flag.DurationVar(&o.idle, "idle", 6*time.Second, "after verification, how long without new events before the session ends")
	flag.DurationVar(&o.moduleTimeout, "module-timeout", 2*time.Minute, "per-module time limit")
	flag.Parse()

	// The local suite and the self-signed push endpoint are test
	// infrastructure; certificate checks are off for both.
	insecure := &http.Client{
		Timeout:   40 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // conformance harness
	}

	push := newPushRouter()
	go servePush(o.pushAddr, push)

	var err error
	variant := map[string]string{"ssf_delivery_mode": o.delivery, "ssf_auth_mode": o.auth}
	if o.auth == "dynamic" {
		variant["client_auth_type"] = o.clientAuth
	}
	for _, kv := range strings.Split(o.variant, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			variant[k] = v
		}
	}
	if o.clientAuth == "private_key_jwt" {
		if o.assertionKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			log.Fatal(err)
		}
	}
	staticToken := random()
	config, err := suiteConfig(o, staticToken)
	if err != nil {
		log.Fatal(err)
	}
	planID, modules, err := createPlan(insecure, o.suite, o.plan, variant, config)
	if err != nil {
		log.Fatal(err)
	}
	if o.modules != "" {
		modules = strings.Split(o.modules, ",")
	}
	slog.Info("created plan", "plan", o.plan, "id", planID, "variant", variant, "modules", len(modules))

	expected := map[string]bool{}
	for _, m := range strings.Split(o.expectedFailures, ",") {
		if m != "" {
			expected[m] = true
		}
	}
	failed := 0
	for _, name := range modules {
		result := runModule(insecure, o, planID, name, push)
		outcome := result.outcome
		switch {
		case outcome == "PASSED" && expected[name]:
			outcome = "PASSED (expected failure no longer fails: remove it from -expected-failures)"
		case outcome != "PASSED" && expected[name]:
			outcome += " (expected)"
		case outcome != "PASSED":
			failed++
		}
		fmt.Printf("%-8s %s %s\n", outcome, name, result.id)
	}
	if failed > 0 {
		os.Exit(1)
	}
}

type moduleResult struct{ id, outcome string }

func runModule(client *http.Client, o options, planID, name string, push *pushRouter) moduleResult {
	module, err := createModuleInstance(client, o.suite, planID, name)
	if err != nil {
		slog.Error("create module", "module", name, "error", err)
		return moduleResult{outcome: "ERROR"}
	}
	if err := waitUntilWaiting(client, o.suite, module.ID, 30*time.Second); err != nil {
		slog.Error("module not ready", "module", name, "error", err)
		return moduleResult{module.ID, "ERROR"}
	}
	exposed, err := fetchExposedValues(client, o.suite, module.ID)
	if err != nil {
		slog.Error("exposed values", "module", name, "error", err)
		return moduleResult{module.ID, "ERROR"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.moduleTimeout)
	defer cancel()
	finished := func() bool {
		st, _, _ := waitUntilFinished(client, o.suite, module.ID, 0)
		return st == "FINISHED" || st == "INTERRUPTED"
	}
	s := &session{o: o, client: client, exposed: exposed, moduleID: module.ID, push: push, finished: finished}
	if err := s.run(ctx); err != nil {
		slog.Error("receiver session", "module", name, "error", err)
	}
	status, result, err := waitUntilFinished(client, o.suite, module.ID, 60*time.Second)
	if err != nil {
		slog.Error("module did not finish", "module", name, "status", status, "error", err)
		return moduleResult{module.ID, "TIMEOUT"}
	}
	if status == "INTERRUPTED" {
		return moduleResult{module.ID, "INTERRUPTED"}
	}
	return moduleResult{module.ID, result}
}

// suiteConfig is the plan configuration: the Receiver's audience, the
// subjects events are sent about, and the credentials the emulated
// Transmitter accepts.
func suiteConfig(o options, staticToken string) ([]byte, error) {
	subjects := []map[string]string{{"format": "email", "email": "ssfgo-user@example.com"}}
	if o.subjects == "caep" {
		subjects = append(subjects, map[string]string{"format": "iss_sub", "iss": "https://idp.example.com", "sub": "ssfgo-user"})
	}
	client := map[string]any{
		"client_id":     "ssfgo-receiver",
		"client_secret": random(),
		"scope":         "ssf.read ssf.manage",
	}
	switch o.clientAuth {
	case "client_secret_jwt":
		client["client_secret_jwt_alg"] = "HS256"
	case "private_key_jwt":
		jwk, err := jose.NewJWK(&o.assertionKey.PublicKey, ssf.PS256)
		if err != nil {
			return nil, err
		}
		jwks, err := jose.MarshalJWKSet(jwk.WithKeyID(assertionKeyID))
		if err != nil {
			return nil, err
		}
		client["jwks"] = json.RawMessage(jwks)
	}
	return json.Marshal(map[string]any{
		"alias":       "ssfgo-rx",
		"description": "SSFgo conformance Receiver",
		"ssf": map[string]any{
			"stream":      map[string]any{"audience": o.audience},
			"subjects":    map[string]any{"valid": subjects},
			"transmitter": map[string]any{"access_token": staticToken},
		},
		"client": client,
	})
}

// pushRouter routes /push/{module} to the Receiver session for that
// module.
type pushRouter struct {
	mu       sync.Mutex
	handlers map[string]http.Handler
}

func newPushRouter() *pushRouter { return &pushRouter{handlers: map[string]http.Handler{}} }

func (p *pushRouter) set(module string, h http.Handler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h == nil {
		delete(p.handlers, module)
		return
	}
	p.handlers[module] = h
}

func (p *pushRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	module := strings.TrimPrefix(r.URL.Path, "/push/")
	p.mu.Lock()
	h := p.handlers[module]
	p.mu.Unlock()
	if h == nil {
		http.NotFound(w, r)
		return
	}
	h.ServeHTTP(w, r)
}

func servePush(addr string, h http.Handler) {
	cert, err := testcert.SelfSigned("host.docker.internal")
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

const assertionKeyID = "ssfgo-receiver-assertion"

func random() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
