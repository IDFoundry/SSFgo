package interop_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/caep/interop"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/storage/memstore"
	"github.com/idfoundry/ssfgo/transmitter"
)

func receiverConfig(t *testing.T, issuer string, client *http.Client) receiver.Config {
	r := ssf.NewRegistry()
	if err := caep.Register(r); err != nil {
		t.Fatal(err)
	}
	return receiver.Config{
		Issuer:      issuer,
		Audience:    "https://rx.example",
		Registry:    r,
		Algorithms:  []ssf.SignatureAlgorithm{ssf.RS256},
		TokenSource: receiver.StaticToken("t"),
		ReplayStore: memstore.NewReplayStore(),
		HTTPClient:  client,
		Logger:      slog.New(slog.DiscardHandler),
	}
}

func TestCheckReceiverConfig(t *testing.T) {
	if err := interop.CheckReceiverConfig(receiverConfig(t, "https://tx.example", nil)); err != nil {
		t.Fatalf("conforming config rejected: %v", err)
	}
	riscOnly := ssf.NewRegistry()
	_ = risc.Register(riscOnly)
	for name, mutate := range map[string]func(*receiver.Config){
		"no RS256":       func(c *receiver.Config) { c.Algorithms = []ssf.SignatureAlgorithm{ssf.ES256} },
		"no CAEP events": func(c *receiver.Config) { c.Registry = riscOnly },
		"no registry":    func(c *receiver.Config) { c.Registry = nil },
	} {
		c := receiverConfig(t, "https://tx.example", nil)
		mutate(&c)
		if err := interop.CheckReceiverConfig(c); !errors.Is(err, interop.ErrNotInterop) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Accepting ES256 as well as RS256 is not a violation.
	c := receiverConfig(t, "https://tx.example", nil)
	c.Algorithms = append(c.Algorithms, ssf.ES256)
	if err := interop.CheckReceiverConfig(c); err != nil {
		t.Errorf("RS256 + ES256: %v", err)
	}
}

func conformingMetadata() ssf.TransmitterMetadata {
	return ssf.TransmitterMetadata{
		SpecVersion:              "1_0",
		Issuer:                   "https://tx.example",
		JWKSURI:                  "https://tx.example/jwks",
		DeliveryMethodsSupported: []ssf.DeliveryMethod{ssf.DeliveryPush, ssf.DeliveryPoll},
		ConfigurationEndpoint:    "https://tx.example/stream",
		StatusEndpoint:           "https://tx.example/status",
		VerificationEndpoint:     "https://tx.example/verify",
		AuthorizationSchemes:     []ssf.AuthorizationScheme{{SpecURN: ssf.OAuth2SpecURN}},
	}
}

func TestCheckTransmitterMetadata(t *testing.T) {
	if err := interop.CheckTransmitterMetadata(conformingMetadata()); err != nil {
		t.Fatalf("conforming metadata rejected: %v", err)
	}
	for name, mutate := range map[string]func(*ssf.TransmitterMetadata){
		"no spec_version":      func(m *ssf.TransmitterMetadata) { m.SpecVersion = "" },
		"draft spec_version":   func(m *ssf.TransmitterMetadata) { m.SpecVersion = "1_0-ID2" },
		"garbage spec_version": func(m *ssf.TransmitterMetadata) { m.SpecVersion = "latest" },
		"no delivery methods":  func(m *ssf.TransmitterMetadata) { m.DeliveryMethodsSupported = nil },
		"no jwks_uri":          func(m *ssf.TransmitterMetadata) { m.JWKSURI = "" },
		"no configuration":     func(m *ssf.TransmitterMetadata) { m.ConfigurationEndpoint = "" },
		"no status":            func(m *ssf.TransmitterMetadata) { m.StatusEndpoint = "" },
		"no verification":      func(m *ssf.TransmitterMetadata) { m.VerificationEndpoint = "" },
		"no OAuth scheme": func(m *ssf.TransmitterMetadata) {
			m.AuthorizationSchemes = []ssf.AuthorizationScheme{{SpecURN: "urn:ietf:rfc:8705"}}
		},
		"no schemes at all": func(m *ssf.TransmitterMetadata) { m.AuthorizationSchemes = nil },
	} {
		md := conformingMetadata()
		mutate(&md)
		if err := interop.CheckTransmitterMetadata(md); !errors.Is(err, interop.ErrNotInterop) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, v := range []string{"1_1", "2_0", "10_0"} {
		md := conformingMetadata()
		md.SpecVersion = v
		if err := interop.CheckTransmitterMetadata(md); err != nil {
			t.Errorf("spec_version %q rejected: %v", v, err)
		}
	}
}

// ApplyReceiver makes receiver.New refuse a Transmitter that does not meet
// the profile, and accept SSFgo's own Transmitter configured for it.
func TestApplyReceiver(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	txCfg := config(t)
	txCfg.Issuer = srv.URL + "/tx"
	if err := interop.ApplyTransmitter(&txCfg); err != nil {
		t.Fatal(err)
	}
	tx, err := transmitter.New(txCfg)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", tx.Handler())
	// A second, non-conforming Transmitter on the same host.
	mux.HandleFunc("/.well-known/ssf-configuration/legacy", func(w http.ResponseWriter, _ *http.Request) {
		md := tx.Metadata()
		md.Issuer = srv.URL + "/legacy"
		md.SpecVersion = "1_0-ID2"
		md.AuthorizationSchemes = nil
		_ = json.NewEncoder(w).Encode(md)
	})
	srv.Config.Handler = mux

	good := receiverConfig(t, srv.URL+"/tx", srv.Client())
	var previousCalled bool
	good.CheckMetadata = func(ssf.TransmitterMetadata) error { previousCalled = true; return nil }
	if err := interop.ApplyReceiver(&good); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.New(context.Background(), good); err != nil {
		t.Fatalf("New against a conforming Transmitter: %v", err)
	}
	if !previousCalled {
		t.Error("ApplyReceiver dropped the existing CheckMetadata")
	}

	legacy := receiverConfig(t, srv.URL+"/legacy", srv.Client())
	if err := interop.ApplyReceiver(&legacy); err != nil {
		t.Fatal(err)
	}
	_, err = receiver.New(context.Background(), legacy)
	if !errors.Is(err, interop.ErrNotInterop) || !strings.Contains(err.Error(), "spec_version") || !strings.Contains(err.Error(), "authorization_schemes") {
		t.Errorf("New against a non-conforming Transmitter = %v", err)
	}

	bad := receiverConfig(t, srv.URL+"/tx", srv.Client())
	bad.Algorithms = []ssf.SignatureAlgorithm{ssf.ES256}
	if err := interop.ApplyReceiver(&bad); err == nil || bad.CheckMetadata != nil {
		t.Error("ApplyReceiver accepted a non-conforming config or modified it")
	}
}
