package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/internal/setcodec"
	"github.com/idfoundry/ssfgo/storage/memstore"
	"github.com/idfoundry/ssfgo/transmitter"
)

const audience = "https://rp.example"

// fixture is an SSFgo Transmitter serving its metadata and keys over TLS,
// and a client that trusts it.
type fixture struct {
	issuer string
	client *http.Client
	key    *rsa.PrivateKey
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	issuer := srv.URL + "/tx"
	tx, err := transmitter.New(transmitter.Config{
		Assurance:       ssf.AssuranceDevelopment,
		Limits:          transmitter.RecommendedLimits(),
		PushRetry:       transmitter.RecommendedPushRetry(),
		PermitEvent:     transmitter.PermitAll,
		Issuer:          issuer,
		SigningKeys:     []transmitter.SigningKey{{Signer: key, Algorithm: ssf.RS256, KeyID: "k1"}},
		EventsSupported: []ssf.EventType{caep.SessionRevokedEventType},
		DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPoll},
		DefaultSubjects: ssf.DefaultSubjectsAll,
		Store:           memstore.NewStreamStore(),
		Authorize: func(context.Context, string) (transmitter.Receiver, error) {
			return transmitter.Receiver{}, transmitter.ErrInvalidToken
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = tx.Handler()
	return fixture{issuer: issuer, client: srv.Client(), key: key}
}

func (f fixture) sign(t *testing.T, mutate func(*ssf.SET)) string {
	t.Helper()
	set := ssf.SET{
		Issuer:   f.issuer,
		Audience: []string{audience},
		JWTID:    "jti-1",
		IssuedAt: time.Now(),
		Subject:  ssf.EmailSubject{Email: "alice@example.com"},
		Event:    caep.SessionRevoked{},
	}
	if mutate != nil {
		mutate(&set)
	}
	token, err := setcodec.Encode(setcodec.Signer{Key: f.key, Algorithm: ssf.RS256, KeyID: "k1"}, set)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

type result struct {
	status         int
	stdout, stderr string
}

func (f fixture) run(stdin string, args ...string) result {
	var stdout, stderr bytes.Buffer
	status := run(args, strings.NewReader(stdin), &stdout, &stderr, f.client)
	return result{status, stdout.String(), stderr.String()}
}

func TestMetadata(t *testing.T) {
	f := newFixture(t)
	got := f.run("", "metadata", f.issuer)
	if got.status != 0 {
		t.Fatalf("metadata = %d: %s", got.status, got.stderr)
	}
	var md ssf.TransmitterMetadata
	if err := json.Unmarshal([]byte(got.stdout), &md); err != nil || md.Issuer != f.issuer || md.JWKSURI == "" {
		t.Errorf("metadata printed %s (%v), want the Transmitter's", got.stdout, err)
	}
}

func TestMetadataRefusesAnotherIssuer(t *testing.T) {
	f := newFixture(t)
	// The metadata names f.issuer, not the issuer asked about.
	location, err := ssf.WellKnownURL(f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	got := f.run("", "metadata", "-metadata-url", location, strings.TrimSuffix(f.issuer, "/tx")+"/other")
	if got.status != 1 || !strings.Contains(got.stderr, "names issuer") {
		t.Errorf("metadata for another issuer = %d: %s; want 1 and why", got.status, got.stderr)
	}
}

func TestVerify(t *testing.T) {
	f := newFixture(t)
	token := f.sign(t, nil)
	dir := t.TempDir()
	file := filepath.Join(dir, "set.jwt")
	if err := os.WriteFile(file, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ stdin, arg string }{
		"argument": {"", token},
		"file":     {"", file},
		"stdin":    {token + "\n", "-"},
	} {
		t.Run(name, func(t *testing.T) {
			args := []string{"verify", "-issuer", f.issuer, "-audience", audience}
			if tc.arg != "" {
				args = append(args, tc.arg)
			}
			got := f.run(tc.stdin, args...)
			if got.status != 0 {
				t.Fatalf("verify = %d: %s", got.status, got.stderr)
			}
			var parts struct{ Header, Claims map[string]any }
			if err := json.Unmarshal([]byte(got.stdout), &parts); err != nil || parts.Claims["jti"] != "jti-1" || parts.Header["kid"] != "k1" {
				t.Errorf("verify printed %s (%v)", got.stdout, err)
			}
			if !strings.HasPrefix(got.stderr, "verified: jti-1 event "+string(caep.SessionRevokedEventType)) {
				t.Errorf("verify reported %q", got.stderr)
			}
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	f := newFixture(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := setcodec.Encode(setcodec.Signer{Key: other, Algorithm: ssf.RS256, KeyID: "k1"}, ssf.SET{
		Issuer: f.issuer, Audience: []string{audience}, JWTID: "forged", IssuedAt: time.Now(),
		Subject: ssf.EmailSubject{Email: "alice@example.com"}, Event: caep.SessionRevoked{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{
		"another audience": f.sign(t, func(s *ssf.SET) { s.Audience = []string{"https://other.example"} }),
		"forged signature": forged,
	} {
		t.Run(name, func(t *testing.T) {
			got := f.run("", "verify", "-issuer", f.issuer, "-audience", audience, token)
			if got.status != 1 || got.stdout != "" {
				t.Errorf("verify = %d, printing %q: %s; want 1 and nothing printed", got.status, got.stdout, got.stderr)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	f := newFixture(t)
	token := f.sign(t, nil)
	if got := f.run("", "decode", token); got.status != 2 || got.stdout != "" {
		t.Errorf("decode without -unverified = %d, printing %q; want 2 and nothing printed", got.status, got.stdout)
	}
	got := f.run(token, "decode", "-unverified")
	if got.status != 0 || !strings.Contains(got.stderr, "NOT VERIFIED") {
		t.Fatalf("decode -unverified = %d: %s", got.status, got.stderr)
	}
	var parts struct{ Claims map[string]any }
	if err := json.Unmarshal([]byte(got.stdout), &parts); err != nil || parts.Claims["iss"] != f.issuer {
		t.Errorf("decode printed %s (%v)", got.stdout, err)
	}
	if got := f.run("", "decode", "-unverified", "e30.bm90IGpzb24.sig"); got.status != 1 {
		t.Errorf("decode of a payload that is not JSON = %d, want 1", got.status)
	}
}

func TestUsage(t *testing.T) {
	f := newFixture(t)
	for _, args := range [][]string{{}, {"unknown"}, {"verify", "token"}, {"metadata"}} {
		if got := f.run("", args...); got.status != 2 {
			t.Errorf("ssf %v = %d, want 2", args, got.status)
		}
	}
}
