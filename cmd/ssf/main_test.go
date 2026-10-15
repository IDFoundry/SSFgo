package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

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
	srv    *httptest.Server
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
	return fixture{issuer: issuer, client: srv.Client(), key: key, srv: srv}
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
			if !strings.Contains(got.stdout, `"verified": true`) {
				t.Errorf("verify printed %s, without \"verified\": true", got.stdout)
			}
			if !strings.HasPrefix(got.stderr, `verified: "jti-1" event `+string(caep.SessionRevokedEventType)) {
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
	// Without its standard error, decode's output must still not pass
	// for verify's.
	if !strings.Contains(got.stdout, `"verified": false`) {
		t.Errorf("decode printed %s, without \"verified\": false", got.stdout)
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

// A SET's strings reach the terminal: whatever in them a terminal would
// act on — C1 controls such as CSI, DEL, bidirectional overrides,
// invalid UTF-8 — must be printed escaped, by verify and by decode.
func TestTerminalControlsEscaped(t *testing.T) {
	f := newFixture(t)
	const hostile = "a\u009b31mb\u202ec\x7fd\U000e0041"
	verified := f.sign(t, func(s *ssf.SET) { s.JWTID = hostile })
	header := base64.RawURLEncoding.EncodeToString([]byte("{\"alg\":\"x\x9b31m\"}"))
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"` + hostile + `"}`))
	for name, args := range map[string][]string{
		"verify": {"verify", "-issuer", f.issuer, "-audience", audience, verified},
		"decode": {"decode", "-unverified", header + "." + claims + ".sig"},
	} {
		t.Run(name, func(t *testing.T) {
			got := f.run("", args...)
			if got.status != 0 {
				t.Fatalf("%s = %d: %s", name, got.status, got.stderr)
			}
			for _, out := range []string{got.stdout, got.stderr} {
				for _, r := range out {
					if r == utf8.RuneError || r == 0x7f || (r >= 0x80 && r <= 0x9f) || unicode.Is(unicode.Cf, r) {
						t.Errorf("printed %U unescaped: %q", r, out)
					}
				}
			}
			if !strings.Contains(got.stdout, `\u009b31m`) {
				t.Errorf("printed %s, without the escaped CSI", got.stdout)
			}
			var parts struct{ Claims map[string]any }
			if err := json.Unmarshal([]byte(got.stdout), &parts); err != nil || parts.Claims["jti"] != hostile {
				t.Errorf("printed %s (%v), not JSON keeping the jti", got.stdout, err)
			}
		})
	}
}

// A file whose name looks like a token — two dots, no slash — is read as
// a file.
func TestVerifyFileNamedLikeToken(t *testing.T) {
	f := newFixture(t)
	t.Chdir(t.TempDir())
	if err := os.WriteFile("captured.2026.jwt", []byte(f.sign(t, nil)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := f.run("", "verify", "-issuer", f.issuer, "-audience", audience, "captured.2026.jwt"); got.status != 0 {
		t.Errorf("verify captured.2026.jwt = %d: %s", got.status, got.stderr)
	}
}

func TestFlagsAfterToken(t *testing.T) {
	f := newFixture(t)
	if got := f.run("", "verify", f.sign(t, nil), "-issuer", f.issuer, "-audience", audience); got.status != 0 {
		t.Errorf("verify TOKEN -issuer … = %d: %s", got.status, got.stderr)
	}
	if got := f.run("", "metadata", f.issuer, "-timeout", "5s"); got.status != 0 {
		t.Errorf("metadata ISSUER -timeout … = %d: %s", got.status, got.stderr)
	}
	// After "--", even what looks like a flag is the argument.
	if got := f.run("", "decode", "-unverified", "--", "-x"); got.status != 1 || !strings.Contains(got.stderr, "no such file") {
		t.Errorf("decode -unverified -- -x = %d: %s; want -x read as a file", got.status, got.stderr)
	}
}

func TestErrorPrefixedOnce(t *testing.T) {
	f := newFixture(t)
	got := f.run("", "verify", "-issuer", f.issuer, "-audience", audience, "-alg", "none", f.sign(t, nil))
	if got.status != 1 || !strings.HasPrefix(got.stderr, "ssf: ") || strings.Contains(got.stderr, "ssf: ssf:") {
		t.Errorf("verify -alg none = %d: %q; want one \"ssf:\" prefix", got.status, got.stderr)
	}
}

// A Transmitter with a development certificate is reached by trusting
// its CA with -ca-file.
func TestCAFile(t *testing.T) {
	f := newFixture(t)
	file := filepath.Join(t.TempDir(), "ca.pem")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	if err := os.WriteFile(file, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	f.client = nil // the system's roots, which do not include the test CA
	if got := f.run("", "metadata", f.issuer); got.status != 1 || !strings.Contains(got.stderr, "certificate") {
		t.Fatalf("metadata without -ca-file = %d: %s; want a certificate error", got.status, got.stderr)
	}
	if got := f.run("", "metadata", "-ca-file", file, f.issuer); got.status != 0 {
		t.Errorf("metadata -ca-file = %d: %s", got.status, got.stderr)
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := f.run("", "metadata", "-ca-file", empty, f.issuer); got.status != 1 || !strings.Contains(got.stderr, "no PEM certificates") {
		t.Errorf("metadata -ca-file with no certificates = %d: %s", got.status, got.stderr)
	}
}

// With -audience-per-stream, a SET addressed to AUDIENCE/STREAM_ID is
// verified by reading that stream with the access token in
// SSF_ACCESS_TOKEN.
func TestVerifyAudiencePerStream(t *testing.T) {
	f := newFixture(t)
	const accessToken = "token-1"
	tx := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Query().Get("stream_id") != "s1" {
			tx.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+accessToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ssf.StreamConfiguration{
			StreamID:        "s1",
			Issuer:          f.issuer,
			Audience:        ssf.Audience{audience + "/s1"},
			EventsSupported: []ssf.EventType{caep.SessionRevokedEventType},
			EventsRequested: []ssf.EventType{caep.SessionRevokedEventType},
			EventsDelivered: []ssf.EventType{caep.SessionRevokedEventType},
			Delivery:        ssf.Delivery{Method: ssf.DeliveryPoll, EndpointURL: f.issuer + "/poll"},
		})
	})
	token := f.sign(t, func(s *ssf.SET) { s.Audience = []string{audience + "/s1"} })
	args := []string{"verify", "-issuer", f.issuer, "-audience", audience, token}
	if got := f.run("", args...); got.status != 1 {
		t.Errorf("verify without -audience-per-stream = %d, want 1", got.status)
	}
	args = append(args, "-audience-per-stream")
	t.Setenv("SSF_ACCESS_TOKEN", "")
	if got := f.run("", args...); got.status != 1 || !strings.Contains(got.stderr, "SSF_ACCESS_TOKEN") {
		t.Errorf("verify -audience-per-stream without a token = %d: %s; want 1 naming SSF_ACCESS_TOKEN", got.status, got.stderr)
	}
	t.Setenv("SSF_ACCESS_TOKEN", accessToken)
	if got := f.run("", args...); got.status != 0 {
		t.Errorf("verify -audience-per-stream = %d: %s", got.status, got.stderr)
	}
}
