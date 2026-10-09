package receiver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

// New checks a ClientCredentials TokenSource, reporting every problem at
// once by field, rather than leaving them to the first token request.
func TestClientCredentialsCheckedByNew(t *testing.T) {
	cfg := newEnv(t).cfg
	cfg.TokenSource = &receiver.ClientCredentials{TokenURL: "http://as.example/token"}
	_, err := receiver.New(context.Background(), cfg)
	if err == nil {
		t.Fatal("New accepted an incomplete ClientCredentials")
	}
	for _, want := range []string{"TokenSource.TokenURL must be an https URL", "TokenSource.ClientID is required", "TokenSource.AuthMethod must be"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

// A typed-nil SigningKey or ReplayStore is reported as missing; its
// methods would panic.
func TestTypedNilsCheckedByNew(t *testing.T) {
	cfg := newEnv(t).cfg
	cfg.Assurance = ssf.AssuranceProduction
	cfg.ReplayStore = (*memstore.ReplayStore)(nil)
	cfg.TokenSource = &receiver.ClientCredentials{TokenURL: "https://as.example/token", ClientID: "rp",
		AuthMethod: receiver.PrivateKeyJWT, SigningKey: (*ecdsa.PrivateKey)(nil), SigningAlgorithm: ssf.ES256}
	_, err := receiver.New(context.Background(), cfg)
	if err == nil {
		t.Fatal("New accepted typed nils")
	}
	for _, want := range []string{"TokenSource.SigningKey is required", "ReplayStore is required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

type wrappedTokens struct{ inner receiver.TokenSource }

func (w wrappedTokens) Token(ctx context.Context) (string, error) { return w.inner.Token(ctx) }
func (w wrappedTokens) Unwrap() receiver.TokenSource              { return w.inner }

// A ClientCredentials wrapped by another TokenSource is still checked,
// key custody included, if the wrapper implements Unwrap.
func TestClientCredentialsCheckedThroughWrapper(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := receiver.Config{
		Assurance:  ssf.AssuranceProduction,
		Limits:     receiver.RecommendedLimits(),
		Issuer:     "https://tx.example",
		Audience:   audience,
		Registry:   ssf.NewRegistry(),
		Algorithms: []ssf.SignatureAlgorithm{ssf.RS256},
		TokenSource: wrappedTokens{&receiver.ClientCredentials{
			TokenURL: "https://as.example/token", ClientID: "rp", AuthMethod: receiver.PrivateKeyJWT,
			SigningKey: key, SigningAlgorithm: ssf.ES256, // an ephemeral key, custody undeclared
		}},
		ReplayStore: memstore.NewReplayStore(),
	}
	_, err = receiver.New(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "TokenSource.SigningKey must be declared durable") {
		t.Errorf("New = %v; want the wrapped key's custody refused", err)
	}
}

// The cached access token is not printed with the ClientCredentials.
func TestClientCredentialsPrintsNoToken(t *testing.T) {
	const token = "AT-very-secret"
	as := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":3600}`, token)
	}))
	defer as.Close()
	cc := &receiver.ClientCredentials{TokenURL: as.URL, ClientID: "rp", ClientSecret: ssf.NewSecret("secret"),
		AuthMethod: receiver.ClientSecretBasic, HTTPClient: as.Client()}
	if _, err := cc.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if s := fmt.Sprintf(verb, cc); strings.Contains(s, token) {
			t.Errorf("%s printed the access token: %s", verb, s)
		}
	}
}

// A failed token request's error carries the response's status and a
// cleaned error code and description, never the body itself.
func TestTokenErrorCleansBody(t *testing.T) {
	for name, c := range map[string]struct {
		body string
		want string
	}{
		"a JSON error": {`{"error":"invalid_client","error_description":"bad\nclient\u001b[31m","debug":"xxxx"}`, "invalid_client"},
		"a large page": {"<html>" + strings.Repeat("x", 10000), "byte body"},
	} {
		t.Run(name, func(t *testing.T) {
			as := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, c.body)
			}))
			defer as.Close()
			cc := &receiver.ClientCredentials{TokenURL: as.URL, ClientID: "rp", ClientSecret: ssf.NewSecret("secret"),
				AuthMethod: receiver.ClientSecretBasic, HTTPClient: as.Client()}
			_, err := cc.Token(context.Background())
			if err == nil {
				t.Fatal("no error")
			}
			msg := err.Error()
			if !strings.Contains(msg, c.want) || strings.Contains(msg, "xxxx") || strings.ContainsAny(msg, "\n\x1b") || len(msg) > 512 {
				t.Errorf("error = %q", msg)
			}
		})
	}
}
