package clientassertion

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/jose"
)

func decode(t *testing.T, tok string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %s", tok)
	}
	var h, c map[string]any
	for i, v := range []*map[string]any{&h, &c} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil || json.Unmarshal(b, v) != nil {
			t.Fatalf("segment %d does not decode", i)
		}
	}
	return h, c
}

func TestClientSecretJWT(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	now := time.Unix(1700000000, 0)
	tok, err := Build(Options{ClientID: "client", Audience: "https://as.example/token", Now: now, Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	h, c := decode(t, tok)
	if h["alg"] != "HS256" {
		t.Errorf("header = %v", h)
	}
	if c["iss"] != "client" || c["sub"] != "client" || c["aud"] != "https://as.example/token" ||
		c["iat"] != float64(now.Unix()) || c["exp"] != float64(now.Add(Lifetime).Unix()) || c["jti"] == "" {
		t.Errorf("claims = %v", c)
	}
	i := strings.LastIndexByte(tok, '.')
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(tok[:i]))
	if tok[i+1:] != base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) {
		t.Error("MAC does not verify")
	}
	if _, err := Build(Options{ClientID: "client", Audience: "a", Now: now, Secret: []byte("short")}); err == nil {
		t.Error("a secret shorter than 32 bytes was accepted")
	}
}

func TestPrivateKeyJWT(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tok, err := Build(Options{ClientID: "client", Audience: "https://as.example/token", Now: time.Now(), Signer: key, Algorithm: ssf.ES256, KeyID: "k"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := jose.ParseCompact(tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(&key.PublicKey, ssf.ES256); err != nil || c.Header.KeyID != "k" {
		t.Errorf("Verify = %v, kid %q", err, c.Header.KeyID)
	}
}

func TestBuildRejects(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	secret := []byte(strings.Repeat("k", 32))
	for name, o := range map[string]Options{
		"no client":   {Audience: "a", Secret: secret},
		"no audience": {ClientID: "c", Secret: secret},
		"no key":      {ClientID: "c", Audience: "a"},
		"both":        {ClientID: "c", Audience: "a", Secret: secret, Signer: key, Algorithm: ssf.ES256},
		"wrong alg":   {ClientID: "c", Audience: "a", Signer: key, Algorithm: ssf.RS256},
	} {
		if _, err := Build(o); err == nil {
			t.Errorf("%s: Build succeeded", name)
		}
	}
}
