package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
)

var (
	keysOnce sync.Once
	rsa2048  *rsa.PrivateKey
	rsa1024  *rsa.PrivateKey
	p256     *ecdsa.PrivateKey
	ed       ed25519.PrivateKey
)

func testKeys(t testing.TB) {
	t.Helper()
	keysOnce.Do(func() {
		var err error
		if rsa2048, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if rsa1024, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
			panic(err)
		}
		if p256, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			panic(err)
		}
		if _, ed, err = ed25519.GenerateKey(rand.Reader); err != nil {
			panic(err)
		}
	})
}

func TestSignVerifyRoundTrip(t *testing.T) {
	testKeys(t)
	cases := []struct {
		alg    ssf.SignatureAlgorithm
		signer crypto.Signer
	}{
		{ssf.RS256, rsa2048},
		{ssf.PS256, rsa2048},
		{ssf.ES256, p256},
		{ssf.EdDSA, ed},
	}
	for _, c := range cases {
		t.Run(c.alg.String(), func(t *testing.T) {
			tok, err := Sign(c.signer, Header{Algorithm: c.alg, Type: "secevent+jwt", KeyID: "k"}, []byte(`{"a":1}`))
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseCompact(tok)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Header.Type != "secevent+jwt" || parsed.Header.KeyID != "k" {
				t.Errorf("header = %+v", parsed.Header)
			}
			if err := parsed.Verify(c.signer.Public(), c.alg); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			for _, other := range []ssf.SignatureAlgorithm{ssf.RS256, ssf.PS256, ssf.ES256, ssf.EdDSA} {
				if other == c.alg {
					continue
				}
				if err := parsed.Verify(c.signer.Public(), other); !errors.Is(err, ErrAlgorithmMismatch) {
					t.Errorf("Verify as %s = %v, want ErrAlgorithmMismatch", other, err)
				}
			}
		})
	}
}

// RS256 and PS256 share a key type, so a signature made with one must
// never verify as the other even when the header is forged to match.
func TestRS256AndPS256AreDistinct(t *testing.T) {
	testKeys(t)
	tok, err := Sign(rsa2048, Header{Algorithm: ssf.PS256}, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCompact(tok)
	if err != nil {
		t.Fatal(err)
	}
	c.Header.Algorithm = ssf.RS256
	if err := c.Verify(&rsa2048.PublicKey, ssf.RS256); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("PS256 signature verified as RS256: %v", err)
	}
}

func TestRSAKeySizeLimits(t *testing.T) {
	testKeys(t)
	for _, alg := range []ssf.SignatureAlgorithm{ssf.RS256, ssf.PS256} {
		if _, err := Sign(rsa1024, Header{Algorithm: alg}, []byte(`{}`)); err == nil {
			t.Errorf("%s: signing with a 1024-bit key succeeded", alg)
		}
		if err := ValidateKeyForAlgorithm(&rsa1024.PublicKey, alg); err == nil {
			t.Errorf("%s: 1024-bit key accepted", alg)
		}
	}
	// A signature from a weak key must not verify even if genuine.
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsa1024, crypto.SHA256, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRSAPKCS1v15(&rsa1024.PublicKey, ssf.RS256, crypto.SHA256, make([]byte, 32), sig); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("verify with 1024-bit key = %v, want ErrInvalidSignature", err)
	}
}

func TestSignRejects(t *testing.T) {
	testKeys(t)
	if _, err := Sign(nil, Header{Algorithm: ssf.RS256}, []byte(`{}`)); err == nil {
		t.Error("nil signer accepted")
	}
	if _, err := Sign(rsa2048, Header{Algorithm: ssf.RS256}, nil); err == nil {
		t.Error("empty payload accepted")
	}
	if _, err := Sign(rsa2048, Header{}, []byte(`{}`)); err == nil {
		t.Error("zero algorithm accepted")
	}
	if _, err := Sign(p256, Header{Algorithm: ssf.RS256}, []byte(`{}`)); err == nil {
		t.Error("EC key accepted for RS256")
	}
	if _, err := Sign(rsa2048, Header{Algorithm: ssf.ES256}, []byte(`{}`)); err == nil {
		t.Error("RSA key accepted for ES256")
	}
}

func TestParseCompactRejects(t *testing.T) {
	testKeys(t)
	valid, err := Sign(p256, Header{Algorithm: ssf.ES256}, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{
		"empty":          "",
		"two segments":   "a.b",
		"four segments":  valid + ".x",
		"empty segment":  "a..c",
		"bad base64":     "!!!.e30.AA",
		"alg none":       "eyJhbGciOiJub25lIn0.e30.AA",
		"alg HS256":      "eyJhbGciOiJIUzI1NiJ9.e30.AA",
		"unknown crit":   "eyJhbGciOiJFUzI1NiIsImNyaXQiOlsiZXhwIl19.e30.AA",
		"header not obj": "WzFd.e30.AA",
	} {
		if _, err := ParseCompact(tok); err == nil {
			t.Errorf("%s: ParseCompact succeeded", name)
		}
	}
	if _, err := ParseCompactMax(valid, 10); !errors.Is(err, ErrTooLarge) {
		t.Errorf("ParseCompactMax = %v, want ErrTooLarge", err)
	}
}

func TestJWKRoundTrip(t *testing.T) {
	testKeys(t)
	cases := []struct {
		alg ssf.SignatureAlgorithm
		pub crypto.PublicKey
	}{
		{ssf.RS256, &rsa2048.PublicKey},
		{ssf.ES256, &p256.PublicKey},
		{ssf.EdDSA, ed.Public()},
	}
	for _, c := range cases {
		t.Run(c.alg.String(), func(t *testing.T) {
			k, err := NewJWK(c.pub, c.alg)
			if err != nil {
				t.Fatal(err)
			}
			data, err := k.WithKeyID("kid-1").MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			var members map[string]any
			if err := json.Unmarshal(data, &members); err != nil {
				t.Fatal(err)
			}
			if members["use"] != "sig" || members["alg"] != c.alg.String() || members["kid"] != "kid-1" {
				t.Errorf("members = %v", members)
			}
			parsed, err := ParseJWK(data, c.alg)
			if err != nil {
				t.Fatal(err)
			}
			eq := parsed.PublicKey().(interface{ Equal(crypto.PublicKey) bool })
			if !eq.Equal(c.pub) || parsed.KeyID() != "kid-1" {
				t.Errorf("parsed key differs")
			}
		})
	}
}

func TestParseJWKRejects(t *testing.T) {
	for name, jwk := range map[string]string{
		"private rsa":  `{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQ"}`,
		"symmetric":    `{"kty":"oct","k":"AAAA"}`,
		"curve P-384":  `{"kty":"EC","crv":"P-384","x":"AA","y":"AA"}`,
		"off curve":    `{"kty":"EC","crv":"P-256","x":"` + strings.Repeat("A", 43) + `","y":"` + strings.Repeat("A", 43) + `"}`,
		"even exp":     `{"kty":"RSA","n":"` + strings.Repeat("_", 342) + `","e":"Ag"}`,
		"unknown kty":  `{"kty":"XYZ"}`,
		"not json":     `nope`,
		"short OKP":    `{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`,
		"rsa too weak": `{"kty":"RSA","n":"` + strings.Repeat("_", 170) + `","e":"AQAB"}`,
	} {
		if _, err := ParseJWK([]byte(jwk), ssf.RS256); err == nil {
			t.Errorf("%s: ParseJWK succeeded", name)
		}
	}
}

func TestParseJWKSet(t *testing.T) {
	testKeys(t)
	rsaJWK, _ := NewJWK(&rsa2048.PublicKey, ssf.RS256)
	ecJWK, _ := NewJWK(&p256.PublicKey, ssf.ES256)
	set, err := MarshalJWKSet(rsaJWK.WithKeyID("r"), ecJWK.WithKeyID("e"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseJWKSet(set)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].KeyID != "r" || keys[0].Algorithm != ssf.RS256 || keys[1].Algorithm != ssf.ES256 {
		t.Fatalf("keys = %+v", keys)
	}
	if keys[0].UsableWith(ssf.PS256) {
		t.Error("a key published for RS256 must not be used for PS256")
	}

	// An RSA key without "alg" may be used with either RSA algorithm.
	var raw map[string]any
	data, _ := rsaJWK.MarshalJSON()
	_ = json.Unmarshal(data, &raw)
	delete(raw, "alg")
	noAlg, _ := json.Marshal(map[string]any{"keys": []any{
		raw,
		map[string]any{"kty": "RSA", "use": "enc", "n": raw["n"], "e": raw["e"]},
		map[string]any{"kty": "unknown"},
		"not an object",
		map[string]any{"kty": "RSA", "alg": "HS256", "n": raw["n"], "e": raw["e"]},
	}})
	keys, err = ParseJWKSet(noAlg)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Algorithm != 0 || !keys[0].UsableWith(ssf.RS256) || !keys[0].UsableWith(ssf.PS256) || keys[0].UsableWith(ssf.ES256) {
		t.Fatalf("keys = %+v", keys)
	}

	if _, err := ParseJWKSet([]byte(`{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQ"}]}`)); !errors.Is(err, ErrPrivateKeyMaterial) {
		t.Errorf("private key in JWKS: err = %v, want ErrPrivateKeyMaterial", err)
	}
	if _, err := ParseJWKSet([]byte(`not json`)); err == nil {
		t.Error("malformed JWKS accepted")
	}
}
