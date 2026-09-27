package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
)

// FuzzParseJWK parses arbitrary bytes as a public JWK for every supported
// algorithm. Any JWK that parses must re-encode and parse back to the same
// key, and must satisfy the algorithm's key requirements.
func FuzzParseJWK(f *testing.F) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, k := range []struct {
		pub crypto.PublicKey
		alg ssf.SignatureAlgorithm
	}{{&rk.PublicKey, ssf.RS256}, {&ek.PublicKey, ssf.ES256}} {
		j, _ := NewJWK(k.pub, k.alg)
		b, _ := j.WithKeyID("seed").MarshalJSON()
		f.Add(b)
	}
	f.Add([]byte(`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`))
	f.Add([]byte(`{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQ"}`))
	f.Add([]byte(`{"kty":"EC","crv":"P-256","x":"","y":""}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, alg := range []ssf.SignatureAlgorithm{ssf.RS256, ssf.PS256, ssf.ES256, ssf.EdDSA} {
			k, err := ParseJWK(data, alg)
			if err != nil {
				continue
			}
			if err := ValidateKeyForAlgorithm(k.PublicKey(), alg); err != nil {
				t.Fatalf("ParseJWK(%s) returned a key that fails its algorithm's checks: %v", alg, err)
			}
			encoded, err := k.MarshalJSON()
			if err != nil {
				t.Fatalf("a parsed %s key does not re-encode: %v", alg, err)
			}
			again, err := ParseJWK(encoded, alg)
			if err != nil {
				t.Fatalf("a re-encoded %s key does not parse: %v\n%s", alg, err, encoded)
			}
			eq, ok := k.PublicKey().(interface{ Equal(crypto.PublicKey) bool })
			if !ok || !eq.Equal(again.PublicKey()) {
				t.Fatalf("%s key changed across a round trip", alg)
			}
		}
	})
}
