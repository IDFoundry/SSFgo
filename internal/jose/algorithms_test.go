package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
)

// RFC 7515 Appendix A.4: a JWS signed with ES512 over P-521, whose 66-byte
// coordinates and 132-byte signature exercise the widest curve.
func TestES512KnownAnswer(t *testing.T) {
	const (
		jwk = `{"kty":"EC","crv":"P-521",` +
			`"x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",` +
			`"y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2"}`
		jws = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA." +
			"AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq" +
			"wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp" +
			"EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
	)
	key, err := ParseJWK([]byte(jwk), ssf.ES512)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCompact(jws)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(key.PublicKey(), ssf.ES512); err != nil {
		t.Errorf("RFC 7515 A.4 did not verify: %v", err)
	}
	if string(c.Payload) != "Payload" {
		t.Errorf("payload %q", c.Payload)
	}
}

// signingKeys returns a fresh key for every algorithm.
func signingKeys(t *testing.T) map[ssf.SignatureAlgorithm]crypto.Signer {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ec := func(c elliptic.Curve) crypto.Signer {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[ssf.SignatureAlgorithm]crypto.Signer{
		ssf.RS256: rsaKey, ssf.RS384: rsaKey, ssf.RS512: rsaKey,
		ssf.PS256: rsaKey, ssf.PS384: rsaKey, ssf.PS512: rsaKey,
		ssf.ES256: ec(elliptic.P256()), ssf.ES384: ec(elliptic.P384()), ssf.ES512: ec(elliptic.P521()),
		ssf.EdDSA: edKey,
	}
}

// Every algorithm signs and verifies, survives a JWK round trip, and
// verifies under its own algorithm only.
func TestEveryAlgorithm(t *testing.T) {
	keys := signingKeys(t)
	if len(keys) != len(ssf.SignatureAlgorithms()) {
		t.Fatalf("test keys cover %d algorithms, want %d", len(keys), len(ssf.SignatureAlgorithms()))
	}
	for _, alg := range ssf.SignatureAlgorithms() {
		t.Run(alg.String(), func(t *testing.T) {
			signer := keys[alg]
			tok, err := Sign(signer, Header{Algorithm: alg, Type: "secevent+jwt", KeyID: "k"}, []byte(`{"jti":"x"}`))
			if err != nil {
				t.Fatal(err)
			}
			c, err := ParseCompact(tok)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Verify(signer.Public(), alg); err != nil {
				t.Fatalf("own signature did not verify: %v", err)
			}

			// The public key survives JWK encoding, alone and in a set.
			j, err := NewJWK(signer.Public(), alg)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(j.WithKeyID("k"))
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseJWK(encoded, alg)
			if err != nil {
				t.Fatalf("ParseJWK(%s): %v", encoded, err)
			}
			if err := c.Verify(parsed.PublicKey(), alg); err != nil {
				t.Errorf("signature did not verify with the decoded JWK: %v", err)
			}
			set, err := ParseJWKSet([]byte(`{"keys":[` + string(encoded) + `]}`))
			if err != nil || len(set) != 1 || set[0].Algorithm != alg || !set[0].UsableWith(alg) {
				t.Errorf("JWKS: %+v, %v", set, err)
			}

			// No other algorithm accepts the token or the key: neither
			// the header nor a key built for one algorithm may stand in
			// for another.
			for _, other := range ssf.SignatureAlgorithms() {
				if other == alg {
					continue
				}
				if err := c.Verify(signer.Public(), other); err == nil {
					t.Errorf("verified as %s", other)
				}
				if set[0].UsableWith(other) {
					t.Errorf("a JWK with alg %s is usable with %s", alg, other)
				}
			}
		})
	}
}

// A key on the wrong curve, or of the wrong type, is refused for an
// algorithm, whether signing or checking a key.
func TestAlgorithmKeyMismatch(t *testing.T) {
	keys := signingKeys(t)
	for _, c := range []struct {
		alg ssf.SignatureAlgorithm
		key crypto.Signer
	}{
		{ssf.ES384, keys[ssf.ES256]},
		{ssf.ES512, keys[ssf.ES384]},
		{ssf.ES256, keys[ssf.ES512]},
		{ssf.RS384, keys[ssf.ES384]},
		{ssf.PS512, keys[ssf.EdDSA]},
		{ssf.ES512, keys[ssf.RS512]},
	} {
		if err := ValidateKeyForAlgorithm(c.key.Public(), c.alg); err == nil {
			t.Errorf("%s accepted a %T key", c.alg, c.key.Public())
		}
		if _, err := Sign(c.key, Header{Algorithm: c.alg}, []byte("{}")); err == nil {
			t.Errorf("%s signed with a %T key", c.alg, c.key)
		}
	}
	// An unknown curve name in a JWK is refused.
	if _, err := ParseJWK([]byte(`{"kty":"EC","crv":"secp256k1","x":"AA","y":"AA"}`), ssf.ES256); err == nil {
		t.Error("secp256k1 JWK accepted")
	}
}
