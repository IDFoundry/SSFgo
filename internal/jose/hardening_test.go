package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
)

// Each segment of a compact JWS has exactly one encoding: a signed token
// cannot be re-encoded into a different string that still verifies.
func TestCompactSegmentsHaveOneEncoding(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Sign(k, Header{Algorithm: ssf.ES256, Type: "secevent+jwt"}, []byte(`{"jti":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCompact(tok); err != nil {
		t.Fatalf("the original token: %v", err)
	}
	parts := strings.Split(tok, ".")
	sig := parts[2]
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	lastBits := sig[:len(sig)-1] + string(alphabet[strings.IndexByte(alphabet, sig[len(sig)-1])^1])
	for name, v := range map[string]string{
		"non-zero unused bits": lastBits,
		"CR LF":                sig[:10] + "\r\n" + sig[10:],
		"standard alphabet":    strings.NewReplacer("-", "+", "_", "/").Replace(sig) + "+",
		"padding":              sig + "=",
	} {
		if _, err := ParseCompact(parts[0] + "." + parts[1] + "." + v); err == nil {
			t.Errorf("%s: re-encoded signature accepted", name)
		}
	}
}

// Header members are read by their exact names; a repeated member or an
// empty crit is refused.
func TestHeaderParsedStrictly(t *testing.T) {
	h, err := parseHeader([]byte(`{"alg":"ES256","ALG":"RS256","KID":"b","kid":"a"}`))
	if err != nil || h.Algorithm != ssf.ES256 || h.KeyID != "a" {
		t.Errorf("case variants: %+v, %v; want alg ES256 and kid a, the others ignored", h, err)
	}
	for name, header := range map[string]string{
		"repeated alg":     `{"alg":"ES256","alg":"RS256"}`,
		"crit overridden":  `{"alg":"RS256","crit":["exp"],"crit":null}`,
		"empty crit":       `{"alg":"RS256","crit":[]}`,
		"null crit":        `{"alg":"RS256","crit":null}`,
		"unknown crit":     `{"alg":"RS256","crit":["exp"],"exp":1}`,
		"not an object":    `["alg"]`,
		"trailing content": `{"alg":"RS256"}{}`,
	} {
		if _, err := parseHeader([]byte(header)); err == nil {
			t.Errorf("%s: %s accepted", name, header)
		}
	}
}

// An Ed25519 key of small order, for which one signature verifies for many
// messages, is refused in any encoding.
func TestEd25519SmallOrderKeysRefused(t *testing.T) {
	for _, k := range smallOrder {
		for _, sign := range []byte{0, 0x80} {
			key := k
			key[31] |= sign
			x := base64.RawURLEncoding.EncodeToString(key[:])
			// An unusable JWKS entry is skipped, like any other.
			if keys, err := ParseJWKSet([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}]}`)); err != nil || len(keys) != 0 {
				t.Errorf("small-order key %x in a JWKS: %d keys, %v; want it skipped", key, len(keys), err)
			}
			if err := ValidateKeyForAlgorithm(ed25519.PublicKey(key[:]), ssf.EdDSA); err == nil {
				t.Errorf("small-order key %x accepted for EdDSA", key)
			}
		}
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateKeyForAlgorithm(pub, ssf.EdDSA); err != nil {
		t.Errorf("an ordinary Ed25519 key: %v", err)
	}
}
