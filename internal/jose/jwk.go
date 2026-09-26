package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	ssf "github.com/idfoundry/ssfgo"
)

// JWK is a validated public signing key together with the algorithm it is
// used with. It is built either by NewJWK, from a key the caller already
// trusts (a Transmitter publishing its JWKS), or by ParseJWK, from
// untrusted wire input.
type JWK struct {
	pub crypto.PublicKey
	alg ssf.SignatureAlgorithm
	kid string
}

// NewJWK wraps pub for use with alg. It fails if pub's type or size does
// not match what alg requires.
func NewJWK(pub crypto.PublicKey, alg ssf.SignatureAlgorithm) (JWK, error) {
	if err := ValidateKeyForAlgorithm(pub, alg); err != nil {
		return JWK{}, err
	}
	return JWK{pub: pub, alg: alg}, nil
}

// WithKeyID returns a copy of k with its "kid" member set.
func (k JWK) WithKeyID(kid string) JWK {
	k.kid = kid
	return k
}

// PublicKey returns the wrapped public key.
func (k JWK) PublicKey() crypto.PublicKey { return k.pub }

// Algorithm returns the algorithm this key is used with.
func (k JWK) Algorithm() ssf.SignatureAlgorithm { return k.alg }

// KeyID returns the key's "kid", if any.
func (k JWK) KeyID() string { return k.kid }

// MarshalJSON encodes k as a public-only JWK with "use":"sig", "alg", and
// "kid" if set.
func (k JWK) MarshalJSON() ([]byte, error) {
	raw := rawJWK{Use: "sig", Alg: k.alg.String(), Kid: k.kid}
	switch pub := k.pub.(type) {
	case *ecdsa.PublicKey:
		b, err := pub.Bytes()
		if err != nil || len(b) != 1+2*p256CoordinateSize {
			return nil, fmt.Errorf("jose: cannot encode EC key as a P-256 JWK")
		}
		raw.Kty, raw.Crv = "EC", "P-256"
		raw.X = base64.RawURLEncoding.EncodeToString(b[1 : 1+p256CoordinateSize])
		raw.Y = base64.RawURLEncoding.EncodeToString(b[1+p256CoordinateSize:])
	case *rsa.PublicKey:
		raw.Kty = "RSA"
		raw.N = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		raw.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	case ed25519.PublicKey:
		raw.Kty, raw.Crv = "OKP", "Ed25519"
		raw.X = base64.RawURLEncoding.EncodeToString(pub)
	default:
		return nil, fmt.Errorf("jose: cannot marshal key type %T", pub)
	}
	return json.Marshal(raw)
}

// rawJWK is the wire form of a JWK (RFC 7517). Members this package does
// not act on are ignored, as RFC 7517 §4 requires. The private-key members
// are listed only so their presence can be rejected.
type rawJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`

	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`

	D  json.RawMessage `json:"d,omitempty"`
	K  json.RawMessage `json:"k,omitempty"`
	P  json.RawMessage `json:"p,omitempty"`
	Q  json.RawMessage `json:"q,omitempty"`
	Dp json.RawMessage `json:"dp,omitempty"`
	Dq json.RawMessage `json:"dq,omitempty"`
	Qi json.RawMessage `json:"qi,omitempty"`
}

// ParseJWK parses a public JWK from untrusted input and checks it against
// alg. It rejects any private-key member: a "public" key carrying one is
// either a leak or an attack, not something to tolerate.
func ParseJWK(data []byte, alg ssf.SignatureAlgorithm) (JWK, error) {
	var raw rawJWK
	if err := json.Unmarshal(data, &raw); err != nil {
		return JWK{}, fmt.Errorf("jose: parse jwk: %w", err)
	}
	pub, err := publicKeyFromRaw(raw)
	if err != nil {
		return JWK{}, err
	}
	if err := ValidateKeyForAlgorithm(pub, alg); err != nil {
		return JWK{}, err
	}
	return JWK{pub: pub, alg: alg, kid: raw.Kid}, nil
}

func publicKeyFromRaw(raw rawJWK) (crypto.PublicKey, error) {
	if raw.D != nil || raw.K != nil || raw.P != nil || raw.Q != nil ||
		raw.Dp != nil || raw.Dq != nil || raw.Qi != nil {
		return nil, ErrPrivateKeyMaterial
	}
	switch raw.Kty {
	case "EC":
		return parseECPublicKey(raw)
	case "RSA":
		return parseRSAPublicKey(raw)
	case "OKP":
		return parseOKPPublicKey(raw)
	default:
		return nil, fmt.Errorf("jose: unsupported key type %q", raw.Kty)
	}
}

func parseECPublicKey(raw rawJWK) (crypto.PublicKey, error) {
	if raw.Crv != "P-256" {
		return nil, fmt.Errorf("jose: unsupported EC curve %q", raw.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(raw.X)
	if err != nil || len(x) != p256CoordinateSize {
		return nil, fmt.Errorf("jose: jwk x must be %d base64url bytes", p256CoordinateSize)
	}
	y, err := base64.RawURLEncoding.DecodeString(raw.Y)
	if err != nil || len(y) != p256CoordinateSize {
		return nil, fmt.Errorf("jose: jwk y must be %d base64url bytes", p256CoordinateSize)
	}
	// ParseUncompressedPublicKey rejects points not on the curve and the
	// point at infinity.
	point := append(append([]byte{0x04}, x...), y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("jose: jwk ec point: %w", err)
	}
	return pub, nil
}

func parseRSAPublicKey(raw rawJWK) (crypto.PublicKey, error) {
	n, err := decodeBigInt(raw.N)
	if err != nil {
		return nil, fmt.Errorf("jose: decode jwk n: %w", err)
	}
	e, err := decodeExponent(raw.E)
	if err != nil {
		return nil, fmt.Errorf("jose: decode jwk e: %w", err)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

func parseOKPPublicKey(raw rawJWK) (crypto.PublicKey, error) {
	if raw.Crv != "Ed25519" {
		return nil, fmt.Errorf("jose: unsupported OKP curve %q", raw.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(raw.X)
	if err != nil || len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("jose: jwk x must be %d base64url bytes for Ed25519", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(x), nil
}

// ValidateKeyForAlgorithm reports whether pub is usable with alg: the right
// key type, curve, and size.
func ValidateKeyForAlgorithm(pub crypto.PublicKey, alg ssf.SignatureAlgorithm) error {
	switch alg {
	case ssf.RS256, ssf.PS256:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("jose: %s requires an RSA public key, got %T", alg, pub)
		}
		if err := checkRSAKeySize(key); err != nil {
			return fmt.Errorf("jose: %s: %w", alg, err)
		}
	case ssf.ES256:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("jose: ES256 requires an ECDSA public key, got %T", pub)
		}
		if key.Curve != elliptic.P256() {
			return fmt.Errorf("jose: ES256 requires curve P-256")
		}
	case ssf.EdDSA:
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("jose: EdDSA requires an Ed25519 public key, got %T", pub)
		}
		if len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("jose: EdDSA requires a %d-byte Ed25519 public key, got %d", ed25519.PublicKeySize, len(key))
		}
	default:
		return fmt.Errorf("jose: unsupported algorithm %v", alg)
	}
	return nil
}

func decodeBigInt(s string) (*big.Int, error) {
	if s == "" {
		return nil, fmt.Errorf("empty value")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func decodeExponent(s string) (int, error) {
	n, err := decodeBigInt(s)
	if err != nil {
		return 0, err
	}
	if !n.IsInt64() {
		return 0, fmt.Errorf("exponent out of range")
	}
	v := n.Int64()
	if v < 3 || v > 1<<31-1 || v%2 == 0 {
		return 0, fmt.Errorf("exponent out of range or not a valid RSA public exponent")
	}
	return int(v), nil
}
