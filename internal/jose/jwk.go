package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"

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
		c := curveOf(pub.Curve)
		if c == nil {
			return nil, fmt.Errorf("jose: cannot encode an EC key on an unsupported curve")
		}
		b, err := pub.Bytes()
		if err != nil || len(b) != 1+2*c.size {
			return nil, fmt.Errorf("jose: cannot encode EC key as a %s JWK", c.name)
		}
		raw.Kty, raw.Crv = "EC", c.name
		raw.X = base64.RawURLEncoding.EncodeToString(b[1 : 1+c.size])
		raw.Y = base64.RawURLEncoding.EncodeToString(b[1+c.size:])
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
	c := curveNamed(raw.Crv)
	if c == nil {
		return nil, fmt.Errorf("jose: unsupported EC curve %q", raw.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(raw.X)
	if err != nil || len(x) != c.size {
		return nil, fmt.Errorf("jose: jwk x must be %d base64url bytes for %s", c.size, c.name)
	}
	y, err := base64.RawURLEncoding.DecodeString(raw.Y)
	if err != nil || len(y) != c.size {
		return nil, fmt.Errorf("jose: jwk y must be %d base64url bytes for %s", c.size, c.name)
	}
	// ParseUncompressedPublicKey rejects points not on the curve and the
	// point at infinity.
	point := append(append([]byte{0x04}, x...), y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(c.curve, point)
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
	if hasSmallOrder(x) {
		return nil, errSmallOrderKey
	}
	return ed25519.PublicKey(x), nil
}

// ValidateKeyForAlgorithm reports whether pub is usable with alg: the right
// key type, curve, and size.
func ValidateKeyForAlgorithm(pub crypto.PublicKey, alg ssf.SignatureAlgorithm) error {
	spec, err := specFor(alg)
	if err != nil {
		return err
	}
	switch spec.family {
	case familyRSAPKCS1, familyRSAPSS:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("jose: %s requires an RSA public key, got %T", alg, pub)
		}
		if err := checkRSAKeySize(key); err != nil {
			return fmt.Errorf("jose: %s: %w", alg, err)
		}
	case familyECDSA:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("jose: %s requires an ECDSA public key, got %T", alg, pub)
		}
		if key.Curve != spec.curve.curve {
			return fmt.Errorf("jose: %s requires curve %s", alg, spec.curve.name)
		}
	case familyEdDSA:
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("jose: EdDSA requires an Ed25519 public key, got %T", pub)
		}
		if len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("jose: EdDSA requires a %d-byte Ed25519 public key, got %d", ed25519.PublicKeySize, len(key))
		}
		if hasSmallOrder(key) {
			return errSmallOrderKey
		}
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

var errSmallOrderKey = errors.New("jose: Ed25519 public key is a point of small order, for which signatures can be forged")

// smallOrder holds every encoding of an Ed25519 point of small order —
// the eight points of order 1, 2, 4 and 8, and the non-canonical encodings
// p and p+1 — with the sign bit cleared (libsodium's blocklist). With such
// a public key, one signature verifies for many messages.
var smallOrder = [][32]byte{
	{0x00}, // order 4
	{0x01}, // the identity, order 1
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05}, // order 8
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a}, // order 8
	ffff(0xec), // p-1: order 2
	ffff(0xed), // p: non-canonical 0, order 4
	ffff(0xee), // p+1: non-canonical 1, order 1
}

// ffff is first followed by 30 0xff bytes and 0x7f.
func ffff(first byte) [32]byte {
	var b [32]byte
	b[0] = first
	for i := 1; i < 31; i++ {
		b[i] = 0xff
	}
	b[31] = 0x7f
	return b
}

// hasSmallOrder reports whether key encodes a point of small order,
// whichever its sign bit.
func hasSmallOrder(key []byte) bool {
	var k [32]byte
	copy(k[:], key)
	k[31] &= 0x7f
	return slices.Contains(smallOrder, k)
}
