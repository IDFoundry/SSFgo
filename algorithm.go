package ssf

import "fmt"

// SignatureAlgorithm is the closed set of JWS algorithms SSFgo signs and
// verifies Security Event Tokens with. A SET's "alg" header is untrusted
// input: a Receiver states which algorithms it accepts before any
// signature is checked, rather than trusting whatever the header claims.
type SignatureAlgorithm uint8

const (
	_ SignatureAlgorithm = iota

	// RS256 is RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518 §3.3), with a
	// minimum 2048-bit modulus. The CAEP Interoperability Profile §2.6
	// requires every event to be signed with it.
	RS256

	// PS256 is RSASSA-PSS using SHA-256 and MGF1 with SHA-256
	// (RFC 7518 §3.5), with a minimum 2048-bit modulus.
	PS256

	// ES256 is ECDSA using the P-256 curve and SHA-256 (RFC 7518 §3.4).
	ES256

	// EdDSA is pure EdDSA using Ed25519 (RFC 8037 §3.1).
	EdDSA
)

// String returns the JOSE "alg" header value for a, or "" if a is not a
// recognized algorithm.
func (a SignatureAlgorithm) String() string {
	switch a {
	case RS256:
		return "RS256"
	case PS256:
		return "PS256"
	case ES256:
		return "ES256"
	case EdDSA:
		return "EdDSA"
	default:
		return ""
	}
}

// IsValid reports whether a is one of the algorithms SSFgo supports.
func (a SignatureAlgorithm) IsValid() bool {
	return a.String() != ""
}

// ParseSignatureAlgorithm maps a JOSE "alg" header value to a
// SignatureAlgorithm. It rejects every value outside the closed set,
// including "none" and every HMAC algorithm: a SET is verified with the
// Transmitter's published public keys, never a shared secret.
func ParseSignatureAlgorithm(alg string) (SignatureAlgorithm, error) {
	switch alg {
	case "RS256":
		return RS256, nil
	case "PS256":
		return PS256, nil
	case "ES256":
		return ES256, nil
	case "EdDSA":
		return EdDSA, nil
	default:
		return 0, fmt.Errorf("ssf: unsupported signature algorithm %q", alg)
	}
}
