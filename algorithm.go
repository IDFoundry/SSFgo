package ssf

import "fmt"

// SignatureAlgorithm is the closed set of JWS algorithms SSFgo signs and
// verifies Security Event Tokens with. A SET's "alg" header is untrusted
// input: a Receiver states which algorithms it accepts before any
// signature is checked, rather than trusting whatever the header claims.
//
// Every asymmetric algorithm of RFC 7518 §3.1 is supported, and EdDSA with
// Ed25519. HMAC and "none" never are: a SET is verified with the
// Transmitter's published public keys, never a shared secret.
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

	// RS384 is RSASSA-PKCS1-v1_5 using SHA-384 (RFC 7518 §3.3).
	RS384

	// RS512 is RSASSA-PKCS1-v1_5 using SHA-512 (RFC 7518 §3.3).
	RS512

	// PS384 is RSASSA-PSS using SHA-384 and MGF1 with SHA-384
	// (RFC 7518 §3.5).
	PS384

	// PS512 is RSASSA-PSS using SHA-512 and MGF1 with SHA-512
	// (RFC 7518 §3.5).
	PS512

	// ES384 is ECDSA using the P-384 curve and SHA-384 (RFC 7518 §3.4).
	ES384

	// ES512 is ECDSA using the P-521 curve and SHA-512 (RFC 7518 §3.4).
	ES512
)

// algorithmNames maps each algorithm to its JOSE "alg" header value.
var algorithmNames = map[SignatureAlgorithm]string{
	RS256: "RS256", RS384: "RS384", RS512: "RS512",
	PS256: "PS256", PS384: "PS384", PS512: "PS512",
	ES256: "ES256", ES384: "ES384", ES512: "ES512",
	EdDSA: "EdDSA",
}

// SignatureAlgorithms returns every algorithm SSFgo supports, in the order
// of their constants.
func SignatureAlgorithms() []SignatureAlgorithm {
	return []SignatureAlgorithm{RS256, PS256, ES256, EdDSA, RS384, RS512, PS384, PS512, ES384, ES512}
}

// String returns the JOSE "alg" header value for a, or "" if a is not a
// recognized algorithm.
func (a SignatureAlgorithm) String() string {
	return algorithmNames[a]
}

// IsValid reports whether a is one of the algorithms SSFgo supports.
func (a SignatureAlgorithm) IsValid() bool {
	return a.String() != ""
}

// ParseSignatureAlgorithm maps a JOSE "alg" header value to a
// SignatureAlgorithm. It rejects every value outside the closed set,
// including "none" and every HMAC algorithm. Matching is exact: "rs256" is
// not RS256.
func ParseSignatureAlgorithm(alg string) (SignatureAlgorithm, error) {
	for a, name := range algorithmNames {
		if name == alg {
			return a, nil
		}
	}
	return 0, fmt.Errorf("ssf: unsupported signature algorithm %q", alg)
}
