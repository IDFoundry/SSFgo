package jose

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"strings"

	ssf "github.com/idfoundry/ssfgo"
)

// DefaultMaxCompactBytes bounds how large a compact serialization
// ParseCompact will parse, to avoid unbounded work on attacker-supplied
// input before any signature has been checked. A SET carries one event and
// one subject, so 64 KiB is generous.
const DefaultMaxCompactBytes = 64 * 1024

// Sign produces a JWS compact serialization:
// BASE64URL(header) || "." || BASE64URL(payload) || "." || BASE64URL(signature).
//
// payload must be non-empty, since ParseCompact rejects an empty segment.
func Sign(signer crypto.Signer, header Header, payload []byte) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("jose: signer is nil")
	}
	if len(payload) == 0 {
		return "", fmt.Errorf("jose: payload is empty")
	}
	headerJSON, err := marshalHeader(header)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payload)

	alg := header.Algorithm
	spec, err := specFor(alg)
	if err != nil {
		return "", err
	}
	var sig []byte
	switch spec.family {
	case familyRSAPKCS1:
		sig, err = signRSAPKCS1v15(signer, alg, spec.hash, digest(spec.hash, []byte(signingInput)))
	case familyRSAPSS:
		sig, err = signRSAPSS(signer, alg, spec.hash, digest(spec.hash, []byte(signingInput)))
	case familyECDSA:
		sig, err = signECDSA(signer, alg, spec, digest(spec.hash, []byte(signingInput)))
	case familyEdDSA:
		// RFC 8037 §3.1: pure EdDSA over the signing input, no pre-hash.
		sig, err = signEdDSA(signer, []byte(signingInput))
	}
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Compact is a parsed, but not yet signature-verified, JWS compact
// serialization. Header and Payload must not be trusted until Verify
// returns nil.
type Compact struct {
	Header  Header
	Payload []byte

	signingInput []byte
	signature    []byte
}

// b64 decodes compact JWS segments strictly: unpadded base64url whose
// unused bits are zero. Together with isBase64URL this gives every
// segment exactly one encoding, so a signed token cannot be re-encoded
// into a different string that still verifies.
var b64 = base64.RawURLEncoding.Strict()

// isBase64URL reports whether s uses only the base64url alphabet. The
// decoder alone would skip CR and LF.
func isBase64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// ParseCompact splits and decodes a compact JWS without verifying its
// signature, rejecting one longer than DefaultMaxCompactBytes.
func ParseCompact(s string) (Compact, error) {
	return ParseCompactMax(s, DefaultMaxCompactBytes)
}

// ParseCompactMax is ParseCompact with an explicit size ceiling in bytes.
func ParseCompactMax(s string, maxBytes int) (Compact, error) {
	if len(s) > maxBytes {
		return Compact{}, fmt.Errorf("%w: %d bytes exceeds the %d byte limit", ErrTooLarge, len(s), maxBytes)
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Compact{}, ErrMalformed
	}
	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]
	if headerB64 == "" || payloadB64 == "" || sigB64 == "" {
		return Compact{}, ErrMalformed
	}

	for _, part := range parts {
		if !isBase64URL(part) {
			return Compact{}, fmt.Errorf("%w: a segment has a character outside the base64url alphabet", ErrMalformed)
		}
	}
	headerJSON, err := b64.DecodeString(headerB64)
	if err != nil {
		return Compact{}, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	header, err := parseHeader(headerJSON)
	if err != nil {
		return Compact{}, err
	}
	payload, err := b64.DecodeString(payloadB64)
	if err != nil {
		return Compact{}, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	sig, err := b64.DecodeString(sigB64)
	if err != nil {
		return Compact{}, fmt.Errorf("%w: signature: %v", ErrMalformed, err)
	}

	return Compact{
		Header:       header,
		Payload:      payload,
		signingInput: []byte(headerB64 + "." + payloadB64),
		signature:    sig,
	}, nil
}

// Verify checks c's signature against pub for exactly alg. It fails if the
// header's own algorithm does not match alg, so a caller must state which
// algorithm it expects rather than trusting the header — this is what
// prevents algorithm-confusion attacks.
func (c Compact) Verify(pub crypto.PublicKey, alg ssf.SignatureAlgorithm) error {
	if c.Header.Algorithm != alg {
		return fmt.Errorf("%w: header has %s, expected %s", ErrAlgorithmMismatch, c.Header.Algorithm, alg)
	}
	spec, err := specFor(alg)
	if err != nil {
		return err
	}
	switch spec.family {
	case familyRSAPKCS1:
		return verifyRSAPKCS1v15(pub, alg, spec.hash, digest(spec.hash, c.signingInput), c.signature)
	case familyRSAPSS:
		return verifyRSAPSS(pub, alg, spec.hash, digest(spec.hash, c.signingInput), c.signature)
	case familyECDSA:
		return verifyECDSA(pub, alg, spec, digest(spec.hash, c.signingInput), c.signature)
	default:
		return verifyEdDSA(pub, c.signingInput, c.signature)
	}
}
