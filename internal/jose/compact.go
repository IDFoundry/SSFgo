package jose

import (
	"crypto"
	"crypto/sha256"
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

	var sig []byte
	switch header.Algorithm {
	case ssf.RS256:
		hash := sha256.Sum256([]byte(signingInput))
		sig, err = signRSAPKCS1v15(signer, hash[:])
	case ssf.PS256:
		hash := sha256.Sum256([]byte(signingInput))
		sig, err = signRSAPSS(signer, hash[:])
	case ssf.ES256:
		hash := sha256.Sum256([]byte(signingInput))
		sig, err = signECDSA(signer, hash[:])
	case ssf.EdDSA:
		// RFC 8037 §3.1: pure EdDSA over the signing input, no pre-hash.
		sig, err = signEdDSA(signer, []byte(signingInput))
	default:
		return "", fmt.Errorf("jose: unsupported algorithm %v", header.Algorithm)
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

	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return Compact{}, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	header, err := parseHeader(headerJSON)
	if err != nil {
		return Compact{}, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return Compact{}, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
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
	switch alg {
	case ssf.RS256:
		hash := sha256.Sum256(c.signingInput)
		return verifyRSAPKCS1v15(pub, hash[:], c.signature)
	case ssf.PS256:
		hash := sha256.Sum256(c.signingInput)
		return verifyRSAPSS(pub, hash[:], c.signature)
	case ssf.ES256:
		hash := sha256.Sum256(c.signingInput)
		return verifyECDSA(pub, hash[:], c.signature)
	case ssf.EdDSA:
		return verifyEdDSA(pub, c.signingInput, c.signature)
	default:
		return fmt.Errorf("jose: unsupported algorithm %v", alg)
	}
}
