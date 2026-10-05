package jose

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"

	ssf "github.com/idfoundry/ssfgo"
)

// SetKey is one usable signing key from a parsed JWK Set.
type SetKey struct {
	KeyID string
	// Algorithm is the key's "alg" member, or zero if the key did not
	// state one. An RSA key without "alg" is usable with every RS and PS
	// algorithm, an EC key with the ES algorithm of its curve; the
	// verifier decides.
	Algorithm ssf.SignatureAlgorithm
	PublicKey crypto.PublicKey
}

// UsableWith reports whether k may verify a signature made with alg.
func (k SetKey) UsableWith(alg ssf.SignatureAlgorithm) bool {
	if k.Algorithm != 0 && k.Algorithm != alg {
		return false
	}
	return ValidateKeyForAlgorithm(k.PublicKey, alg) == nil
}

// ParseJWKSet parses a JWK Set (RFC 7517 §5). Entries that are malformed,
// use an unsupported key type or algorithm, or are marked "use":"enc" are
// skipped: one unusable entry does not invalidate the rest of the set. An
// entry carrying private key material is an error, since it means the
// publisher is leaking secrets and nothing it serves can be trusted.
func ParseJWKSet(body []byte) ([]SetKey, error) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("jose: malformed jwks: %w", err)
	}
	var out []SetKey
	for _, entry := range set.Keys {
		var raw rawJWK
		if err := json.Unmarshal(entry, &raw); err != nil {
			continue
		}
		if raw.Use != "" && raw.Use != "sig" {
			continue
		}
		pub, err := publicKeyFromRaw(raw)
		if errors.Is(err, ErrPrivateKeyMaterial) {
			return nil, fmt.Errorf("jose: jwks entry %q: %w", raw.Kid, err)
		}
		if err != nil {
			continue
		}
		key := SetKey{KeyID: raw.Kid, PublicKey: pub}
		if raw.Alg != "" {
			alg, err := ssf.ParseSignatureAlgorithm(raw.Alg)
			if err != nil || ValidateKeyForAlgorithm(pub, alg) != nil {
				continue
			}
			key.Algorithm = alg
		} else if !anyAlgorithmFits(pub) {
			continue
		}
		out = append(out, key)
	}
	return out, nil
}

func anyAlgorithmFits(pub crypto.PublicKey) bool {
	for _, alg := range ssf.SignatureAlgorithms() {
		if ValidateKeyForAlgorithm(pub, alg) == nil {
			return true
		}
	}
	return false
}

// MarshalJWKSet encodes keys as a JWK Set document.
func MarshalJWKSet(keys ...JWK) ([]byte, error) {
	entries := make([]JWK, len(keys))
	copy(entries, keys)
	return json.Marshal(struct {
		Keys []JWK `json:"keys"`
	}{entries})
}
