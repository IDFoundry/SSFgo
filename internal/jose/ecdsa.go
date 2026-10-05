package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"

	ssf "github.com/idfoundry/ssfgo"
)

// A JWS ECDSA signature is R and S concatenated, each in the curve's fixed
// width (RFC 7518 §3.4) — not the ASN.1 DER encoding crypto.Signer
// implementations return.

func signECDSA(signer crypto.Signer, alg ssf.SignatureAlgorithm, spec algSpec, hash []byte) ([]byte, error) {
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("jose: %s signer must use an ECDSA key, got %T", alg, signer.Public())
	}
	if pub.Curve != spec.curve.curve {
		return nil, fmt.Errorf("jose: %s requires curve %s", alg, spec.curve.name)
	}

	der, err := signer.Sign(rand.Reader, hash, spec.hash)
	if err != nil {
		return nil, fmt.Errorf("jose: ecdsa sign: %w", err)
	}
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		return nil, fmt.Errorf("jose: decode ecdsa signature: %w", err)
	}
	size := spec.curve.size
	if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 || parsed.R.BitLen() > 8*size || parsed.S.BitLen() > 8*size {
		return nil, fmt.Errorf("jose: ecdsa signer returned an out-of-range signature")
	}
	out := make([]byte, 2*size)
	parsed.R.FillBytes(out[:size])
	parsed.S.FillBytes(out[size:])
	return out, nil
}

func verifyECDSA(pubKey crypto.PublicKey, alg ssf.SignatureAlgorithm, spec algSpec, hash, sig []byte) error {
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: %s requires an ECDSA public key, got %T", ErrInvalidSignature, alg, pubKey)
	}
	if pub.Curve != spec.curve.curve {
		return fmt.Errorf("%w: %s requires curve %s", ErrInvalidSignature, alg, spec.curve.name)
	}
	size := spec.curve.size
	if len(sig) != 2*size {
		return fmt.Errorf("%w: malformed %s signature length %d", ErrInvalidSignature, alg, len(sig))
	}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	if !ecdsa.Verify(pub, hash, r, s) {
		return ErrInvalidSignature
	}
	return nil
}
