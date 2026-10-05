package jose

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	ssf "github.com/idfoundry/ssfgo"
)

// minRSAModulusBits is the smallest RSA key accepted for signing or
// verification. RFC 7518 §3.3 and §3.5 require 2048 bits for every RS and
// PS algorithm, and the CAEP Interoperability Profile §2.6 repeats it for
// RS256.
const minRSAModulusBits = 2048

// maxRSAModulusBits caps every RSA key accepted. RFC 7518 sets no ceiling,
// but RSA cost grows faster than linearly with modulus size, so an
// oversized key published in a JWKS is a cheap resource-exhaustion vector.
const maxRSAModulusBits = 8192

func checkRSAKeySize(pub *rsa.PublicKey) error {
	if pub == nil || pub.N == nil {
		return fmt.Errorf("RSA public key is empty")
	}
	if bits := pub.N.BitLen(); bits < minRSAModulusBits || bits > maxRSAModulusBits {
		return fmt.Errorf("RSA key must be %d to %d bits, got %d", minRSAModulusBits, maxRSAModulusBits, bits)
	}
	return nil
}

func rsaSigner(signer crypto.Signer, alg ssf.SignatureAlgorithm) (*rsa.PublicKey, error) {
	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("jose: %s signer must use an RSA key, got %T", alg, signer.Public())
	}
	if err := checkRSAKeySize(pub); err != nil {
		return nil, fmt.Errorf("jose: %s: %w", alg, err)
	}
	return pub, nil
}

func rsaVerifier(pubKey crypto.PublicKey, alg ssf.SignatureAlgorithm) (*rsa.PublicKey, error) {
	pub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %s requires an RSA public key, got %T", ErrInvalidSignature, alg, pubKey)
	}
	if err := checkRSAKeySize(pub); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalidSignature, alg, err)
	}
	return pub, nil
}

// pssOptions are RFC 7518 §3.5's: MGF1 with the algorithm's hash, and a
// salt as long as its output.
func pssOptions(h crypto.Hash) *rsa.PSSOptions {
	return &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
}

func signRSAPKCS1v15(signer crypto.Signer, alg ssf.SignatureAlgorithm, h crypto.Hash, hash []byte) ([]byte, error) {
	if _, err := rsaSigner(signer, alg); err != nil {
		return nil, err
	}
	sig, err := signer.Sign(rand.Reader, hash, h)
	if err != nil {
		return nil, fmt.Errorf("jose: rsa pkcs1v15 sign: %w", err)
	}
	return sig, nil
}

func verifyRSAPKCS1v15(pubKey crypto.PublicKey, alg ssf.SignatureAlgorithm, h crypto.Hash, hash, sig []byte) error {
	pub, err := rsaVerifier(pubKey, alg)
	if err != nil {
		return err
	}
	if err := rsa.VerifyPKCS1v15(pub, h, hash, sig); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return nil
}

func signRSAPSS(signer crypto.Signer, alg ssf.SignatureAlgorithm, h crypto.Hash, hash []byte) ([]byte, error) {
	if _, err := rsaSigner(signer, alg); err != nil {
		return nil, err
	}
	sig, err := signer.Sign(rand.Reader, hash, pssOptions(h))
	if err != nil {
		return nil, fmt.Errorf("jose: rsa-pss sign: %w", err)
	}
	return sig, nil
}

func verifyRSAPSS(pubKey crypto.PublicKey, alg ssf.SignatureAlgorithm, h crypto.Hash, hash, sig []byte) error {
	pub, err := rsaVerifier(pubKey, alg)
	if err != nil {
		return err
	}
	if err := rsa.VerifyPSS(pub, h, hash, sig, pssOptions(h)); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return nil
}
