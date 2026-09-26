package jose

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// minRSAModulusBits is the smallest RSA key accepted for signing or
// verification. RFC 7518 §3.3 and §3.5 require 2048 bits, and the CAEP
// Interoperability Profile §2.6 repeats it for RS256.
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

func rsaSigner(signer crypto.Signer, alg string) (*rsa.PublicKey, error) {
	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("jose: %s signer must use an RSA key, got %T", alg, signer.Public())
	}
	if err := checkRSAKeySize(pub); err != nil {
		return nil, fmt.Errorf("jose: %s: %w", alg, err)
	}
	return pub, nil
}

func rsaVerifier(pubKey crypto.PublicKey, alg string) (*rsa.PublicKey, error) {
	pub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %s requires an RSA public key, got %T", ErrInvalidSignature, alg, pubKey)
	}
	if err := checkRSAKeySize(pub); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalidSignature, alg, err)
	}
	return pub, nil
}

func pssOptions() *rsa.PSSOptions {
	return &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
}

func signRSAPKCS1v15(signer crypto.Signer, hash []byte) ([]byte, error) {
	if _, err := rsaSigner(signer, "RS256"); err != nil {
		return nil, err
	}
	sig, err := signer.Sign(rand.Reader, hash, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("jose: rsa pkcs1v15 sign: %w", err)
	}
	return sig, nil
}

func verifyRSAPKCS1v15(pubKey crypto.PublicKey, hash, sig []byte) error {
	pub, err := rsaVerifier(pubKey, "RS256")
	if err != nil {
		return err
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash, sig); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return nil
}

func signRSAPSS(signer crypto.Signer, hash []byte) ([]byte, error) {
	if _, err := rsaSigner(signer, "PS256"); err != nil {
		return nil, err
	}
	sig, err := signer.Sign(rand.Reader, hash, pssOptions())
	if err != nil {
		return nil, fmt.Errorf("jose: rsa-pss sign: %w", err)
	}
	return sig, nil
}

func verifyRSAPSS(pubKey crypto.PublicKey, hash, sig []byte) error {
	pub, err := rsaVerifier(pubKey, "PS256")
	if err != nil {
		return err
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, hash, sig, pssOptions()); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return nil
}
