package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
)

// stubSigner is a crypto.Signer whose public key and signature are fixed,
// to drive the signing paths a real key never takes.
type stubSigner struct {
	pub crypto.PublicKey
	sig []byte
	err error
}

func (s stubSigner) Public() crypto.PublicKey { return s.pub }

func (s stubSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return s.sig, s.err
}

func TestVerifyECDSARejects(t *testing.T) {
	testKeys(t)
	hash := sha256.Sum256([]byte("input"))
	good, err := signECDSA(p256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyECDSA(&p256.PublicKey, hash[:], good); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 1
	otherHash := sha256.Sum256([]byte("other input"))

	for _, c := range []struct {
		name string
		pub  crypto.PublicKey
		hash []byte
		sig  []byte
	}{
		{"RSA key", &rsa2048.PublicKey, hash[:], good},
		{"Ed25519 key", ed.Public(), hash[:], good},
		{"P-384 key", &p384.PublicKey, hash[:], good},
		{"short signature", &p256.PublicKey, hash[:], good[:63]},
		{"long signature", &p256.PublicKey, hash[:], append(good, 0)},
		{"DER signature", &p256.PublicKey, hash[:], make([]byte, 70)},
		{"tampered signature", &p256.PublicKey, hash[:], tampered},
		{"other input", &p256.PublicKey, otherHash[:], good},
		{"zero signature", &p256.PublicKey, hash[:], make([]byte, 64)},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := verifyECDSA(c.pub, c.hash, c.sig); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("verifyECDSA = %v, want ErrInvalidSignature", err)
			}
		})
	}
}

func TestSignECDSARejects(t *testing.T) {
	testKeys(t)
	hash := sha256.Sum256([]byte("input"))
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		signer crypto.Signer
	}{
		{"RSA key", rsa2048},
		{"P-384 key", p384},
		{"signer error", stubSigner{pub: &p256.PublicKey, err: errors.New("hsm unavailable")}},
		{"signature not DER", stubSigner{pub: &p256.PublicKey, sig: []byte("not DER")}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if sig, err := signECDSA(c.signer, hash[:]); err == nil {
				t.Errorf("signECDSA = %x, want an error", sig)
			}
		})
	}
}

func TestVerifyEdDSARejects(t *testing.T) {
	testKeys(t)
	msg := []byte("input")
	good, err := signEdDSA(ed, msg)
	if err != nil {
		t.Fatal(err)
	}
	pub := ed.Public().(ed25519.PublicKey)
	if err := verifyEdDSA(pub, msg, good); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	tampered := append([]byte(nil), good...)
	tampered[0] ^= 1

	for _, c := range []struct {
		name string
		pub  crypto.PublicKey
		msg  []byte
		sig  []byte
	}{
		{"ECDSA key", &p256.PublicKey, msg, good},
		{"pointer to Ed25519 key", &pub, msg, good},
		{"short key", pub[:16], msg, good},
		{"short signature", pub, msg, good[:63]},
		{"long signature", pub, msg, append(good, 0)},
		{"tampered signature", pub, msg, tampered},
		{"other input", pub, []byte("other input"), good},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := verifyEdDSA(c.pub, c.msg, c.sig); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("verifyEdDSA = %v, want ErrInvalidSignature", err)
			}
		})
	}
}

func TestSignEdDSARejects(t *testing.T) {
	testKeys(t)
	pub := ed.Public().(ed25519.PublicKey)
	for _, c := range []struct {
		name   string
		signer crypto.Signer
	}{
		{"ECDSA key", p256},
		{"short key", stubSigner{pub: pub[:16]}},
		{"signer error", stubSigner{pub: pub, err: errors.New("hsm unavailable")}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if sig, err := signEdDSA(c.signer, []byte("input")); err == nil {
				t.Errorf("signEdDSA = %x, want an error", sig)
			}
		})
	}
}
