package jose

import (
	"crypto"
	"crypto/elliptic"
	_ "crypto/sha256" // registers SHA-256 with crypto.Hash
	_ "crypto/sha512" // registers SHA-384 and SHA-512 with crypto.Hash
	"fmt"

	ssf "github.com/idfoundry/ssfgo"
)

// family is a signature scheme; each algorithm is a family with a hash
// and, for ECDSA, a curve.
type family int

const (
	familyRSAPKCS1 family = iota + 1
	familyRSAPSS
	familyECDSA
	familyEdDSA
)

// algSpec is what an algorithm requires of its key and signature.
type algSpec struct {
	family family
	hash   crypto.Hash // zero for EdDSA, which signs the input itself
	curve  *ecCurve    // ECDSA only
}

// ecCurve is a curve ECDSA algorithms use, with its JWK "crv" name and the
// fixed byte width of its coordinates and of R and S in a JWS signature
// (RFC 7518 §3.4).
type ecCurve struct {
	curve elliptic.Curve
	name  string
	size  int
}

var (
	curveP256 = &ecCurve{elliptic.P256(), "P-256", 32}
	curveP384 = &ecCurve{elliptic.P384(), "P-384", 48}
	curveP521 = &ecCurve{elliptic.P521(), "P-521", 66}
)

var ecCurves = []*ecCurve{curveP256, curveP384, curveP521}

var algSpecs = map[ssf.SignatureAlgorithm]algSpec{
	ssf.RS256: {familyRSAPKCS1, crypto.SHA256, nil},
	ssf.RS384: {familyRSAPKCS1, crypto.SHA384, nil},
	ssf.RS512: {familyRSAPKCS1, crypto.SHA512, nil},
	ssf.PS256: {familyRSAPSS, crypto.SHA256, nil},
	ssf.PS384: {familyRSAPSS, crypto.SHA384, nil},
	ssf.PS512: {familyRSAPSS, crypto.SHA512, nil},
	ssf.ES256: {familyECDSA, crypto.SHA256, curveP256},
	ssf.ES384: {familyECDSA, crypto.SHA384, curveP384},
	ssf.ES512: {familyECDSA, crypto.SHA512, curveP521},
	ssf.EdDSA: {familyEdDSA, 0, nil},
}

func specFor(alg ssf.SignatureAlgorithm) (algSpec, error) {
	s, ok := algSpecs[alg]
	if !ok {
		return algSpec{}, fmt.Errorf("jose: unsupported algorithm %v", alg)
	}
	return s, nil
}

// digest hashes input with h.
func digest(h crypto.Hash, input []byte) []byte {
	d := h.New()
	d.Write(input)
	return d.Sum(nil)
}

// curveNamed returns the curve with JWK "crv" name, or nil.
func curveNamed(name string) *ecCurve {
	for _, c := range ecCurves {
		if c.name == name {
			return c
		}
	}
	return nil
}

// curveOf returns the supported curve c is, or nil.
func curveOf(c elliptic.Curve) *ecCurve {
	for _, ec := range ecCurves {
		if ec.curve == c {
			return ec
		}
	}
	return nil
}
