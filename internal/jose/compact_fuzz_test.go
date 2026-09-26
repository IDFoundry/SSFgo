package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
)

// FuzzParseCompact exercises ParseCompact against arbitrary strings — the
// entry point every received SET goes through before its signature is
// checked. A successfully parsed value must also survive Verify without
// panicking, whether or not the signature checks out.
func FuzzParseCompact(f *testing.F) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	valid, err := Sign(priv, Header{Algorithm: ssf.ES256, Type: "test+jwt"}, []byte(`{"hello":"world"}`))
	if err != nil {
		f.Fatalf("sign: %v", err)
	}

	f.Add(valid)
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("a.b.c")
	f.Add("a.b.c.d")
	f.Add(valid + ".")
	f.Add(valid[:len(valid)-1])
	f.Add("eyJhbGciOiJub25lIn0.e30.")

	f.Fuzz(func(t *testing.T, s string) {
		compact, err := ParseCompact(s)
		if err != nil {
			return
		}
		_ = compact.Verify(&priv.PublicKey, ssf.ES256)
	})
}
