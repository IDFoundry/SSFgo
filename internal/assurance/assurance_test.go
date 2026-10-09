package assurance

import (
	"crypto"
	"fmt"
	"io"
	"strings"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
)

type declares storage.Capabilities

func (d declares) Capabilities() storage.Capabilities { return storage.Capabilities(d) }

func TestCheck(t *testing.T) {
	memory := declares{}
	durable := declares{Durable: true}
	shared := declares{Durable: true, CrossInstanceConsistent: true}
	for name, c := range map[string]struct {
		level  ssf.Assurance
		scaled bool
		store  any
		url    string
		want   string // "" for no error
	}{
		"no level":                  {0, false, shared, "", "Assurance is required"},
		"unknown level":             {3, false, shared, "", "Assurance is required"},
		"development, memory":       {ssf.AssuranceDevelopment, true, memory, "https://localhost", ""},
		"production, memory":        {ssf.AssuranceProduction, false, memory, "", "S must declare itself durable"},
		"production, undeclared":    {ssf.AssuranceProduction, false, struct{}{}, "", "S must declare itself durable"},
		"production, durable":       {ssf.AssuranceProduction, false, durable, "https://tx.example", ""},
		"scaled, durable only":      {ssf.AssuranceProduction, true, durable, "", "S must declare itself consistent across instances"},
		"scaled, shared":            {ssf.AssuranceProduction, true, shared, "", ""},
		"production, localhost":     {ssf.AssuranceProduction, false, shared, "https://localhost:8443/ssf", "U must not be a loopback host"},
		"production, loopback IP":   {ssf.AssuranceProduction, false, shared, "https://127.0.0.1", "U must not be a loopback host"},
		"production, loopback v6":   {ssf.AssuranceProduction, false, shared, "https://[::1]/", "U must not be a loopback host"},
		"production, .localhost":    {ssf.AssuranceProduction, false, shared, "https://tx.localhost", "U must not be a loopback host"},
		"production, missing store": {ssf.AssuranceProduction, false, nil, "", ""},
	} {
		errs := Check(c.level, c.scaled, Deps{Stores: []Store{{Field: "S", Store: c.store}}, URLs: []URL{{Field: "U", Value: c.url}}})
		var got []string
		for _, err := range errs {
			got = append(got, err.Error())
		}
		joined := strings.Join(got, "; ")
		if (c.want == "") != (len(errs) == 0) || !strings.Contains(joined, c.want) {
			t.Errorf("%s: %q, want %q", name, joined, c.want)
		}
	}
}

// Keys are held to the same rules as stores: durable in production, and
// shared by every instance when scaled.
func TestCheckKeys(t *testing.T) {
	for name, c := range map[string]struct {
		level   ssf.Assurance
		scaled  bool
		custody ssf.KeyCustody
		want    string
	}{
		"development, undeclared": {ssf.AssuranceDevelopment, true, ssf.KeyCustody{}, ""},
		"production, undeclared":  {ssf.AssuranceProduction, false, ssf.KeyCustody{}, "K must be declared durable"},
		"production, durable":     {ssf.AssuranceProduction, false, ssf.KeyCustody{Durable: true}, ""},
		"scaled, durable only":    {ssf.AssuranceProduction, true, ssf.KeyCustody{Durable: true}, "K must be declared shared by every instance"},
		"scaled, shared":          {ssf.AssuranceProduction, true, ssf.KeyCustody{Durable: true, CrossInstanceConsistent: true}, ""},
	} {
		errs := Check(c.level, c.scaled, Deps{Keys: []Key{{Field: "K", Custody: c.custody}}})
		joined := fmt.Sprint(errs)
		if (c.want == "") != (len(errs) == 0) || !strings.Contains(joined, c.want) {
			t.Errorf("%s: %s, want %q", name, joined, c.want)
		}
	}
}

type kmsKey struct{ crypto.Signer }

func (kmsKey) KeyCustody() ssf.KeyCustody { return ssf.KeyCustody{Durable: true} }

// Custody declared in the configuration wins over what a signer declares;
// a signer that declares nothing has no custody.
func TestCustodyOf(t *testing.T) {
	shared := ssf.KeyCustody{Durable: true, CrossInstanceConsistent: true}
	for _, c := range []struct {
		signer   crypto.Signer
		declared ssf.KeyCustody
		want     ssf.KeyCustody
	}{
		{nil, ssf.KeyCustody{}, ssf.KeyCustody{}},
		{kmsKey{}, ssf.KeyCustody{}, ssf.KeyCustody{Durable: true}},
		{kmsKey{}, shared, shared},
		{nil, shared, shared},
		{(*ptrKey)(nil), ssf.KeyCustody{}, ssf.KeyCustody{}}, // its KeyCustody would panic
	} {
		if got := CustodyOf(c.signer, c.declared); got != c.want {
			t.Errorf("CustodyOf(%T, %+v) = %+v, want %+v", c.signer, c.declared, got, c.want)
		}
	}
}

// ptrKey declares its custody through a pointer, so a nil *ptrKey panics
// if asked.
type ptrKey struct{ custody ssf.KeyCustody }

func (k *ptrKey) Public() crypto.PublicKey                                  { return nil }
func (k *ptrKey) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, nil }
func (k *ptrKey) KeyCustody() ssf.KeyCustody                                { return k.custody }

// Every spelling of a host that reaches this machine is loopback.
func TestLoopback(t *testing.T) {
	for _, u := range []string{
		"https://localhost/", "https://LOCALHOST./", "https://app.localhost/",
		"https://127.0.0.1/", "https://127.1/", "https://127.0.1/", "https://2130706433/",
		"https://0x7f000001/", "https://0x7f.1/", "https://0177.0.0.1/", "https://127.255.255.254/",
		"https://0.0.0.0/", "https://0/", "https://[::]/", "https://[::1]/",
		"https://[0:0:0:0:0:0:0:1]/", "https://[::ffff:127.0.0.1]/", "https://[::1%25lo0]/",
	} {
		if !Loopback(u) {
			t.Errorf("Loopback(%s) = false", u)
		}
	}
	for _, u := range []string{
		"https://example.com/", "https://128.0.0.1/", "https://0x80.1/", "https://1.2.3.4/",
		"https://127.example/", "https://localhost.example/", "https://[2001:db8::1]/",
		"https://127.0.0.0.1/", "https://127.1_0/", "https://4294967296/", "https://127.256.0.1/",
		"https://0x7f/", "not a url\x7f",
	} {
		if Loopback(u) {
			t.Errorf("Loopback(%s) = true", u)
		}
	}
}

func TestIsNil(t *testing.T) {
	var key *ptrKey
	var signer crypto.Signer = key
	var m map[string]string
	for _, v := range []any{nil, key, signer, m, []int(nil), (func())(nil)} {
		if !IsNil(v) {
			t.Errorf("IsNil(%#v) = false", v)
		}
	}
	for _, v := range []any{&ptrKey{}, kmsKey{}, 0, "", map[string]string{}} {
		if IsNil(v) {
			t.Errorf("IsNil(%#v) = true", v)
		}
	}
}
