package ssf_test

import (
	"fmt"

	ssf "github.com/idfoundry/ssfgo"
)

// A Secret is withheld wherever it is printed or logged; Reveal gives it
// up where it is sent.
func ExampleSecret() {
	header := ssf.NewSecret("Bearer s3cret")
	fmt.Printf("%v %+v %#v\n", header, ssf.Delivery{AuthorizationHeader: header}, header)
	fmt.Println(header.Reveal())
	// Output:
	// [REDACTED] {Method: EndpointURL: AuthorizationHeader:[REDACTED]} ssf.Secret([REDACTED])
	// Bearer s3cret
}

// A Transmitter's metadata is at a well-known location derived from its
// issuer (SSF 1.0 §7.2).
func ExampleWellKnownURL() {
	u, err := ssf.WellKnownURL("https://idp.example.com/tenants/acme")
	if err != nil {
		panic(err)
	}
	fmt.Println(u)
	// Output: https://idp.example.com/.well-known/ssf-configuration/tenants/acme
}
