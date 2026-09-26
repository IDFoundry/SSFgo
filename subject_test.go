package ssf

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

// specSubjects are the Subject Identifier examples printed in RFC 9493 §3.2
// and SSF 1.0 §3, with the value each must parse to.
var specSubjects = []struct {
	name string
	json string
	want Subject
}{
	{"RFC9493 Figure 4 account", `{"format":"account","uri":"acct:example.user@service.example.com"}`,
		AccountSubject{URI: "acct:example.user@service.example.com"}},
	{"RFC9493 Figure 5 email", `{"format":"email","email":"user@example.com"}`,
		EmailSubject{Email: "user@example.com"}},
	{"RFC9493 Figure 6 iss_sub", `{"format":"iss_sub","iss":"https://issuer.example.com/","sub":"145234573"}`,
		IssSubSubject{Issuer: "https://issuer.example.com/", Subject: "145234573"}},
	{"RFC9493 Figure 7 opaque", `{"format":"opaque","id":"11112222333344445555"}`,
		OpaqueSubject{ID: "11112222333344445555"}},
	{"RFC9493 Figure 8 phone_number", `{"format":"phone_number","phone_number":"+12065550100"}`,
		PhoneNumberSubject{PhoneNumber: "+12065550100"}},
	{"RFC9493 Figure 9 did", `{"format":"did","url":"did:example:123456"}`,
		DIDSubject{URL: "did:example:123456"}},
	{"RFC9493 Figure 10 did URL", `{"format":"did","url":"did:example:123456/did/url/path?versionId=1"}`,
		DIDSubject{URL: "did:example:123456/did/url/path?versionId=1"}},
	{"RFC9493 Figure 11 uri", `{"format":"uri","uri":"https://user.example.com/"}`,
		URISubject{URI: "https://user.example.com/"}},
	{"RFC9493 Figure 12 urn", `{"format":"uri","uri":"urn:uuid:4e851e98-83c4-4743-a5da-150ecb53042f"}`,
		URISubject{URI: "urn:uuid:4e851e98-83c4-4743-a5da-150ecb53042f"}},
	{"RFC9493 Figure 13 aliases", `{"format":"aliases","identifiers":[
		{"format":"email","email":"user@example.com"},
		{"format":"phone_number","phone_number":"+12065550100"},
		{"format":"email","email":"user+qualifier@example.com"}]}`,
		AliasesSubject{Identifiers: []Subject{
			EmailSubject{Email: "user@example.com"},
			PhoneNumberSubject{PhoneNumber: "+12065550100"},
			EmailSubject{Email: "user+qualifier@example.com"},
		}}},
	{"SSF Figure 2 complex", `{"format":"complex",
		"user":{"format":"email","email":"bar@example.com"},
		"tenant":{"format":"iss_sub","iss":"https://example.com/idp1","sub":"1234"}}`,
		ComplexSubject{
			User:   EmailSubject{Email: "bar@example.com"},
			Tenant: IssSubSubject{Issuer: "https://example.com/idp1", Subject: "1234"},
		}},
	{"SSF Figure 3 jwt_id", `{"format":"jwt_id","iss":"https://idp.example.com/123456789/","jti":"B70BA622-9515-4353-A866-823539EECBC8"}`,
		JWTIDSubject{Issuer: "https://idp.example.com/123456789/", JWTID: "B70BA622-9515-4353-A866-823539EECBC8"}},
	{"SSF Figure 4 saml_assertion_id", `{"format":"saml_assertion_id","issuer":"https://idp.example.com/123456789/","assertion_id":"_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"}`,
		SAMLAssertionIDSubject{Issuer: "https://idp.example.com/123456789/", AssertionID: "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"}},
	{"SSF Figure 5 ip-addresses", `{"format":"ip-addresses","ip-addresses":["10.29.37.75","2001:0db8:0000:0000:0000:8a2e:0370:7334"]}`,
		IPAddressesSubject{Addresses: []netip.Addr{
			netip.MustParseAddr("10.29.37.75"),
			netip.MustParseAddr("2001:db8::8a2e:370:7334"),
		}}},
	{"SSF Figure 13 proprietary", `{"format":"catalog_item","catalog_id":"c0384/winter/2354122"}`,
		ProprietarySubject{FormatName: "catalog_item", Members: map[string]json.RawMessage{
			"catalog_id": json.RawMessage(`"c0384/winter/2354122"`),
		}}},
	{"complex with additional member", `{"format":"complex","user":{"format":"opaque","id":"u"},"x_custom":{"format":"opaque","id":"c"}}`,
		ComplexSubject{
			User:       OpaqueSubject{ID: "u"},
			Additional: map[string]Subject{"x_custom": OpaqueSubject{ID: "c"}},
		}},
	{"complex containing aliases", `{"format":"complex","user":{"format":"aliases","identifiers":[{"format":"opaque","id":"u"}]}}`,
		ComplexSubject{User: AliasesSubject{Identifiers: []Subject{OpaqueSubject{ID: "u"}}}}},
	{"unknown members ignored", `{"format":"email","email":"a@b.example","display":"A"}`,
		EmailSubject{Email: "a@b.example"}},
}

func TestParseSubjectSpecExamples(t *testing.T) {
	for _, c := range specSubjects {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseSubject([]byte(c.json))
			if err != nil {
				t.Fatalf("ParseSubject: %v", err)
			}
			if !SubjectsEqual(got, c.want) {
				t.Fatalf("got %#v, want %#v", got, c.want)
			}

			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			again, err := ParseSubject(encoded)
			if err != nil {
				t.Fatalf("ParseSubject(Marshal(s)): %v", err)
			}
			if !SubjectsEqual(again, got) {
				t.Fatalf("round trip changed the subject: %s", encoded)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			if _, ok := fields["display"]; ok {
				t.Error("an ignored member was re-emitted")
			}
		})
	}
}

func TestMarshalPutsFormatFirst(t *testing.T) {
	b, err := json.Marshal(ComplexSubject{
		Tenant: OpaqueSubject{ID: "t"},
		User:   EmailSubject{Email: "u@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"format":"complex","user":{"format":"email","email":"u@example.com"},"tenant":{"format":"opaque","id":"t"}}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestParseSubjectRejects(t *testing.T) {
	for name, in := range map[string]string{
		"not an object":           `"email"`,
		"null":                    `null`,
		"no format":               `{"email":"a@b.example"}`,
		"google subject_type":     `{"subject_type":"email","email":"a@b.example"}`,
		"format not a string":     `{"format":1}`,
		"empty format":            `{"format":""}`,
		"email missing":           `{"format":"email"}`,
		"email null":              `{"format":"email","email":null}`,
		"email no at":             `{"format":"email","email":"nobody"}`,
		"email number":            `{"format":"email","email":5}`,
		"iss_sub missing sub":     `{"format":"iss_sub","iss":"https://i"}`,
		"opaque empty":            `{"format":"opaque","id":""}`,
		"phone without plus":      `{"format":"phone_number","phone_number":"2065550100"}`,
		"account not acct":        `{"format":"account","uri":"mailto:a@b.example"}`,
		"did not did":             `{"format":"did","url":"https://x"}`,
		"uri relative":            `{"format":"uri","uri":"/relative"}`,
		"jwt_id missing jti":      `{"format":"jwt_id","iss":"https://i"}`,
		"saml missing id":         `{"format":"saml_assertion_id","issuer":"https://i"}`,
		"ip empty":                `{"format":"ip-addresses","ip-addresses":[]}`,
		"ip invalid":              `{"format":"ip-addresses","ip-addresses":["300.1.1.1"]}`,
		"ip zone":                 `{"format":"ip-addresses","ip-addresses":["fe80::1%eth0"]}`,
		"aliases empty":           `{"format":"aliases","identifiers":[]}`,
		"aliases nested":          `{"format":"aliases","identifiers":[{"format":"aliases","identifiers":[{"format":"opaque","id":"x"}]}]}`,
		"aliases with complex":    `{"format":"aliases","identifiers":[{"format":"complex","user":{"format":"opaque","id":"x"}}]}`,
		"aliases invalid member":  `{"format":"aliases","identifiers":[{"format":"email"}]}`,
		"complex empty":           `{"format":"complex"}`,
		"complex nested":          `{"format":"complex","user":{"format":"complex","device":{"format":"opaque","id":"d"}}}`,
		"complex invalid member":  `{"format":"complex","user":{"format":"email"}}`,
		"complex member a string": `{"format":"complex","user":"alice"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if s, err := ParseSubject([]byte(in)); err == nil {
				t.Fatalf("ParseSubject succeeded: %#v", s)
			} else if !errors.Is(err, ErrInvalidSubject) {
				t.Errorf("error %v does not wrap ErrInvalidSubject", err)
			}
		})
	}
}

func TestMarshalRejectsInvalid(t *testing.T) {
	for name, s := range map[string]Subject{
		"empty email":                 EmailSubject{},
		"complex with nil additional": ComplexSubject{Additional: map[string]Subject{"x": nil}},
		"complex shadowing user":      ComplexSubject{Additional: map[string]Subject{"user": OpaqueSubject{ID: "u"}}},
		"complex with format member":  ComplexSubject{Additional: map[string]Subject{"format": OpaqueSubject{ID: "u"}}},
		"proprietary registered":      ProprietarySubject{FormatName: FormatEmail},
		"proprietary no format":       ProprietarySubject{},
		"proprietary format member":   ProprietarySubject{FormatName: "x", Members: map[string]json.RawMessage{"format": json.RawMessage(`"y"`)}},
		"proprietary invalid JSON":    ProprietarySubject{FormatName: "x", Members: map[string]json.RawMessage{"a": json.RawMessage(`{`)}},
		"aliases with nil":            AliasesSubject{Identifiers: []Subject{nil}},
	} {
		t.Run(name, func(t *testing.T) {
			if b, err := json.Marshal(s); err == nil {
				t.Fatalf("Marshal succeeded: %s", b)
			}
		})
	}
}

func TestSubjectsMatch(t *testing.T) {
	tenant := OpaqueSubject{ID: "example-a38h4792-uw2"}
	jdoe := EmailSubject{Email: "jdoe@example.com"}
	cases := []struct {
		name string
		a, b Subject
		want bool
	}{
		{"identical simple", jdoe, EmailSubject{Email: "jdoe@example.com"}, true},
		{"different simple", jdoe, EmailSubject{Email: "JDoe@example.com"}, false},
		{"different format", OpaqueSubject{ID: "x"}, URISubject{URI: "urn:x"}, false},
		// SSF 1.0 §8.1.3.1: the Receiver's less restrictive subject
		// matches the Transmitter's more specific one.
		{"SSF §8.1.3.1 less restrictive",
			ComplexSubject{Tenant: tenant},
			ComplexSubject{Tenant: tenant, User: jdoe}, true},
		// SSF 1.0 §8.1.3.1: a more restrictive subject still matches,
		// since the member only one side defines is a wildcard.
		{"SSF §8.1.3.1 more restrictive",
			ComplexSubject{Tenant: tenant, User: jdoe},
			ComplexSubject{Tenant: tenant}, true},
		{"conflicting member",
			ComplexSubject{Tenant: tenant, User: jdoe},
			ComplexSubject{Tenant: tenant, User: EmailSubject{Email: "other@example.com"}}, false},
		{"disjoint members", ComplexSubject{User: jdoe}, ComplexSubject{Device: OpaqueSubject{ID: "d"}}, true},
		{"additional members compared",
			ComplexSubject{Additional: map[string]Subject{"x": OpaqueSubject{ID: "1"}}},
			ComplexSubject{Additional: map[string]Subject{"x": OpaqueSubject{ID: "2"}}}, false},
		{"simple never matches complex", jdoe, ComplexSubject{User: jdoe}, false},
		{"proprietary whitespace-insensitive",
			ProprietarySubject{FormatName: "x", Members: map[string]json.RawMessage{"a": json.RawMessage(`{"b": 1}`)}},
			ProprietarySubject{FormatName: "x", Members: map[string]json.RawMessage{"a": json.RawMessage(`{"b":1}`)}}, true},
		{"aliases order matters",
			AliasesSubject{Identifiers: []Subject{jdoe, tenant}},
			AliasesSubject{Identifiers: []Subject{tenant, jdoe}}, false},
		{"ip addresses",
			IPAddressesSubject{Addresses: []netip.Addr{netip.MustParseAddr("::1")}},
			IPAddressesSubject{Addresses: []netip.Addr{netip.MustParseAddr("0:0::1")}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SubjectsMatch(c.a, c.b); got != c.want {
				t.Errorf("SubjectsMatch = %v, want %v", got, c.want)
			}
			if got := SubjectsMatch(c.b, c.a); got != c.want {
				t.Errorf("SubjectsMatch is not symmetric")
			}
		})
	}
}

func TestSubjectFormats(t *testing.T) {
	for _, c := range specSubjects {
		var probe struct {
			Format SubjectFormat `json:"format"`
		}
		if err := json.Unmarshal([]byte(c.json), &probe); err != nil {
			t.Fatal(err)
		}
		if got := c.want.Format(); got != probe.Format {
			t.Errorf("%s: Format() = %s, want %s", c.name, got, probe.Format)
		}
	}
	// Every concrete type must be reachable through ParseSubject.
	seen := map[reflect.Type]bool{}
	for _, c := range specSubjects {
		seen[reflect.TypeOf(c.want)] = true
	}
	if len(seen) != 13 {
		t.Errorf("spec examples cover %d subject types, want all 13", len(seen))
	}
}

func FuzzParseSubject(f *testing.F) {
	for _, c := range specSubjects {
		f.Add([]byte(c.json))
	}
	f.Add([]byte(`{"format":"complex","user":{"format":"aliases","identifiers":[]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := ParseSubject(data)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("a parsed subject failed to marshal: %v", err)
		}
		again, err := ParseSubject(encoded)
		if err != nil {
			t.Fatalf("a marshaled subject failed to parse: %v\n%s", err, encoded)
		}
		if !SubjectsEqual(s, again) || !SubjectsMatch(s, again) {
			t.Fatalf("round trip changed the subject: %s", encoded)
		}
	})
}

func TestProprietaryEqualityIgnoresEscaping(t *testing.T) {
	a := ProprietarySubject{FormatName: "x", Members: map[string]json.RawMessage{"a": json.RawMessage(`"&"`)}}
	b := ProprietarySubject{FormatName: "x", Members: map[string]json.RawMessage{"a": json.RawMessage(`"&"`)}}
	if !SubjectsEqual(a, b) {
		t.Error(`"&" and "&" are the same JSON string`)
	}
	c := ProprietarySubject{FormatName: "x", Members: map[string]json.RawMessage{"a": json.RawMessage(`"&amp;"`)}}
	if SubjectsEqual(a, c) {
		t.Error("different strings compared equal")
	}
}
