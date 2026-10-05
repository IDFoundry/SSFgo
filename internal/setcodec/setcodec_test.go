package setcodec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/internal/jose"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/scim"
)

var (
	keyOnce sync.Once
	rsaKey  *rsa.PrivateKey
	ecKey   *ecdsa.PrivateKey
)

func keys(t testing.TB) (*rsa.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		if rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			panic(err)
		}
	})
	return rsaKey, ecKey
}

func registry(t testing.TB) *ssf.Registry {
	t.Helper()
	r := ssf.NewRegistry()
	if err := caep.Register(r); err != nil {
		t.Fatal(err)
	}
	if err := risc.Register(r); err != nil {
		t.Fatal(err)
	}
	if err := scim.Register(r); err != nil {
		t.Fatal(err)
	}
	return r
}

// farFuture is late enough that every spec example's "iat" is in the past,
// including SSF §5 Figure 13's typo'd 15203800012.
var farFuture = time.Unix(20000000000, 0)

func options(t testing.TB, iss, aud string) VerifyOptions {
	rk, ek := keys(t)
	return VerifyOptions{
		Issuer:     iss,
		Audience:   aud,
		Algorithms: []ssf.SignatureAlgorithm{ssf.RS256},
		Keys: []jose.SetKey{
			{KeyID: "rsa-1", PublicKey: &rk.PublicKey},
			{KeyID: "ec-1", Algorithm: ssf.ES256, PublicKey: &ek.PublicKey},
		},
		Registry: registry(t),
		Now:      func() time.Time { return farFuture },
	}
}

// signRaw signs an arbitrary claims payload, bypassing Encode's
// validation, so tests can present Decode with SETs Encode would refuse.
func signRaw(t testing.TB, signer crypto.Signer, h jose.Header, claims []byte) string {
	t.Helper()
	tok, err := jose.Sign(signer, h, claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func rsaHeader() jose.Header {
	return jose.Header{Algorithm: ssf.RS256, Type: TypeHeader, KeyID: "rsa-1"}
}

func TestDecodeSpecExamples(t *testing.T) {
	rk, _ := keys(t)
	files, err := filepath.Glob("testdata/spec/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no spec vectors: %v", err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var claims struct {
				Iss    string                     `json:"iss"`
				Aud    json.RawMessage            `json:"aud"`
				Events map[string]json.RawMessage `json:"events"`
				SubID  struct {
					Format string `json:"format"`
				} `json:"sub_id"`
			}
			if err := json.Unmarshal(raw, &claims); err != nil {
				t.Fatal(err)
			}
			aud, err := audienceClaim(claims.Aud)
			if err != nil {
				t.Fatal(err)
			}

			opts := options(t, claims.Iss, aud[len(aud)-1])
			set, err := Decode(signRaw(t, rk, rsaHeader(), raw), opts)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			for typ := range claims.Events {
				if got := set.Event.EventType(); string(got) != typ {
					t.Errorf("event type = %s, want %s", got, typ)
				}
			}
			if got := string(set.Subject.Format()); got != claims.SubID.Format {
				t.Errorf("subject format = %s, want %s", got, claims.SubID.Format)
			}

			// Re-encoding the decoded SET must reproduce it exactly.
			tok, err := Encode(Signer{Key: rk, Algorithm: ssf.RS256, KeyID: "rsa-1"}, set)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			again, err := Decode(tok, opts)
			if err != nil {
				t.Fatalf("Decode(Encode(set)): %v", err)
			}
			if !reflect.DeepEqual(set, again) {
				t.Errorf("round trip changed the SET:\n got %#v\nwant %#v", again, set)
			}
		})
	}
}

func validSET() ssf.SET {
	return ssf.SET{
		Issuer:        "https://tx.example.com",
		Audience:      []string{"https://rx.example.com"},
		JWTID:         "jti-1",
		IssuedAt:      time.Unix(1700000000, 0),
		TransactionID: "txn-1",
		Subject:       ssf.EmailSubject{Email: "user@example.com"},
		Event: caep.SessionRevoked{Common: caep.Common{
			ReasonAdmin: ssf.LocalizedText{"en": "Admin revoked session"},
		}},
	}
}

func TestEncodeShape(t *testing.T) {
	rk, _ := keys(t)
	signer := Signer{Key: rk, Algorithm: ssf.RS256, KeyID: "rsa-1"}

	decodeSegment := func(tok string, i int) map[string]any {
		t.Helper()
		seg, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[i])
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(seg, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	tok, err := Encode(signer, validSET())
	if err != nil {
		t.Fatal(err)
	}
	header := decodeSegment(tok, 0)
	if header["typ"] != "secevent+jwt" || header["alg"] != "RS256" || header["kid"] != "rsa-1" {
		t.Errorf("header = %v", header)
	}
	claims := decodeSegment(tok, 1)
	if claims["aud"] != "https://rx.example.com" {
		t.Errorf("single aud should encode as a string, got %#v", claims["aud"])
	}
	for _, forbidden := range []string{"sub", "exp"} {
		if _, ok := claims[forbidden]; ok {
			t.Errorf("claim %q must not be present", forbidden)
		}
	}
	events := claims["events"].(map[string]any)
	ev := events[string(caep.SessionRevokedEventType)].(map[string]any)
	if _, ok := ev["event_timestamp"]; ok {
		t.Errorf("zero event_timestamp should be omitted, got %v", ev)
	}

	multi := validSET()
	multi.Audience = []string{"a", "b"}
	tok, err = Encode(signer, multi)
	if err != nil {
		t.Fatal(err)
	}
	if aud, ok := decodeSegment(tok, 1)["aud"].([]any); !ok || len(aud) != 2 {
		t.Errorf("several aud values should encode as an array, got %#v", decodeSegment(tok, 1)["aud"])
	}
}

func TestEncodeRejectsInvalidSET(t *testing.T) {
	rk, _ := keys(t)
	signer := Signer{Key: rk, Algorithm: ssf.RS256}
	cases := map[string]func(*ssf.SET){
		"no iss":         func(s *ssf.SET) { s.Issuer = "" },
		"no aud":         func(s *ssf.SET) { s.Audience = nil },
		"empty aud":      func(s *ssf.SET) { s.Audience = []string{""} },
		"no jti":         func(s *ssf.SET) { s.JWTID = "" },
		"no iat":         func(s *ssf.SET) { s.IssuedAt = time.Time{} },
		"no subject":     func(s *ssf.SET) { s.Subject = nil },
		"bad subject":    func(s *ssf.SET) { s.Subject = ssf.EmailSubject{} },
		"no event":       func(s *ssf.SET) { s.Event = nil },
		"invalid event":  func(s *ssf.SET) { s.Event = caep.CredentialChange{} },
		"empty reason":   func(s *ssf.SET) { s.Event = caep.SessionRevoked{Common: caep.Common{ReasonAdmin: ssf.LocalizedText{}}} },
		"stream subject": func(s *ssf.SET) { s.Event = ssf.Verification{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			set := validSET()
			mutate(&set)
			if _, err := Encode(signer, set); err == nil {
				t.Fatal("Encode succeeded, want error")
			}
		})
	}
}

func baseClaims() map[string]any {
	return map[string]any{
		"iss": "https://tx.example.com",
		"aud": "https://rx.example.com",
		"jti": "jti-1",
		"iat": 1700000000,
		"sub_id": map[string]any{
			"format": "email", "email": "user@example.com",
		},
		"events": map[string]any{
			string(caep.SessionRevokedEventType): map[string]any{
				"reason_admin": map[string]any{"en": "revoked"},
			},
		},
	}
}

func TestDecodeRejects(t *testing.T) {
	rk, ek := keys(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	type tc struct {
		mutate func(map[string]any)
		header jose.Header
		signer crypto.Signer
		opts   func(*VerifyOptions)
		code   string
		is     error
	}
	cases := map[string]tc{
		"typ JWT": {header: jose.Header{Algorithm: ssf.RS256, Type: "JWT"}, code: CodeInvalidRequest},
		"no typ":  {header: jose.Header{Algorithm: ssf.RS256}, code: CodeInvalidRequest},
		"sub":     {mutate: func(c map[string]any) { c["sub"] = "x" }, code: CodeInvalidRequest},
		"exp":     {mutate: func(c map[string]any) { c["exp"] = 1 }, code: CodeInvalidRequest},
		"two events": {mutate: func(c map[string]any) {
			c["events"].(map[string]any)[string(risc.AccountEnabledEventType)] = map[string]any{}
		}, code: CodeInvalidRequest},
		"no events":     {mutate: func(c map[string]any) { c["events"] = map[string]any{} }, code: CodeInvalidRequest},
		"events array":  {mutate: func(c map[string]any) { c["events"] = []any{} }, code: CodeInvalidRequest},
		"wrong iss":     {mutate: func(c map[string]any) { c["iss"] = "https://evil.example" }, code: CodeInvalidIssuer},
		"wrong aud":     {mutate: func(c map[string]any) { c["aud"] = "someone-else" }, code: CodeInvalidAudience},
		"aud array":     {mutate: func(c map[string]any) { c["aud"] = []any{"x", "y"} }, code: CodeInvalidAudience},
		"aud numeric":   {mutate: func(c map[string]any) { c["aud"] = 5 }, code: CodeInvalidRequest},
		"no iss":        {mutate: func(c map[string]any) { delete(c, "iss") }, code: CodeInvalidRequest},
		"no jti":        {mutate: func(c map[string]any) { delete(c, "jti") }, code: CodeInvalidRequest},
		"no iat":        {mutate: func(c map[string]any) { delete(c, "iat") }, code: CodeInvalidRequest},
		"string iat":    {mutate: func(c map[string]any) { c["iat"] = "1700000000" }, code: CodeInvalidRequest},
		"future iat":    {mutate: func(c map[string]any) { c["iat"] = 1700000000 + 3600 }, opts: func(o *VerifyOptions) { o.Now = func() time.Time { return time.Unix(1700000000, 0) } }, code: CodeInvalidRequest},
		"no sub_id":     {mutate: func(c map[string]any) { delete(c, "sub_id") }, code: CodeInvalidRequest},
		"bad sub_id":    {mutate: func(c map[string]any) { c["sub_id"] = map[string]any{"format": "email"} }, code: CodeInvalidRequest},
		"legacy sub_id": {mutate: func(c map[string]any) { c["sub_id"] = map[string]any{"subject_type": "email", "email": "a@b"} }, code: CodeInvalidRequest},
		"unknown event": {
			mutate: func(c map[string]any) { c["events"] = map[string]any{"https://example.com/custom": map[string]any{}} },
			code:   CodeInvalidRequest, is: ssf.ErrUnsupportedEventType,
		},
		"reason string": {
			mutate: func(c map[string]any) {
				c["events"] = map[string]any{string(caep.SessionRevokedEventType): map[string]any{"reason_admin": "revoked"}}
			},
			code: CodeInvalidRequest, is: ssf.ErrInvalidEvent,
		},
		"verification with email subject": {
			mutate: func(c map[string]any) {
				c["events"] = map[string]any{string(ssf.VerificationEventType): map[string]any{"state": "s"}}
			},
			code: CodeInvalidRequest, is: ssf.ErrInvalidEvent,
		},
		"identifier-changed with iss_sub subject": {
			mutate: func(c map[string]any) {
				c["sub_id"] = map[string]any{"format": "iss_sub", "iss": "https://i", "sub": "s"}
				c["events"] = map[string]any{string(risc.IdentifierChangedEventType): map[string]any{}}
			},
			code: CodeInvalidRequest, is: ssf.ErrInvalidEvent,
		},
		"algorithm not accepted": {header: jose.Header{Algorithm: ssf.PS256, Type: TypeHeader, KeyID: "rsa-1"}, code: CodeInvalidKey},
		"unknown kid":            {header: jose.Header{Algorithm: ssf.RS256, Type: TypeHeader, KeyID: "nope"}, code: CodeInvalidKey},
		"wrong key":              {signer: other, code: CodeInvalidKey},
		"kid of wrong key type": {
			header: jose.Header{Algorithm: ssf.ES256, Type: TypeHeader, KeyID: "rsa-1"}, signer: ek,
			opts: func(o *VerifyOptions) { o.Algorithms = append(o.Algorithms, ssf.ES256) }, code: CodeInvalidKey,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			claims := baseClaims()
			if c.mutate != nil {
				c.mutate(claims)
			}
			payload, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			h := rsaHeader()
			if c.header.Algorithm != 0 {
				h = c.header
			}
			var signer crypto.Signer = rk
			if c.signer != nil {
				signer = c.signer
			}
			opts := options(t, "https://tx.example.com", "https://rx.example.com")
			opts.Now = nil
			if c.opts != nil {
				c.opts(&opts)
			}
			_, err = Decode(signRaw(t, signer, h, payload), opts)
			de, ok := IsDecodeError(err)
			if !ok {
				t.Fatalf("Decode error = %v, want *DecodeError", err)
			}
			if de.Code != c.code {
				t.Errorf("code = %s, want %s (%v)", de.Code, c.code, err)
			}
			if c.is != nil && !errors.Is(err, c.is) {
				t.Errorf("error %v does not wrap %v", err, c.is)
			}
		})
	}
}

func TestDecodeAccepts(t *testing.T) {
	rk, ek := keys(t)
	cases := map[string]struct {
		mutate func(map[string]any)
		header jose.Header
		signer crypto.Signer
		opts   func(*VerifyOptions)
	}{
		"baseline":          {},
		"full media type":   {header: jose.Header{Algorithm: ssf.RS256, Type: "application/secevent+JWT", KeyID: "rsa-1"}},
		"no kid tries keys": {header: jose.Header{Algorithm: ssf.RS256, Type: TypeHeader}},
		"aud array":         {mutate: func(c map[string]any) { c["aud"] = []any{"x", "https://rx.example.com"} }},
		"unknown members ignored": {mutate: func(c map[string]any) {
			c["extra"] = true
			c["sub_id"].(map[string]any)["extra"] = 1
			c["events"].(map[string]any)[string(caep.SessionRevokedEventType)].(map[string]any)["extra"] = "x"
		}},
		"small clock skew": {
			mutate: func(c map[string]any) { c["iat"] = 1700000030 },
			opts:   func(o *VerifyOptions) { o.Now = func() time.Time { return time.Unix(1700000000, 0) } },
		},
		"ES256": {
			header: jose.Header{Algorithm: ssf.ES256, Type: TypeHeader, KeyID: "ec-1"}, signer: ek,
			opts: func(o *VerifyOptions) { o.Algorithms = []ssf.SignatureAlgorithm{ssf.ES256} },
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			claims := baseClaims()
			if c.mutate != nil {
				c.mutate(claims)
			}
			payload, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			h := rsaHeader()
			if c.header.Algorithm != 0 {
				h = c.header
			}
			var signer crypto.Signer = rk
			if c.signer != nil {
				signer = c.signer
			}
			opts := options(t, "https://tx.example.com", "https://rx.example.com")
			if c.opts != nil {
				c.opts(&opts)
			}
			set, err := Decode(signRaw(t, signer, h, payload), opts)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if _, ok := set.Event.(caep.SessionRevoked); !ok {
				t.Errorf("event = %T, want caep.SessionRevoked", set.Event)
			}
		})
	}
}

func TestDecodeRequiresPolicy(t *testing.T) {
	_, err := Decode("a.b.c", VerifyOptions{})
	if err == nil {
		t.Fatal("Decode with empty options succeeded")
	}
	if _, ok := IsDecodeError(err); ok {
		t.Error("a missing policy is a programming error, not a DecodeError")
	}
}

func TestDecodeTamperedPayload(t *testing.T) {
	rk, _ := keys(t)
	tok, err := Encode(Signer{Key: rk, Algorithm: ssf.RS256, KeyID: "rsa-1"}, validSET())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	payload = []byte(strings.Replace(string(payload), "user@example.com", "boss@example.com", 1))
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)

	_, err = Decode(strings.Join(parts, "."), options(t, "https://tx.example.com", "https://rx.example.com"))
	if de, ok := IsDecodeError(err); !ok || de.Code != CodeInvalidKey {
		t.Fatalf("Decode(tampered) = %v, want invalid_key", err)
	}
}

func FuzzDecode(f *testing.F) {
	rk, _ := keys(f)
	tok, err := Encode(Signer{Key: rk, Algorithm: ssf.RS256, KeyID: "rsa-1"}, validSET())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(tok)
	f.Add("")
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	opts := options(f, "https://tx.example.com", "https://rx.example.com")
	f.Fuzz(func(t *testing.T, s string) {
		set, err := Decode(s, opts)
		if err != nil {
			if _, ok := IsDecodeError(err); !ok {
				t.Fatalf("Decode returned a non-DecodeError: %v", err)
			}
			return
		}
		if err := set.Validate(); err != nil {
			t.Fatalf("Decode returned an invalid SET: %v", err)
		}
	})
}

// googleStyleSET is shaped like the SETs Google's RISC Transmitter sends:
// no sub_id, and the subject inside the event, typed with subject_type.
func googleStyleSET(t *testing.T) string {
	rk, _ := keys(t)
	claims := map[string]any{
		"iss": "https://tx.example.com",
		"aud": "https://rx.example.com",
		"jti": "g-1",
		"iat": 1700000000,
		"events": map[string]any{
			string(risc.AccountDisabledEventType): map[string]any{
				"subject": map[string]any{"subject_type": "iss-sub", "iss": "https://accounts.google.com/", "sub": "7375626A656374"},
				"reason":  "hijacking",
			},
		},
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return signRaw(t, rk, rsaHeader(), payload)
}

func TestLegacySubjects(t *testing.T) {
	tok := googleStyleSET(t)
	opts := options(t, "https://tx.example.com", "https://rx.example.com")

	if _, err := Decode(tok, opts); err == nil {
		t.Fatal("a SET without sub_id decoded without opting in")
	}
	opts.LegacyEventSubject = true
	if _, err := Decode(tok, opts); err == nil {
		t.Fatal("subject_type decoded without opting in")
	}
	opts.LegacySubjectType = true
	set, err := Decode(tok, opts)
	if err != nil {
		t.Fatalf("Decode with both options: %v", err)
	}
	want := ssf.IssSubSubject{Issuer: "https://accounts.google.com/", Subject: "7375626A656374"}
	if !ssf.SubjectsEqual(set.Subject, want) {
		t.Errorf("subject = %#v", set.Subject)
	}
	if ev, ok := set.Event.(risc.AccountDisabled); !ok || ev.Reason != risc.DisabledHijacking {
		t.Errorf("event = %#v", set.Event)
	}

	// sub_id wins over the event subject when both are present.
	rk, _ := keys(t)
	claims := baseClaims()
	claims["events"] = map[string]any{string(caep.SessionRevokedEventType): map[string]any{
		"subject":      map[string]any{"format": "email", "email": "legacy@example.com"},
		"reason_admin": map[string]any{"en": "x"},
	}}
	payload, _ := json.Marshal(claims)
	set, err = Decode(signRaw(t, rk, rsaHeader(), payload), opts)
	if err != nil || !ssf.SubjectsEqual(set.Subject, ssf.EmailSubject{Email: "user@example.com"}) {
		t.Errorf("sub_id should take precedence: %v, %v", set.Subject, err)
	}
}

func TestNormalizeSubjectType(t *testing.T) {
	for in, want := range map[string]string{
		`{"subject_type":"email","email":"a@b.example"}`:              `{"email":"a@b.example","format":"email"}`,
		`{"subject_type":"phone","phone_number":"+1555"}`:             `{"format":"phone_number","phone_number":"+1555"}`,
		`{"format":"email","subject_type":"x","email":"a@b.example"}`: `{"format":"email","subject_type":"x","email":"a@b.example"}`,
		`not json`: `not json`,
	} {
		if got := string(normalizeSubjectType(json.RawMessage(in))); got != want {
			t.Errorf("normalizeSubjectType(%s) = %s, want %s", in, got, want)
		}
	}
}
