package ssf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// A Secret is withheld however it is printed, logged or encoded, except
// by Reveal and by the wire form of a type that must carry it.
func TestSecretWithheld(t *testing.T) {
	const value = "Bearer s3cret"
	s := NewSecret(value)
	d := Delivery{Method: DeliveryPush, EndpointURL: "https://rx.example/events", AuthorizationHeader: s}
	cfg := StreamConfiguration{StreamID: "a", Delivery: d}
	held := struct {
		name     string
		delivery Delivery // unexported: fmt prints it by reflection
		secret   Secret
	}{"x", d, s}
	for _, format := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%X", "%d", "%t", "%o", "%b", "%c", "%U", "%e"} {
		for _, v := range []any{s, &s, d, &d, cfg, held, &held} {
			if out := fmt.Sprintf(format, v); strings.Contains(out, "s3cret") {
				t.Errorf("%s of %T revealed the secret: %s", format, v, out)
			}
		}
	}
	var buf bytes.Buffer
	for _, h := range []slog.Handler{slog.NewJSONHandler(&buf, nil), slog.NewTextHandler(&buf, nil)} {
		slog.New(h).Info("x", "secret", s, "delivery", d, "config", cfg, "held", held)
	}
	if strings.Contains(buf.String(), "s3cret") {
		t.Errorf("slog revealed the secret: %s", buf.String())
	}
	if _, err := json.Marshal(struct{ S Secret }{s}); !errors.Is(err, ErrSecretSerialization) {
		t.Errorf("json.Marshal of a struct holding a Secret = %v, want ErrSecretSerialization", err)
	}
	var decoded Secret
	if err := decoded.UnmarshalText([]byte(value)); err != nil {
		t.Fatal(err)
	}
	if s.Reveal() != value || s.IsZero() || !(Secret{}).IsZero() || s != NewSecret(value) ||
		decoded != s || NewSecret("") != (Secret{}) || (Secret{}).Reveal() != "" || s == NewSecret("other") {
		t.Error("Reveal, IsZero or == misbehave")
	}
}

// A Delivery's JSON is its wire form: the Authorization header goes out
// and comes back.
func TestDeliveryWireForm(t *testing.T) {
	d := Delivery{Method: DeliveryPush, EndpointURL: "https://rx.example/events", AuthorizationHeader: NewSecret("Bearer s3cret")}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"method":"urn:ietf:rfc:8935","endpoint_url":"https://rx.example/events","authorization_header":"Bearer s3cret"}`; string(b) != want {
		t.Errorf("encoded %s\nwant    %s", b, want)
	}
	var back Delivery
	if err := json.Unmarshal(b, &back); err != nil || back != d {
		t.Errorf("decoded %#v, %v", back, err)
	}
	if b, _ := json.Marshal(Delivery{Method: DeliveryPoll}); strings.Contains(string(b), "authorization_header") {
		t.Errorf("an empty header was encoded: %s", b)
	}
}
