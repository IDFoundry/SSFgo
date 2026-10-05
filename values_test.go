package ssf

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNumericDate(t *testing.T) {
	var d NumericDate
	if err := json.Unmarshal([]byte(`1615304991`), &d); err != nil {
		t.Fatal(err)
	}
	if !d.Equal(time.Unix(1615304991, 0)) {
		t.Errorf("got %v", d.Time)
	}
	if err := json.Unmarshal([]byte(`1615304991.5`), &d); err != nil {
		t.Fatal(err)
	}
	if d.UnixMilli() != 1615304991500 {
		t.Errorf("fractional seconds lost: %v", d.Time)
	}
	b, err := json.Marshal(d)
	if err != nil || string(b) != "1615304991" {
		t.Errorf("Marshal = %s, %v; want whole seconds", b, err)
	}

	// 0.01 was found by FuzzWireTypes: it decoded, then encoded as 0,
	// which does not decode.
	for _, bad := range []string{`"1615304991"`, `null`, `true`, `-1`, `0`, `0.01`, `1e20`, `{}`} {
		if err := json.Unmarshal([]byte(bad), &d); err == nil {
			t.Errorf("Unmarshal(%s) succeeded", bad)
		}
	}
	if _, err := json.Marshal(NumericDate{}); err == nil {
		t.Error("marshaling a zero NumericDate succeeded")
	}

	var withOmit struct {
		T NumericDate `json:"t,omitzero"`
	}
	if b, _ := json.Marshal(withOmit); string(b) != `{}` {
		t.Errorf("omitzero did not omit: %s", b)
	}
}

func TestLocalizedText(t *testing.T) {
	var lt LocalizedText
	if err := json.Unmarshal([]byte(`{"en":"Hi","es-410":"Hola","zh-Hant-TW":"你好"}`), &lt); err != nil {
		t.Fatal(err)
	}
	if err := lt.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
	for _, bad := range []string{`"Session terminated"`, `["en"]`, `{"en":1}`, `null`} {
		if err := json.Unmarshal([]byte(bad), &lt); err == nil {
			t.Errorf("Unmarshal(%s) succeeded", bad)
		}
	}
	for name, lt := range map[string]LocalizedText{
		"empty":         {},
		"empty tag":     {"": "x"},
		"space in tag":  {"en US": "x"},
		"long subtag":   {"abcdefghi": "x"},
		"trailing dash": {"en-": "x"},
	} {
		if err := lt.Validate(); err == nil {
			t.Errorf("%s: Validate succeeded", name)
		}
	}
}

func TestSignatureAlgorithm(t *testing.T) {
	if n := len(SignatureAlgorithms()); n != 10 {
		t.Errorf("%d algorithms, want 10", n)
	}
	for _, alg := range SignatureAlgorithms() {
		parsed, err := ParseSignatureAlgorithm(alg.String())
		if err != nil || parsed != alg || !alg.IsValid() {
			t.Errorf("%s did not round trip", alg)
		}
	}
	for _, bad := range []string{"none", "HS256", "HS384", "HS512", "ES256K", "Ed25519", "", "rs256", "RS1024"} {
		if _, err := ParseSignatureAlgorithm(bad); err == nil {
			t.Errorf("ParseSignatureAlgorithm(%q) succeeded", bad)
		}
	}
	if SignatureAlgorithm(0).IsValid() || SignatureAlgorithm(99).String() != "" {
		t.Error("an unknown algorithm reported itself valid")
	}
}
