package ssf

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWellKnownURL(t *testing.T) {
	for issuer, want := range map[string]string{
		// SSF 1.0 §7.2.1, Figures 16 and 17.
		"https://tr.example.com":         "https://tr.example.com/.well-known/ssf-configuration",
		"https://tr.example.com/issuer1": "https://tr.example.com/.well-known/ssf-configuration/issuer1",
		// A terminating "/" is removed first.
		"https://tr.example.com/":             "https://tr.example.com/.well-known/ssf-configuration",
		"https://tr.example.com/a/b/":         "https://tr.example.com/.well-known/ssf-configuration/a/b",
		"https://tr.example.com:8443/tenant1": "https://tr.example.com:8443/.well-known/ssf-configuration/tenant1",
	} {
		got, err := WellKnownURL(issuer)
		if err != nil || got != want {
			t.Errorf("WellKnownURL(%q) = %q, %v; want %q", issuer, got, err, want)
		}
	}
	for _, bad := range []string{"http://tr.example.com", "https://tr.example.com?x=1", "https://tr.example.com#f", "https://user@tr.example.com", "tr.example.com", ""} {
		if _, err := WellKnownURL(bad); err == nil {
			t.Errorf("WellKnownURL(%q) succeeded", bad)
		}
	}
}

func TestTransmitterMetadataOmitsEmptyArrays(t *testing.T) {
	b, err := json.Marshal(TransmitterMetadata{Issuer: "https://tr.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"issuer":"https://tr.example.com"}` {
		t.Errorf("got %s", b)
	}
}

func TestAudience(t *testing.T) {
	var a Audience
	if err := json.Unmarshal([]byte(`"x"`), &a); err != nil || len(a) != 1 || a[0] != "x" {
		t.Errorf("string aud: %v, %v", a, err)
	}
	if err := json.Unmarshal([]byte(`["x","y"]`), &a); err != nil || len(a) != 2 {
		t.Errorf("array aud: %v, %v", a, err)
	}
	for _, bad := range []string{`null`, `1`, `{}`, `[1]`} {
		if err := json.Unmarshal([]byte(bad), &a); err == nil {
			t.Errorf("Unmarshal(%s) succeeded", bad)
		}
	}
	if b, _ := json.Marshal(Audience{"x"}); string(b) != `"x"` {
		t.Errorf("single aud encodes as %s", b)
	}
	if b, _ := json.Marshal(Audience{"x", "y"}); string(b) != `["x","y"]` {
		t.Errorf("several aud values encode as %s", b)
	}
}

func TestStreamConfigurationAlwaysHasEventsDelivered(t *testing.T) {
	b, err := json.Marshal(StreamConfiguration{StreamID: "s", Issuer: "https://i", Audience: Audience{"a"}, Delivery: Delivery{Method: DeliveryPoll}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"events_delivered":[]`) {
		t.Errorf("got %s", b)
	}
	var back StreamConfiguration
	if err := json.Unmarshal(b, &back); err != nil || back.StreamID != "s" {
		t.Errorf("round trip: %+v, %v", back, err)
	}
}

func TestSubjectRequests(t *testing.T) {
	// SSF 1.0 §8.1.3.2 Figure 40.
	in := `{"stream_id":"f67e39a0a4d34d56b3aa1bc4cff0069f","subject":{"format":"email","email":"example.user@example.com"},"verified":true}`
	var add AddSubjectRequest
	if err := json.Unmarshal([]byte(in), &add); err != nil {
		t.Fatal(err)
	}
	if add.StreamID != "f67e39a0a4d34d56b3aa1bc4cff0069f" || add.Verified == nil || !*add.Verified ||
		!SubjectsEqual(add.Subject, EmailSubject{Email: "example.user@example.com"}) {
		t.Errorf("parsed %+v", add)
	}
	out, err := json.Marshal(add)
	if err != nil || string(out) != in {
		t.Errorf("Marshal = %s, %v", out, err)
	}

	var remove RemoveSubjectRequest
	if err := json.Unmarshal([]byte(`{"stream_id":"s","subject":{"format":"opaque","id":"x"}}`), &remove); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"subject":{"format":"opaque","id":"x"}}`,
		`{"stream_id":"s"}`,
		// SSF 1.0 §8.1.3.3 Figure 42 uses format "phone", which RFC 9493
		// does not define; it parses as a proprietary format, so check an
		// outright invalid subject instead.
		`{"stream_id":"s","subject":{"format":"email"}}`,
		`[]`,
	} {
		if err := json.Unmarshal([]byte(bad), &remove); err == nil {
			t.Errorf("Unmarshal(%s) succeeded", bad)
		}
	}
	if _, err := json.Marshal(RemoveSubjectRequest{StreamID: "s"}); err == nil {
		t.Error("marshaling a request without a subject succeeded")
	}
}
