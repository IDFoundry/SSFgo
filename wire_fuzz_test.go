package ssf

import (
	"encoding/json"
	"maps"
	"slices"
	"testing"
)

// FuzzWireTypes decodes arbitrary JSON into every type with a custom
// decoder. Whatever decodes must re-encode and decode back to the same
// value.
func FuzzWireTypes(f *testing.F) {
	for _, s := range []string{
		`1615304991`, `1615304991.5`, `"1615304991"`, `null`, `-1`,
		`{"en":"x","es-410":"y"}`, `{}`, `"text"`,
		`"aud"`, `["a","b"]`, `[]`, `[1]`,
		`{"stream_id":"s","subject":{"format":"email","email":"a@b.example"},"verified":true}`,
		`{"stream_id":"s","subject":{"format":"complex","user":{"format":"opaque","id":"u"}}}`,
		`{"stream_id":"","subject":null}`,
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var d NumericDate
		if json.Unmarshal(data, &d) == nil {
			var back NumericDate
			roundTrip(t, "NumericDate", d, &back)
			if back.Unix() != d.Unix() {
				t.Fatalf("NumericDate %d came back as %d", d.Unix(), back.Unix())
			}
		}

		var lt LocalizedText
		if json.Unmarshal(data, &lt) == nil {
			var back LocalizedText
			roundTrip(t, "LocalizedText", lt, &back)
			if !maps.Equal(lt, back) {
				t.Fatalf("LocalizedText changed: %v -> %v", lt, back)
			}
		}

		var aud Audience
		if json.Unmarshal(data, &aud) == nil {
			var back Audience
			roundTrip(t, "Audience", aud, &back)
			if !slices.Equal(aud, back) {
				t.Fatalf("Audience changed: %v -> %v", aud, back)
			}
		}

		var add AddSubjectRequest
		if json.Unmarshal(data, &add) == nil {
			var back AddSubjectRequest
			roundTrip(t, "AddSubjectRequest", add, &back)
			if back.StreamID != add.StreamID || !SubjectsEqual(back.Subject, add.Subject) ||
				(back.Verified == nil) != (add.Verified == nil) || (add.Verified != nil && *back.Verified != *add.Verified) {
				t.Fatalf("AddSubjectRequest changed: %+v -> %+v", add, back)
			}
		}

		var remove RemoveSubjectRequest
		if json.Unmarshal(data, &remove) == nil {
			var back RemoveSubjectRequest
			roundTrip(t, "RemoveSubjectRequest", remove, &back)
			if back.StreamID != remove.StreamID || !SubjectsEqual(back.Subject, remove.Subject) {
				t.Fatalf("RemoveSubjectRequest changed: %+v -> %+v", remove, back)
			}
		}

		// Types without custom decoders must still survive a round trip.
		var sc StreamConfiguration
		if json.Unmarshal(data, &sc) == nil {
			var back StreamConfiguration
			roundTrip(t, "StreamConfiguration", sc, &back)
		}
	})
}

func roundTrip(t *testing.T, name string, v any, into any) {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s decoded but does not re-encode: %v", name, err)
	}
	if err := json.Unmarshal(encoded, into); err != nil {
		t.Fatalf("%s re-encoded as %s, which does not decode: %v", name, encoded, err)
	}
}
