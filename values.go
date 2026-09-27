package ssf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"
)

// NumericDate is a JSON number of seconds since the Unix epoch
// (RFC 7519 §2), as used by "iat" and CAEP's "event_timestamp".
//
// The zero value means "absent": use it with the `omitzero` struct tag.
// Encoding truncates to whole seconds; decoding accepts fractional
// seconds.
type NumericDate struct {
	time.Time
}

// NewNumericDate returns t as a NumericDate truncated to whole seconds.
func NewNumericDate(t time.Time) NumericDate {
	return NumericDate{t.Truncate(time.Second)}
}

// MarshalJSON implements json.Marshaler.
func (d NumericDate) MarshalJSON() ([]byte, error) {
	if d.IsZero() {
		return nil, fmt.Errorf("ssf: cannot encode a zero NumericDate")
	}
	return strconv.AppendInt(nil, d.Unix(), 10), nil
}

// UnmarshalJSON implements json.Unmarshaler. It rejects anything but a
// JSON number, including a numeric string.
func (d *NumericDate) UnmarshalJSON(data []byte) error {
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&n); err != nil {
		return fmt.Errorf("ssf: NumericDate must be a JSON number")
	}
	if len(data) > 0 && data[0] == '"' {
		return fmt.Errorf("ssf: NumericDate must be a JSON number, not a string")
	}
	f, err := n.Float64()
	// Below one second the value would encode as 0 — "absent" — and could
	// not be decoded again.
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 1 || f > maxNumericDate {
		return fmt.Errorf("ssf: NumericDate %s is out of range", n)
	}
	sec, frac := math.Modf(f)
	d.Time = time.Unix(int64(sec), int64(frac*1e9)).UTC()
	return nil
}

// maxNumericDate is 9999-12-31T23:59:59Z. Later values are almost
// certainly milliseconds sent by mistake, and rejecting them keeps the
// conversion to time.Time exact.
const maxNumericDate = 253402300799

// LocalizedText is a JSON object mapping BCP 47 language tags (RFC 5646)
// to human-readable text, as used by CAEP's "reason_admin" and
// "reason_user" (CAEP 1.0 §2).
//
// A nil or empty LocalizedText means "absent": use it with the `omitempty`
// struct tag. When present it must hold at least one entry.
type LocalizedText map[string]string

// Validate reports whether t is non-empty and every key is a plausible
// language tag. The tag grammar is not checked in full.
func (t LocalizedText) Validate() error {
	if len(t) == 0 {
		return fmt.Errorf("ssf: localized text must contain at least one language tag")
	}
	for tag := range t {
		if !plausibleLanguageTag(tag) {
			return fmt.Errorf("ssf: %q is not a BCP 47 language tag", tag)
		}
	}
	return nil
}

// plausibleLanguageTag accepts hyphen-separated alphanumeric subtags of 1
// to 8 characters, the outer shape every RFC 5646 tag has.
func plausibleLanguageTag(tag string) bool {
	n := 0
	for i := 0; i <= len(tag); i++ {
		if i == len(tag) || tag[i] == '-' {
			if n == 0 || n > 8 {
				return false
			}
			n = 0
			continue
		}
		if !isAlphanumeric(tag[i]) {
			return false
		}
		n++
	}
	return true
}

func isAlphanumeric(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

// UnmarshalJSON implements json.Unmarshaler. It rejects anything but a
// JSON object of strings — CAEP 1.0 §2 does not permit a bare string.
func (t *LocalizedText) UnmarshalJSON(data []byte) error {
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil || m == nil {
		return fmt.Errorf("ssf: localized text must be a JSON object of strings keyed by language tag")
	}
	*t = m
	return nil
}
