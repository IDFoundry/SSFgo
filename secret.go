package ssf

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"unique"
)

// ErrSecretSerialization is returned by Secret.MarshalText, so a Secret
// is never serialized — into a log line, a JSON body, a debug dump — by
// code that does not know it holds one.
var ErrSecretSerialization = errors.New("ssf: secret values cannot be marshaled")

// Secret holds a credential — a client secret, a push Authorization
// header — that must not reach a log, an error message or a debug dump by
// accident. Every fmt verb, LogValue and MarshalText withhold it, as does
// fmt printing a struct that holds a Secret in an unexported field; Reveal
// is the only way to read it, at the point it is sent.
//
// A Secret can be decoded, and compared with ==. A wire type that must
// carry one, such as Delivery, reveals it in its own MarshalJSON.
type Secret struct {
	// value is held by handle, not as a string: fmt prints an unexported
	// field by reflection, without calling its methods, and would print a
	// string; it prints a handle's pointer. Handles of equal strings are
	// equal, so == still compares values.
	value unique.Handle[string]
}

// NewSecret returns value as a Secret.
func NewSecret(value string) Secret {
	if value == "" {
		return Secret{}
	}
	return Secret{value: unique.Make(value)}
}

// Reveal returns the secret value.
func (s Secret) Reveal() string {
	if s.IsZero() {
		return ""
	}
	return s.value.Value()
}

// IsZero reports whether s holds no value.
func (s Secret) IsZero() bool { return s == Secret{} }

// String returns a fixed placeholder, never the value.
func (s Secret) String() string { return "[REDACTED]" }

// GoString implements fmt.GoStringer, so %#v withholds the value too.
func (s Secret) GoString() string { return "ssf.Secret([REDACTED])" }

// Format implements fmt.Formatter, so every verb — %d and %x included —
// prints the placeholder, and %#v the GoString.
func (s Secret) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, s.GoString())
		return
	}
	_, _ = io.WriteString(f, s.String())
}

// LogValue implements slog.LogValuer, so a Secret logged as an attribute
// is withheld.
func (s Secret) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalText always fails, so a Secret in a struct cannot be serialized
// by encoding/json or encoding/xml without a MarshalJSON that reveals it
// on purpose.
func (s Secret) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// UnmarshalText implements encoding.TextUnmarshaler: a Secret can be read
// from the wire.
func (s *Secret) UnmarshalText(text []byte) error {
	*s = NewSecret(string(text))
	return nil
}
