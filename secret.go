package ssf

import (
	"errors"
	"log/slog"
)

// ErrSecretSerialization is returned by Secret.MarshalText, so a Secret
// is never serialized — into a log line, a JSON body, a debug dump — by
// code that does not know it holds one.
var ErrSecretSerialization = errors.New("ssf: secret values cannot be marshaled")

// Secret holds a credential — a client secret, a push Authorization
// header — that must not reach a log, an error message or a debug dump by
// accident. String, GoString, LogValue and MarshalText all withhold it;
// Reveal is the only way to read it, at the point it is sent.
//
// A Secret can be decoded, and compared with ==. A wire type that must
// carry one, such as Delivery, reveals it in its own MarshalJSON.
type Secret struct {
	value string
}

// NewSecret returns value as a Secret.
func NewSecret(value string) Secret { return Secret{value: value} }

// Reveal returns the secret value.
func (s Secret) Reveal() string { return s.value }

// IsZero reports whether s holds no value.
func (s Secret) IsZero() bool { return s.value == "" }

// String returns a fixed placeholder, never the value.
func (s Secret) String() string { return "[REDACTED]" }

// GoString implements fmt.GoStringer, so %#v withholds the value too.
func (s Secret) GoString() string { return "ssf.Secret([REDACTED])" }

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
	s.value = string(text)
	return nil
}
