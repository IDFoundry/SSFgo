package peertext

import (
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"invalid_key: no key k1":    "invalid_key: no key k1",
		"line\nforged: entry":       "line?forged: entry",
		"\x1b[31mred\u202eevil":     "?[31mred???evil",
		strings.Repeat("x", 40_000): strings.Repeat("x", 61) + "...",
	} {
		if got := Clean(in, 64); got != want {
			t.Errorf("Clean(%.20q) = %q, want %q", in, got, want)
		}
	}
}
