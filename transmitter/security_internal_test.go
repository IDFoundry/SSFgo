package transmitter

import (
	"net/netip"
	"testing"
)

// Addresses that embed an IPv4 address must not smuggle an internal one
// past the push client.
func TestEmbeddedIPv4(t *testing.T) {
	for addr, want := range map[string]bool{
		"64:ff9b::7f00:1":    false, // NAT64 to 127.0.0.1
		"64:ff9b::a9fe:a9fe": false, // NAT64 to 169.254.169.254
		"64:ff9b::a00:1":     false, // NAT64 to 10.0.0.1
		"64:ff9b::808:808":   true,  // NAT64 to 8.8.8.8 stays usable
		"::7f00:1":           false, // IPv4-compatible
		"2002:7f00:1::1":     false, // 6to4
		"2001:0:7f00:1::1":   false, // Teredo
	} {
		if got := isPublic(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isPublic(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestValidHeaderValue(t *testing.T) {
	for v, want := range map[string]bool{
		"Bearer abc":              true,
		"Bearer a\tb":             true,
		"":                        true,
		"Bearer abc\r\nX-Evil: 1": false,
		"Bearer \x00":             false,
		"Bearer \x7f":             false,
	} {
		if got := validHeaderValue(v); got != want {
			t.Errorf("validHeaderValue(%q) = %v, want %v", v, got, want)
		}
	}
	if validHeaderValue(string(make([]byte, maxHeaderBytes+1))) {
		t.Error("an oversized header value was accepted")
	}
}
