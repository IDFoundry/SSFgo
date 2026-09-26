package transmitter

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestIsPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8":              true,
		"2606:4700:4700::1111": true,
		"127.0.0.1":            false,
		"::1":                  false,
		"10.1.2.3":             false,
		"172.16.0.1":           false,
		"192.168.1.1":          false,
		"169.254.169.254":      false, // cloud metadata
		"fe80::1":              false,
		"fc00::1":              false,
		"0.0.0.0":              false,
		"100.64.0.1":           false,
		"::ffff:127.0.0.1":     false, // IPv4-mapped loopback
		"224.0.0.1":            false,
		"198.18.0.1":           false,
		"2001:db8::1":          false,
	} {
		if got := isPublic(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isPublic(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestPushClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	_, err := NewPushClient(time.Second).Post(srv.URL, "application/secevent+jwt", nil)
	if !errors.Is(err, ErrNonPublicAddress) {
		t.Fatalf("POST to loopback = %v, want ErrNonPublicAddress", err)
	}
}

func TestPushClientDoesNotFollowRedirects(t *testing.T) {
	c := NewPushClient(time.Second)
	req := httptest.NewRequest("POST", "https://rx.example/events", nil)
	if err := c.CheckRedirect(req, []*http.Request{req}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("CheckRedirect = %v", err)
	}
}
