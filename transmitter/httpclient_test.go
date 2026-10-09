package transmitter

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
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

// A host in AllowedPrivatePushHosts may reach a private address, but
// nothing else non-public: loopback, link-local and the rest stay refused.
func TestPrivateAddressControl(t *testing.T) {
	for addr, want := range map[string]bool{
		"10.1.2.3:443":            true,
		"192.168.1.1:443":         true,
		"[fd00::1]:443":           true,
		"[::ffff:10.0.0.1]:443":   true,
		"8.8.8.8:443":             true,
		"127.0.0.1:443":           false,
		"[::1]:443":               false,
		"169.254.169.254:80":      false,
		"0.0.0.0:443":             false,
		"100.64.0.1:443":          false,
		"[fe80::1]:443":           false,
		"[64:ff9b::7f00:1]:443":   false, // NAT64 of loopback
		"[64:ff9b::a00:1]:443":    false, // NAT64 of 10.0.0.1: translated, not private
		"not-an-address:443":      false,
		"[2001:db8::1]:443":       false,
		"198.18.0.1:443":          false,
		"224.0.0.1:443":           false,
		"[::ffff:127.0.0.1]:443":  false,
		"[::ffff:169.254.0.1]:80": false,
	} {
		if err := privateAddressControl("tcp", addr, nil); (err == nil) != want {
			t.Errorf("privateAddressControl(%s) = %v, want allowed %v", addr, err, want)
		}
	}
}

// Naming a loopback host in AllowedPrivatePushHosts does not let a push
// reach it, and a wrapped transport keeps the address check beneath it.
func TestPushClientAdjustmentsKeepTheCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	wrapped := 0
	wrap := func(rt http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			wrapped++
			return rt.RoundTrip(req)
		})
	}
	c := newPushClient(time.Second, []string{"127.0.0.1", "LOCALHOST."}, wrap)
	for _, u := range []string{srv.URL, strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)} {
		if _, err := c.Post(u, "application/secevent+jwt", nil); !errors.Is(err, ErrNonPublicAddress) {
			t.Errorf("POST to %s = %v, want ErrNonPublicAddress", u, err)
		}
	}
	if wrapped != 2 {
		t.Errorf("PushTransport saw %d requests, want 2", wrapped)
	}
	req := httptest.NewRequest("POST", "https://rx.example/events", nil)
	if err := c.CheckRedirect(req, []*http.Request{req}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("CheckRedirect = %v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
