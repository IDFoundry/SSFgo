package transmitter

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrNonPublicAddress is returned when a push delivery would connect to a
// loopback, private, link-local or otherwise non-public address.
var ErrNonPublicAddress = errors.New("transmitter: refusing to connect to a non-public address")

// NewPushClient returns the HTTP client the Transmitter uses for push
// delivery when Config.HTTPClient is nil. Push endpoints are chosen by
// Receivers, so the client is built to limit server-side request forgery:
//
//   - it connects only to public unicast addresses, checked on the address
//     actually dialled, so a hostname that resolves — or later re-resolves
//     — to an internal address is refused;
//   - it does not follow redirects, which could otherwise lead anywhere;
//   - it gives up after timeout.
//
// Deployments that push to Receivers on a private network supply their own
// client through Config.HTTPClient.
func NewPushClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			if !isPublic(ip) {
				return fmt.Errorf("%w: %s", ErrNonPublicAddress, ip)
			}
			return nil
		},
	}
	transport := &http.Transport{
		Proxy:                 nil, // a proxy would hide the address actually reached
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// isPublic reports whether ip is a globally routable unicast address.
func isPublic(ip netip.Addr) bool {
	ip = ip.Unmap()
	switch {
	case !ip.IsValid(), ip.IsUnspecified(), ip.IsLoopback(), ip.IsPrivate(),
		ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast():
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// nonPublicPrefixes are special-purpose ranges netip's predicates do not
// cover (RFC 6890 and successors).
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
}
