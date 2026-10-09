package transmitter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
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
// Config.PushTransport and Config.AllowedPrivatePushHosts adjust the
// client a Transmitter builds without giving these up.
func NewPushClient(timeout time.Duration) *http.Client {
	return newPushClient(timeout, nil, nil)
}

// newPushClient is NewPushClient letting the hosts in allowedPrivate reach
// private addresses, and with its transport wrapped by wrap, if not nil.
func newPushClient(timeout time.Duration, allowedPrivate []string, wrap func(http.RoundTripper) http.RoundTripper) *http.Client {
	public := &net.Dialer{Timeout: 10 * time.Second, Control: PublicAddressControl}
	private := &net.Dialer{Timeout: 10 * time.Second, Control: privateAddressControl}
	allowed := map[string]bool{}
	for _, h := range allowedPrivate {
		allowed[normalHost(h)] = true
	}
	transport := &http.Transport{
		Proxy: nil, // a proxy would hide the address actually reached
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err == nil && allowed[normalHost(host)] {
				return private.DialContext(ctx, network, address)
			}
			return public.DialContext(ctx, network, address)
		},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	var rt http.RoundTripper = transport
	if wrap != nil {
		rt = wrap(transport)
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: rt,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func normalHost(h string) string { return strings.TrimSuffix(strings.ToLower(h), ".") }

// PublicAddressControl is a net.Dialer Control function that refuses, with
// ErrNonPublicAddress, to connect to anything but a public unicast address.
// It sees the address actually dialled, after name resolution, so DNS
// rebinding cannot get around it. NewPushClient uses it.
func PublicAddressControl(_, address string, _ syscall.RawConn) error {
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
}

// privateAddressControl is PublicAddressControl also admitting private
// addresses (RFC 1918, IPv6 unique local), for AllowedPrivatePushHosts.
func privateAddressControl(network, address string, c syscall.RawConn) error {
	err := PublicAddressControl(network, address, c)
	if !errors.Is(err, ErrNonPublicAddress) {
		return err
	}
	host, _, _ := net.SplitHostPort(address) // parsed by PublicAddressControl
	if ip, perr := netip.ParseAddr(host); perr == nil && ip.Unmap().IsPrivate() {
		return nil
	}
	return err
}

// isPublic reports whether ip is a globally routable unicast address.
func isPublic(ip netip.Addr) bool {
	ip = ip.Unmap()
	// NAT64 (RFC 6052) addresses reach the IPv4 address in their last 32
	// bits through a translator; judge that address instead.
	if nat64WellKnown.Contains(ip) {
		b := ip.As16()
		return isPublic(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	}
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
	netip.MustParsePrefix("64:ff9b::/32"),    // the rest of NAT64's range, beyond the well-known /96 judged above
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("::/96"),           // deprecated IPv4-compatible (RFC 4291 §2.5.5.1)
	netip.MustParsePrefix("2002::/16"),       // 6to4: embeds an IPv4 address
	netip.MustParsePrefix("2001::/32"),       // Teredo: embeds an IPv4 address
	netip.MustParsePrefix("::ffff:0:0:0/96"), // IPv4-translated (RFC 6145): embeds an IPv4 address
	netip.MustParsePrefix("fec0::/10"),       // deprecated site-local (RFC 3879)
	netip.MustParsePrefix("100::/64"),        // discard-only (RFC 6666)
	netip.MustParsePrefix("2001:2::/48"),     // benchmarking (RFC 5180)
}

// nat64WellKnown is the NAT64 well-known prefix (RFC 6052 §2.1).
var nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
