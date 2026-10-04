package receiver

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// maxRedirects matches net/http's own default limit.
const maxRedirects = 10

// httpsOnlyRedirects returns a copy of c that refuses to follow a redirect
// to anything but https, or one that would carry credentials to another
// origin, then applies c's own redirect policy.
//
// net/http copies the Authorization header to a redirect target with the
// same host name regardless of scheme or port, so an https→http redirect
// would send the Receiver's access token, or its client credentials, in
// cleartext. Metadata and JWKS fetched over a redirected http connection
// could likewise be substituted by anyone on the path.
//
// A 307 or 308 also replays the request body, which can hold a client
// secret, a client assertion or the push endpoint's authorization_header,
// and net/http keeps Authorization for a subdomain. So a request with a
// body or an Authorization header follows a redirect only within its own
// origin; unauthenticated GETs, such as for metadata and JWKS, may still
// be redirected to another https host.
func httpsOnlyRedirects(c *http.Client) *http.Client {
	guarded := *c
	previous := c.CheckRedirect
	guarded.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("receiver: refusing to follow a redirect to non-https %s", req.URL.Redacted())
		}
		if first := via[0]; carriesCredentials(first) && origin(req.URL) != origin(first.URL) {
			return fmt.Errorf("receiver: refusing to follow a redirect that would carry credentials from %s to %s", origin(first.URL), origin(req.URL))
		}
		if previous != nil {
			return previous(req, via)
		}
		if len(via) >= maxRedirects {
			return errors.New("receiver: stopped after too many redirects")
		}
		return nil
	}
	return &guarded
}

// carriesCredentials reports whether req sends anything a redirect must
// not take elsewhere: an Authorization header, or a body.
func carriesCredentials(req *http.Request) bool {
	return req.Header.Get("Authorization") != "" ||
		(req.Method != http.MethodGet && req.Method != http.MethodHead)
}

// origin is u's scheme, host and port, with the default port made explicit.
func origin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
	}
	return u.Scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}
