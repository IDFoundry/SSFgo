package receiver

import (
	"errors"
	"fmt"
	"net/http"
)

// maxRedirects matches net/http's own default limit.
const maxRedirects = 10

// httpsOnlyRedirects returns a copy of c that refuses to follow a redirect
// to anything but https, then applies c's own redirect policy.
//
// net/http copies the Authorization header to a redirect target with the
// same host name regardless of scheme or port, so an https→http redirect
// would send the Receiver's access token, or its client credentials, in
// cleartext. Metadata and JWKS fetched over a redirected http connection
// could likewise be substituted by anyone on the path.
func httpsOnlyRedirects(c *http.Client) *http.Client {
	guarded := *c
	previous := c.CheckRedirect
	guarded.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("receiver: refusing to follow a redirect to non-https %s", req.URL.Redacted())
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
