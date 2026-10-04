package transmitter

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// Access is what a Receiver may do through the stream management API.
type Access uint8

const (
	// AccessNone grants nothing: every request is refused with 403.
	AccessNone Access = iota
	// AccessRead allows reading stream configurations and statuses — the
	// CAEP Interoperability Profile's "ssf.read" scope (§2.7.3) — and
	// polling a poll stream, acknowledgements included: for poll delivery
	// it is the credential events are delivered on. Configurations read
	// with it omit the push delivery's authorization_header.
	AccessRead
	// AccessManage allows every operation — the "ssf.manage" scope.
	AccessManage
)

// AccessFromScopes maps OAuth scopes to Access using the scopes the CAEP
// Interoperability Profile §2.7.3 defines.
func AccessFromScopes(scopes []string) Access {
	access := AccessNone
	for _, s := range scopes {
		switch s {
		case "ssf.manage":
			return AccessManage
		case "ssf.read":
			access = AccessRead
		}
	}
	return access
}

// Receiver is the identity behind an authorized request.
type Receiver struct {
	// ID identifies the Receiver. Streams belong to the Receiver that
	// created them; no other Receiver can see or change them.
	ID string
	// Audience is the "aud" of streams this Receiver creates, and so of
	// every SET sent on them (SSF 1.0 §8.1.1).
	Audience []string
	// Access is what the Receiver may do.
	Access Access
}

// ErrInvalidToken is returned by an AuthorizeFunc for an access token
// that is unknown, expired or revoked. The Transmitter answers 401.
var ErrInvalidToken = errors.New("transmitter: invalid access token")

// AuthorizeFunc resolves an OAuth 2.0 bearer access token to the Receiver
// it was issued to (CAEP Interoperability Profile §2.7.2: the Transmitter
// is the resource server). It returns ErrInvalidToken, possibly wrapped,
// when the token is not valid; any other error is a server failure.
//
// The Transmitter extracts the token from the Authorization header only,
// never from the query string (RFC 6750 §2.1; CAEP Interop §2.7.2).
type AuthorizeFunc func(ctx context.Context, accessToken string) (Receiver, error)

// bearerToken returns the RFC 6750 §2.1 bearer token in r's Authorization
// header, or "" if there is none.
func bearerToken(r *http.Request) string {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}
