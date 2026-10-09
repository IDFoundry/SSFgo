package storage

import (
	"context"
	"time"
)

// RevocationKind says what a RevocationKey names.
type RevocationKind string

// The things a revocation can cover.
const (
	// RevokeUser covers every token of a user: Issuer is the identity
	// provider, Value the user's subject identifier at it.
	RevokeUser RevocationKind = "user"
	// RevokeSession covers the tokens of one session: Issuer is the
	// identity provider, Value the session's identifier ("sid").
	RevokeSession RevocationKind = "session"
	// RevokeEmail covers every token of a user known by email address:
	// Issuer is the identity provider, Value the address with ASCII
	// letters in lowercase.
	RevokeEmail RevocationKind = "email"
)

// RevocationKey identifies whose tokens a revocation covers.
type RevocationKey struct {
	// Kind is what the key names: a user, a session or an email address.
	Kind RevocationKind
	// Issuer is the identity provider the Value belongs to.
	Issuer string
	// Value identifies the user, session or address at Issuer, as Kind
	// describes.
	Value string
}

// RevocationStore records that the tokens a key covers, issued at or
// before some time, are revoked. A Receiver records revocations as
// security events arrive; an application checks its tokens against them.
type RevocationStore interface {
	// Revoke records that key's tokens issued at or before at are revoked,
	// until expires, when the record may be dropped. A key already
	// revoked keeps the later of the two times, and the later expiry.
	Revoke(ctx context.Context, key RevocationKey, at, expires time.Time) error
	// RevokedAt returns the time before which key's tokens are revoked,
	// and whether a record that has not expired by now exists.
	RevokedAt(ctx context.Context, key RevocationKey, now time.Time) (at time.Time, ok bool, err error)
}
