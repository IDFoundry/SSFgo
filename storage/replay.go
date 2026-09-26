package storage

import (
	"context"
	"time"
)

// ReplayStore remembers which SETs a Receiver has processed, so a SET
// delivered twice — which RFC 8935 §2 and RFC 8936 §2.4 both allow — is
// acknowledged without being handled twice.
//
// Every method is safe for concurrent use.
type ReplayStore interface {
	// MarkSET records the SET identified by issuer and jti as processed
	// until the given time. It reports false, without changing anything,
	// if the SET is already recorded and not yet expired. The check and
	// the record must be atomic.
	MarkSET(ctx context.Context, issuer, jti string, until time.Time) (fresh bool, err error)
	// ForgetSET removes a record, so a SET whose handling failed can be
	// processed when it is delivered again. Forgetting an unknown SET is
	// not an error.
	ForgetSET(ctx context.Context, issuer, jti string) error
}
