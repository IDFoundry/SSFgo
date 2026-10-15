package storage

import (
	"context"
	"strconv"
	"time"
)

// ReplayStore remembers which SETs a Receiver has handled, so a SET
// delivered twice — which RFC 8935 §2 and RFC 8936 §2.4 both allow — is
// acknowledged without being handled twice.
//
// A SET is claimed while its handlers run and recorded as handled only
// once they succeed, so a copy that arrives meanwhile — at another
// instance, or after a crash — is never acknowledged on the strength of
// handling that may yet fail. A claim lasts until its lease ends: the
// holder renews it while handling, and a claim whose holder stopped
// renewing it, having crashed, can be taken.
//
// Leases are judged by each instance's clock, so instances sharing a
// store must keep their clocks well within the margin a holder renews
// ahead of its lease's end: SSFgo's Receiver renews every third of a
// one-minute lease, so seconds apart, not tens of seconds. An instance
// whose clock runs further ahead takes over a live claim, and the SET is
// handled twice; it is never lost.
//
// Every method is safe for concurrent use, and each is atomic.
type ReplayStore interface {
	// ClaimSET claims the SET identified by issuer and jti for holder — a
	// non-empty value unique to this handling — until leaseUntil. It reports
	// ClaimAcquired if there is no record of the SET, or only an expired
	// one, having recorded the claim; ClaimHeld if another claim's lease
	// has not ended; and ClaimDone if the SET is recorded as handled and
	// the record has not expired. Only ClaimAcquired changes anything.
	ClaimSET(ctx context.Context, issuer, jti, holder string, leaseUntil time.Time) (ClaimOutcome, error)
	// RenewClaim extends holder's claim on the SET to leaseUntil. It
	// reports false, changing nothing, if holder no longer holds it.
	RenewClaim(ctx context.Context, issuer, jti, holder string, leaseUntil time.Time) (held bool, err error)
	// CompleteSET records the SET as handled until the given time,
	// replacing any claim on it.
	CompleteSET(ctx context.Context, issuer, jti string, until time.Time) error
	// ReleaseClaim removes holder's claim on the SET, so that it is
	// handled when it is delivered again. It changes nothing if holder
	// does not hold it, and releasing an unknown SET is not an error.
	ReleaseClaim(ctx context.Context, issuer, jti, holder string) error
}

// ClaimOutcome is what ReplayStore.ClaimSET found.
type ClaimOutcome uint8

// The outcomes of ReplayStore.ClaimSET. The zero value is none of them.
const (
	// ClaimAcquired is a SET now claimed for the caller to handle.
	ClaimAcquired ClaimOutcome = iota + 1
	// ClaimHeld is a SET another holder is handling.
	ClaimHeld
	// ClaimDone is a SET already handled.
	ClaimDone
)

// String returns the outcome's name, such as "ClaimAcquired", or
// "ClaimOutcome(n)" for none of them.
func (o ClaimOutcome) String() string {
	switch o {
	case ClaimAcquired:
		return "ClaimAcquired"
	case ClaimHeld:
		return "ClaimHeld"
	case ClaimDone:
		return "ClaimDone"
	}
	return "ClaimOutcome(" + strconv.Itoa(int(o)) + ")"
}
