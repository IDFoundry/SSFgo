package receiver

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
)

// ErrSETInProgress is the error for a SET that another Receiver sharing
// the ReplayStore — another instance of the same deployment — is
// handling. The SET is not acknowledged, so the Transmitter delivers it
// again, and it is handled then if that handling failed. Hooks.SET reports
// it as SETFailed with this error.
var ErrSETInProgress = errors.New("receiver: the SET is being handled by another instance")

// ErrClaimLost is the cause with which a handler's context is cancelled
// when this Receiver can no longer be sure it holds the claim on the SET:
// a renewal found another instance had claimed it, or none got through
// for half a lease, so another instance may claim it before the lease
// ends. The handler should stop; the handling fails, and the SET is
// delivered again. A handler that finishes anyway still counts, but the
// SET may then be handled twice.
var ErrClaimLost = errors.New("receiver: the claim on the SET was lost while handling it")

// claimLease is how long a claim on a SET lasts unless renewed: after a
// crash, how long until a redelivery of the SET the crashed process was
// handling is handled. A claim is renewed every third of it while the
// handlers run, however long they take.
var claimLease = time.Minute

// heldClaim is one handling's claim on a SET: who holds it, and until
// when the store will keep it unrenewed.
type heldClaim struct {
	holder string
	until  time.Time
}

// claim claims set in the ReplayStore for one handling, returning the
// claim with what the store found.
func (r *Receiver) claim(ctx context.Context, set ssf.SET) (heldClaim, storage.ClaimOutcome, error) {
	c := heldClaim{holder: rand.Text(), until: time.Now().Add(claimLease)}
	var outcome storage.ClaimOutcome
	err := r.storeCall(ctx, set, "ClaimSET", func() (err error) {
		outcome, err = r.cfg.ReplayStore.ClaimSET(ctx, set.Issuer, set.JWTID, c.holder, c.until)
		return err
	})
	return c, outcome, err
}

// handleClaimed runs set's handlers under claim c, renewing it while they
// run, with a context cancelled with ErrClaimLost if the claim is lost.
// Once they succeed it records the SET as handled until the given time;
// if they fail it releases the claim, so a redelivery is handled.
func (r *Receiver) handleClaimed(ctx context.Context, set ssf.SET, c heldClaim, until time.Time) (err error) {
	hctx, lost := context.WithCancelCause(ctx)
	defer lost(nil)
	stop := r.renewWhileHandling(ctx, set, c, lost)
	done := false
	defer func() {
		stop()
		store := context.WithoutCancel(ctx)
		if done && err == nil {
			// The handlers ran: the SET is acknowledged even if this
			// fails, as refusing would have them run again. Its claim
			// then lasts until the lease ends.
			if cerr := r.storeCall(ctx, set, "CompleteSET", func() error {
				return r.cfg.ReplayStore.CompleteSET(store, set.Issuer, set.JWTID, until)
			}); cerr != nil {
				r.cfg.Logger.ErrorContext(ctx, "ssf receiver: record handled SET", "jti", set.JWTID, "error", cerr)
			}
			return
		}
		if rerr := r.storeCall(ctx, set, "ReleaseClaim", func() error {
			return r.cfg.ReplayStore.ReleaseClaim(store, set.Issuer, set.JWTID, c.holder)
		}); rerr != nil {
			r.cfg.Logger.ErrorContext(ctx, "ssf receiver: release failed SET", "jti", set.JWTID, "error", rerr)
		}
	}()
	err = r.dispatch(hctx, set)
	done = true
	if err != nil && errors.Is(context.Cause(hctx), ErrClaimLost) {
		err = fmt.Errorf("%w: %w", ErrClaimLost, err)
	}
	return err
}

// renewWhileHandling renews claim c on set every third of claimLease
// until the returned stop is called. It calls lost with ErrClaimLost once
// the claim is lost, or once renewals have failed for so long that half a
// lease or less remains: the handlers then have that long to stop before
// another instance can claim the SET.
func (r *Receiver) renewWhileHandling(ctx context.Context, set ssf.SET, c heldClaim, lost context.CancelCauseFunc) (stop func()) {
	quit := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		tick := time.NewTicker(claimLease / 3)
		defer tick.Stop()
		heldUntil := c.until
		for {
			select {
			case <-quit:
				return
			case <-tick.C:
			}
			next := time.Now().Add(claimLease)
			var held bool
			renewCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), claimLease/3)
			err := r.storeCall(ctx, set, "RenewClaim", func() (err error) {
				held, err = r.cfg.ReplayStore.RenewClaim(renewCtx, set.Issuer, set.JWTID, c.holder, next)
				return err
			})
			cancel()
			switch {
			case err == nil && held:
				heldUntil = next
			case err == nil:
				// The lease ended before a renewal got through, and the
				// SET was claimed again: it may be handled twice.
				r.cfg.Logger.WarnContext(ctx, "ssf receiver: lost claim on SET while handling it", "jti", set.JWTID)
				lost(ErrClaimLost)
				return
			case time.Until(heldUntil) <= claimLease/2:
				r.cfg.Logger.WarnContext(ctx, "ssf receiver: gave up claim on SET, renewals failing", "jti", set.JWTID, "error", err)
				lost(ErrClaimLost)
				return
			default:
				r.cfg.Logger.WarnContext(ctx, "ssf receiver: renew claim on SET", "jti", set.JWTID, "error", err)
			}
		}
	})
	return func() {
		close(quit)
		wg.Wait()
	}
}

// storeCall runs f, a call to the ReplayStore's method, turning a panic
// into an error: a bug in the application's store fails the SET's
// handling, which is retried, rather than the process.
func (r *Receiver) storeCall(ctx context.Context, set ssf.SET, method string, f func() error) (err error) {
	defer func() {
		if v := recover(); v != nil {
			r.cfg.Logger.ErrorContext(ctx, "ssf receiver: replay store panicked", "method", method, "jti", set.JWTID,
				"panic", v, "stack", string(debug.Stack()))
			err = fmt.Errorf("receiver: ReplayStore.%s panicked: %v", method, v)
		}
	}()
	return f()
}
