package receiver

import (
	"context"
	"crypto/rand"
	"errors"
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

// claimLease is how long a claim on a SET lasts unless renewed: after a
// crash, how long until a redelivery of the SET the crashed process was
// handling is handled. A claim is renewed every third of it while the
// handlers run, however long they take.
var claimLease = time.Minute

// claim claims set in the ReplayStore for one handling, returning the
// holder that identifies it with what the store found.
func (r *Receiver) claim(ctx context.Context, set ssf.SET) (string, storage.ClaimOutcome, error) {
	holder := rand.Text()
	outcome, err := r.cfg.ReplayStore.ClaimSET(ctx, set.Issuer, set.JWTID, holder, time.Now().Add(claimLease))
	return holder, outcome, err
}

// handleClaimed runs set's handlers under holder's claim, renewing it
// while they run. Once they succeed it records the SET as handled until
// the given time; if they fail or panic — a panic is re-raised — it
// releases the claim, so a redelivery is handled.
func (r *Receiver) handleClaimed(ctx context.Context, set ssf.SET, holder string, until time.Time) (err error) {
	stop := r.renewWhileHandling(ctx, set, holder)
	done := false
	defer func() {
		stop()
		store := context.WithoutCancel(ctx)
		if done && err == nil {
			// The handlers ran: the SET is acknowledged even if this
			// fails, as refusing would have them run again. Its claim
			// then lasts until the lease ends.
			if cerr := r.cfg.ReplayStore.CompleteSET(store, set.Issuer, set.JWTID, until); cerr != nil {
				r.cfg.Logger.ErrorContext(ctx, "ssf receiver: record handled SET", "jti", set.JWTID, "error", cerr)
			}
			return
		}
		if rerr := r.cfg.ReplayStore.ReleaseClaim(store, set.Issuer, set.JWTID, holder); rerr != nil {
			r.cfg.Logger.ErrorContext(ctx, "ssf receiver: release failed SET", "jti", set.JWTID, "error", rerr)
		}
	}()
	err = r.dispatch(ctx, set)
	done = true
	return err
}

// renewWhileHandling renews holder's claim on set every third of
// claimLease until the returned stop is called.
func (r *Receiver) renewWhileHandling(ctx context.Context, set ssf.SET, holder string) (stop func()) {
	quit := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		tick := time.NewTicker(claimLease / 3)
		defer tick.Stop()
		for {
			select {
			case <-quit:
				return
			case <-tick.C:
			}
			renewCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), claimLease/3)
			held, err := r.cfg.ReplayStore.RenewClaim(renewCtx, set.Issuer, set.JWTID, holder, time.Now().Add(claimLease))
			cancel()
			switch {
			case err != nil:
				r.cfg.Logger.WarnContext(ctx, "ssf receiver: renew claim on SET", "jti", set.JWTID, "error", err)
			case !held:
				// The lease ended before a renewal got through, and the
				// SET was claimed again: it may be handled twice.
				r.cfg.Logger.WarnContext(ctx, "ssf receiver: lost claim on SET while handling it", "jti", set.JWTID)
				return
			}
		}
	})
	return func() {
		close(quit)
		wg.Wait()
	}
}
