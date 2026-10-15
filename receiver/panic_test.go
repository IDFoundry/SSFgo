package receiver_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

// A panicking handler fails the SET's handling — the Transmitter delivers
// it again — rather than escaping the library: under RunPoller it would
// otherwise end the process.
func TestHandlerPanicRecovered(t *testing.T) {
	e := newEnv(t)
	var panics atomic.Int32
	receiver.On(e.rx, func(context.Context, ssf.SET, caep.SessionRevoked) error {
		if panics.Add(-1) >= 0 {
			panic("handler bug")
		}
		return nil
	})
	panics.Store(1)
	h := e.rx.PushHandler(receiver.PushOptions{})
	tok := sign(t, e, nil)
	if got := push(t, h, "", tok); got.status != http.StatusInternalServerError {
		t.Errorf("panicking handler: push = %+v; want 500", got)
	}
	// The SET was not recorded as handled: its redelivery is handled.
	if got := push(t, h, "", tok); got.status != http.StatusAccepted {
		t.Errorf("redelivery: push = %+v; want 202", got)
	}
}

// replayPanics panics in the named ReplayStore method, as a buggy store
// might.
type replayPanics struct {
	storage.ReplayStore
	method string
}

func (s replayPanics) ClaimSET(ctx context.Context, iss, jti, holder string, until time.Time) (storage.ClaimOutcome, error) {
	s.maybePanic("ClaimSET")
	return s.ReplayStore.ClaimSET(ctx, iss, jti, holder, until)
}

func (s replayPanics) RenewClaim(ctx context.Context, iss, jti, holder string, until time.Time) (bool, error) {
	s.maybePanic("RenewClaim")
	return s.ReplayStore.RenewClaim(ctx, iss, jti, holder, until)
}

func (s replayPanics) CompleteSET(ctx context.Context, iss, jti string, until time.Time) error {
	s.maybePanic("CompleteSET")
	return s.ReplayStore.CompleteSET(ctx, iss, jti, until)
}

func (s replayPanics) ReleaseClaim(ctx context.Context, iss, jti, holder string) error {
	s.maybePanic("ReleaseClaim")
	return s.ReplayStore.ReleaseClaim(ctx, iss, jti, holder)
}

func (s replayPanics) maybePanic(method string) {
	if s.method == method {
		panic("store bug in " + method)
	}
}

// A panicking ReplayStore fails the SET's handling, or is logged, rather
// than escaping the library — on the polling path, or on the goroutine
// that renews a claim, it would otherwise end the process.
func TestReplayStorePanicRecovered(t *testing.T) {
	receiver.SetClaimLease(t, 60*time.Millisecond)
	for method, want := range map[string]int{
		"ClaimSET":     http.StatusInternalServerError,
		"RenewClaim":   http.StatusInternalServerError, // renewals keep failing, so the claim is lost
		"CompleteSET":  http.StatusAccepted,            // the handlers ran: the SET is acknowledged
		"ReleaseClaim": http.StatusInternalServerError, // the handler failed
	} {
		t.Run(method, func(t *testing.T) {
			e := newEnv(t, func(c *receiver.Config) { c.ReplayStore = replayPanics{memstore.NewReplayStore(), method} })
			receiver.On(e.rx, func(ctx context.Context, _ ssf.SET, _ caep.SessionRevoked) error {
				switch method {
				case "RenewClaim":
					<-ctx.Done()
					return ctx.Err()
				case "ReleaseClaim":
					return errors.New("handler failed")
				}
				return nil
			})
			if got := push(t, e.rx.PushHandler(receiver.PushOptions{}), "", sign(t, e, nil)); got.status != want {
				t.Errorf("push = %d, want %d", got.status, want)
			}
			if method == "ClaimSET" {
				ack, errs := receiver.ProcessPolled(e.rx, "stream", map[string]string{"p": sign(t, e, func(s *ssf.SET) { s.JWTID = "p" })})
				if len(ack) != 0 || len(errs) != 0 {
					t.Errorf("polled: ack %v, errors %v; want neither, so the SET is delivered again", ack, errs)
				}
			}
		})
	}
}

type panickingTokens struct{}

func (panickingTokens) Token(context.Context) (string, error) { panic("token source bug") }

// A panicking TokenSource fails the request that needed a token — a poll,
// say, under RunPoller — rather than the process.
func TestTokenSourcePanicRecovered(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	stream, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := e.cfg
	cfg.TokenSource = panickingTokens{}
	rx, err := receiver.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rx.Poll(ctx, stream, receiver.PollOptions{}); err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Errorf("Poll = %v, want an error saying the TokenSource panicked", err)
	}
}
