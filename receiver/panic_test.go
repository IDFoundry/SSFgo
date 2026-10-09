package receiver_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
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
