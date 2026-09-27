package receiver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/receiver"
)

// FuzzPushHandler sends arbitrary bodies to a Receiver's push endpoint —
// the input anyone who can reach it controls. Whatever arrives, the
// handler must answer 202 or an RFC 8935 400 error: never a 500, never a
// panic.
func FuzzPushHandler(f *testing.F) {
	e := newEnv(f)
	receiver.On(e.rx, func(context.Context, ssf.SET, caep.SessionRevoked) error { return nil })
	h := e.rx.PushHandler(receiver.PushOptions{})

	valid := sign(f, e, nil)
	parts := strings.Split(valid, ".")
	f.Add([]byte(valid))
	f.Add([]byte(""))
	f.Add([]byte("a.b.c"))
	f.Add([]byte(parts[0] + "." + parts[1] + "."))
	f.Add([]byte(parts[0] + ".e30." + parts[2]))
	f.Add([]byte("eyJhbGciOiJub25lIiwidHlwIjoic2VjZXZlbnQrand0In0.e30."))
	f.Add([]byte(strings.Repeat("A", 70*1024)))

	f.Fuzz(func(t *testing.T, body []byte) {
		req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/secevent+jwt")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusAccepted:
		case http.StatusBadRequest:
			var e struct {
				Err string `json:"err"`
			}
			if json.Unmarshal(rec.Body.Bytes(), &e) != nil || e.Err == "" {
				t.Fatalf("400 without an RFC 8935 error body: %s", rec.Body.Bytes())
			}
		default:
			t.Fatalf("push handler answered %d: %s", rec.Code, rec.Body.Bytes())
		}
	})
}

// FuzzPollResponse makes a (compromised or broken) Transmitter's poll
// endpoint return arbitrary bodies. The Receiver must return an error or a
// result, never panic, and never acknowledge a SET it did not verify.
func FuzzPollResponse(f *testing.F) {
	e := newEnv(f)
	var body atomic.Value
	body.Store([]byte("{}"))
	mux := http.NewServeMux()
	mux.HandleFunc("/fuzz-poll", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body.Load().([]byte))
	})
	mux.Handle("/", e.txSrv.Config.Handler)
	e.txSrv.Config.Handler = mux
	stream := ssf.StreamConfiguration{
		StreamID: "fuzz-stream",
		Delivery: ssf.Delivery{Method: ssf.DeliveryPoll, EndpointURL: e.txSrv.URL + "/fuzz-poll"},
	}
	var handled atomic.Int64
	receiver.On(e.rx, func(context.Context, ssf.SET, caep.SessionRevoked) error { handled.Add(1); return nil })

	valid := sign(f, e, nil)
	seed, _ := json.Marshal(map[string]any{"sets": map[string]string{"jti-1": valid}, "moreAvailable": true})
	f.Add(seed)
	f.Add([]byte(`{"sets":{}}`))
	f.Add([]byte(`{"sets":{"x":"a.b.c","y":""}}`))
	f.Add([]byte(`{"sets":null,"moreAvailable":"yes"}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, resp []byte) {
		body.Store(resp)
		before := handled.Load()
		res, err := e.rx.Poll(context.Background(), stream, receiver.PollOptions{})
		if err != nil {
			return
		}
		if n := handled.Load() - before; n > int64(res.Received) {
			t.Fatalf("handled %d SETs from a response holding %d", n, res.Received)
		}
	})
}
