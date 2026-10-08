package receiver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/setcodec"
	"github.com/idfoundry/ssfgo/receiver"
)

// perStreamTransmitter makes the test Transmitter give each stream the
// audience "<audience>/<stream_id>", as some Transmitters do. It returns
// the number of single-stream reads, and a switch that makes them fail.
func perStreamTransmitter(t *testing.T, e *env) (reads *atomic.Int32, failReads *atomic.Bool) {
	t.Helper()
	reads, failReads = new(atomic.Int32), new(atomic.Bool)
	tx := e.txSrv.Config.Handler
	e.txSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Has("stream_id") {
			reads.Add(1)
			if failReads.Load() {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		rec := httptest.NewRecorder()
		tx.ServeHTTP(rec, r)
		body := rec.Body.Bytes()
		var stream map[string]any
		if json.Unmarshal(body, &stream) == nil && stream["stream_id"] != nil {
			stream["aud"] = audience + "/" + stream["stream_id"].(string)
			body, _ = json.Marshal(stream)
		}
		for k, v := range rec.Header() {
			if k != "Content-Length" {
				w.Header()[k] = v
			}
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(body)
	})
	return reads, failReads
}

func perStream(c *receiver.Config) { c.AudiencePerStream = true }

func TestAudiencePerStreamOffByDefault(t *testing.T) {
	e := newEnv(t)
	perStreamTransmitter(t, e)
	c, err := e.rx.CreateStream(context.Background(), receiver.StreamRequest{})
	if !errors.Is(err, receiver.ErrAudienceMismatch) {
		t.Fatalf("CreateStream = %v; want ErrAudienceMismatch", err)
	}
	got := push(t, e.rx.PushHandler(receiver.PushOptions{}), "", sign(t, e, func(s *ssf.SET) {
		s.Audience = []string{audience + "/" + c.StreamID}
	}))
	if got.status != http.StatusBadRequest || got.err != setcodec.CodeInvalidAudience {
		t.Errorf("push = %+v; want 400 %s", got, setcodec.CodeInvalidAudience)
	}
}

func TestAudiencePerStream(t *testing.T) {
	e := newEnv(t, perStream)
	reads, _ := perStreamTransmitter(t, e)
	ctx := context.Background()
	c, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	var rec recorder
	rec.install(e.rx)
	h := e.rx.PushHandler(receiver.PushOptions{})
	for name, aud := range map[string][]string{
		"the stream's audience":  {audience + "/" + c.StreamID},
		"the Receiver's own too": {audience},
		"among others":           {"https://other.example", audience + "/" + c.StreamID},
	} {
		if got := push(t, h, "", sign(t, e, func(s *ssf.SET) { s.Audience = aud })); got.status != http.StatusAccepted {
			t.Errorf("%s: push = %+v; want 202", name, got)
		}
	}
	if n := reads.Load(); n != 0 {
		t.Errorf("the Transmitter was asked about a stream the Receiver created %d times", n)
	}

	for name, aud := range map[string]string{
		"a nested path":        audience + "/" + c.StreamID + "/x",
		"an empty stream ID":   audience + "/",
		"another prefix":       "https://rx.example.org/" + c.StreamID,
		"a stream not its own": audience + "/app",
	} {
		got := push(t, h, "", sign(t, e, func(s *ssf.SET) { s.Audience = []string{aud} }))
		if got.status != http.StatusBadRequest || got.err != setcodec.CodeInvalidAudience {
			t.Errorf("%s: push = %+v; want 400 %s", name, got, setcodec.CodeInvalidAudience)
		}
	}

	// A deleted stream's audience is no longer accepted.
	if err := e.rx.DeleteStream(ctx, c.StreamID); err != nil {
		t.Fatal(err)
	}
	got := push(t, h, "", sign(t, e, func(s *ssf.SET) { s.Audience = []string{audience + "/" + c.StreamID} }))
	if got.status != http.StatusBadRequest || got.err != setcodec.CodeInvalidAudience {
		t.Errorf("deleted stream: push = %+v; want 400 %s", got, setcodec.CodeInvalidAudience)
	}
}

// Another Receiver instance, which has not seen the stream, asks the
// Transmitter about it once, and accepts its SETs.
func TestAudiencePerStreamLooksUpUnknownStream(t *testing.T) {
	e := newEnv(t, perStream)
	reads, failReads := perStreamTransmitter(t, e)
	ctx := context.Background()
	c, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := receiver.New(ctx, e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := other.PushHandler(receiver.PushOptions{})
	signed := func() string {
		return sign(t, e, func(s *ssf.SET) { s.Audience = []string{audience + "/" + c.StreamID} })
	}

	// The Transmitter cannot answer: the SET is to be delivered again,
	// not rejected.
	failReads.Store(true)
	if got := push(t, h, "", signed()); got.status != http.StatusInternalServerError {
		t.Errorf("lookup failing: push = %+v; want 500", got)
	}
	failReads.Store(false)
	reads.Store(0)
	for range 3 {
		if got := push(t, h, "", signed()); got.status != http.StatusAccepted {
			t.Errorf("push = %+v; want 202", got)
		}
	}
	if n := reads.Load(); n != 1 {
		t.Errorf("the Transmitter was asked %d times; want once", n)
	}
}

// SETs naming a stream that is not the Receiver's are rejected, and the
// Transmitter is asked about that stream at most once a minute.
func TestAudiencePerStreamLookupRateLimited(t *testing.T) {
	e := newEnv(t, perStream)
	reads, _ := perStreamTransmitter(t, e)
	h := e.rx.PushHandler(receiver.PushOptions{})
	for range 5 {
		got := push(t, h, "", sign(t, e, func(s *ssf.SET) { s.Audience = []string{audience + "/app"} }))
		if got.status != http.StatusBadRequest || got.err != setcodec.CodeInvalidAudience {
			t.Errorf("push = %+v; want 400 %s", got, setcodec.CodeInvalidAudience)
		}
	}
	if n := reads.Load(); n != 1 {
		t.Errorf("the Transmitter was asked %d times; want once", n)
	}
}

func TestAudiencePerStreamConfig(t *testing.T) {
	cfg := newEnv(t).cfg
	cfg.Audience = "rp/"
	cfg.AudiencePerStream = true
	_, err := receiver.New(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "AudiencePerStream") {
		t.Errorf("New = %v; want an error naming AudiencePerStream", err)
	}
}

// SETs arriving together for a stream the Receiver has not seen share one
// lookup, and none is rejected while it runs.
func TestAudiencePerStreamConcurrentLookup(t *testing.T) {
	e := newEnv(t, perStream)
	reads, _ := perStreamTransmitter(t, e)
	ctx := context.Background()
	c, err := e.rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := receiver.New(ctx, e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := other.PushHandler(receiver.PushOptions{})
	tokens := make([]string, 8)
	for i := range tokens {
		tokens[i] = sign(t, e, func(s *ssf.SET) {
			s.Audience = []string{audience + "/" + c.StreamID}
			s.JWTID = fmt.Sprintf("concurrent-%d", i)
		})
	}
	var wg sync.WaitGroup
	for _, tok := range tokens {
		wg.Go(func() {
			if got := push(t, h, "", tok); got.status != http.StatusAccepted {
				t.Errorf("push = %+v; want 202", got)
			}
		})
	}
	wg.Wait()
	if n := reads.Load(); n != 1 {
		t.Errorf("the Transmitter was asked %d times; want once", n)
	}
}
