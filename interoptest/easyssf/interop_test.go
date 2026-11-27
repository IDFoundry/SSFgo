// Package easyssf tests SSFgo's Transmitter against easyssf
// (https://easyssf.org), an independent SSF Receiver, in Go and in Java.
// See ../README.md.
package easyssf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/ssftest"
)

// waitTimeout bounds every wait for the peer: registering its stream,
// verifying it, and handling an event.
const waitTimeout = 30 * time.Second

// received is an event a peer's handler was given.
type received struct {
	EventType string `json:"type"`
	Email     string `json:"email"`
	Delivery  string `json:"delivery"`
}

// peer is a Receiver under test, running against tx with the delivery
// method it was started with.
type peer interface {
	// StreamID waits until the peer has registered its stream at the
	// Transmitter, and returns the stream's identifier.
	StreamID(t *testing.T) string
	// Verify has the peer request a verification event with a state of its
	// own (SSF 1.0 §8.1.4.2), and waits until it has accepted the event the
	// Transmitter sends.
	Verify(t *testing.T)
	// Next waits for the next event the peer's handler is given.
	Next(t *testing.T) received
	// Stop stops the peer, which deletes its stream, and waits until it
	// has. Calling it again does nothing.
	Stop(t *testing.T)
}

// events are what each run emits, and what the peer must hand its handler,
// in order.
var events = []struct {
	subject ssf.Subject
	event   ssf.Event
	want    received
}{
	{
		ssf.EmailSubject{Email: "alice@example.com"},
		caep.SessionRevoked{Common: caep.Common{EventTimestamp: ssf.NewNumericDate(time.Now()), InitiatingEntity: caep.InitiatedByAdmin}},
		received{EventType: string(caep.SessionRevoked{}.EventType()), Email: "alice@example.com"},
	},
	{
		ssf.EmailSubject{Email: "bob@example.com"},
		risc.AccountDisabled{Reason: risc.DisabledHijacking},
		received{EventType: string(risc.AccountDisabled{}.EventType()), Email: "bob@example.com"},
	},
}

// run checks a peer against tx: it registers a stream with the delivery
// method asked for, verifies it, is handed each emitted event about the
// right subject, and deletes its stream when it stops.
func run(t *testing.T, tx *ssftest.Transmitter, p peer, delivery string) {
	t.Helper()
	id := p.StreamID(t)

	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	status, method := getStream(ctx, t, tx, id)
	if status != http.StatusOK {
		t.Fatalf("GET the peer's stream %q: status %d", id, status)
	}
	if method != methodURI[delivery] {
		t.Fatalf("the peer registered a stream with delivery %q, want %q", method, methodURI[delivery])
	}

	p.Verify(t)

	for _, e := range events {
		if err := tx.Emit(ctx, e.subject, e.event); err != nil {
			t.Fatalf("Emit %s: %v", e.event.EventType(), err)
		}
		got := p.Next(t)
		want := e.want
		want.Delivery = delivery
		if got != want {
			t.Fatalf("the peer handled %+v, want %+v", got, want)
		}
	}

	p.Stop(t)
	if status, _ := getStream(ctx, t, tx, id); status != http.StatusNotFound {
		t.Fatalf("GET the peer's stream %q after it stopped: status %d, want 404 (deleted)", id, status)
	}
}

// getStream reads stream id from the Transmitter's stream configuration
// endpoint (SSF 1.0 §8.1.1.2), with the peer's credentials, and returns
// the status and, if found, the stream's delivery method.
func getStream(ctx context.Context, t *testing.T, tx *ssftest.Transmitter, id string) (int, string) {
	t.Helper()
	token, err := tx.ReceiverConfig(nil).TokenSource.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := tx.Transmitter().Metadata().ConfigurationEndpoint + "?stream_id=" + url.QueryEscape(id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := tx.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, ""
	}
	var stream struct {
		Delivery struct {
			Method string `json:"method"`
		} `json:"delivery"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&stream); err != nil {
		t.Fatalf("GET stream %q: %v", id, err)
	}
	return resp.StatusCode, stream.Delivery.Method
}

// methodURI maps each delivery method to its URI (SSF 1.0 §6.1).
var methodURI = map[string]string{
	"push": string(ssf.DeliveryPush),
	"poll": string(ssf.DeliveryPoll),
}
