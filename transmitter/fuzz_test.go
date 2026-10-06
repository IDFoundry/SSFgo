package transmitter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/transmitter"
)

// FuzzManagementAPI sends arbitrary requests, with a valid Receiver token,
// to every Transmitter endpoint: stream configuration, status, subjects,
// verification and poll. Whatever the method, query and body, the
// Transmitter must never answer 500 or panic, and every JSON response must
// be valid JSON.
func FuzzManagementAPI(f *testing.F) {
	fx := newFixture(f, func(c *transmitter.Config) {
		c.Limits = transmitter.Limits{
			StreamsPerReceiver: 5, SubjectRulesPerStream: 50, QueuedSETsPerStream: 50,
			LongPollTimeout: time.Millisecond, // a poll that asks to wait must not stall the fuzzer
		}
	})
	md := fx.metadata()
	const fixedStream = "fuzz-stream"
	paths := []string{
		pathOf(md.ConfigurationEndpoint),
		pathOf(md.StatusEndpoint),
		pathOf(md.AddSubjectEndpoint),
		pathOf(md.RemoveSubjectEndpoint),
		pathOf(md.VerificationEndpoint),
		pathOf(fx.issuer) + "/ssf/poll/" + fixedStream,
		pathOf(md.JWKSURI),
		"/.well-known/ssf-configuration" + pathOf(fx.issuer),
	}
	methods := []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete}
	handler := fx.tx.Handler()
	ensureStream := func() {
		_, err := fx.store.Stream(context.Background(), fixedStream)
		if errors.Is(err, storage.ErrNotFound) {
			_ = fx.store.CreateStream(context.Background(), storage.Stream{
				ID: fixedStream, ReceiverID: "alice", Audience: []string{"https://alice.example"},
				Delivery:        ssf.Delivery{Method: ssf.DeliveryPoll, EndpointURL: fx.issuer + "/ssf/poll/" + fixedStream},
				EventsRequested: interopEvents, EventsDelivered: interopEvents, Status: ssf.StreamEnabled,
			}, storage.CreateOptions{})
		}
	}

	seeds := []struct {
		path, method uint8
		query, body  string
	}{
		{0, 1, "", `{"events_requested":["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],"delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"https://rx.example/p","authorization_header":"Bearer x"}}`},
		{0, 0, "stream_id=" + fixedStream, ""},
		{0, 2, "", `{"stream_id":"` + fixedStream + `","description":"d","aud":["x"],"events_delivered":[]}`},
		{0, 3, "", `{"stream_id":"` + fixedStream + `"}`},
		{0, 4, "stream_id=" + fixedStream, ""},
		{1, 1, "", `{"stream_id":"` + fixedStream + `","status":"paused","reason":"r"}`},
		{2, 1, "", `{"stream_id":"` + fixedStream + `","subject":{"format":"complex","user":{"format":"email","email":"a@b.example"}}}`},
		{3, 1, "", `{"stream_id":"` + fixedStream + `","subject":{"format":"aliases","identifiers":[{"format":"opaque","id":"x"}]}}`},
		{4, 1, "", `{"stream_id":"` + fixedStream + `","state":"s"}`},
		{5, 1, "", `{"ack":["a","b"],"setErrs":{"c":{"err":"invalid_key","description":"d"}},"maxEvents":2,"returnImmediately":true}`},
		{5, 1, "", `{"maxEvents":0}`},
		{0, 1, "", `;{ broken`},
	}
	for _, s := range seeds {
		f.Add(s.path, s.method, s.query, []byte(s.body))
	}

	f.Fuzz(func(t *testing.T, path, method uint8, query string, body []byte) {
		ensureStream()
		target := paths[int(path)%len(paths)]
		if query != "" {
			target += "?" + query
		}
		req, err := http.NewRequest(methods[int(method)%len(methods)], "https://tx.example"+target, bytes.NewReader(body))
		if err != nil {
			return // not a request any client could send
		}
		req.Header.Set("Authorization", "Bearer alice")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("%s %s -> %d: %s", req.Method, target, rec.Code, rec.Body.Bytes())
		}
		if rec.Header().Get("Content-Type") == "application/json" && !json.Valid(rec.Body.Bytes()) {
			t.Fatalf("%s %s returned invalid JSON: %q", req.Method, target, rec.Body.Bytes())
		}
	})
}

func pathOf(u string) string {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		panic(err)
	}
	return req.URL.Path
}
