package scim_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/receiver"
	"github.com/idfoundry/ssfgo/scim"
	"github.com/idfoundry/ssfgo/storage/memstore"
	"github.com/idfoundry/ssfgo/transmitter"
)

var allTypes = []ssf.EventType{
	scim.FeedAddEventType, scim.FeedRemoveEventType,
	scim.CreateNoticeEventType, scim.CreateFullEventType,
	scim.PatchNoticeEventType, scim.PatchFullEventType,
	scim.PutNoticeEventType, scim.PutFullEventType,
	scim.DeleteEventType, scim.ActivateEventType, scim.DeactivateEventType,
	scim.AsyncResponseEventType,
}

func registry(t *testing.T) *ssf.Registry {
	t.Helper()
	r := ssf.NewRegistry()
	if err := scim.Register(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRegister(t *testing.T) {
	r := registry(t)
	for _, typ := range allTypes {
		if !r.Supports(typ) {
			t.Errorf("%s not registered", typ)
		}
	}
	if got := len(r.Types()); got != 2+12 {
		t.Errorf("registry holds %d types, want 14", got)
	}
	if err := scim.Register(r); err == nil {
		t.Error("registering SCIM twice succeeded")
	}
}

func TestDecode(t *testing.T) {
	r := registry(t)
	for _, c := range []struct {
		typ     ssf.EventType
		payload string
		want    ssf.Event
	}{
		{scim.FeedAddEventType, `{}`, scim.FeedAdd{}},
		{scim.DeleteEventType, `{"unknown":1}`, scim.Delete{}},
		{scim.CreateFullEventType, `{"data": {"userName": "jdoe"}, "version": "v1"}`,
			scim.CreateFull{Data: json.RawMessage(`{"userName":"jdoe"}`), Version: "v1"}},
		{scim.PatchNoticeEventType, `{"attributes":["members"],"version":"a330bc54f0671c9"}`,
			scim.PatchNotice{Attributes: []string{"members"}, Version: "a330bc54f0671c9"}},
		{scim.AsyncResponseEventType, `{"method":"POST","bulkId":"qwerty","status":"201"}`,
			scim.AsyncResponse{Method: "POST", BulkID: "qwerty", Status: "201"}},
	} {
		got, err := r.Decode(c.typ, json.RawMessage(c.payload))
		if err != nil {
			t.Errorf("%s: %v", c.typ, err)
			continue
		}
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(c.want)
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("%s: decoded %s, want %s", c.typ, gotJSON, wantJSON)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	r := registry(t)
	for name, c := range map[string]struct {
		typ     ssf.EventType
		payload string
	}{
		"full without data":            {scim.CreateFullEventType, `{}`},
		"full with attributes too":     {scim.PutFullEventType, `{"data":{},"attributes":["a"]}`},
		"data not an object":           {scim.PatchFullEventType, `{"data":"x"}`},
		"notice without attributes":    {scim.CreateNoticeEventType, `{}`},
		"notice with data too":         {scim.PatchNoticeEventType, `{"attributes":["a"],"data":{}}`},
		"full with Attributes too":     {scim.PutFullEventType, `{"data":{},"Attributes":["a"]}`},
		"notice with DATA too":         {scim.PatchNoticeEventType, `{"attributes":["a"],"DATA":{}}`},
		"empty attribute name":         {scim.PutNoticeEventType, `{"attributes":[""]}`},
		"async without method":         {scim.AsyncResponseEventType, `{"status":"200"}`},
		"async with unknown method":    {scim.AsyncResponseEventType, `{"method":"GET","status":"200"}`},
		"async with numeric status":    {scim.AsyncResponseEventType, `{"method":"PUT","status":200}`},
		"async status not a code":      {scim.AsyncResponseEventType, `{"method":"PUT","status":"ok"}`},
		"async error without response": {scim.AsyncResponseEventType, `{"method":"PUT","status":"400"}`},
		"async response not an object": {scim.AsyncResponseEventType, `{"method":"PUT","status":"500","response":"x"}`},
		"event not an object":          {scim.FeedRemoveEventType, `[]`},
	} {
		if _, err := r.Decode(c.typ, json.RawMessage(c.payload)); !errors.Is(err, ssf.ErrInvalidEvent) {
			t.Errorf("%s: %v, want ErrInvalidEvent", name, err)
		}
	}
}

// A SCIM event's subject must be a SCIM resource (RFC 9967 §2.1).
func TestSubjectMustBeSCIM(t *testing.T) {
	resource := ssf.SCIMSubject{URI: "/Users/2b2f880af6674ac284bae9381673d462"}
	for _, typ := range allTypes {
		e, err := registry(t).Decode(typ, json.RawMessage(validPayload(typ)))
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		c, ok := e.(ssf.SubjectConstrainedEvent)
		if !ok {
			t.Fatalf("%s does not constrain its subject", typ)
		}
		if err := c.ValidateSubject(resource); err != nil {
			t.Errorf("%s with a scim subject: %v", typ, err)
		}
		if err := c.ValidateSubject(ssf.EmailSubject{Email: "jdoe@example.com"}); err == nil {
			t.Errorf("%s accepted an email subject", typ)
		}
	}
}

func validPayload(typ ssf.EventType) string {
	switch typ {
	case scim.CreateFullEventType, scim.PatchFullEventType, scim.PutFullEventType:
		return `{"data":{}}`
	case scim.CreateNoticeEventType, scim.PatchNoticeEventType, scim.PutNoticeEventType:
		return `{"attributes":["userName"]}`
	case scim.AsyncResponseEventType:
		return `{"method":"DELETE","status":"204"}`
	}
	return `{}`
}

// A SCIM service provider emits an asynchronous response under the txn it
// returned to the client, and a Receiver gets it, typed, with that txn.
func TestEmitAndReceive(t *testing.T) {
	ctx := context.Background()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	issuer := srv.URL + "/scim"
	tx, err := transmitter.New(transmitter.Config{
		Assurance:       ssf.AssuranceDevelopment,
		Limits:          transmitter.RecommendedLimits(),
		PushRetry:       transmitter.RecommendedPushRetry(),
		Issuer:          issuer,
		SigningKeys:     []transmitter.SigningKey{{Signer: key, Algorithm: ssf.RS256, KeyID: "k1"}},
		EventsSupported: allTypes,
		DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPoll},
		DefaultSubjects: ssf.DefaultSubjectsAll,
		Store:           memstore.NewStreamStore(),
		Authorize: func(context.Context, string) (transmitter.Receiver, error) {
			return transmitter.Receiver{ID: "rx", Audience: []string{"https://rx.example"}, Access: transmitter.AccessManage}, nil
		},
		PermitEvent: transmitter.PermitAll,
		Logger:      slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = tx.Handler()

	rx, err := receiver.New(ctx, receiver.Config{
		Assurance:   ssf.AssuranceDevelopment,
		Limits:      receiver.RecommendedLimits(),
		Issuer:      issuer,
		Audience:    "https://rx.example",
		Registry:    registry(t),
		Algorithms:  []ssf.SignatureAlgorithm{ssf.RS256},
		TokenSource: receiver.StaticToken("token"),
		ReplayStore: memstore.NewReplayStore(),
		HTTPClient:  srv.Client(),
		Logger:      slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []ssf.SET
	receiver.On(rx, func(_ context.Context, set ssf.SET, e scim.AsyncResponse) error {
		got = append(got, set)
		return nil
	})
	stream, err := rx.CreateStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}

	resource := ssf.SCIMSubject{
		URI:        "/Users/2819c223-7f76-453a-919d-413861904646",
		Attributes: map[string]json.RawMessage{"userName": json.RawMessage(`"jdoe"`)},
	}
	failure := scim.AsyncResponse{Method: "PUT", Status: "400",
		Response: json.RawMessage(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"scimType":"invalidSyntax","status":"400"}`)}
	if err := tx.EmitTxn(ctx, "734f0614e3274f288f93ac74119dcf78", resource, failure); err != nil {
		t.Fatal(err)
	}
	if err := tx.EmitTxn(ctx, strings.Repeat("t", transmitter.MaxTxnLength+1), resource, failure); err == nil {
		t.Error("EmitTxn with an over-long txn succeeded")
	}
	if err := tx.EmitTxn(ctx, "", resource, failure); err == nil {
		t.Error("EmitTxn without a txn succeeded")
	}
	if err := tx.Emit(ctx, ssf.EmailSubject{Email: "jdoe@example.com"}, scim.Deactivate{}); err == nil {
		t.Error("a SCIM event about an email subject was emitted")
	}
	if _, err := rx.Poll(ctx, stream, receiver.PollOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("received %d asynchronous responses, want 1", len(got))
	}
	set := got[0]
	if set.TransactionID != "734f0614e3274f288f93ac74119dcf78" || !ssf.SubjectsEqual(set.Subject, resource) {
		t.Errorf("txn %q, subject %#v", set.TransactionID, set.Subject)
	}
	if e := set.Event.(scim.AsyncResponse); e.Status != "400" || string(e.Response) != string(failure.Response) {
		t.Errorf("event %#v", e)
	}
}
