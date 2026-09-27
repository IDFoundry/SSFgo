package transmitter_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/internal/jose"
	"github.com/idfoundry/ssfgo/internal/setcodec"
	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/storage/memstore"
	"github.com/idfoundry/ssfgo/transmitter"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func signingKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		if testKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return testKey
}

var interopEvents = []ssf.EventType{
	caep.SessionRevokedEventType,
	caep.CredentialChangeEventType,
	caep.DeviceComplianceChangeEventType,
}

// tokens maps test bearer tokens to Receivers.
var tokens = map[string]transmitter.Receiver{
	"alice":          {ID: "alice", Audience: []string{"https://alice.example"}, Access: transmitter.AccessManage},
	"alice-readonly": {ID: "alice", Audience: []string{"https://alice.example"}, Access: transmitter.AccessRead},
	"bob":            {ID: "bob", Audience: []string{"https://bob.example", "https://bob.example/mobile"}, Access: transmitter.AccessManage},
	"nobody":         {ID: "nobody", Audience: []string{"x"}, Access: transmitter.AccessNone},
	"broken":         {ID: "", Audience: nil, Access: transmitter.AccessManage},
}

type fixture struct {
	t      testing.TB
	srv    *httptest.Server
	store  *memstore.StreamStore
	tx     *transmitter.Transmitter
	issuer string
	now    time.Time
}

func newFixture(t testing.TB, mutate ...func(*transmitter.Config)) *fixture {
	t.Helper()
	f := &fixture{t: t, store: memstore.NewStreamStore(), now: time.Unix(1700000000, 0)}
	f.srv = httptest.NewUnstartedServer(nil)
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.issuer = f.srv.URL + "/tenant-a"

	cfg := transmitter.Config{
		Issuer:          f.issuer,
		SigningKeys:     []transmitter.SigningKey{{Signer: signingKey(t), Algorithm: ssf.RS256, KeyID: "k1"}},
		EventsSupported: interopEvents,
		DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPush, ssf.DeliveryPoll},
		DefaultSubjects: ssf.DefaultSubjectsAll,
		Store:           f.store,
		Authorize: func(_ context.Context, token string) (transmitter.Receiver, error) {
			if token == "explode" {
				return transmitter.Receiver{}, errors.New("database down")
			}
			rx, ok := tokens[token]
			if !ok {
				return transmitter.Receiver{}, transmitter.ErrInvalidToken
			}
			return rx, nil
		},
		MultipleStreamsPerReceiver: true,
		MinVerificationInterval:    30 * time.Second,
		Now:                        func() time.Time { return f.now },
		Logger:                     slog.New(slog.DiscardHandler),
	}
	for _, m := range mutate {
		m(&cfg)
	}
	tx, err := transmitter.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.tx = tx
	f.srv.Config.Handler = tx.Handler()
	return f
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func (r response) json(t testing.TB, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
}

func (f *fixture) do(method, url, token string, body any) response {
	f.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			f.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		f.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return response{res.StatusCode, res.Header, data}
}

func (f *fixture) metadata() ssf.TransmitterMetadata { return f.tx.Metadata() }

func expect(t testing.TB, r response, status int) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status = %d, want %d; body %s", r.status, status, r.body)
	}
}

func (f *fixture) create(token string, body any) ssf.StreamConfiguration {
	f.t.Helper()
	r := f.do("POST", f.metadata().ConfigurationEndpoint, token, body)
	expect(f.t, r, http.StatusCreated)
	var c ssf.StreamConfiguration
	r.json(f.t, &c)
	return c
}

func pushBody() map[string]any {
	return map[string]any{
		"description":      "Stream for OIDF Conformance Test-Suite",
		"events_requested": interopEvents,
		"delivery": map[string]any{
			"method":               ssf.DeliveryPush,
			"endpoint_url":         "https://rx.example/ssf-push",
			"authorization_header": "Bearer push-token",
		},
	}
}

func TestConfigValidation(t *testing.T) {
	good := func() transmitter.Config {
		return transmitter.Config{
			Issuer:          "https://tx.example",
			SigningKeys:     []transmitter.SigningKey{{Signer: signingKey(t), Algorithm: ssf.RS256, KeyID: "k1"}},
			EventsSupported: interopEvents,
			DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPoll},
			DefaultSubjects: ssf.DefaultSubjectsNone,
			Store:           memstore.NewStreamStore(),
			Authorize:       func(context.Context, string) (transmitter.Receiver, error) { return transmitter.Receiver{}, nil },
		}
	}
	if _, err := transmitter.New(good()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for name, mutate := range map[string]func(*transmitter.Config){
		"http issuer":          func(c *transmitter.Config) { c.Issuer = "http://tx.example" },
		"issuer with query":    func(c *transmitter.Config) { c.Issuer = "https://tx.example?x=1" },
		"issuer with fragment": func(c *transmitter.Config) { c.Issuer = "https://tx.example#x" },
		"no keys":              func(c *transmitter.Config) { c.SigningKeys = nil },
		"no kid":               func(c *transmitter.Config) { c.SigningKeys[0].KeyID = "" },
		"key/alg mismatch":     func(c *transmitter.Config) { c.SigningKeys[0].Algorithm = ssf.ES256 },
		"duplicate kid": func(c *transmitter.Config) {
			c.SigningKeys = append(c.SigningKeys, c.SigningKeys[0])
		},
		"no events":             func(c *transmitter.Config) { c.EventsSupported = nil },
		"no delivery":           func(c *transmitter.Config) { c.DeliveryMethods = nil },
		"unknown delivery":      func(c *transmitter.Config) { c.DeliveryMethods = []ssf.DeliveryMethod{"urn:x"} },
		"no default subjects":   func(c *transmitter.Config) { c.DefaultSubjects = "" },
		"no store":              func(c *transmitter.Config) { c.Store = nil },
		"no authorize":          func(c *transmitter.Config) { c.Authorize = nil },
		"fractional interval":   func(c *transmitter.Config) { c.MinVerificationInterval = 1500 * time.Millisecond },
		"braces in issuer path": func(c *transmitter.Config) { c.Issuer = "https://tx.example/{x}" },
		"negative retry":        func(c *transmitter.Config) { c.PushRetry.MaxAttempts = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			c := good()
			mutate(&c)
			if _, err := transmitter.New(c); err == nil {
				t.Fatal("New succeeded")
			}
		})
	}
}

// TestMetadata mirrors the checks in the OIDF openid-ssf-transmitter-metadata
// module, including the CAEP Interop profile's.
func TestMetadata(t *testing.T) {
	f := newFixture(t)
	wellKnown, err := ssf.WellKnownURL(f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(wellKnown, "/.well-known/ssf-configuration/tenant-a") {
		t.Fatalf("well-known URL = %s", wellKnown)
	}
	r := f.do("GET", wellKnown, "", nil)
	expect(t, r, http.StatusOK)
	if ct := r.header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var raw map[string]any
	r.json(t, &raw)
	var md ssf.TransmitterMetadata
	r.json(t, &md)

	if md.Issuer != f.issuer {
		t.Errorf("issuer = %q, want %q", md.Issuer, f.issuer)
	}
	if md.SpecVersion != "1_0" {
		t.Errorf("spec_version = %q", md.SpecVersion)
	}
	for _, name := range []string{"jwks_uri", "configuration_endpoint", "status_endpoint", "add_subject_endpoint", "remove_subject_endpoint", "verification_endpoint"} {
		v, _ := raw[name].(string)
		if !strings.HasPrefix(v, "https://") {
			t.Errorf("%s = %q, want an https URL", name, v)
		}
	}
	if len(md.AuthorizationSchemes) != 1 || md.AuthorizationSchemes[0].SpecURN != "urn:ietf:rfc:6749" {
		t.Errorf("authorization_schemes = %v", md.AuthorizationSchemes)
	}
	if md.DefaultSubjects != ssf.DefaultSubjectsAll {
		t.Errorf("default_subjects = %q", md.DefaultSubjects)
	}
	if len(md.DeliveryMethodsSupported) != 2 {
		t.Errorf("delivery_methods_supported = %v", md.DeliveryMethodsSupported)
	}
	for name, v := range raw {
		if arr, ok := v.([]any); ok && len(arr) == 0 {
			t.Errorf("%s is an empty array; SSF 1.0 §7.2.3 requires omitting it", name)
		}
	}

	r = f.do("GET", md.JWKSURI, "", nil)
	expect(t, r, http.StatusOK)
	keys, err := jose.ParseJWKSet(r.body)
	if err != nil || len(keys) != 1 || keys[0].KeyID != "k1" || keys[0].Algorithm != ssf.RS256 {
		t.Fatalf("JWKS = %+v, %v", keys, err)
	}
	if bytes.Contains(r.body, []byte(`"d"`)) {
		t.Error("JWKS leaks private key material")
	}
}

// Neither the Config slices passed to New nor the metadata returned by
// Metadata may alias the Transmitter's own state.
func TestConfigAndMetadataAreCopied(t *testing.T) {
	events := []ssf.EventType{caep.SessionRevokedEventType}
	methods := []ssf.DeliveryMethod{ssf.DeliveryPoll}
	tx, err := transmitter.New(transmitter.Config{
		Issuer:          "https://tx.example",
		SigningKeys:     []transmitter.SigningKey{{Signer: signingKey(t), Algorithm: ssf.RS256, KeyID: "k1"}},
		EventsSupported: events,
		DeliveryMethods: methods,
		DefaultSubjects: ssf.DefaultSubjectsAll,
		Store:           memstore.NewStreamStore(),
		Authorize:       func(context.Context, string) (transmitter.Receiver, error) { return transmitter.Receiver{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	methods[0] = ssf.DeliveryPush
	events[0] = "https://example.com/other"
	md := tx.Metadata()
	if md.DeliveryMethodsSupported[0] != ssf.DeliveryPoll {
		t.Error("changing the Config slice after New changed the Transmitter")
	}
	md.DeliveryMethodsSupported[0] = ssf.DeliveryPush
	md.AuthorizationSchemes[0].SpecURN = "urn:evil"
	if again := tx.Metadata(); again.DeliveryMethodsSupported[0] != ssf.DeliveryPoll || again.AuthorizationSchemes[0].SpecURN != ssf.OAuth2SpecURN {
		t.Error("changing returned metadata changed the Transmitter")
	}
	if err := tx.Emit(context.Background(), ssf.EmailSubject{Email: "a@b.example"}, caep.SessionRevoked{}); err != nil {
		t.Errorf("session-revoked must still be supported after the caller's slice changed: %v", err)
	}
}

func TestMetadataAtIssuerWithoutPath(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	tx, err := transmitter.New(transmitter.Config{
		Issuer:          srv.URL + "/",
		SigningKeys:     []transmitter.SigningKey{{Signer: signingKey(t), Algorithm: ssf.RS256, KeyID: "k1"}},
		EventsSupported: interopEvents,
		DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPoll},
		DefaultSubjects: ssf.DefaultSubjectsNone,
		Store:           memstore.NewStreamStore(),
		Authorize:       func(context.Context, string) (transmitter.Receiver, error) { return transmitter.Receiver{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = tx.Handler()
	res, err := srv.Client().Get(srv.URL + "/.well-known/ssf-configuration")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if got := tx.Metadata().ConfigurationEndpoint; got != srv.URL+"/ssf/stream" {
		t.Errorf("configuration_endpoint = %s", got)
	}
}

// TestStreamLifecycle mirrors openid-ssf-stream-control-happy-path.
func TestStreamLifecycle(t *testing.T) {
	f := newFixture(t)
	md := f.metadata()
	body := pushBody()
	body["events_requested"] = append(interopEvents, "https://example.com/unknown")

	created := f.create("alice", body)
	if created.StreamID == "" || created.Issuer != f.issuer {
		t.Fatalf("create = %+v", created)
	}
	if len(created.Audience) != 1 || created.Audience[0] != "https://alice.example" {
		t.Errorf("aud = %v", created.Audience)
	}
	if len(created.EventsDelivered) != 3 {
		t.Errorf("events_delivered = %v, want the three supported events requested", created.EventsDelivered)
	}
	if created.Delivery.Method != ssf.DeliveryPush || created.Delivery.EndpointURL != "https://rx.example/ssf-push" ||
		created.Delivery.AuthorizationHeader != "Bearer push-token" {
		t.Errorf("delivery = %+v", created.Delivery)
	}
	if created.MinVerificationInterval != 30 {
		t.Errorf("min_verification_interval = %d", created.MinVerificationInterval)
	}

	byID := md.ConfigurationEndpoint + "?stream_id=" + created.StreamID
	r := f.do("GET", byID, "alice-readonly", nil)
	expect(t, r, http.StatusOK)
	if cc := r.header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	var read ssf.StreamConfiguration
	r.json(t, &read)
	if read.StreamID != created.StreamID || read.Description != created.Description {
		t.Errorf("read = %+v", read)
	}

	// PATCH, as the suite sends it: the original body plus stream_id and a
	// new description.
	patch := pushBody()
	patch["stream_id"] = created.StreamID
	patch["description"] = "Updated Stream"
	delete(patch, "events_requested")
	r = f.do("PATCH", md.ConfigurationEndpoint, "alice", patch)
	expect(t, r, http.StatusOK)
	var updated ssf.StreamConfiguration
	r.json(t, &updated)
	if updated.Description != "Updated Stream" || len(updated.EventsRequested) != 4 {
		t.Errorf("PATCH changed or lost properties: %+v", updated)
	}

	// PUT without events_requested or delivery resets both.
	r = f.do("PUT", md.ConfigurationEndpoint, "alice", map[string]any{
		"stream_id": created.StreamID, "description": "Replaced",
	})
	expect(t, r, http.StatusOK)
	var replaced ssf.StreamConfiguration
	r.json(t, &replaced)
	if replaced.Description != "Replaced" || len(replaced.EventsRequested) != 0 || len(replaced.EventsDelivered) != 0 {
		t.Errorf("PUT kept properties it should reset: %+v", replaced)
	}
	if replaced.Delivery.Method != ssf.DeliveryPoll || !strings.HasPrefix(replaced.Delivery.EndpointURL, f.issuer+"/ssf/poll/") {
		t.Errorf("PUT without delivery should default to poll: %+v", replaced.Delivery)
	}

	// Status read, then every status change the suite makes.
	statusURL := md.StatusEndpoint + "?stream_id=" + created.StreamID
	r = f.do("GET", statusURL, "alice-readonly", nil)
	expect(t, r, http.StatusOK)
	var st ssf.StreamState
	r.json(t, &st)
	if st.Status != ssf.StreamEnabled {
		t.Errorf("initial status = %q", st.Status)
	}
	for _, status := range []ssf.StreamStatus{ssf.StreamPaused, ssf.StreamDisabled, ssf.StreamEnabled} {
		r = f.do("POST", md.StatusEndpoint, "alice", map[string]any{"stream_id": created.StreamID, "status": status, "reason": "test"})
		expect(t, r, http.StatusOK)
		r.json(t, &st)
		if st.Status != status || st.Reason != "test" || st.StreamID != created.StreamID {
			t.Errorf("status update = %+v", st)
		}
	}

	expect(t, f.do("DELETE", byID, "alice", nil), http.StatusNoContent)
	expect(t, f.do("GET", byID, "alice", nil), http.StatusNotFound)
}

func TestCreateDefaultsToPoll(t *testing.T) {
	f := newFixture(t)
	c := f.create("alice", map[string]any{"events_requested": interopEvents})
	if c.Delivery.Method != ssf.DeliveryPoll || c.Delivery.EndpointURL != f.issuer+"/ssf/poll/"+c.StreamID {
		t.Errorf("delivery = %+v", c.Delivery)
	}
	// The Receiver may not choose the poll endpoint.
	c = f.create("alice", map[string]any{"delivery": map[string]any{"method": ssf.DeliveryPoll, "endpoint_url": "https://evil.example"}})
	if c.Delivery.EndpointURL != f.issuer+"/ssf/poll/"+c.StreamID {
		t.Errorf("Receiver-supplied poll endpoint was used: %+v", c.Delivery)
	}
}

func TestCreateWithoutPollSupportRequiresDelivery(t *testing.T) {
	f := newFixture(t, func(c *transmitter.Config) { c.DeliveryMethods = []ssf.DeliveryMethod{ssf.DeliveryPush} })
	r := f.do("POST", f.metadata().ConfigurationEndpoint, "alice", map[string]any{})
	expect(t, r, http.StatusBadRequest)
	r = f.do("POST", f.metadata().ConfigurationEndpoint, "alice", map[string]any{"delivery": map[string]any{"method": ssf.DeliveryPoll}})
	expect(t, r, http.StatusBadRequest)
	f.create("alice", pushBody())
}

func TestListStreams(t *testing.T) {
	f := newFixture(t)
	url := f.metadata().ConfigurationEndpoint

	r := f.do("GET", url, "alice", nil)
	expect(t, r, http.StatusOK)
	if strings.TrimSpace(string(r.body)) != "[]" {
		t.Errorf("no streams: body = %s, want []", r.body)
	}
	a1 := f.create("alice", pushBody())
	a2 := f.create("alice", pushBody())
	f.create("bob", pushBody())

	var list []ssf.StreamConfiguration
	r = f.do("GET", url, "alice", nil)
	expect(t, r, http.StatusOK)
	r.json(t, &list)
	if len(list) != 2 || list[0].StreamID != a1.StreamID || list[1].StreamID != a2.StreamID {
		t.Errorf("alice's streams = %+v", list)
	}
}

func TestSingleStreamPerReceiver(t *testing.T) {
	f := newFixture(t, func(c *transmitter.Config) { c.MultipleStreamsPerReceiver = false })
	f.create("alice", pushBody())
	expect(t, f.do("POST", f.metadata().ConfigurationEndpoint, "alice", pushBody()), http.StatusConflict)
	f.create("bob", pushBody())
}

// TestAuthorization mirrors the suite's *WithInvalidAccessToken modules and
// the CAEP Interop §2.7.2/§2.7.3 resource-server rules.
func TestAuthorization(t *testing.T) {
	f := newFixture(t)
	md := f.metadata()
	stream := f.create("alice", pushBody())
	byID := md.ConfigurationEndpoint + "?stream_id=" + stream.StreamID

	cases := []struct {
		name, method, url, token string
		body                     any
		status                   int
		wwwAuth                  string
	}{
		{"create, no token", "POST", md.ConfigurationEndpoint, "", pushBody(), 401, "Bearer"},
		{"create, invalid token", "POST", md.ConfigurationEndpoint, "invalid:123", pushBody(), 401, `Bearer error="invalid_token"`},
		{"read, invalid token", "GET", byID, "invalid:123", nil, 401, `Bearer error="invalid_token"`},
		{"update, invalid token", "PATCH", md.ConfigurationEndpoint, "invalid:123", map[string]any{"stream_id": stream.StreamID}, 401, ""},
		{"replace, invalid token", "PUT", md.ConfigurationEndpoint, "invalid:123", map[string]any{"stream_id": stream.StreamID}, 401, ""},
		{"delete, invalid token", "DELETE", byID, "invalid:123", nil, 401, ""},
		{"status, invalid token", "GET", md.StatusEndpoint + "?stream_id=" + stream.StreamID, "invalid:123", nil, 401, ""},
		{"read-only token creates", "POST", md.ConfigurationEndpoint, "alice-readonly", pushBody(), 403, `Bearer error="insufficient_scope"`},
		{"read-only token deletes", "DELETE", byID, "alice-readonly", nil, 403, ""},
		{"read-only token verifies", "POST", md.VerificationEndpoint, "alice-readonly", map[string]any{"stream_id": stream.StreamID}, 403, ""},
		{"read-only token updates status", "POST", md.StatusEndpoint, "alice-readonly", map[string]any{"stream_id": stream.StreamID, "status": "paused"}, 403, ""},
		{"no access at all reads", "GET", byID, "nobody", nil, 403, ""},
		{"authorizer failure", "GET", byID, "explode", nil, 500, ""},
		{"receiver without identity", "GET", byID, "broken", nil, 500, ""},
		{"another receiver's stream", "GET", byID, "bob", nil, 404, ""},
		{"delete another receiver's stream", "DELETE", byID, "bob", nil, 404, ""},
		{"update another receiver's stream", "PATCH", md.ConfigurationEndpoint, "bob", map[string]any{"stream_id": stream.StreamID}, 404, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := f.do(c.method, c.url, c.token, c.body)
			expect(t, r, c.status)
			if c.wwwAuth != "" && r.header.Get("WWW-Authenticate") != c.wwwAuth {
				t.Errorf("WWW-Authenticate = %q, want %q", r.header.Get("WWW-Authenticate"), c.wwwAuth)
			}
		})
	}

	// RFC 6750 §2.3 / CAEP Interop §2.7.2: a token in the query string is
	// not accepted.
	expect(t, f.do("GET", byID+"&access_token=alice", "", nil), http.StatusUnauthorized)

	if got, _ := f.store.Stream(context.Background(), stream.StreamID); got.ReceiverID != "alice" {
		t.Error("the stream was changed by a refused request")
	}
}

// TestBadRequests mirrors the suite's *WithBrokenInput / *WithInvalidBody /
// *UnknownStream modules and the remaining SSF §8 400/404 cases.
func TestBadRequests(t *testing.T) {
	f := newFixture(t)
	md := f.metadata()
	stream := f.create("alice", pushBody())
	deleted := f.create("alice", pushBody())
	expect(t, f.do("DELETE", md.ConfigurationEndpoint+"?stream_id="+deleted.StreamID, "alice", nil), http.StatusNoContent)

	const broken = ";{ broken"
	cases := []struct {
		name, method, url string
		body              any
		status            int
	}{
		{"create, broken JSON", "POST", md.ConfigurationEndpoint, broken, 400},
		{"create, array body", "POST", md.ConfigurationEndpoint, "[]", 400},
		{"create, events_requested not an array", "POST", md.ConfigurationEndpoint, map[string]any{"events_requested": "x"}, 400},
		{"create, delivery not an object", "POST", md.ConfigurationEndpoint, map[string]any{"delivery": "push"}, 400},
		{"create, unknown delivery method", "POST", md.ConfigurationEndpoint, map[string]any{"delivery": map[string]any{"method": "urn:x"}}, 400},
		{"create, push without endpoint", "POST", md.ConfigurationEndpoint, map[string]any{"delivery": map[string]any{"method": ssf.DeliveryPush}}, 400},
		{"create, push URL with credentials", "POST", md.ConfigurationEndpoint, map[string]any{"delivery": map[string]any{"method": ssf.DeliveryPush, "endpoint_url": "https://user:pass@rx.example"}}, 400},
		{"create, push to http", "POST", md.ConfigurationEndpoint, map[string]any{"delivery": map[string]any{"method": ssf.DeliveryPush, "endpoint_url": "http://rx.example"}}, 400},
		{"create, description null", "POST", md.ConfigurationEndpoint, map[string]any{"description": nil}, 400},
		{"update, broken JSON", "PATCH", md.ConfigurationEndpoint, broken, 400},
		{"update, no stream_id", "PATCH", md.ConfigurationEndpoint, map[string]any{"description": "x"}, 400},
		{"update, unknown stream", "PATCH", md.ConfigurationEndpoint, map[string]any{"stream_id": deleted.StreamID, "description": "x"}, 404},
		{"update, different iss", "PATCH", md.ConfigurationEndpoint, map[string]any{"stream_id": stream.StreamID, "iss": "https://evil.example"}, 400},
		{"update, different aud", "PATCH", md.ConfigurationEndpoint, map[string]any{"stream_id": stream.StreamID, "aud": "https://evil.example"}, 400},
		{"update, stale events_delivered", "PATCH", md.ConfigurationEndpoint, map[string]any{"stream_id": stream.StreamID, "events_delivered": []string{}}, 400},
		{"update, different events_supported", "PATCH", md.ConfigurationEndpoint, map[string]any{"stream_id": stream.StreamID, "events_supported": []string{"x"}}, 400},
		{"update, min_verification_interval", "PATCH", md.ConfigurationEndpoint, map[string]any{"stream_id": stream.StreamID, "min_verification_interval": 1}, 400},
		{"update, inactivity_timeout", "PATCH", md.ConfigurationEndpoint, map[string]any{"stream_id": stream.StreamID, "inactivity_timeout": 60}, 400},
		{"replace, broken JSON", "PUT", md.ConfigurationEndpoint, broken, 400},
		{"replace, unknown stream", "PUT", md.ConfigurationEndpoint, map[string]any{"stream_id": deleted.StreamID}, 404},
		{"delete, no stream_id", "DELETE", md.ConfigurationEndpoint, nil, 400},
		{"delete, unknown stream", "DELETE", md.ConfigurationEndpoint + "?stream_id=" + deleted.StreamID, nil, 404},
		{"read, unknown stream", "GET", md.ConfigurationEndpoint + "?stream_id=" + deleted.StreamID, nil, 404},
		{"status, no stream_id", "GET", md.StatusEndpoint, nil, 400},
		{"status, unknown stream", "GET", md.StatusEndpoint + "?stream_id=" + deleted.StreamID, nil, 404},
		{"status update, invalid status", "POST", md.StatusEndpoint, map[string]any{"stream_id": stream.StreamID, "status": "stopped"}, 400},
		{"status update, no status", "POST", md.StatusEndpoint, map[string]any{"stream_id": stream.StreamID}, 400},
		{"status update, unknown stream", "POST", md.StatusEndpoint, map[string]any{"stream_id": deleted.StreamID, "status": "paused"}, 404},
		{"add subject, broken JSON", "POST", md.AddSubjectEndpoint, broken, 400},
		{"add subject, no subject", "POST", md.AddSubjectEndpoint, map[string]any{"stream_id": stream.StreamID}, 400},
		{"add subject, invalid subject", "POST", md.AddSubjectEndpoint, map[string]any{"stream_id": stream.StreamID, "subject": map[string]any{"format": "email"}}, 400},
		{"add subject, unknown stream", "POST", md.AddSubjectEndpoint, map[string]any{"stream_id": deleted.StreamID, "subject": map[string]any{"format": "opaque", "id": "x"}}, 404},
		{"remove subject, unknown stream", "POST", md.RemoveSubjectEndpoint, map[string]any{"stream_id": deleted.StreamID, "subject": map[string]any{"format": "opaque", "id": "x"}}, 404},
		{"verify, broken JSON", "POST", md.VerificationEndpoint, broken, 400},
		{"verify, no stream_id", "POST", md.VerificationEndpoint, map[string]any{}, 400},
		{"verify, unknown stream", "POST", md.VerificationEndpoint, map[string]any{"stream_id": deleted.StreamID}, 404},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			expect(t, f.do(c.method, c.url, "alice", c.body), c.status)
		})
	}

	got, _ := f.store.Stream(context.Background(), stream.StreamID)
	if got.Description != "Stream for OIDF Conformance Test-Suite" || got.Status != ssf.StreamEnabled {
		t.Errorf("a rejected request changed the stream: %+v", got)
	}
}

func TestPatchAcceptsMatchingTransmitterFields(t *testing.T) {
	f := newFixture(t)
	c := f.create("bob", pushBody())
	// A Receiver that reads the configuration, edits it and sends it back
	// whole must succeed (SSF 1.0 §8.1.1.4).
	c.Description = "edited"
	r := f.do("PUT", f.metadata().ConfigurationEndpoint, "bob", c)
	expect(t, r, http.StatusOK)
	var got ssf.StreamConfiguration
	r.json(t, &got)
	if got.Description != "edited" || got.Delivery.AuthorizationHeader != "Bearer push-token" || len(got.EventsDelivered) != 3 {
		t.Errorf("read-modify-replace lost data: %+v", got)
	}
}

// TestSubjects mirrors openid-ssf-stream-subject-control-happy-path.
func TestSubjects(t *testing.T) {
	f := newFixture(t)
	md := f.metadata()
	stream := f.create("alice", pushBody())
	subject := map[string]any{"format": "opaque", "id": "valid"}

	r := f.do("POST", md.AddSubjectEndpoint, "alice", map[string]any{"stream_id": stream.StreamID, "subject": subject, "verified": true})
	expect(t, r, http.StatusOK)
	if len(r.body) != 0 {
		t.Errorf("add subject body = %s, want empty", r.body)
	}
	rules, _ := f.store.SubjectRules(context.Background(), stream.StreamID)
	if len(rules) != 1 || !rules[0].Included || !ssf.SubjectsEqual(rules[0].Subject, ssf.OpaqueSubject{ID: "valid"}) {
		t.Fatalf("stored rules = %v", rules)
	}
	expect(t, f.do("POST", md.RemoveSubjectEndpoint, "alice", map[string]any{"stream_id": stream.StreamID, "subject": subject}), http.StatusNoContent)
	if rules, _ := f.store.SubjectRules(context.Background(), stream.StreamID); len(rules) != 1 || rules[0].Included {
		t.Errorf("remove should leave an exclude rule: %v", rules)
	}
	expect(t, f.do("POST", md.AddSubjectEndpoint, "bob", map[string]any{"stream_id": stream.StreamID, "subject": subject}), http.StatusNotFound)
}

func TestVerification(t *testing.T) {
	f := newFixture(t)
	md := f.metadata()
	stream := f.create("bob", pushBody())
	ctx := context.Background()

	expect(t, f.do("POST", md.VerificationEndpoint, "bob", map[string]any{"stream_id": stream.StreamID, "state": "abc"}), http.StatusNoContent)
	queued, err := f.store.PendingEvents(ctx, stream.StreamID, 0, false)
	if err != nil || len(queued) != 1 {
		t.Fatalf("queued = %v, %v", queued, err)
	}

	// The queued SET verifies as a Receiver would check it.
	set, err := setcodec.Decode(queued[0].SET, setcodec.VerifyOptions{
		Issuer:     f.issuer,
		Audience:   "https://bob.example/mobile",
		Algorithms: []ssf.SignatureAlgorithm{ssf.RS256},
		Keys:       []jose.SetKey{{KeyID: "k1", PublicKey: signingKey(t).Public()}},
		Registry:   ssf.NewRegistry(),
		Now:        func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatalf("queued verification SET does not verify: %v", err)
	}
	if v, ok := set.Event.(ssf.Verification); !ok || v.State != "abc" {
		t.Errorf("event = %#v", set.Event)
	}
	if !ssf.SubjectsEqual(set.Subject, ssf.OpaqueSubject{ID: stream.StreamID}) || set.JWTID != queued[0].JTI {
		t.Errorf("sub_id = %v, jti = %s", set.Subject, set.JWTID)
	}
	if len(set.Audience) != 2 {
		t.Errorf("aud = %v, want the stream's audience", set.Audience)
	}

	// Within min_verification_interval: 429 with Retry-After.
	f.now = f.now.Add(10 * time.Second)
	r := f.do("POST", md.VerificationEndpoint, "bob", map[string]any{"stream_id": stream.StreamID})
	expect(t, r, http.StatusTooManyRequests)
	if ra := r.header.Get("Retry-After"); ra != "20" {
		t.Errorf("Retry-After = %q, want 20", ra)
	}
	f.now = f.now.Add(20 * time.Second)
	expect(t, f.do("POST", md.VerificationEndpoint, "bob", map[string]any{"stream_id": stream.StreamID}), http.StatusNoContent)

	// Disabling the stream discards what is queued, and a disabled stream
	// accepts verification requests but holds nothing.
	expect(t, f.do("POST", md.StatusEndpoint, "bob", map[string]any{"stream_id": stream.StreamID, "status": "disabled"}), http.StatusOK)
	if queued, _ := f.store.PendingEvents(ctx, stream.StreamID, 0, false); len(queued) != 0 {
		t.Errorf("disabling left %d events queued", len(queued))
	}
	f.now = f.now.Add(time.Minute)
	expect(t, f.do("POST", md.VerificationEndpoint, "bob", map[string]any{"stream_id": stream.StreamID}), http.StatusNoContent)
	if queued, _ := f.store.PendingEvents(ctx, stream.StreamID, 0, false); len(queued) != 0 {
		t.Errorf("disabled stream queued an event: %d queued", len(queued))
	}
}

func TestMethodNotAllowed(t *testing.T) {
	f := newFixture(t)
	r := f.do("DELETE", f.metadata().StatusEndpoint, "alice", nil)
	expect(t, r, http.StatusMethodNotAllowed)
}

func TestStoreFailureIs500(t *testing.T) {
	f := newFixture(t, func(c *transmitter.Config) { c.Store = failingStore{memstore.NewStreamStore()} })
	expect(t, f.do("GET", f.metadata().ConfigurationEndpoint, "alice", nil), http.StatusInternalServerError)
}

type failingStore struct{ storage.StreamStore }

func (failingStore) StreamsForReceiver(context.Context, string) ([]storage.Stream, error) {
	return nil, errors.New("disk on fire")
}
