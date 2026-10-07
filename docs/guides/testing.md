# Testing with ssftest

An application plays one SSF role, and needs the other to test against.
[`ssftest`](../../ssftest) runs it in-process: a real SSFgo Transmitter
or Receiver on a TLS test server, with keys, certificates and
credentials generated per test and closed when the test ends. No mocks:
your code speaks the protocol to a real implementation.

## Testing a Receiver

`ssftest.NewTransmitter` starts a Transmitter supporting every event type
and both delivery methods. `ReceiverConfig` returns a `receiver.Config`
for it; set anything else your application needs before `receiver.New`:

```go
func TestRevokedSessionEnded(t *testing.T) {
	ctx := context.Background()
	tx := ssftest.NewTransmitter(t)
	registry := ssf.NewRegistry()
	if err := caep.Register(registry); err != nil {
		t.Fatal(err)
	}
	rx, err := receiver.New(ctx, tx.ReceiverConfig(registry))
	if err != nil {
		t.Fatal(err)
	}
	app := newApp(rx) // yours: installs its handlers
	stream, err := rx.EnsureStream(ctx, receiver.StreamRequest{})
	if err != nil {
		t.Fatal(err)
	}
	alice := ssf.IssSubSubject{Issuer: tx.Issuer(), Subject: "alice"}
	if err := tx.Emit(ctx, alice, caep.SessionRevoked{Common: caep.Common{EventTimestamp: ssf.NewNumericDate(time.Now())}}); err != nil {
		t.Fatal(err)
	}
	if _, err := rx.Poll(ctx, stream, receiver.PollOptions{}); err != nil {
		t.Fatal(err)
	}
	if app.signedIn(alice) {
		t.Error("alice is still signed in after session-revoked")
	}
}
```

`tx.SetAvailable(false)` makes the Transmitter answer 503 until set back,
to test how your Receiver copes with an outage. For push, pass
`ssftest.NewTransmitter` an option setting its `HTTPClient` to a client
that trusts your push endpoint.

## Testing a Transmitter

`ssftest.NewReceiver` starts a Receiver's push endpoint. Build your
Transmitter to push with its client and to accept the Receiver's token,
connect the Receiver, and point a stream at the endpoint:

```go
func TestSessionRevokedDelivered(t *testing.T) {
	ctx := context.Background()
	rx := ssftest.NewReceiver(t)
	tx, issuer, client := startTransmitter(t, rx.PushClient()) // yours: your Transmitter, on a test server
	rx.Connect(receiver.Config{
		Issuer:      issuer,
		Audience:    ssftest.ReceiverAudience, // your Authorize must give it this audience
		TokenSource: receiver.StaticToken("test-receiver-token"),
		HTTPClient:  client, // trusts your Transmitter's test server
	})
	if _, err := rx.Receiver().CreateStream(ctx, rx.PushStreamRequest()); err != nil {
		t.Fatal(err)
	}
	revokeSession(t, tx, "alice") // yours: whatever makes your Transmitter emit
	sets := rx.WaitFor(1)
	if _, ok := sets[0].Event.(caep.SessionRevoked); !ok {
		t.Errorf("received %T, want session-revoked", sets[0].Event)
	}
}
```

`Connect` fills in a registry of every event type, every signature
algorithm and in-memory storage where the configuration leaves them
unset. `WaitFor` fails the test after `ssftest.WaitTimeout`.

ssftest is for tests only: it trusts nothing but its own test servers,
and holds no secrets worth keeping.
