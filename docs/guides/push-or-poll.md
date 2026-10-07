# Push or poll in Go

SSF delivers SETs one of two ways, and the Receiver chooses per stream:

- **Push** (RFC 8935): the Transmitter sends each SET to an HTTPS
  endpoint the Receiver serves. Delivery is prompt, but the Receiver must
  be reachable from the Transmitter.
- **Poll** (RFC 8936): the Receiver asks the Transmitter for SETs. It
  needs no inbound endpoint — behind a firewall, say — and with long
  polling it is nearly as prompt.

A Transmitter offers the methods in `transmitter.Config.DeliveryMethods`.
SSFgo implements both on each side.

## Push

On the Receiver, serve the endpoint and give the Transmitter a secret
Authorization header to send with every push. The handler refuses a push
without it:

```go
pushAuth := ssf.NewSecret("Bearer " + randomToken())
http.Handle("/ssf/events", rx.PushHandler(receiver.PushOptions{AuthorizationHeader: pushAuth}))

stream, err := rx.EnsureStream(ctx, receiver.StreamRequest{Delivery: &ssf.Delivery{
	Method:              ssf.DeliveryPush,
	EndpointURL:         "https://rp.example.com/ssf/events",
	AuthorizationHeader: pushAuth,
}})
if err != nil {
	return err
}
```

The handler answers 202 once a SET is verified and handled, 400 with an
RFC 8935 error for one it rejects, and 500 when a handler fails — so the
Transmitter delivers it again. A redelivered SET is acknowledged without
being handled twice.

On the Transmitter, `Run` delivers, retrying failures with exponential
backoff. Push makes the Transmitter connect to URLs Receivers choose, so
the default client refuses private and loopback addresses; restrict
endpoints further with `AllowPushEndpoint`:

```go
cfg.PushRetry = transmitter.RecommendedPushRetry()
cfg.AllowPushEndpoint = func(rx transmitter.Receiver, endpoint *url.URL) error {
	if !strings.HasSuffix(endpoint.Hostname(), ".customers.example.com") {
		return errors.New("push endpoints must be on customers.example.com")
	}
	return nil
}
tx, err := transmitter.New(cfg)
if err != nil {
	return err
}
go func() { _ = tx.Run(ctx) }()
```

A client you supply for other reasons keeps the address check if its
dialer uses `transmitter.PublicAddressControl`.

## Poll

On the Receiver, a stream without a `Delivery` is a poll stream.
`RunPoller` long-polls it until the context ends, acknowledging what it
handled:

```go
stream, err := rx.EnsureStream(ctx, receiver.StreamRequest{}) // a nil Delivery asks for poll
if err != nil {
	return err
}
go func() { _ = rx.RunPoller(ctx, stream) }()
```

For more control, call `rx.Poll(ctx, stream, receiver.PollOptions{Wait:
true})` yourself; what it handled is acknowledged with the next poll.

On the Transmitter, poll needs nothing beyond `Handler()`.
`transmitter.Limits.LongPollTimeout` is how long a waiting poll is held
before it is answered empty; keep it under the idle timeout of any proxy
in between.

## Either way

If the Transmitter advertises an `inactivity_timeout`, a stream the
Receiver neither polls nor otherwise uses is paused, disabled or deleted
when it passes. A push Receiver, which never calls the Transmitter while
SETs arrive, keeps its stream active with `KeepAlive`:

```go
go func() { _ = rx.KeepAlive(ctx, stream.StreamID) }()
```

## See also

- [GETTING_STARTED.md](../../GETTING_STARTED.md) for the rest of each
  role's setup.
- [Observability](observability.md) to watch delivery.
