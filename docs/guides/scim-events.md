# SCIM events in Go

A SCIM service provider — a directory provisioning users and groups —
can tell the systems it provisions what changed, as security events
(RFC 9967), rather than leave them to poll. The [`scim`](../../scim)
package implements these events on SSF: resources created, patched,
replaced, deleted, activated and deactivated, feed membership changes,
and the completion of asynchronous SCIM requests.

Every SCIM event's subject is an `ssf.SCIMSubject`: the resource's path
relative to the service provider's base URI, and optionally its
`externalId`, `id` and attributes.

## Full or notice

The provisioning events come in two modes, each its own type:

- **Full** — `scim.CreateFull`, `PutFull`, `PatchFull` — carry the
  resource, or the SCIM PATCH request, in `Data`.
- **Notice** — `scim.CreateNotice`, `PutNotice`, `PatchNotice` — name the
  attributes that changed. The Receiver fetches the resource with a SCIM
  GET of the subject's URI if it needs it, under its own authorization.

Notice keeps personal data out of the event stream; full saves a
round trip.

## A Transmitter

Register the event types, list the ones you send in `EventsSupported`,
and emit them. The events of one SCIM transaction share a `txn`
(RFC 9967 §2.2), so emit each with `EmitTxn`:

```go
registry := ssf.NewRegistry()
if err := scim.Register(registry); err != nil {
	return err
}
user := ssf.SCIMSubject{URI: "/Users/2b2f880af6674ac284bae9381673d462", ExternalID: "jdoe"}
txn := "734f0614e3274f288f93ac74119dcf78" // one SCIM transaction
if err := tx.EmitTxn(ctx, txn, user, scim.PatchNotice{Attributes: []string{"emails", "name.familyName"}}); err != nil {
	return err
}
if err := tx.EmitTxn(ctx, txn, user, scim.Deactivate{}); err != nil {
	return err
}
```

RFC 9967 lets one SET carry several events; SSFgo sends exactly one per
SET, sharing the `txn`. For an asynchronous SCIM request, the
`scim.AsyncResponse` event's `txn` must be the value the service provider
returned to the client in `Set-Txn`.

## A Receiver

Register the types, request them on the stream, and handle each:

```go
receiver.On(rx, func(ctx context.Context, set ssf.SET, e scim.PatchNotice) error {
	resource := set.Subject.(ssf.SCIMSubject) // every SCIM event's subject is one
	return refreshFromSCIM(ctx, resource.URI, e.Attributes) // yours: a SCIM GET
})
receiver.On(rx, func(ctx context.Context, set ssf.SET, _ scim.Deactivate) error {
	return disableAccount(ctx, set.Subject.(ssf.SCIMSubject).URI) // yours
})
_, err := rx.EnsureStream(ctx, receiver.StreamRequest{
	EventsRequested: []ssf.EventType{scim.PatchNoticeEventType, scim.DeactivateEventType},
})
if err != nil {
	return err
}
```

A SET carrying several events is rejected as `invalid_request`.

To stop accepting a deactivated user's tokens too, the
[session revocation](session-revocation.md#scim-resources) guide maps SCIM
resources to users with `KeysFor`.
