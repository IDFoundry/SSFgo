# The CAEP Interoperability Profile in Go

SSF and CAEP leave choices open: which signing algorithms, which subject
formats, which claims an event must carry. The [CAEP Interoperability
Profile 1.0](https://openid.net/specs/openid-caep-interoperability-profile-1_0.html)
fixes them, so independently built Transmitters and Receivers work
together. The [`caep/interop`](../../caep/interop) package holds a
configuration — and, on a Transmitter, every event emitted — to it.

## A Transmitter

`ApplyTransmitter` checks the configuration against the profile, and
installs `interop.ValidateEvent` as its event validator, so `Emit`
refuses an event the profile does not allow:

```go
cfg := transmitter.Config{
	Issuer:          "https://idp.example.com",
	SigningKeys:     []transmitter.SigningKey{{Signer: key, Algorithm: ssf.RS256, KeyID: "2026-10"}},
	EventsSupported: interop.EventTypes(), // the profile's event types
	DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPush, ssf.DeliveryPoll},
	DefaultSubjects: ssf.DefaultSubjectsNone,
	// ... Store, Authorize, PermitEvent, Limits, PushRetry, Assurance
}
if err := interop.ApplyTransmitter(&cfg); err != nil {
	return err // the configuration does not meet the profile
}
```

`ApplyTransmitter` requires RS256 as the active signing algorithm (§2.6),
both push and poll delivery (§2.3.8.1), and at least one of the profile's
event types (§3). `ValidateEvent` requires each CAEP event's subject to
be an email or iss_sub identifier (§2.5), and session-revoked,
credential-change and device-compliance-change to carry a non-empty
`reason_admin` (§3.1–§3.3). The profile's `ssf.read` and `ssf.manage`
scopes are yours to check in `Authorize`; `transmitter.AccessFromScopes`
maps them. An event that meets the profile:

```go
err = tx.Emit(ctx, ssf.IssSubSubject{Issuer: "https://idp.example.com", Subject: "alice"},
	caep.SessionRevoked{Common: caep.Common{
		EventTimestamp: ssf.NewNumericDate(time.Now()),
		ReasonAdmin:    ssf.LocalizedText{"en": "Signed out by an administrator"},
	}})
```

## A Receiver

`ApplyReceiver` checks the Receiver's configuration, and makes
`receiver.New` refuse a Transmitter whose metadata does not meet the
profile:

```go
rcfg := receiver.Config{
	Issuer:      "https://idp.example.com",
	Audience:    "https://rp.example.com",
	Registry:    registry, // with caep.Register
	Algorithms:  []ssf.SignatureAlgorithm{ssf.RS256},
	TokenSource: tokens,
	ReplayStore: replay,
	Assurance:   ssf.AssuranceProduction,
	Limits:      receiver.RecommendedLimits(),
}
if err := interop.ApplyReceiver(&rcfg); err != nil {
	return err
}
rx, err := receiver.New(ctx, rcfg) // fails if the Transmitter's metadata is not interoperable
if err != nil {
	return err
}
```

## Conformance

SSFgo passes the OpenID Foundation's CAEP Interoperability conformance
plans for both roles; [conformance/README.md](../../conformance/README.md)
records the results and how to run them.
