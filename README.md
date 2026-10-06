# SSFgo

SSFgo is a lightweight Go implementation of the OpenID Shared Signals
Framework, CAEP and RISC, providing embeddable Transmitter and Receiver
capabilities with a focus on standards compliance and interoperability.

> **Status: API frozen for v1.0, not yet released.** Both roles are
> implemented; once `v1.0.0` is tagged the API is covered by
> [COMPATIBILITY.md](COMPATIBILITY.md). The Transmitter passes every
> module of the OIDF CAEP Interoperability Profile Transmitter plan, and
> the Receiver every module of the Receiver plan — see
> [conformance/README.md](conformance/README.md). The full matrix runs
> daily in CI. OIDF has not yet opened SSF certification. See
> [ROADMAP.md](ROADMAP.md).

## Specifications

| Specification | Status in SSFgo |
|---|---|
| [OpenID Shared Signals Framework 1.0][ssf] | Transmitter and Receiver |
| [OpenID CAEP 1.0][caep] | all 8 event types |
| [OpenID RISC 1.0][risc] | all 14 event types |
| [RFC 9967][rfc9967] SCIM events | all 12 event types and the `scim` subject; one event per SET |
| [CAEP Interoperability Profile 1.0][caep-interop] | both roles pass the OIDF plans; `caep/interop` enforces the profile for each |
| [RFC 8417][rfc8417] Security Event Token | done |
| [RFC 9493][rfc9493] Subject Identifiers | done |
| [RFC 8935][rfc8935] Push delivery / [RFC 8936][rfc8936] Poll delivery | both sides |

The module has no third-party dependencies. Durable storage for
PostgreSQL and SQLite is a separate module,
[`storage/sqlstore`](storage/sqlstore), which imports no database driver
itself.

## Usage

A Transmitter — for example inside an identity provider — serves the SSF
endpoints and emits events:

```go
tx, err := transmitter.New(transmitter.Config{
	Issuer:          "https://idp.example.com/ssf",
	SigningKeys:     []transmitter.SigningKey{{Signer: key, Algorithm: ssf.RS256, KeyID: "2026-09"}},
	EventsSupported: interop.EventTypes(),
	DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPush, ssf.DeliveryPoll},
	DefaultSubjects: ssf.DefaultSubjectsAll,
	Store:           memstore.NewStreamStore(),
	Authorize:       authorizeAccessToken, // your OAuth resource-server check
	PermitEvent:     permitEvent,          // which Receiver may see which subject's events
})
go tx.Run(ctx) // push delivery
http.ListenAndServeTLS(":443", cert, key, tx.Handler())

tx.Emit(ctx, ssf.IssSubSubject{Issuer: iss, Subject: "alice"}, caep.SessionRevoked{
	Common: caep.Common{ReasonAdmin: ssf.LocalizedText{"en": "Suspicious activity"}},
})
```

A Receiver — for example inside a relying party — creates a stream and
handles typed events:

```go
rx, err := receiver.New(ctx, receiver.Config{
	Issuer:      "https://idp.example.com/ssf",
	Audience:    "https://rp.example.com",
	Registry:    registry, // ssf.NewRegistry() + caep.Register
	Algorithms:  []ssf.SignatureAlgorithm{ssf.RS256},
	TokenSource: &receiver.ClientCredentials{TokenURL: tokenURL, ClientID: id, ClientSecret: secret, AuthMethod: receiver.ClientSecretBasic},
	ReplayStore: memstore.NewReplayStore(),
})
// Optional: interop.ApplyReceiver(&cfg) before receiver.New holds the
// Transmitter to the CAEP Interoperability Profile.
receiver.On(rx, func(ctx context.Context, set ssf.SET, e caep.SessionRevoked) error {
	return sessions.RevokeAll(ctx, set.Subject)
})
http.Handle("/ssf/events", rx.PushHandler(receiver.PushOptions{AuthorizationHeader: pushSecret}))
// Creates the stream on the first start; later starts reuse it, updating
// whatever changed, and wait out a Transmitter that is briefly unavailable.
stream, err := rx.EnsureStream(ctx, receiver.StreamRequest{Delivery: &ssf.Delivery{
	Method: ssf.DeliveryPush, EndpointURL: "https://rp.example.com/ssf/events", AuthorizationHeader: pushSecret,
}})
```

`memstore` keeps everything in memory. To survive restarts, or to run
several Transmitter instances on one database, use `storage/sqlstore`:

```go
// go get github.com/idfoundry/ssfgo/storage/sqlstore
db, err := sql.Open("pgx", dsn) // any database/sql driver for PostgreSQL or SQLite
err = sqlstore.CreateSchema(ctx, db, sqlstore.Postgres)
store, err := sqlstore.NewStreamStore(db, sqlstore.Postgres)   // transmitter.Config.Store
replay, err := sqlstore.NewReplayStore(db, sqlstore.Postgres)  // receiver.Config.ReplayStore
```

[`examples/session-revocation`](examples/session-revocation) runs both
sides in one process: `go run ./examples/session-revocation`.

## Design

See [ARCHITECTURE.md](ARCHITECTURE.md), and [SECURITY.md](SECURITY.md) for
the security model and how to report a vulnerability.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Changes are listed in
[CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE).

[ssf]: https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html
[caep]: https://openid.net/specs/openid-caep-1_0-final.html
[risc]: https://openid.net/specs/openid-risc-1_0-final.html
[caep-interop]: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html
[rfc8417]: https://www.rfc-editor.org/rfc/rfc8417
[rfc9967]: https://www.rfc-editor.org/rfc/rfc9967
[rfc9493]: https://www.rfc-editor.org/rfc/rfc9493
[rfc8935]: https://www.rfc-editor.org/rfc/rfc8935
[rfc8936]: https://www.rfc-editor.org/rfc/rfc8936
