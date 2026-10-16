# SSFgo

[![Release](https://img.shields.io/github/v/release/IDFoundry/SSFgo?filter=v*)](https://github.com/IDFoundry/SSFgo/releases)
[![CI](https://github.com/IDFoundry/SSFgo/actions/workflows/ci.yml/badge.svg)](https://github.com/IDFoundry/SSFgo/actions/workflows/ci.yml)
[![SSF Conformance](https://github.com/IDFoundry/SSFgo/actions/workflows/conformance.yml/badge.svg)](https://github.com/IDFoundry/SSFgo/actions/workflows/conformance.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/idfoundry/ssfgo.svg)](https://pkg.go.dev/github.com/idfoundry/ssfgo)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/IDFoundry/SSFgo/badge)](https://securityscorecards.dev/viewer/?uri=github.com/IDFoundry/SSFgo)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[![Quality Gate](https://sonarcloud.io/api/project_badges/quality_gate?project=IDFoundry_SSFgo)](https://sonarcloud.io/summary/new_code?id=IDFoundry_SSFgo)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_SSFgo&metric=coverage)](https://sonarcloud.io/summary/new_code?id=IDFoundry_SSFgo)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_SSFgo&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=IDFoundry_SSFgo)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_SSFgo&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=IDFoundry_SSFgo)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_SSFgo&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=IDFoundry_SSFgo)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_SSFgo&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=IDFoundry_SSFgo)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_SSFgo&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=IDFoundry_SSFgo)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_SSFgo&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=IDFoundry_SSFgo)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_SSFgo&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=IDFoundry_SSFgo)

SSFgo is a lightweight Go implementation of the OpenID Shared Signals
Framework, CAEP and RISC, providing embeddable Transmitter and Receiver
capabilities with a focus on standards compliance and interoperability.

> **Status: pre-1.0.** Both roles are implemented. Releases are v0.x,
> where a minor release may break the API; once `v1.0.0` is tagged it is
> covered by [COMPATIBILITY.md](COMPATIBILITY.md). The Transmitter passes every
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

## Install

Requires Go 1.26.6 or later (per `go.mod`'s `go` directive).

```sh
go get github.com/idfoundry/ssfgo
go get github.com/idfoundry/ssfgo/storage/sqlstore # durable storage, optional
```

## Usage

[GETTING_STARTED.md](GETTING_STARTED.md) walks through embedding each
role step by step, and [docs/guides](docs/guides) covers one feature
each — session revocation, push or poll, the CAEP Interoperability
Profile, SCIM events, storage and scaling, testing, observability and
keys in a KMS or HSM. In
brief:

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
	Assurance:       ssf.AssuranceDevelopment, // AssuranceProduction refuses in-memory stores: use storage/sqlstore
	Authorize:       authorizeAccessToken, // your OAuth resource-server check
	PermitEvent:     permitEvent,          // which Receiver may see which subject's events
	Limits:          transmitter.RecommendedLimits(),
	PushRetry:       transmitter.RecommendedPushRetry(),
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
	Algorithms:  receiver.RecommendedAlgorithms(),
	TokenSource: &receiver.ClientCredentials{TokenURL: tokenURL, ClientID: id, ClientSecret: ssf.NewSecret(secret), AuthMethod: receiver.ClientSecretBasic},
	ReplayStore: memstore.NewReplayStore(),
	Assurance:   ssf.AssuranceDevelopment,
	Limits:      receiver.RecommendedLimits(), // replay window, key age, clock skew
})
// Optional: interop.ApplyReceiver(&cfg) before receiver.New holds the
// Transmitter to the CAEP Interoperability Profile.
receiver.On(rx, func(ctx context.Context, set ssf.SET, e caep.SessionRevoked) error {
	return sessions.RevokeAll(ctx, set.Subject)
})
pushSecret := ssf.NewSecret("Bearer " + randomToken) // withheld from logs and %v; Reveal() reads it
http.Handle("/ssf/events", rx.PushHandler(receiver.PushOptions{AuthorizationHeader: pushSecret}))
// Creates the stream on the first start; later starts reuse it, updating
// whatever changed, and wait out a Transmitter that is briefly unavailable.
stream, err := rx.EnsureStream(ctx, receiver.StreamRequest{Delivery: &ssf.Delivery{
	Method: ssf.DeliveryPush, EndpointURL: "https://rp.example.com/ssf/events", AuthorizationHeader: pushSecret,
}})
```

`memstore` keeps everything in memory, so `ssf.AssuranceProduction`
refuses it. To survive restarts, or to run several instances on one
database (`HorizontallyScaled`, which needs PostgreSQL), use
`storage/sqlstore`:

```go
// go get github.com/idfoundry/ssfgo/storage/sqlstore
db, err := sql.Open("pgx", dsn) // any database/sql driver for PostgreSQL or SQLite
err = sqlstore.CreateSchema(ctx, db, sqlstore.Postgres)
store, err := sqlstore.NewStreamStore(ctx, db, sqlstore.Postgres)   // transmitter.Config.Store
replay, err := sqlstore.NewReplayStore(ctx, db, sqlstore.Postgres)  // receiver.Config.ReplayStore
revocations, err := sqlstore.NewRevocationStore(ctx, db, sqlstore.Postgres) // revocation.Options.Store
```

[`examples/session-revocation`](examples/session-revocation) runs both
sides in one process: `cd examples/session-revocation && go run .`. Like
every example, it is its own module and uses only the public API.

To revoke tokens as events arrive, [`revocation`](revocation) records
what session-revoked, account-disabled and similar events mean and checks
the application's validated tokens against it:

```go
rev, err := revocation.New(revocation.Options{
	Store:     memstore.NewRevocationStore(),
	Issuers:   revocation.SameIssuer,           // or StaticTokenIssuers{transmitter: tokenIssuer}
	Events:    revocation.RecommendedEvents(),  // session-revoked, account-disabled, ...
	Retention: 24 * time.Hour,                  // at least the longest token lifetime
	Assurance: ssf.AssuranceDevelopment,        // production needs a durable store, e.g. sqlstore
})
if err := rev.Register(rx); err != nil { // fails if rx's Registry lacks one of Events
	return err
}
api = rev.Middleware(tokenOf, api)   // 401 for a token issued before its revocation
```

Both roles report what they do through optional `Hooks` in their config,
for metrics or traces without a dependency on any metrics library, and
answer readiness probes with `Ready`:

```go
cfg.Hooks = receiver.Hooks{SET: func(ctx context.Context, i receiver.SETInfo) {
	setsTotal.WithLabelValues(string(i.EventType), i.Outcome.String()).Inc() // e.g. Prometheus
}}
http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
	if err := rx.Ready(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
})
```

To test an application that plays one role, [`ssftest`](ssftest) runs the
other in-process: `ssftest.NewTransmitter` for testing a Receiver,
`ssftest.NewReceiver` for testing a Transmitter.

```go
tx := ssftest.NewTransmitter(t)
rx, err := receiver.New(ctx, tx.ReceiverConfig(registry))
stream, err := rx.EnsureStream(ctx, receiver.StreamRequest{})
err = tx.Emit(ctx, subject, caep.SessionRevoked{...})
_, err = rx.Poll(ctx, stream, receiver.PollOptions{}) // your handlers run
```

## Command line

`ssf` inspects a Transmitter and its SETs with the Receiver's own checks:

```sh
go install github.com/idfoundry/ssfgo/cmd/ssf@latest

ssf metadata https://tx.example.com      # discover it as a Receiver does, or say why one would refuse it
ssf verify -issuer https://tx.example.com -audience https://rp.example.com set.jwt
ssf decode -unverified < set.jwt         # print a SET without checking anything
```

`verify` checks a SET's signature against the Transmitter's published
keys, and its issuer, audience, age, event type and subject, as delivery
does — through `receiver.Receiver.Verify`, which applications can call too.
Its JSON says `"verified": true` or `false`, and output escapes control
characters a SET might carry. `-ca-file` trusts a development
Transmitter's certificate; `-audience-per-stream` accepts per-stream
audiences, reading the stream with the token in `SSF_ACCESS_TOKEN`.

## Design

See [ARCHITECTURE.md](ARCHITECTURE.md), and [SECURITY.md](SECURITY.md) for
the security model and how to report a vulnerability.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Changes are listed in
[CHANGELOG.md](CHANGELOG.md), and [UPGRADING.md](UPGRADING.md) says what
to change for each breaking one.

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
