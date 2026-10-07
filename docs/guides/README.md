# Guides

Short guides to one feature or use case each: what it is, when you need
it, and the SSFgo code for each role involved. For wiring a whole
deployment, start with [GETTING_STARTED](../../GETTING_STARTED.md). The
code in these guides is built against the library in CI.

| Guide | Covers |
|---|---|
| [Session revocation in Go](session-revocation.md) | Refusing the tokens of sessions and accounts an identity provider revokes: the `revocation` package, its middleware, and mapping Transmitters to token issuers |
| [Push or poll in Go](push-or-poll.md) | Choosing a delivery method, and what each needs on each side: push endpoints and their protection, long polling, keeping streams active |
| [The CAEP Interoperability Profile in Go](caep-interop.md) | Holding a Transmitter or Receiver to the profile with `caep/interop` |
| [SCIM events in Go](scim-events.md) | Provisioning events (RFC 9967): full and notice modes, transactions, and handling them |
| [Storage and scaling in Go](storage-and-scaling.md) | memstore and sqlstore, production assurance, running several instances, and writing your own store |
| [Testing with ssftest](testing.md) | Testing a Receiver or a Transmitter against a real in-process counterpart |
| [Observability in Go](observability.md) | Hooks for metrics and traces, and readiness probes |
