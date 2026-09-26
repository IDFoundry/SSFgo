# SSFgo

SSFgo is a lightweight Go implementation of the OpenID Shared Signals
Framework, CAEP and RISC, providing embeddable Transmitter and Receiver
capabilities with a focus on standards compliance and interoperability.

> **Status: pre-release.** The Transmitter is complete: stream
> management, poll and push delivery, and event routing pass every module
> of the OIDF CAEP Interoperability Profile Transmitter test plan, in all
> four auth × delivery variants. The Receiver (v0.4) is next. See [ROADMAP.md](ROADMAP.md) and
> [conformance/README.md](conformance/README.md).

## Specifications

| Specification | Status in SSFgo |
|---|---|
| [OpenID Shared Signals Framework 1.0][ssf] | Transmitter done; Receiver in progress |
| [OpenID CAEP 1.0][caep] | all 8 event types |
| [OpenID RISC 1.0][risc] | all 14 event types |
| [CAEP Interoperability Profile 1.0][caep-interop] | Transmitter passes the OIDF plan; `caep/interop` enforces the profile |
| [RFC 8417][rfc8417] Security Event Token | done |
| [RFC 9493][rfc9493] Subject Identifiers | done |
| [RFC 8935][rfc8935] Push delivery / [RFC 8936][rfc8936] Poll delivery | Transmitter side done |

The module has no third-party dependencies.

## Design

See [ARCHITECTURE.md](ARCHITECTURE.md).

## License

MIT — see [LICENSE](LICENSE).

[ssf]: https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html
[caep]: https://openid.net/specs/openid-caep-1_0-final.html
[risc]: https://openid.net/specs/openid-risc-1_0-final.html
[caep-interop]: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html
[rfc8417]: https://www.rfc-editor.org/rfc/rfc8417
[rfc9493]: https://www.rfc-editor.org/rfc/rfc9493
[rfc8935]: https://www.rfc-editor.org/rfc/rfc8935
[rfc8936]: https://www.rfc-editor.org/rfc/rfc8936
