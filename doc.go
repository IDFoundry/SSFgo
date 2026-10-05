// Package ssf holds the value types shared by every part of SSFgo: subject
// identifiers (RFC 9493 and OpenID Shared Signals Framework 1.0 §3), the
// Event contract and Registry that event families such as caep, risc and
// scim plug into, SSF's own verification and stream-updated events, and the
// decoded view of a Security Event Token (SET).
//
// This package knows nothing about any particular event family. It never
// imports caep, risc or scim; they register themselves with a Registry
// instead.
//
// Encoding and signing SETs is deliberately not exposed here. Applications
// emit typed events through a Transmitter and receive verified SETs from a
// Receiver; neither needs to build a JWT by hand.
package ssf
