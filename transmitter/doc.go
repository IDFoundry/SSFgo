// Package transmitter is an embeddable SSF Transmitter (OpenID Shared
// Signals Framework 1.0).
//
// It serves the Transmitter Configuration Metadata, the signing JWKS and
// the stream management API (SSF 1.0 §7, §8) as one http.Handler. The
// application supplies the decisions SSF leaves to it — who a bearer token
// belongs to, which events it can emit, where streams are stored — through
// Config; it never handles the protocol messages itself.
//
//	tx, err := transmitter.New(transmitter.Config{...})
//	if err != nil { ... }
//	http.ListenAndServeTLS(addr, cert, key, tx.Handler())
//
// The handler routes on the full request path, derived from the issuer,
// so it must be mounted at the root of the issuer's host.
package transmitter
