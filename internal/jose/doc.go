// Package jose implements the JWS and JWK primitives SSFgo needs to sign
// and verify Security Event Tokens: compact serialization, RS256, PS256,
// ES256 and EdDSA signatures, and public JWK / JWK Set parsing.
//
// It is adapted from FAPIgo's internal/jose, with RS256 added (the CAEP
// Interoperability Profile §2.6 requires it) and JWE support removed (SSF
// does not use it). It encodes no SSF policy: which algorithms and keys
// are acceptable is decided one layer up, in internal/setcodec.
package jose
