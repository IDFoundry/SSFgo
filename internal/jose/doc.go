// Package jose implements the JWS and JWK primitives SSFgo needs to sign
// and verify Security Event Tokens: compact serialization; RSASSA-PKCS1-v1_5
// and RSASSA-PSS with SHA-256, -384 and -512, ECDSA on P-256, P-384 and
// P-521, and EdDSA with Ed25519 — every asymmetric algorithm of RFC 7518
// §3.1, and RFC 8037's; and public JWK / JWK Set parsing.
//
// It is adapted from FAPIgo's internal/jose, with RS256 added (the CAEP
// Interoperability Profile §2.6 requires it) and JWE support removed (SSF
// does not use it). It encodes no SSF policy: which algorithms and keys
// are acceptable is decided one layer up, in internal/setcodec.
package jose
