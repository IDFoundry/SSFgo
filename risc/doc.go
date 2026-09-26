// Package risc implements the event types of OpenID Risk Incident Sharing
// and Coordination 1.0 (RISC) on top of the Shared Signals Framework.
//
// Call Register to add them to an ssf.Registry:
//
//	r := ssf.NewRegistry()
//	if err := risc.Register(r); err != nil { ... }
//
// RISC and CAEP are independent event families. The deprecated RISC
// sessions-revoked event is its own type here, not an alias of CAEP's
// session-revoked; register both families to receive both.
package risc
