// Package caep implements the eight event types of OpenID Continuous
// Access Evaluation Profile 1.0 (CAEP) on top of the Shared Signals
// Framework.
//
// Call Register to add them to an ssf.Registry:
//
//	r := ssf.NewRegistry()
//	if err := caep.Register(r); err != nil { ... }
package caep
