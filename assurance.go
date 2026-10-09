package ssf

import "strconv"

// Assurance is the deployment a Transmitter, Receiver or Revoker is
// configured for. It is required: there is no default, and the zero value
// is invalid.
type Assurance uint8

const (
	// AssuranceDevelopment accepts what tests and local development use:
	// in-memory stores, loopback hosts.
	AssuranceDevelopment Assurance = iota + 1
	// AssuranceProduction refuses them: every store must declare it is
	// durable (storage.Capabilities), and, when the deployment is
	// horizontally scaled, consistent across instances; every signing key
	// must be declared durable (KeyCustody); the issuer and endpoints
	// configured must not be loopback hosts.
	AssuranceProduction
)

// IsValid reports whether a is AssuranceDevelopment or
// AssuranceProduction.
func (a Assurance) IsValid() bool {
	return a == AssuranceDevelopment || a == AssuranceProduction
}

// String returns "development" or "production".
func (a Assurance) String() string {
	switch a {
	case AssuranceDevelopment:
		return "development"
	case AssuranceProduction:
		return "production"
	}
	return "Assurance(" + strconv.Itoa(int(a)) + ")"
}
