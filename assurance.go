package ssf

// Assurance is the deployment a Transmitter, Receiver or Revoker is
// configured for. It is required: there is no default.
type Assurance string

const (
	// AssuranceDevelopment accepts what tests and local development use:
	// in-memory stores, loopback hosts.
	AssuranceDevelopment Assurance = "development"
	// AssuranceProduction refuses them: every store must declare it is
	// durable (storage.Capabilities), and, when the deployment is
	// horizontally scaled, consistent across instances; the issuer and
	// endpoints configured must not be loopback hosts.
	AssuranceProduction Assurance = "production"
)

// IsValid reports whether a is AssuranceDevelopment or
// AssuranceProduction.
func (a Assurance) IsValid() bool {
	return a == AssuranceDevelopment || a == AssuranceProduction
}
