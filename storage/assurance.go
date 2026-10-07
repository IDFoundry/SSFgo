package storage

// StoreAssurance is a store's declaration of its operational guarantees.
// A store optionally implements it; under ssf.AssuranceProduction the
// Transmitter, the Receiver and revocation each refuse a store that does
// not declare the guarantees they need, rather than trusting that a store
// meant for tests — an in-memory map — is fit for production.
//
// The declaration is the implementer's own, not verified. A store should
// also pass the storagetest contract suite for each interface it
// implements, which checks what is observable through it; durability and
// consistency across instances are not, and remain the implementer's
// responsibility.
type StoreAssurance interface {
	Capabilities() Capabilities
}

// Capabilities are what a store's implementer asserts about it.
type Capabilities struct {
	// Durable means what the store holds survives a process restart. An
	// in-memory map is not durable: a Receiver restarted on one would
	// accept replays of SETs it had handled, and a Revoker would forget
	// its revocations.
	Durable bool

	// CrossInstanceConsistent means several processes or hosts can share
	// the store safely, each seeing the others' writes and its atomic
	// operations holding across them — a shared database, not a
	// per-process map or a file on one host. Required for a horizontally
	// scaled deployment.
	CrossInstanceConsistent bool
}

// CapabilitiesOf returns what store declares, or none if it does not
// implement StoreAssurance.
func CapabilitiesOf(store any) Capabilities {
	if a, ok := store.(StoreAssurance); ok {
		return a.Capabilities()
	}
	return Capabilities{}
}
