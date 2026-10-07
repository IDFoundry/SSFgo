package ssf

// KeyCustody is what is declared about how a private key is held. Under
// AssuranceProduction a Transmitter's signing keys, and a Receiver's
// private_key_jwt key, must be declared durable — and, when the
// deployment is horizontally scaled, shared by every instance — because
// nothing about a crypto.Signer says whether its key survives a restart.
//
// A Transmitter signs SETs when it queues them, so a signing key made
// afresh at each start strands every SET queued before a restart: the
// Receiver no longer finds its key, and rejects it. Instances with keys of
// their own sign SETs that only some JWKS documents verify.
type KeyCustody struct {
	// Durable means the key survives a process restart: held by a KMS or
	// an HSM, or loaded from durable storage, rather than generated at
	// startup.
	Durable bool
	// CrossInstanceConsistent means every instance of a horizontally
	// scaled deployment uses the same key.
	CrossInstanceConsistent bool
}

// KeyCustodyAssurance is implemented by a crypto.Signer that declares how
// its key is held — a KMS or HSM client, say. A key that neither
// implements it nor has custody declared for it in its configuration
// counts as neither durable nor shared.
type KeyCustodyAssurance interface {
	KeyCustody() KeyCustody
}
