# Keys in a KMS or HSM

A Transmitter signs every SET, and a Receiver using `private_key_jwt`
signs its client assertions. SSFgo takes each key as a `crypto.Signer` —
a public key and a `Sign` operation — and never reads private key
material, so the key can stay in a cloud KMS or an HSM and never enter
your process. Most KMS SDKs and PKCS#11 libraries already provide a
`crypto.Signer`; for a service that doesn't, the adapter below is all it
takes.

## Custody

Nothing about a `crypto.Signer` says how its key is held, so you declare
it, as an `ssf.KeyCustody`:

- **Durable**: the key survives a restart. A Transmitter signs SETs when
  it queues them, so a key generated at each start strands every SET
  queued before a restart: Receivers no longer find its key, and reject
  it.
- **CrossInstanceConsistent**: every instance uses the same key, so a SET
  any instance signs verifies against the JWKS any instance serves.

Under `ssf.AssuranceProduction` every signing key must be declared
durable, and with `HorizontallyScaled` shared too; `New` refuses one that
isn't. Under `ssf.AssuranceDevelopment` a key from `rsa.GenerateKey` is
fine.

## Adapting a signing service

A signer can declare its own custody by implementing
`ssf.KeyCustodyAssurance`:

```go
// kmsSigner adapts a remote signing service — a cloud KMS key, say — to
// crypto.Signer. The private key never leaves the service.
type kmsSigner struct {
	service signingService // yours: your KMS client
	keyName string
	public  crypto.PublicKey // fetched once from the service
}

func (s *kmsSigner) Public() crypto.PublicKey { return s.public }

// Sign signs a digest SSFgo has already hashed. For RS256, opts is the
// hash; for PS256, an *rsa.PSSOptions asking for a salt as long as the
// hash; for ES256 the signature must be ASN.1 DER, as crypto.Signer
// requires. crypto.Signer carries no context, so bound the call with a
// timeout in your client.
func (s *kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.service.AsymmetricSign(context.Background(), s.keyName, digest, opts)
}

// KeyCustody implements ssf.KeyCustodyAssurance: the service holds the
// key, durably, and every instance signs with it.
func (s *kmsSigner) KeyCustody() ssf.KeyCustody {
	return ssf.KeyCustody{Durable: true, CrossInstanceConsistent: true}
}
```

## Configure the Transmitter

```go
signer := &kmsSigner{service: kms, keyName: "projects/idp/locations/global/keyRings/ssf/cryptoKeys/set-signing/cryptoKeyVersions/3", public: publicKey}
cfg.SigningKeys = []transmitter.SigningKey{{Signer: signer, Algorithm: ssf.RS256, KeyID: "set-signing-3"}}
cfg.Assurance = ssf.AssuranceProduction
cfg.HorizontallyScaled = true
```

A signer from an SDK doesn't declare its custody; declare it alongside.
It is your assertion, and nothing verifies it:

```go
cfg.SigningKeys = []transmitter.SigningKey{{
	Signer:    sdkSigner, // yours: your KMS SDK's crypto.Signer
	Algorithm: ssf.ES256,
	KeyID:     "set-signing-es-1",
	Custody:   ssf.KeyCustody{Durable: true, CrossInstanceConsistent: true},
}}
```

The `KeyID` is the key's `kid` in the published JWKS; make it change
with every key, so Receivers can tell them apart.

## A Receiver's client key

With `private_key_jwt`, the Receiver authenticates to the authorization
server with a key whose public half the server has registered. The same
rules apply:

```go
tokens := &receiver.ClientCredentials{
	TokenURL:          "https://idp.example.com/oauth2/token",
	ClientID:          "rp",
	AuthMethod:        receiver.PrivateKeyJWT,
	SigningKey:        clientKey, // yours: a KMS-backed crypto.Signer
	SigningAlgorithm:  ssf.RS256,
	KeyID:             "rp-1",
	SigningKeyCustody: ssf.KeyCustody{Durable: true, CrossInstanceConsistent: true},
}
```

## Rotation

The first of `SigningKeys` signs; every key listed is published. To
rotate, create the new key version, put it first, and keep the old one
published until every Receiver has refetched the JWKS and every SET
signed with it has been delivered — at least `receiver.Limits.KeyMaxAge`
(24 hours in `RecommendedLimits`). A Receiver meeting an unknown `kid`
refetches at once, so SETs signed with the new key verify from the
start:

```go
next := &kmsSigner{service: kms, keyName: "projects/idp/locations/global/keyRings/ssf/cryptoKeys/set-signing/cryptoKeyVersions/4", public: nextPublicKey}
cfg.SigningKeys = []transmitter.SigningKey{
	{Signer: next, Algorithm: ssf.RS256, KeyID: "set-signing-4"},   // signs from now on
	{Signer: signer, Algorithm: ssf.RS256, KeyID: "set-signing-3"}, // still published
}
```

Then drop the old key from the list, and disable the old key version in
the KMS.
