# Other Transmitters

SSF 1.0 leaves some choices to the Transmitter: where it publishes its
metadata, what a stream's `aud` is, how it names "every session". An
SSFgo Receiver assumes the strictest reading by default, so against a
Transmitter that chose otherwise, something fails — loudly, at `New` or
when a stream is created, or by rejecting SETs. Each setting below opts
in to one such choice, for that Transmitter only.

## What to set, and when

| Symptom | Setting | What it costs |
|---|---|---|
| `New` cannot find the metadata: the Transmitter publishes it somewhere other than the locations SSF 1.0 §7.2, OpenID Providers and RISC use | `receiver.Config.MetadataURL` | Nothing: the metadata must still name `Issuer` |
| `New` refuses metadata whose endpoints are on another host than the issuer's | `receiver.Config.TrustedOrigins` | The access token goes to those origins too: list only the Transmitter's own |
| Creating a stream fails with `ErrAudienceMismatch`, the stream's `aud` being `<client_id>/<stream_id>` | `receiver.Config.AudiencePerStream`, with your OAuth client ID as `Audience` | A SET naming a stream the Receiver has not seen makes it read that stream from the Transmitter, bounded per stream |
| Revoking every session of a user revokes nothing: the session-revoked event names a placeholder session such as `ALL` | `revocation.Options.AllSessions` | A real session of that name would revoke all of the user's sessions |
| SETs are rejected for their subject: the Transmitter predates SSF 1.0, sending `subject` in the event or `subject_type` | `receiver.Config.AcceptLegacySubjects` | Older subject forms are accepted, from this Receiver's Transmitter only |
| SETs are discarded for a critical subject member the Receiver does not know | `receiver.Config.SubjectMembers` | None, if your handlers really act on the members listed |
| SETs are rejected for their algorithm | `receiver.Config.Algorithms` | None for an asymmetric algorithm; each key is used only with the algorithm its type allows |
| Stream management or polling is refused with 403 | the `Scopes` of your `TokenSource`: `ssf.manage` to manage streams, `ssf.read` to read and poll | — |

Leave each off until a Transmitter needs it: every one widens what the
Receiver accepts.

## Keycloak

Keycloak 26.8 ships an SSF Transmitter as an experimental feature
(`--features=ssf`), tested against SSFgo weekly in
[`interoptest`](../../interoptest/README.md). By default it gives each
stream the audience `<client_id>/<stream_id>`, and revokes every session
of a user by naming the session `ALL`:

```go
rx, err := receiver.New(ctx, receiver.Config{
	Issuer:            "https://keycloak.example.com/realms/acme",
	Audience:          "rp", // the receiver client's ID
	AudiencePerStream: true, // the stream's "aud" is rp/<stream_id>
	Registry:          registry,
	Algorithms:        receiver.RecommendedAlgorithms(),
	TokenSource: &receiver.ClientCredentials{
		TokenURL:     "https://keycloak.example.com/realms/acme/protocol/openid-connect/token",
		ClientID:     "rp",
		ClientSecret: ssf.NewSecret(os.Getenv("SSF_CLIENT_SECRET")),
		AuthMethod:   receiver.ClientSecretBasic,
		Scopes:       []string{"ssf.manage", "ssf.read"}, // client scopes Keycloak creates
	},
	ReplayStore: replay,
	Assurance:   ssf.AssuranceProduction,
	Limits:      receiver.RecommendedLimits(),
})
if err != nil {
	return err
}
rev, err := revocation.New(revocation.Options{
	Store:       revocations,
	Issuers:     revocation.SameIssuer, // Keycloak issues the tokens it revokes
	Events:      revocation.RecommendedEvents(),
	Retention:   24 * time.Hour,
	Assurance:   ssf.AssuranceProduction,
	AllSessions: "ALL", // Keycloak's "log out all sessions"
})
if err != nil {
	return err
}
```

Setting the receiver client's `ssf.streamAudience` attribute to your
Receiver's audience removes the need for `AudiencePerStream`. Events
reach a stream only for the client's default subjects — the
`ssf.defaultSubjects` attribute `ALL`, or users added to the stream.
Keycloak's account-disabled reasons, such as `disabled-by-admin`, are
its own; SSFgo accepts reasons RISC 1.0 does not list.
[`interoptest/README.md`](../../interoptest/README.md) records the rest of
what Keycloak does that isn't obvious.
