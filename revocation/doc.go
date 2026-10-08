// Package revocation turns the security events a Receiver gets into
// revoked tokens: a session revoked, an account disabled or purged, a SCIM
// resource deactivated or deleted. A Revoker records each in a
// storage.RevocationStore, and answers whether a token the application
// already validated has since been revoked — as a call, or as net/http
// middleware.
//
//	rev, err := revocation.New(memstore.NewRevocationStore(), revocation.Options{
//		Issuers:   revocation.SameIssuer, // the identity provider is its own Transmitter
//		Events:    revocation.RecommendedEvents(),
//		Retention: 24 * time.Hour, // at least the longest token lifetime
//		Assurance: ssf.AssuranceDevelopment, // production needs a durable store
//	})
//	rev.Register(rx) // handle the events of Options.Events
//	api := rev.Middleware(func(r *http.Request) (revocation.Token, bool) {
//		claims, ok := validatedClaims(r) // the application's own token check
//		return revocation.Token{Issuer: claims.Iss, Subject: claims.Sub, SessionID: claims.Sid, IssuedAt: claims.Iat}, ok
//	}, apiHandler)
//
// Options.Issuers says which token issuer each Transmitter speaks for; its
// events revoke tokens of that issuer and no other. Within it, an event's
// subject maps to what it revokes: an iss_sub subject, or a complex
// subject's iss_sub "user", naming that issuer, to that user's tokens; a
// complex subject's "session" to that session's tokens — for
// session-revoked, only the session if the subject names one, unless it
// is Options.AllSessions, which stands for all of them. Email
// subjects map only with Options.MatchEmail. Subjects with no default
// mapping — SCIM resources, whose identifiers are not token subjects —
// need Options.KeysFor.
//
// Tokens issued at or before the event are revoked; tokens issued later —
// the user signing in again — are not.
package revocation
