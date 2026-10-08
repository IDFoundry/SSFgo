package revocation_test

import (
	"context"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/revocation"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/scim"
	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

// FuzzIssuerScope holds the Revoker to its trust boundary for any subject:
// a SET from the one trusted Transmitter revokes only tokens of the issuer
// it speaks for, never with an empty identifier, and a SET from any other
// Transmitter revokes nothing.
func FuzzIssuerScope(f *testing.F) {
	for _, s := range []string{
		`{"format":"iss_sub","iss":"https://idp-a.example","sub":"alice"}`,
		`{"format":"iss_sub","iss":"https://idp-b.example","sub":"bob"}`,
		`{"format":"email","email":"alice@example.com"}`,
		`{"format":"complex","user":{"format":"iss_sub","iss":"https://idp-a.example","sub":"alice"},"session":{"format":"opaque","id":"ALL"}}`,
		`{"format":"complex","user":{"format":"iss_sub","iss":"https://idp-b.example","sub":"bob"},"session":{"format":"iss_sub","iss":"https://idp-b.example","sub":"sid"}}`,
		`{"format":"aliases","identifiers":[{"format":"opaque","id":"x"},{"format":"iss_sub","iss":"https://idp-b.example","sub":"bob"}]}`,
		`{"format":"scim","uri":"/Users/1"}`,
	} {
		for event := range byte(3) {
			f.Add([]byte(s), event, true)
			f.Add([]byte(s), event, false)
		}
	}
	const trusted, tokenIssuer = "https://tx-a.example", "https://idp-a.example"
	events := []ssf.Event{caep.SessionRevoked{}, risc.AccountDisabled{}, scim.Deactivate{}}
	f.Fuzz(func(t *testing.T, subject []byte, event byte, fromTrusted bool) {
		s, err := ssf.ParseSubject(subject)
		if err != nil {
			return
		}
		set := ssf.SET{Issuer: "https://tx-b.example", IssuedAt: time.Now(), Subject: s, Event: events[int(event)%len(events)]}
		if fromTrusted {
			set.Issuer = trusted
		}
		var recorded []storage.RevocationKey
		r, err := revocation.New(memstore.NewRevocationStore(), revocation.Options{
			Issuers:     revocation.StaticTokenIssuers{trusted: tokenIssuer},
			Events:      revocation.RecommendedEvents(),
			Retention:   time.Hour,
			Assurance:   ssf.AssuranceDevelopment,
			MatchEmail:  true,
			AllSessions: "ALL",
			OnRevoke: func(_ context.Context, keys []storage.RevocationKey, _ ssf.SET) error {
				recorded = append(recorded, keys...)
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Handle(context.Background(), set); err != nil {
			t.Fatal(err)
		}
		if !fromTrusted && len(recorded) > 0 {
			t.Fatalf("an untrusted Transmitter revoked %v", recorded)
		}
		for _, k := range recorded {
			if k.Issuer != tokenIssuer || k.Value == "" {
				t.Fatalf("revoked %+v from %s", k, subject)
			}
		}
	})
}
