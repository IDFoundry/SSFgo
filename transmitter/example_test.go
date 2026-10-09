package transmitter_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/storage/memstore"
	"github.com/idfoundry/ssfgo/transmitter"
)

// A Transmitter for development — a key made at start, an in-memory
// store — serving its metadata. New does no I/O; Handler serves the
// metadata, the JWKS and the stream management API.
func ExampleNew() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	tx, err := transmitter.New(transmitter.Config{
		Issuer:          "https://idp.example.com",
		SigningKeys:     []transmitter.SigningKey{{Signer: key, Algorithm: ssf.RS256, KeyID: "dev"}},
		EventsSupported: []ssf.EventType{caep.SessionRevokedEventType},
		DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPoll},
		DefaultSubjects: ssf.DefaultSubjectsNone,
		Store:           memstore.NewStreamStore(),
		Assurance:       ssf.AssuranceDevelopment,
		Limits:          transmitter.RecommendedLimits(),
		Authorize: func(context.Context, string) (transmitter.Receiver, error) {
			return transmitter.Receiver{}, transmitter.ErrInvalidToken // yours: check the access token
		},
		PermitEvent: transmitter.PermitAll,
	})
	if err != nil {
		panic(err) // every problem with the configuration, each naming its field
	}

	rec := httptest.NewRecorder()
	tx.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://idp.example.com/.well-known/ssf-configuration", nil))
	var md ssf.TransmitterMetadata
	if err := json.Unmarshal(rec.Body.Bytes(), &md); err != nil {
		panic(err)
	}
	fmt.Println(rec.Code, md.Issuer, md.DeliveryMethodsSupported)
	// Output: 200 https://idp.example.com [urn:ietf:rfc:8936]
}
