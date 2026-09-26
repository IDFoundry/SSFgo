package interop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/caep/interop"
	"github.com/idfoundry/ssfgo/risc"
	"github.com/idfoundry/ssfgo/storage/memstore"
	"github.com/idfoundry/ssfgo/transmitter"
)

func config(t *testing.T) transmitter.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return transmitter.Config{
		Issuer:          "https://tx.example",
		SigningKeys:     []transmitter.SigningKey{{Signer: key, Algorithm: ssf.RS256, KeyID: "k"}},
		EventsSupported: []ssf.EventType{caep.SessionRevokedEventType},
		DeliveryMethods: []ssf.DeliveryMethod{ssf.DeliveryPoll, ssf.DeliveryPush},
		DefaultSubjects: ssf.DefaultSubjectsAll,
		Store:           memstore.New(),
		Authorize:       func(context.Context, string) (transmitter.Receiver, error) { return transmitter.Receiver{}, nil },
	}
}

func TestCheckTransmitterConfig(t *testing.T) {
	if err := interop.CheckTransmitterConfig(config(t)); err != nil {
		t.Fatalf("conforming config rejected: %v", err)
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, mutate := range map[string]func(*transmitter.Config){
		"ES256 key": func(c *transmitter.Config) {
			c.SigningKeys[0] = transmitter.SigningKey{Signer: ec, Algorithm: ssf.ES256, KeyID: "k"}
		},
		"PS256 key":        func(c *transmitter.Config) { c.SigningKeys[0].Algorithm = ssf.PS256 },
		"no keys":          func(c *transmitter.Config) { c.SigningKeys = nil },
		"poll only":        func(c *transmitter.Config) { c.DeliveryMethods = []ssf.DeliveryMethod{ssf.DeliveryPoll} },
		"no interop event": func(c *transmitter.Config) { c.EventsSupported = []ssf.EventType{caep.RiskLevelChangeEventType} },
	} {
		c := config(t)
		mutate(&c)
		if err := interop.CheckTransmitterConfig(c); !errors.Is(err, interop.ErrNotInterop) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidateEvent(t *testing.T) {
	reason := caep.Common{ReasonAdmin: ssf.LocalizedText{"en": "why"}}
	email := ssf.EmailSubject{Email: "a@example.com"}
	cases := []struct {
		name    string
		subject ssf.Subject
		event   ssf.Event
		ok      bool
	}{
		{"session-revoked, email", email, caep.SessionRevoked{Common: reason}, true},
		{"credential-change, iss_sub", ssf.IssSubSubject{Issuer: "https://i", Subject: "s"}, caep.CredentialChange{Common: reason, CredentialType: "pin", ChangeType: "create"}, true},
		{"device-compliance-change needs no reason", email, caep.DeviceComplianceChange{PreviousStatus: caep.Compliant, CurrentStatus: caep.NotCompliant}, true},
		{"session-revoked without reason_admin", email, caep.SessionRevoked{}, false},
		{"credential-change without reason_admin", email, caep.CredentialChange{CredentialType: "pin", ChangeType: "create"}, false},
		{"opaque subject", ssf.OpaqueSubject{ID: "x"}, caep.SessionRevoked{Common: reason}, false},
		{"complex subject", ssf.ComplexSubject{User: email}, caep.SessionRevoked{Common: reason}, false},
		{"RISC event is out of scope", ssf.OpaqueSubject{ID: "x"}, risc.AccountDisabled{}, true},
	}
	for _, c := range cases {
		err := interop.ValidateEvent(c.subject, c.event)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestApply(t *testing.T) {
	c := config(t)
	called := false
	c.EventValidator = func(ssf.Subject, ssf.Event) error { called = true; return nil }
	if err := interop.Apply(&c); err != nil {
		t.Fatal(err)
	}
	if err := c.EventValidator(ssf.OpaqueSubject{ID: "x"}, caep.SessionRevoked{}); !errors.Is(err, interop.ErrNotInterop) || !called {
		t.Errorf("installed validator: %v, previous called %v", err, called)
	}
	bad := config(t)
	bad.DeliveryMethods = []ssf.DeliveryMethod{ssf.DeliveryPush}
	if err := interop.Apply(&bad); err == nil || bad.EventValidator != nil {
		t.Error("Apply accepted a non-conforming config or modified it")
	}
}
