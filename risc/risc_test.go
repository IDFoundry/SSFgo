package risc_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/risc"
)

var allTypes = []ssf.EventType{
	risc.AccountCredentialChangeRequiredEventType, risc.AccountPurgedEventType,
	risc.AccountDisabledEventType, risc.AccountEnabledEventType,
	risc.IdentifierChangedEventType, risc.IdentifierRecycledEventType,
	risc.CredentialCompromiseEventType, risc.OptInEventType,
	risc.OptOutInitiatedEventType, risc.OptOutCancelledEventType,
	risc.OptOutEffectiveEventType, risc.RecoveryActivatedEventType,
	risc.RecoveryInformationChangedEventType, risc.SessionsRevokedEventType,
}

func registry(t *testing.T) *ssf.Registry {
	t.Helper()
	r := ssf.NewRegistry()
	if err := risc.Register(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRegister(t *testing.T) {
	r := registry(t)
	for _, typ := range allTypes {
		if !r.Supports(typ) {
			t.Errorf("%s not registered", typ)
		}
	}
	if got := len(r.Types()); got != 2+14 {
		t.Errorf("registry holds %d types, want 16", got)
	}
	if err := risc.Register(r); err == nil {
		t.Error("registering RISC twice succeeded")
	}
	// CAEP and RISC coexist: CAEP's session-revoked and RISC's deprecated
	// sessions-revoked are different event types.
	if err := caep.Register(r); err != nil {
		t.Fatalf("CAEP alongside RISC: %v", err)
	}
}

// Every attribute-free RISC event decodes from the empty object the OIDF
// conformance suite sends for it, and ignores unknown members.
func TestEmptyEvents(t *testing.T) {
	r := registry(t)
	for _, typ := range allTypes {
		switch typ {
		case risc.CredentialCompromiseEventType:
			continue
		}
		for _, payload := range []string{`{}`, `{"unknown":1}`} {
			e, err := r.Decode(typ, json.RawMessage(payload))
			if err != nil {
				t.Errorf("%s %s: %v", typ, payload, err)
				continue
			}
			if e.EventType() != typ {
				t.Errorf("decoded %T for %s", e, typ)
			}
		}
	}
}

func TestDecode(t *testing.T) {
	r := registry(t)
	cases := []struct {
		typ  ssf.EventType
		json string
		want ssf.Event
	}{
		{risc.AccountDisabledEventType, `{"reason":"hijacking"}`, risc.AccountDisabled{Reason: risc.DisabledHijacking}},
		{risc.AccountDisabledEventType, `{"reason":"bulk-account"}`, risc.AccountDisabled{Reason: risc.DisabledBulkAccount}},
		// A reason RISC does not list, as Transmitters send.
		{risc.AccountDisabledEventType, `{"reason":"disabled-by-admin"}`, risc.AccountDisabled{Reason: "disabled-by-admin"}},
		{risc.IdentifierChangedEventType, `{"new-value":"john.roe@example.com"}`, risc.IdentifierChanged{NewValue: "john.roe@example.com"}},
		{risc.CredentialCompromiseEventType, `{"credential_type":"password"}`, risc.CredentialCompromise{CredentialType: caep.CredentialPassword}},
		{risc.CredentialCompromiseEventType,
			`{"credential_type":"pin","event_timestamp":1615304991,"reason_admin":{"en":"Found in breach corpus"}}`,
			risc.CredentialCompromise{
				CredentialType: caep.CredentialPIN,
				EventTimestamp: ssf.NewNumericDate(time.Unix(1615304991, 0).UTC()),
				ReasonAdmin:    ssf.LocalizedText{"en": "Found in breach corpus"},
			}},
	}
	for _, c := range cases {
		got, err := r.Decode(c.typ, json.RawMessage(c.json))
		if err != nil {
			t.Errorf("%s: %v", c.json, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("got %#v, want %#v", got, c.want)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	r := registry(t)
	for name, c := range map[string]struct {
		typ  ssf.EventType
		json string
	}{
		"disabled reason not a string": {risc.AccountDisabledEventType, `{"reason":5}`},
		"compromise no type":           {risc.CredentialCompromiseEventType, `{}`},
		"compromise reason string":     {risc.CredentialCompromiseEventType, `{"credential_type":"password","reason_admin":"leaked"}`},
		"compromise empty reason":      {risc.CredentialCompromiseEventType, `{"credential_type":"password","reason_user":{}}`},
		"identifier new-value number":  {risc.IdentifierChangedEventType, `{"new-value":5}`},
	} {
		if _, err := r.Decode(c.typ, json.RawMessage(c.json)); !errors.Is(err, ssf.ErrInvalidEvent) {
			t.Errorf("%s: error = %v, want ErrInvalidEvent", name, err)
		}
	}
}

func TestIdentifierEventsRequireEmailOrPhone(t *testing.T) {
	for _, ev := range []ssf.SubjectConstrainedEvent{risc.IdentifierChanged{}, risc.IdentifierRecycled{}} {
		for _, ok := range []ssf.Subject{
			ssf.EmailSubject{Email: "a@b.example"},
			ssf.PhoneNumberSubject{PhoneNumber: "+12065550100"},
		} {
			if err := ev.ValidateSubject(ok); err != nil {
				t.Errorf("%T rejected %T: %v", ev, ok, err)
			}
		}
		if err := ev.ValidateSubject(ssf.IssSubSubject{Issuer: "https://i", Subject: "s"}); err == nil {
			t.Errorf("%T accepted an iss_sub subject", ev)
		}
	}
}
