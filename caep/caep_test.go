package caep_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
)

func registry(t *testing.T) *ssf.Registry {
	t.Helper()
	r := ssf.NewRegistry()
	if err := caep.Register(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRegister(t *testing.T) {
	r := registry(t)
	for _, typ := range []ssf.EventType{
		caep.SessionRevokedEventType, caep.TokenClaimsChangeEventType,
		caep.CredentialChangeEventType, caep.AssuranceLevelChangeEventType,
		caep.DeviceComplianceChangeEventType, caep.SessionEstablishedEventType,
		caep.SessionPresentedEventType, caep.RiskLevelChangeEventType,
	} {
		if !r.Supports(typ) {
			t.Errorf("%s not registered", typ)
		}
	}
	if got := len(r.Types()); got != 2+8 {
		t.Errorf("registry holds %d types, want 10", got)
	}
	if err := caep.Register(r); err == nil {
		t.Error("registering CAEP twice succeeded")
	}
}

// TestDecode decodes payloads shaped like those the OIDF conformance suite
// sends (AbstractOIDSSFReceiverTestModule.generateSsfEventExample).
func TestDecode(t *testing.T) {
	ts := ssf.NewNumericDate(time.Unix(1615304991, 0).UTC())
	cases := []struct {
		typ  ssf.EventType
		json string
		want ssf.Event
	}{
		{caep.SessionRevokedEventType,
			`{"initiating_entity":"policy","reason_admin":{"en":"Policy Violation: C076E82F"},"reason_user":{"en":"Land speed violation.","es":"Violacion de velocidad en tierra."},"event_timestamp":1615304991}`,
			caep.SessionRevoked{Common: caep.Common{
				EventTimestamp: ts, InitiatingEntity: caep.InitiatedByPolicy,
				ReasonAdmin: ssf.LocalizedText{"en": "Policy Violation: C076E82F"},
				ReasonUser:  ssf.LocalizedText{"en": "Land speed violation.", "es": "Violacion de velocidad en tierra."},
			}}},
		{caep.TokenClaimsChangeEventType,
			`{"event_timestamp":1615304991,"claims":{"role":"ro-admin"}}`,
			caep.TokenClaimsChange{Common: caep.Common{EventTimestamp: ts}, Claims: map[string]any{"role": "ro-admin"}}},
		{caep.CredentialChangeEventType,
			`{"event_timestamp":1615304991,"credential_type":"fido2-roaming","change_type":"create","fido2_aaguid":"accced6a-63f5-490a-9eea-e59bc1896cfc","friendly_name":"Jane's USB authenticator","initiating_entity":"user","reason_admin":{"en":"User self-enrollment"}}`,
			caep.CredentialChange{
				Common: caep.Common{
					EventTimestamp: ts, InitiatingEntity: caep.InitiatedByUser,
					ReasonAdmin: ssf.LocalizedText{"en": "User self-enrollment"},
				},
				CredentialType: caep.CredentialFIDO2Roaming, ChangeType: caep.ChangeCreate,
				FIDO2AAGUID: "accced6a-63f5-490a-9eea-e59bc1896cfc", FriendlyName: "Jane's USB authenticator",
			}},
		{caep.AssuranceLevelChangeEventType,
			`{"namespace":"NIST-AAL","current_level":"nist-aal2","previous_level":"nist-aal1","change_direction":"increase","initiating_entity":"user","event_timestamp":1615304991}`,
			caep.AssuranceLevelChange{
				Common:    caep.Common{EventTimestamp: ts, InitiatingEntity: caep.InitiatedByUser},
				Namespace: caep.NamespaceNISTAAL, CurrentLevel: "nist-aal2", PreviousLevel: "nist-aal1",
				ChangeDirection: caep.Increase,
			}},
		{caep.DeviceComplianceChangeEventType,
			`{"current_status":"not-compliant","previous_status":"compliant","initiating_entity":"policy","event_timestamp":1615304991}`,
			caep.DeviceComplianceChange{
				Common:         caep.Common{EventTimestamp: ts, InitiatingEntity: caep.InitiatedByPolicy},
				PreviousStatus: caep.Compliant, CurrentStatus: caep.NotCompliant,
			}},
		{caep.SessionEstablishedEventType,
			`{"event_timestamp":1615304991,"fp_ua":"abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611","acr":"AAL2","amr":["otp"],"ext_id":"12345"}`,
			caep.SessionEstablished{
				Common:               caep.Common{EventTimestamp: ts},
				UserAgentFingerprint: "abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611",
				ACR:                  "AAL2", AMR: []string{"otp"}, ExternalID: "12345",
			}},
		{caep.SessionPresentedEventType,
			`{"event_timestamp":1615304991,"fp_ua":"abb0","ext_id":"12345"}`,
			caep.SessionPresented{Common: caep.Common{EventTimestamp: ts}, UserAgentFingerprint: "abb0", ExternalID: "12345"}},
		{caep.RiskLevelChangeEventType,
			`{"current_level":"LOW","previous_level":"HIGH","event_timestamp":1615304991,"principal":"USER","risk_reason":"PASSWORD_FOUND_IN_DATA_BREACH"}`,
			caep.RiskLevelChange{
				Common:     caep.Common{EventTimestamp: ts},
				RiskReason: "PASSWORD_FOUND_IN_DATA_BREACH", Principal: caep.PrincipalUser,
				CurrentLevel: caep.RiskLow, PreviousLevel: caep.RiskHigh,
			}},
	}
	r := registry(t)
	for _, c := range cases {
		t.Run(string(c.typ), func(t *testing.T) {
			got, err := r.Decode(c.typ, json.RawMessage(c.json))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got  %#v\nwant %#v", got, c.want)
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			again, err := r.Decode(c.typ, encoded)
			if err != nil || !reflect.DeepEqual(again, got) {
				t.Fatalf("round trip: %v\n%s", err, encoded)
			}
		})
	}
}

func TestDecodeRejects(t *testing.T) {
	r := registry(t)
	cases := map[string]struct {
		typ  ssf.EventType
		json string
	}{
		"initiating_entity unknown":    {caep.SessionRevokedEventType, `{"initiating_entity":"robot"}`},
		"reason_admin string":          {caep.SessionRevokedEventType, `{"reason_admin":"revoked"}`},
		"reason_admin empty":           {caep.SessionRevokedEventType, `{"reason_admin":{}}`},
		"reason_user bad tag":          {caep.SessionRevokedEventType, `{"reason_user":{"en_US":"x"}}`},
		"event_timestamp string":       {caep.SessionRevokedEventType, `{"event_timestamp":"1615304991"}`},
		"claims missing":               {caep.TokenClaimsChangeEventType, `{}`},
		"claims empty":                 {caep.TokenClaimsChangeEventType, `{"claims":{}}`},
		"credential_type missing":      {caep.CredentialChangeEventType, `{"change_type":"create"}`},
		"change_type unknown":          {caep.CredentialChangeEventType, `{"credential_type":"pin","change_type":"rotate"}`},
		"namespace missing":            {caep.AssuranceLevelChangeEventType, `{"current_level":"x"}`},
		"current_level missing":        {caep.AssuranceLevelChangeEventType, `{"namespace":"x"}`},
		"change_direction unknown":     {caep.AssuranceLevelChangeEventType, `{"namespace":"x","current_level":"y","change_direction":"up"}`},
		"previous_status missing":      {caep.DeviceComplianceChangeEventType, `{"current_status":"compliant"}`},
		"current_status unknown":       {caep.DeviceComplianceChangeEventType, `{"previous_status":"compliant","current_status":"unknown"}`},
		"amr not array":                {caep.SessionEstablishedEventType, `{"amr":"otp"}`},
		"principal missing":            {caep.RiskLevelChangeEventType, `{"current_level":"LOW"}`},
		"current_level lowercase":      {caep.RiskLevelChangeEventType, `{"principal":"USER","current_level":"low"}`},
		"previous_level unknown":       {caep.RiskLevelChangeEventType, `{"principal":"USER","current_level":"LOW","previous_level":"EXTREME"}`},
		"credential_change not object": {caep.CredentialChangeEventType, `[]`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if e, err := r.Decode(c.typ, json.RawMessage(c.json)); !errors.Is(err, ssf.ErrInvalidEvent) {
				t.Fatalf("Decode = %#v, %v; want ErrInvalidEvent", e, err)
			}
		})
	}
}

func TestNonStandardCredentialTypeAccepted(t *testing.T) {
	e := caep.CredentialChange{CredentialType: "smartcard", ChangeType: caep.ChangeRevoke}
	if err := e.Validate(); err != nil {
		t.Fatalf("a mutually agreed credential_type was rejected: %v", err)
	}
	if e.CredentialType.IsStandard() || !caep.CredentialPassword.IsStandard() {
		t.Error("IsStandard misclassifies")
	}
}

func TestZeroCommonClaimsOmitted(t *testing.T) {
	b, err := json.Marshal(caep.SessionRevoked{})
	if err != nil || string(b) != `{}` {
		t.Errorf("Marshal(SessionRevoked{}) = %s, %v", b, err)
	}
}
