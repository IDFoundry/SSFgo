package caep

import (
	ssf "github.com/idfoundry/ssfgo"
)

// SessionRevoked signals that the session identified by the subject has
// been revoked (CAEP 1.0 §3.1). EventTimestamp, if set, is when the
// revocation occurred.
type SessionRevoked struct {
	Common
}

// EventType implements ssf.Event.
func (SessionRevoked) EventType() ssf.EventType { return SessionRevokedEventType }

// Validate implements ssf.Event.
func (e SessionRevoked) Validate() error { return e.validate(SessionRevokedEventType) }

// TokenClaimsChange signals that claims in a token identified by the
// subject have changed (CAEP 1.0 §3.2).
type TokenClaimsChange struct {
	Common
	// Claims holds one or more claims with their new values. Required.
	Claims map[string]any `json:"claims"`
}

// EventType implements ssf.Event.
func (TokenClaimsChange) EventType() ssf.EventType { return TokenClaimsChangeEventType }

// Validate implements ssf.Event.
func (e TokenClaimsChange) Validate() error {
	if len(e.Claims) == 0 {
		return invalid(TokenClaimsChangeEventType, "claims must hold at least one claim")
	}
	return e.validate(TokenClaimsChangeEventType)
}

// CredentialType is the kind of credential a CredentialChange concerns
// (CAEP 1.0 §3.3.1). Values other than the constants below are permitted
// when Transmitter and Receiver agree on them.
type CredentialType string

const (
	CredentialPassword             CredentialType = "password"
	CredentialPIN                  CredentialType = "pin"
	CredentialX509                 CredentialType = "x509"
	CredentialFIDO2Platform        CredentialType = "fido2-platform"
	CredentialFIDO2Roaming         CredentialType = "fido2-roaming"
	CredentialFIDOU2F              CredentialType = "fido-u2f"
	CredentialVerifiableCredential CredentialType = "verifiable-credential" //nolint:gosec // G101: a credential type name, not a credential
	CredentialPhoneVoice           CredentialType = "phone-voice"
	CredentialPhoneSMS             CredentialType = "phone-sms"
	CredentialApp                  CredentialType = "app"
)

// IsStandard reports whether t is one of the values CAEP 1.0 §3.3.1 lists.
func (t CredentialType) IsStandard() bool {
	switch t {
	case CredentialPassword, CredentialPIN, CredentialX509, CredentialFIDO2Platform,
		CredentialFIDO2Roaming, CredentialFIDOU2F, CredentialVerifiableCredential,
		CredentialPhoneVoice, CredentialPhoneSMS, CredentialApp:
		return true
	default:
		return false
	}
}

// ChangeType is what happened to a credential (CAEP 1.0 §3.3.1).
type ChangeType string

const (
	ChangeCreate ChangeType = "create"
	ChangeRevoke ChangeType = "revoke"
	ChangeUpdate ChangeType = "update"
	ChangeDelete ChangeType = "delete"
)

// CredentialChange signals that a credential was created, changed,
// revoked or deleted (CAEP 1.0 §3.3).
type CredentialChange struct {
	Common
	CredentialType CredentialType `json:"credential_type"`
	ChangeType     ChangeType     `json:"change_type"`
	FriendlyName   string         `json:"friendly_name,omitempty"`
	X509Issuer     string         `json:"x509_issuer,omitempty"`
	X509Serial     string         `json:"x509_serial,omitempty"`
	FIDO2AAGUID    string         `json:"fido2_aaguid,omitempty"`
}

// EventType implements ssf.Event.
func (CredentialChange) EventType() ssf.EventType { return CredentialChangeEventType }

// Validate implements ssf.Event. A non-standard credential_type is
// accepted, since CAEP 1.0 permits mutually agreed values.
func (e CredentialChange) Validate() error {
	if e.CredentialType == "" {
		return invalid(CredentialChangeEventType, "credential_type is required")
	}
	switch e.ChangeType {
	case ChangeCreate, ChangeRevoke, ChangeUpdate, ChangeDelete:
	default:
		return invalid(CredentialChangeEventType, "change_type %q is not create, revoke, update or delete", e.ChangeType)
	}
	return e.validate(CredentialChangeEventType)
}

// Assurance level namespaces CAEP 1.0 §3.4.1 lists. Other values name a
// namespace agreed between Transmitter and Receiver.
const (
	NamespaceRFC8176     = "RFC8176"
	NamespaceRFC6711     = "RFC6711"
	NamespaceISOIEC29115 = "ISO-IEC-29115"
	NamespaceNISTIAL     = "NIST-IAL"
	NamespaceNISTAAL     = "NIST-AAL"
	NamespaceNISTFAL     = "NIST-FAL"
)

// ChangeDirection says whether an assurance level rose or fell
// (CAEP 1.0 §3.4.1).
type ChangeDirection string

const (
	Increase ChangeDirection = "increase"
	Decrease ChangeDirection = "decrease"
)

// AssuranceLevelChange signals a change in authentication assurance since
// the initial login (CAEP 1.0 §3.4).
type AssuranceLevelChange struct {
	Common
	// Namespace is the namespace of CurrentLevel and PreviousLevel.
	// Required.
	Namespace string `json:"namespace"`
	// CurrentLevel is the new assurance level. Required.
	CurrentLevel string `json:"current_level"`
	// PreviousLevel is empty when the Transmitter does not know it.
	PreviousLevel   string          `json:"previous_level,omitempty"`
	ChangeDirection ChangeDirection `json:"change_direction,omitempty"`
}

// EventType implements ssf.Event.
func (AssuranceLevelChange) EventType() ssf.EventType { return AssuranceLevelChangeEventType }

// Validate implements ssf.Event.
func (e AssuranceLevelChange) Validate() error {
	if e.Namespace == "" || e.CurrentLevel == "" {
		return invalid(AssuranceLevelChangeEventType, "namespace and current_level are required")
	}
	switch e.ChangeDirection {
	case "", Increase, Decrease:
	default:
		return invalid(AssuranceLevelChangeEventType, "change_direction %q is not increase or decrease", e.ChangeDirection)
	}
	return e.validate(AssuranceLevelChangeEventType)
}

// ComplianceStatus is a device's compliance status (CAEP 1.0 §3.5.1).
type ComplianceStatus string

const (
	Compliant    ComplianceStatus = "compliant"
	NotCompliant ComplianceStatus = "not-compliant"
)

func (s ComplianceStatus) valid() bool { return s == Compliant || s == NotCompliant }

// DeviceComplianceChange signals that a device's compliance status changed
// (CAEP 1.0 §3.5).
type DeviceComplianceChange struct {
	Common
	PreviousStatus ComplianceStatus `json:"previous_status"`
	CurrentStatus  ComplianceStatus `json:"current_status"`
}

// EventType implements ssf.Event.
func (DeviceComplianceChange) EventType() ssf.EventType { return DeviceComplianceChangeEventType }

// Validate implements ssf.Event.
func (e DeviceComplianceChange) Validate() error {
	if !e.PreviousStatus.valid() || !e.CurrentStatus.valid() {
		return invalid(DeviceComplianceChangeEventType, "previous_status and current_status must each be compliant or not-compliant")
	}
	return e.validate(DeviceComplianceChangeEventType)
}

// SessionEstablished signals that the Transmitter established a new
// session for the subject (CAEP 1.0 §3.6). EventTimestamp, if set, is
// when.
type SessionEstablished struct {
	Common
	// UserAgentFingerprint is the "fp_ua" claim.
	UserAgentFingerprint string `json:"fp_ua,omitempty"`
	// ACR is the session's authentication context class reference, as in
	// an OpenID Connect ID Token.
	ACR string `json:"acr,omitempty"`
	// AMR lists the session's authentication methods, as in an OpenID
	// Connect ID Token.
	AMR []string `json:"amr,omitempty"`
	// ExternalID correlates the session with a broader one, such as a
	// federated SAML session.
	ExternalID string `json:"ext_id,omitempty"`
}

// EventType implements ssf.Event.
func (SessionEstablished) EventType() ssf.EventType { return SessionEstablishedEventType }

// Validate implements ssf.Event. Every event-specific claim is optional.
func (e SessionEstablished) Validate() error { return e.validate(SessionEstablishedEventType) }

// SessionPresented signals that the Transmitter observed the session at
// EventTimestamp (CAEP 1.0 §3.7).
type SessionPresented struct {
	Common
	// UserAgentFingerprint is the "fp_ua" claim.
	UserAgentFingerprint string `json:"fp_ua,omitempty"`
	// ExternalID correlates the session with a broader one.
	ExternalID string `json:"ext_id,omitempty"`
}

// EventType implements ssf.Event.
func (SessionPresented) EventType() ssf.EventType { return SessionPresentedEventType }

// Validate implements ssf.Event. Every event-specific claim is optional.
func (e SessionPresented) Validate() error { return e.validate(SessionPresentedEventType) }

// RiskLevel is an abstracted risk level (CAEP 1.0 §3.8.1).
type RiskLevel string

const (
	RiskLow    RiskLevel = "LOW"
	RiskMedium RiskLevel = "MEDIUM"
	RiskHigh   RiskLevel = "HIGH"
)

func (l RiskLevel) valid() bool { return l == RiskLow || l == RiskMedium || l == RiskHigh }

// Principal is the kind of entity a RiskLevelChange concerns
// (CAEP 1.0 §3.8.1). Other values are permitted for other SSF subject
// principals.
type Principal string

const (
	PrincipalUser    Principal = "USER"
	PrincipalDevice  Principal = "DEVICE"
	PrincipalSession Principal = "SESSION"
	PrincipalTenant  Principal = "TENANT"
	PrincipalOrgUnit Principal = "ORG_UNIT"
	PrincipalGroup   Principal = "GROUP"
)

// RiskLevelChange signals a change in the subject's assessed risk level
// (CAEP 1.0 §3.8).
type RiskLevelChange struct {
	Common
	// RiskReason is RECOMMENDED: why the risk level changed.
	RiskReason string `json:"risk_reason,omitempty"`
	// Principal is the kind of entity involved. Required.
	Principal Principal `json:"principal"`
	// CurrentLevel is required.
	CurrentLevel RiskLevel `json:"current_level"`
	// PreviousLevel is empty when the Transmitter does not know it.
	PreviousLevel RiskLevel `json:"previous_level,omitempty"`
}

// EventType implements ssf.Event.
func (RiskLevelChange) EventType() ssf.EventType { return RiskLevelChangeEventType }

// Validate implements ssf.Event.
func (e RiskLevelChange) Validate() error {
	if e.Principal == "" {
		return invalid(RiskLevelChangeEventType, "principal is required")
	}
	if !e.CurrentLevel.valid() {
		return invalid(RiskLevelChangeEventType, "current_level %q is not LOW, MEDIUM or HIGH", e.CurrentLevel)
	}
	if e.PreviousLevel != "" && !e.PreviousLevel.valid() {
		return invalid(RiskLevelChangeEventType, "previous_level %q is not LOW, MEDIUM or HIGH", e.PreviousLevel)
	}
	return e.validate(RiskLevelChangeEventType)
}
