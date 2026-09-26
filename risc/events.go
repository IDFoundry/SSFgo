package risc

import (
	"fmt"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
)

// The base URI for RISC event types (RISC 1.0 §2).
const eventTypeBase = "https://schemas.openid.net/secevent/risc/event-type/"

// RISC 1.0 event types.
const (
	AccountCredentialChangeRequiredEventType ssf.EventType = eventTypeBase + "account-credential-change-required"
	AccountPurgedEventType                   ssf.EventType = eventTypeBase + "account-purged"
	AccountDisabledEventType                 ssf.EventType = eventTypeBase + "account-disabled"
	AccountEnabledEventType                  ssf.EventType = eventTypeBase + "account-enabled"
	IdentifierChangedEventType               ssf.EventType = eventTypeBase + "identifier-changed"
	IdentifierRecycledEventType              ssf.EventType = eventTypeBase + "identifier-recycled"
	CredentialCompromiseEventType            ssf.EventType = eventTypeBase + "credential-compromise"
	OptInEventType                           ssf.EventType = eventTypeBase + "opt-in"
	OptOutInitiatedEventType                 ssf.EventType = eventTypeBase + "opt-out-initiated"
	OptOutCancelledEventType                 ssf.EventType = eventTypeBase + "opt-out-cancelled"
	OptOutEffectiveEventType                 ssf.EventType = eventTypeBase + "opt-out-effective"
	RecoveryActivatedEventType               ssf.EventType = eventTypeBase + "recovery-activated"
	RecoveryInformationChangedEventType      ssf.EventType = eventTypeBase + "recovery-information-changed"

	// Deprecated: RISC 1.0 §2.11 requires new implementations to use
	// caep.SessionRevokedEventType instead.
	SessionsRevokedEventType ssf.EventType = eventTypeBase + "sessions-revoked"
)

// Register adds every RISC 1.0 event type, including the deprecated
// sessions-revoked, to r. Receivers must still be able to accept events
// from Transmitters that send it.
func Register(r *ssf.Registry) error {
	for _, register := range []func(*ssf.Registry) error{
		ssf.Register[AccountCredentialChangeRequired],
		ssf.Register[AccountPurged],
		ssf.Register[AccountDisabled],
		ssf.Register[AccountEnabled],
		ssf.Register[IdentifierChanged],
		ssf.Register[IdentifierRecycled],
		ssf.Register[CredentialCompromise],
		ssf.Register[OptIn],
		ssf.Register[OptOutInitiated],
		ssf.Register[OptOutCancelled],
		ssf.Register[OptOutEffective],
		ssf.Register[RecoveryActivated],
		ssf.Register[RecoveryInformationChanged],
		ssf.Register[SessionsRevoked],
	} {
		if err := register(r); err != nil {
			return err
		}
	}
	return nil
}

func invalid(typ ssf.EventType, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %s", ssf.ErrInvalidEvent, typ, fmt.Sprintf(format, args...))
}

// AccountCredentialChangeRequired signals that the account was required
// to change a credential (RISC 1.0 §2.1).
type AccountCredentialChangeRequired struct{}

// EventType implements ssf.Event.
func (AccountCredentialChangeRequired) EventType() ssf.EventType {
	return AccountCredentialChangeRequiredEventType
}

// Validate implements ssf.Event.
func (AccountCredentialChangeRequired) Validate() error { return nil }

// AccountPurged signals that the account was permanently deleted
// (RISC 1.0 §2.2).
type AccountPurged struct{}

// EventType implements ssf.Event.
func (AccountPurged) EventType() ssf.EventType { return AccountPurgedEventType }

// Validate implements ssf.Event.
func (AccountPurged) Validate() error { return nil }

// DisabledReason is why an account was disabled (RISC 1.0 §2.3).
type DisabledReason string

const (
	DisabledHijacking   DisabledReason = "hijacking"
	DisabledBulkAccount DisabledReason = "bulk-account"
)

// AccountDisabled signals that the account was disabled (RISC 1.0 §2.3).
type AccountDisabled struct {
	// Reason is optional.
	Reason DisabledReason `json:"reason,omitempty"`
}

// EventType implements ssf.Event.
func (AccountDisabled) EventType() ssf.EventType { return AccountDisabledEventType }

// Validate implements ssf.Event.
func (e AccountDisabled) Validate() error {
	switch e.Reason {
	case "", DisabledHijacking, DisabledBulkAccount:
		return nil
	default:
		return invalid(AccountDisabledEventType, "reason %q is not hijacking or bulk-account", e.Reason)
	}
}

// AccountEnabled signals that the account was enabled (RISC 1.0 §2.4).
type AccountEnabled struct{}

// EventType implements ssf.Event.
func (AccountEnabled) EventType() ssf.EventType { return AccountEnabledEventType }

// Validate implements ssf.Event.
func (AccountEnabled) Validate() error { return nil }

// IdentifierChanged signals that the identifier in the subject changed
// (RISC 1.0 §2.5). The SET's sub_id carries the old value and must be an
// email or phone_number subject.
type IdentifierChanged struct {
	// NewValue is the new identifier, if disclosed.
	NewValue string `json:"new-value,omitempty"`
}

// EventType implements ssf.Event.
func (IdentifierChanged) EventType() ssf.EventType { return IdentifierChangedEventType }

// Validate implements ssf.Event.
func (IdentifierChanged) Validate() error { return nil }

// ValidateSubject implements ssf.SubjectConstrainedEvent.
func (IdentifierChanged) ValidateSubject(s ssf.Subject) error {
	return requireEmailOrPhone(IdentifierChangedEventType, s)
}

// IdentifierRecycled signals that the identifier in the subject now
// belongs to a different user (RISC 1.0 §2.6). The SET's sub_id must be
// an email or phone_number subject.
type IdentifierRecycled struct{}

// EventType implements ssf.Event.
func (IdentifierRecycled) EventType() ssf.EventType { return IdentifierRecycledEventType }

// Validate implements ssf.Event.
func (IdentifierRecycled) Validate() error { return nil }

// ValidateSubject implements ssf.SubjectConstrainedEvent.
func (IdentifierRecycled) ValidateSubject(s ssf.Subject) error {
	return requireEmailOrPhone(IdentifierRecycledEventType, s)
}

func requireEmailOrPhone(typ ssf.EventType, s ssf.Subject) error {
	switch s.(type) {
	case ssf.EmailSubject, ssf.PhoneNumberSubject:
		return nil
	default:
		return invalid(typ, "sub_id must be an email or phone_number subject, got %q", s.Format())
	}
}

// CredentialCompromise signals that a credential of the subject was found
// to be compromised (RISC 1.0 §2.7).
type CredentialCompromise struct {
	// CredentialType takes the values CAEP 1.0 §3.3.1 defines. Required.
	CredentialType caep.CredentialType `json:"credential_type"`
	// EventTimestamp is when the Transmitter discovered the compromise.
	EventTimestamp ssf.NumericDate `json:"event_timestamp,omitzero"`
	// ReasonAdmin and ReasonUser use CAEP's localized form (CAEP 1.0 §2).
	// RISC 1.0 §2.7 does not define their type; SSFgo follows CAEP so the
	// two families encode reasons the same way.
	ReasonAdmin ssf.LocalizedText `json:"reason_admin,omitempty"`
	ReasonUser  ssf.LocalizedText `json:"reason_user,omitempty"`
}

// EventType implements ssf.Event.
func (CredentialCompromise) EventType() ssf.EventType { return CredentialCompromiseEventType }

// Validate implements ssf.Event.
func (e CredentialCompromise) Validate() error {
	if e.CredentialType == "" {
		return invalid(CredentialCompromiseEventType, "credential_type is required")
	}
	if e.ReasonAdmin != nil {
		if err := e.ReasonAdmin.Validate(); err != nil {
			return invalid(CredentialCompromiseEventType, "reason_admin: %v", err)
		}
	}
	if e.ReasonUser != nil {
		if err := e.ReasonUser.Validate(); err != nil {
			return invalid(CredentialCompromiseEventType, "reason_user: %v", err)
		}
	}
	return nil
}

// OptIn signals that the account opted in to RISC event exchange
// (RISC 1.0 §2.8.1).
type OptIn struct{}

// EventType implements ssf.Event.
func (OptIn) EventType() ssf.EventType { return OptInEventType }

// Validate implements ssf.Event.
func (OptIn) Validate() error { return nil }

// OptOutInitiated signals that the account started opting out of RISC
// event exchange (RISC 1.0 §2.8.2).
type OptOutInitiated struct{}

// EventType implements ssf.Event.
func (OptOutInitiated) EventType() ssf.EventType { return OptOutInitiatedEventType }

// Validate implements ssf.Event.
func (OptOutInitiated) Validate() error { return nil }

// OptOutCancelled signals that the account cancelled its opt-out
// (RISC 1.0 §2.8.3).
type OptOutCancelled struct{}

// EventType implements ssf.Event.
func (OptOutCancelled) EventType() ssf.EventType { return OptOutCancelledEventType }

// Validate implements ssf.Event.
func (OptOutCancelled) Validate() error { return nil }

// OptOutEffective signals that the account's opt-out took effect
// (RISC 1.0 §2.8.4).
type OptOutEffective struct{}

// EventType implements ssf.Event.
func (OptOutEffective) EventType() ssf.EventType { return OptOutEffectiveEventType }

// Validate implements ssf.Event.
func (OptOutEffective) Validate() error { return nil }

// RecoveryActivated signals that the account activated a recovery flow
// (RISC 1.0 §2.9).
type RecoveryActivated struct{}

// EventType implements ssf.Event.
func (RecoveryActivated) EventType() ssf.EventType { return RecoveryActivatedEventType }

// Validate implements ssf.Event.
func (RecoveryActivated) Validate() error { return nil }

// RecoveryInformationChanged signals that the account changed some of its
// recovery information (RISC 1.0 §2.10).
type RecoveryInformationChanged struct{}

// EventType implements ssf.Event.
func (RecoveryInformationChanged) EventType() ssf.EventType {
	return RecoveryInformationChangedEventType
}

// Validate implements ssf.Event.
func (RecoveryInformationChanged) Validate() error { return nil }

// SessionsRevoked signals that all sessions of the account were revoked
// (RISC 1.0 §2.11).
//
// Deprecated: RISC 1.0 §2.11 requires new implementations to emit
// caep.SessionRevoked instead. It remains so Receivers can accept it.
type SessionsRevoked struct{}

// EventType implements ssf.Event.
func (SessionsRevoked) EventType() ssf.EventType { return SessionsRevokedEventType }

// Validate implements ssf.Event.
func (SessionsRevoked) Validate() error { return nil }
