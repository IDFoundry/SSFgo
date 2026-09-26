package caep

import (
	"fmt"

	ssf "github.com/idfoundry/ssfgo"
)

// The base URI for CAEP event types (CAEP 1.0 §3).
const eventTypeBase = "https://schemas.openid.net/secevent/caep/event-type/"

// CAEP 1.0 event types.
const (
	SessionRevokedEventType         ssf.EventType = eventTypeBase + "session-revoked"
	TokenClaimsChangeEventType      ssf.EventType = eventTypeBase + "token-claims-change"
	CredentialChangeEventType       ssf.EventType = eventTypeBase + "credential-change"
	AssuranceLevelChangeEventType   ssf.EventType = eventTypeBase + "assurance-level-change"
	DeviceComplianceChangeEventType ssf.EventType = eventTypeBase + "device-compliance-change"
	SessionEstablishedEventType     ssf.EventType = eventTypeBase + "session-established"
	SessionPresentedEventType       ssf.EventType = eventTypeBase + "session-presented"
	RiskLevelChangeEventType        ssf.EventType = eventTypeBase + "risk-level-change"
)

// Register adds every CAEP 1.0 event type to r.
func Register(r *ssf.Registry) error {
	for _, register := range []func(*ssf.Registry) error{
		ssf.Register[SessionRevoked],
		ssf.Register[TokenClaimsChange],
		ssf.Register[CredentialChange],
		ssf.Register[AssuranceLevelChange],
		ssf.Register[DeviceComplianceChange],
		ssf.Register[SessionEstablished],
		ssf.Register[SessionPresented],
		ssf.Register[RiskLevelChange],
	} {
		if err := register(r); err != nil {
			return err
		}
	}
	return nil
}

// InitiatingEntity describes what invoked an event (CAEP 1.0 §2).
type InitiatingEntity string

const (
	InitiatedByAdmin  InitiatingEntity = "admin"
	InitiatedByUser   InitiatingEntity = "user"
	InitiatedByPolicy InitiatingEntity = "policy"
	InitiatedBySystem InitiatingEntity = "system"
)

// Common holds the optional claims every CAEP event may carry
// (CAEP 1.0 §2). It is embedded in each event type.
type Common struct {
	// EventTimestamp is when the event occurred. Each event type defines
	// exactly what that means.
	EventTimestamp ssf.NumericDate `json:"event_timestamp,omitzero"`
	// InitiatingEntity describes what invoked the event.
	InitiatingEntity InitiatingEntity `json:"initiating_entity,omitempty"`
	// ReasonAdmin is a localized message for logging and auditing.
	ReasonAdmin ssf.LocalizedText `json:"reason_admin,omitempty"`
	// ReasonUser is a localized message for display to the end user.
	ReasonUser ssf.LocalizedText `json:"reason_user,omitempty"`
}

// validate checks c's members against CAEP 1.0 §2.
func (c Common) validate(typ ssf.EventType) error {
	switch c.InitiatingEntity {
	case "", InitiatedByAdmin, InitiatedByUser, InitiatedByPolicy, InitiatedBySystem:
	default:
		return invalid(typ, "initiating_entity %q is not admin, user, policy or system", c.InitiatingEntity)
	}
	// A present-but-empty object decodes to a non-nil empty map, which
	// CAEP 1.0 §2 forbids ("one or more key/value pairs").
	if c.ReasonAdmin != nil {
		if err := c.ReasonAdmin.Validate(); err != nil {
			return invalid(typ, "reason_admin: %v", err)
		}
	}
	if c.ReasonUser != nil {
		if err := c.ReasonUser.Validate(); err != nil {
			return invalid(typ, "reason_user: %v", err)
		}
	}
	return nil
}

func invalid(typ ssf.EventType, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %s", ssf.ErrInvalidEvent, typ, fmt.Sprintf(format, args...))
}
