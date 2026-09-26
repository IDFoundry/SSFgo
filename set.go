package ssf

import (
	"fmt"
	"time"
)

// SET is the content of a Security Event Token (RFC 8417) as profiled by
// SSF 1.0 §4: one event about one primary subject.
//
// A Receiver hands handlers a SET only after verifying its signature,
// issuer, audience and freshness. A Transmitter builds SETs itself from
// the events an application emits; applications never construct or sign
// one directly.
type SET struct {
	// Issuer is the "iss" claim: the Transmitter's issuer identifier.
	Issuer string
	// Audience is the "aud" claim. It holds at least one value.
	Audience []string
	// JWTID is the "jti" claim, unique per SET.
	JWTID string
	// IssuedAt is the "iat" claim.
	IssuedAt time.Time
	// TransactionID is the optional "txn" claim (SSF 1.0 §4.1.9). SETs
	// caused by the same underlying occurrence may share it.
	TransactionID string
	// Subject is the "sub_id" claim (SSF 1.0 §3.1).
	Subject Subject
	// Event is the single entry of the "events" claim.
	Event Event
}

// Validate reports whether s has every member SSF 1.0 §4 requires and
// whether its event and subject are valid together.
func (s SET) Validate() error {
	switch {
	case s.Issuer == "":
		return fmt.Errorf("ssf: SET: iss is required")
	case len(s.Audience) == 0:
		return fmt.Errorf("ssf: SET: aud is required")
	case s.JWTID == "":
		return fmt.Errorf("ssf: SET: jti is required")
	case s.IssuedAt.IsZero():
		return fmt.Errorf("ssf: SET: iat is required")
	case s.Subject == nil:
		return fmt.Errorf("ssf: SET: sub_id is required")
	case s.Event == nil:
		return fmt.Errorf("ssf: SET: an event is required")
	}
	for i, a := range s.Audience {
		if a == "" {
			return fmt.Errorf("ssf: SET: aud value %d is empty", i)
		}
	}
	if err := s.Subject.Validate(); err != nil {
		return fmt.Errorf("ssf: SET: sub_id: %w", err)
	}
	if err := s.Event.Validate(); err != nil {
		return fmt.Errorf("ssf: SET: %w", err)
	}
	if c, ok := s.Event.(SubjectConstrainedEvent); ok {
		if err := c.ValidateSubject(s.Subject); err != nil {
			return fmt.Errorf("ssf: SET: %w", err)
		}
	}
	return nil
}
