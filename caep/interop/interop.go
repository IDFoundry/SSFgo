// Package interop applies the OpenID CAEP Interoperability Profile 1.0 to
// an SSFgo Transmitter or Receiver.
//
// Most of the profile is met by SSFgo unconditionally: Transmitter
// metadata always carries spec_version, jwks_uri, the management
// endpoints and the OAuth 2.0 authorization scheme (§2.3); SETs always
// carry exactly one event (§2.8.1); access tokens are only accepted in the
// Authorization header (§2.7.2); a Receiver takes its keys from jwks_uri
// (§2.4.2) and authenticates with OAuth 2.0 (§2.4.3). This package covers
// the rest, which depends on how a deployment is configured, what it
// emits, and which Transmitter a Receiver talks to:
//
//	cfg := transmitter.Config{...}
//	if err := interop.ApplyTransmitter(&cfg); err != nil { ... }
//	tx, err := transmitter.New(cfg)
//
//	rcfg := receiver.Config{...}
//	if err := interop.ApplyReceiver(&rcfg); err != nil { ... }
//	rx, err := receiver.New(ctx, rcfg) // fails if the Transmitter does not meet the profile
package interop

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/caep"
	"github.com/idfoundry/ssfgo/transmitter"
)

// EventTypes returns the CAEP event types the profile's use cases are
// built on (§3.1–§3.3). An implementation supports at least one.
func EventTypes() []ssf.EventType {
	return []ssf.EventType{
		caep.SessionRevokedEventType,
		caep.CredentialChangeEventType,
		caep.DeviceComplianceChangeEventType,
	}
}

// SubjectFormats returns the subject identifier formats CAEP events may
// use under the profile (§2.5). The opaque format is reserved for the
// verification event.
func SubjectFormats() []ssf.SubjectFormat {
	return []ssf.SubjectFormat{ssf.FormatEmail, ssf.FormatIssSub}
}

// ErrNotInterop is wrapped by every error this package returns.
var ErrNotInterop = errors.New("caep interop profile")

// CheckTransmitterConfig reports every way cfg falls short of the profile.
func CheckTransmitterConfig(cfg transmitter.Config) error {
	var errs []error
	if len(cfg.SigningKeys) == 0 || cfg.SigningKeys[0].Algorithm != ssf.RS256 {
		errs = append(errs, errors.New("§2.6: events must be signed with RS256, so the active signing key must be an RS256 key"))
	}
	for _, m := range []ssf.DeliveryMethod{ssf.DeliveryPush, ssf.DeliveryPoll} {
		if !slices.Contains(cfg.DeliveryMethods, m) {
			errs = append(errs, fmt.Errorf("§2.3.8.1: delivery method %s must be supported", m))
		}
	}
	if !slices.ContainsFunc(EventTypes(), func(e ssf.EventType) bool { return slices.Contains(cfg.EventsSupported, e) }) {
		errs = append(errs, errors.New("§3: EventsSupported must include session-revoked, credential-change or device-compliance-change"))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %w", ErrNotInterop, err)
	}
	return nil
}

// ValidateEvent enforces the profile's rules on a CAEP event before it is
// emitted: the subject uses email or iss_sub (§2.5), and session-revoked
// and credential-change carry a non-empty reason_admin (§3.1, §3.2).
// Events outside CAEP are not constrained by the profile and pass.
func ValidateEvent(subject ssf.Subject, event ssf.Event) error {
	typ := event.EventType()
	if !strings.HasPrefix(string(typ), "https://schemas.openid.net/secevent/caep/") {
		return nil
	}
	if !slices.Contains(SubjectFormats(), subject.Format()) {
		return fmt.Errorf("%w: §2.5: CAEP events must use an email or iss_sub subject, not %q", ErrNotInterop, subject.Format())
	}
	var reason ssf.LocalizedText
	switch e := event.(type) {
	case caep.SessionRevoked:
		reason = e.ReasonAdmin
	case caep.CredentialChange:
		reason = e.ReasonAdmin
	default:
		return nil
	}
	if len(reason) == 0 {
		return fmt.Errorf("%w: %s must carry a non-empty reason_admin", ErrNotInterop, typ)
	}
	return nil
}

// ApplyTransmitter checks cfg against the profile and installs
// ValidateEvent as its EventValidator, running after any validator cfg
// already has.
func ApplyTransmitter(cfg *transmitter.Config) error {
	if err := CheckTransmitterConfig(*cfg); err != nil {
		return err
	}
	previous := cfg.EventValidator
	cfg.EventValidator = func(s ssf.Subject, e ssf.Event) error {
		if previous != nil {
			if err := previous(s, e); err != nil {
				return err
			}
		}
		return ValidateEvent(s, e)
	}
	return nil
}
