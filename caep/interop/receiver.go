package interop

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/receiver"
)

// CheckReceiverConfig reports every way cfg falls short of the profile's
// Receiver requirements.
//
// It does not restrict which subject formats a Receiver accepts: the
// profile requires Receivers to accept email and iss_sub (§2.5), not to
// refuse other formats, and rejecting them would only break interoperation.
func CheckReceiverConfig(cfg receiver.Config) error {
	var errs []error
	if !slices.Contains(cfg.Algorithms, ssf.RS256) {
		errs = append(errs, errors.New("§2.6: events are signed with RS256, so Algorithms must include RS256"))
	}
	if cfg.Registry == nil || !slices.ContainsFunc(EventTypes(), cfg.Registry.Supports) {
		errs = append(errs, errors.New("§3: the Registry must hold session-revoked, credential-change or device-compliance-change (caep.Register adds all three)"))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %w", ErrNotInterop, err)
	}
	return nil
}

// CheckTransmitterMetadata reports every way a Transmitter's
// configuration metadata falls short of the profile (§2.3.1–§2.3.7), so a
// Receiver can refuse a Transmitter it would not interoperate with.
func CheckTransmitterMetadata(md ssf.TransmitterMetadata) error {
	var errs []error
	if !specVersionAtLeast10(md.SpecVersion) {
		errs = append(errs, fmt.Errorf("§2.3.1: spec_version must be 1_0 or greater, got %q", md.SpecVersion))
	}
	if len(md.DeliveryMethodsSupported) == 0 {
		errs = append(errs, errors.New("§2.3.2: delivery_methods_supported is required"))
	}
	for _, f := range []struct{ section, name, value string }{
		{"§2.3.3", "jwks_uri", md.JWKSURI},
		{"§2.3.4", "configuration_endpoint", md.ConfigurationEndpoint},
		{"§2.3.5", "status_endpoint", md.StatusEndpoint},
		{"§2.3.6", "verification_endpoint", md.VerificationEndpoint},
	} {
		if f.value == "" {
			errs = append(errs, fmt.Errorf("%s: %s is required", f.section, f.name))
		}
	}
	if !slices.ContainsFunc(md.AuthorizationSchemes, func(s ssf.AuthorizationScheme) bool { return s.SpecURN == ssf.OAuth2SpecURN }) {
		errs = append(errs, fmt.Errorf("§2.3.7: authorization_schemes must include %s", ssf.OAuth2SpecURN))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %w", ErrNotInterop, err)
	}
	return nil
}

// specVersionAtLeast10 reports whether v names SSF 1_0 or a later version.
// Implementer's drafts ("1_0-ID2") and an absent value, which SSF 1.0 §7.1
// reads as "1_0-ID1", are earlier.
func specVersionAtLeast10(v string) bool {
	major, minor, ok := strings.Cut(v, "_")
	if !ok || strings.Contains(minor, "-") {
		return false
	}
	ma, err1 := strconv.Atoi(major)
	mi, err2 := strconv.Atoi(minor)
	return err1 == nil && err2 == nil && ma >= 1 && mi >= 0
}

// ApplyReceiver checks cfg against the profile and installs
// CheckTransmitterMetadata as its CheckMetadata, running after any check
// cfg already has, so receiver.New refuses a Transmitter that does not meet
// the profile.
func ApplyReceiver(cfg *receiver.Config) error {
	if err := CheckReceiverConfig(*cfg); err != nil {
		return err
	}
	previous := cfg.CheckMetadata
	cfg.CheckMetadata = func(md ssf.TransmitterMetadata) error {
		if previous != nil {
			if err := previous(md); err != nil {
				return err
			}
		}
		return CheckTransmitterMetadata(md)
	}
	return nil
}
