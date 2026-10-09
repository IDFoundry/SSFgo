package ssf

import (
	"fmt"
	"net/url"
	"strings"
)

// SpecVersion is the "spec_version" SSFgo implements (SSF 1.0 §7.1).
const SpecVersion = "1_0"

// WellKnownPath is the path segment Transmitter Configuration Metadata is
// published under (SSF 1.0 §7.2).
const WellKnownPath = "/.well-known/ssf-configuration"

// DefaultSubjects says whether newly created streams include every
// appropriate subject or none (SSF 1.0 §7.1).
type DefaultSubjects string

const (
	// DefaultSubjectsAll adds every appropriate subject to new streams;
	// Receivers remove the ones they do not want.
	DefaultSubjectsAll DefaultSubjects = "ALL"
	// DefaultSubjectsNone adds no subjects to new streams; Receivers add
	// the ones they want.
	DefaultSubjectsNone DefaultSubjects = "NONE"
)

// AuthorizationScheme names a scheme protecting the stream management API
// (SSF 1.0 §7.1.1).
type AuthorizationScheme struct {
	// SpecURN is the URN of the specification defining the scheme, such
	// as OAuth2SpecURN.
	SpecURN string `json:"spec_urn"`
}

// OAuth2SpecURN is the authorization scheme spec_urn for OAuth 2.0
// (RFC 6749). The CAEP Interoperability Profile §2.3.7 requires
// Transmitters to advertise it.
const OAuth2SpecURN = "urn:ietf:rfc:6749" // NOSONAR: a public RFC identifier, not a secret

// TransmitterMetadata is the Transmitter Configuration Metadata document
// (SSF 1.0 §7.1). Array members with no elements are omitted, as §7.2.3
// requires.
type TransmitterMetadata struct {
	// SpecVersion is the version of SSF implemented, such as SpecVersion.
	SpecVersion string `json:"spec_version,omitempty"`
	// Issuer is the Transmitter's issuer identifier, an https URL. A
	// Receiver checks it against the issuer it expected.
	Issuer string `json:"issuer"`
	// JWKSURI is where the Transmitter publishes the keys that sign its
	// SETs. It must be https.
	JWKSURI string `json:"jwks_uri,omitempty"`
	// DeliveryMethodsSupported are the delivery methods the Transmitter
	// supports.
	DeliveryMethodsSupported []DeliveryMethod `json:"delivery_methods_supported,omitempty"`
	// ConfigurationEndpoint is the stream configuration endpoint
	// (SSF 1.0 §8.1.1); empty if not supported.
	ConfigurationEndpoint string `json:"configuration_endpoint,omitempty"`
	// StatusEndpoint is the stream status endpoint (SSF 1.0 §8.1.2);
	// empty if not supported.
	StatusEndpoint string `json:"status_endpoint,omitempty"`
	// AddSubjectEndpoint is the Add Subject endpoint (SSF 1.0 §8.1.3.2);
	// empty if not supported.
	AddSubjectEndpoint string `json:"add_subject_endpoint,omitempty"`
	// RemoveSubjectEndpoint is the Remove Subject endpoint
	// (SSF 1.0 §8.1.3.3); empty if not supported.
	RemoveSubjectEndpoint string `json:"remove_subject_endpoint,omitempty"`
	// VerificationEndpoint is the Verification endpoint
	// (SSF 1.0 §8.1.4.2); empty if not supported.
	VerificationEndpoint string `json:"verification_endpoint,omitempty"`
	// CriticalSubjectMembers names complex-subject members a Receiver
	// must understand: a Receiver rejects a SET whose subject carries
	// one it does not process (SSF 1.0 §3.6).
	CriticalSubjectMembers []string `json:"critical_subject_members,omitempty"`
	// AuthorizationSchemes are the schemes protecting the stream
	// management API.
	AuthorizationSchemes []AuthorizationScheme `json:"authorization_schemes,omitempty"`
	// DefaultSubjects says whether new streams include every subject or
	// none; empty if the Transmitter does not say.
	DefaultSubjects DefaultSubjects `json:"default_subjects,omitempty"`
}

// ValidateIssuer reports whether issuer is an https URL with no query or
// fragment (SSF 1.0 §7.1).
func ValidateIssuer(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" ||
		strings.HasSuffix(issuer, "?") || strings.HasSuffix(issuer, "#") || u.User != nil {
		return fmt.Errorf("ssf: issuer %q must be an https URL with no query, fragment or userinfo", issuer)
	}
	return nil
}

// WellKnownURL returns where issuer publishes its Transmitter
// Configuration Metadata: "/.well-known/ssf-configuration" inserted
// between the host and any path, with a trailing "/" removed first
// (SSF 1.0 §7.2).
func WellKnownURL(issuer string) (string, error) {
	if err := ValidateIssuer(issuer); err != nil {
		return "", err
	}
	u, _ := url.Parse(issuer)
	u.Path = WellKnownPath + strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}
