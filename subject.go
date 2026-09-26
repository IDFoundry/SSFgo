package ssf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"reflect"
	"sort"
	"strings"
)

// SubjectFormat is the value of a Subject Identifier's "format" member
// (RFC 9493 §3).
type SubjectFormat string

// Subject Identifier formats registered by RFC 9493 §3.2.
const (
	FormatAccount     SubjectFormat = "account"
	FormatEmail       SubjectFormat = "email"
	FormatIssSub      SubjectFormat = "iss_sub"
	FormatOpaque      SubjectFormat = "opaque"
	FormatPhoneNumber SubjectFormat = "phone_number"
	FormatDID         SubjectFormat = "did"
	FormatURI         SubjectFormat = "uri"
	FormatAliases     SubjectFormat = "aliases"
)

// Subject Identifier formats defined by SSF 1.0 §3.5, and the complex
// subject format of SSF 1.0 §3.3.
const (
	FormatJWTID           SubjectFormat = "jwt_id"
	FormatSAMLAssertionID SubjectFormat = "saml_assertion_id"
	FormatIPAddresses     SubjectFormat = "ip-addresses"
	FormatComplex         SubjectFormat = "complex"
)

// ErrInvalidSubject is wrapped by every error that reports a malformed or
// incomplete subject.
var ErrInvalidSubject = errors.New("ssf: invalid subject")

// Subject is a Subject Member value (SSF 1.0 §3.1.4): either a simple
// Subject Identifier (RFC 9493) or a ComplexSubject.
//
// Subject is a closed set. Its implementations are exactly the *Subject
// types in this package, so a type switch over them is exhaustive. A
// format agreed between two parties out of band (SSF 1.0 §3.4) is carried
// by ProprietarySubject.
//
// MarshalJSON validates before encoding, so an invalid subject can never
// be emitted.
type Subject interface {
	// Format returns the value of the subject's "format" member.
	Format() SubjectFormat
	// Validate reports whether every member the format requires is
	// present and well formed.
	Validate() error
	json.Marshaler

	isSubject()
}

func invalid(format SubjectFormat, msg string) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalidSubject, format, msg)
}

// AccountSubject identifies a subject by an "acct" URI (RFC 9493 §3.2.1).
type AccountSubject struct {
	URI string
}

// EmailSubject identifies a subject by email address (RFC 9493 §3.2.2).
// Addresses are compared exactly; a Receiver that needs provider-specific
// canonicalization (RFC 9493 §3.2.2.1) applies it itself.
type EmailSubject struct {
	Email string
}

// IssSubSubject identifies a subject by issuer and subject
// (RFC 9493 §3.2.3).
type IssSubSubject struct {
	Issuer  string
	Subject string
}

// OpaqueSubject identifies a subject by an opaque string
// (RFC 9493 §3.2.4). SSF's verification and stream-updated events use it
// to carry a stream ID.
type OpaqueSubject struct {
	ID string
}

// PhoneNumberSubject identifies a subject by telephone number
// (RFC 9493 §3.2.5).
type PhoneNumberSubject struct {
	PhoneNumber string
}

// DIDSubject identifies a subject by a Decentralized Identifier URL
// (RFC 9493 §3.2.6).
type DIDSubject struct {
	URL string
}

// URISubject identifies a subject by URI (RFC 9493 §3.2.7).
type URISubject struct {
	URI string
}

// AliasesSubject identifies one subject by several Subject Identifiers
// (RFC 9493 §3.2.8). Its identifiers may not themselves be aliases or
// complex subjects.
type AliasesSubject struct {
	Identifiers []Subject
}

// JWTIDSubject identifies a JWT by its issuer and "jti" (SSF 1.0 §3.5.1).
type JWTIDSubject struct {
	Issuer string
	JWTID  string
}

// SAMLAssertionIDSubject identifies a SAML 2.0 assertion
// (SSF 1.0 §3.5.2).
type SAMLAssertionIDSubject struct {
	Issuer      string
	AssertionID string
}

// IPAddressesSubject identifies a subject by the IP addresses the
// Transmitter observed for it (SSF 1.0 §3.5.3).
type IPAddressesSubject struct {
	Addresses []netip.Addr
}

// ComplexSubject describes one Subject Principal through several of its
// attributes (SSF 1.0 §3.3). At least one member must be set. Members are
// simple subjects: a ComplexSubject never nests another.
//
// Additional carries member names beyond those SSF 1.0 §3.3 lists; its
// keys must not repeat a named member or "format".
type ComplexSubject struct {
	User        Subject
	Device      Subject
	Session     Subject
	Application Subject
	Tenant      Subject
	OrgUnit     Subject
	Group       Subject
	Additional  map[string]Subject
}

// ProprietarySubject carries a Subject Identifier whose format is agreed
// between Transmitter and Receiver out of band (SSF 1.0 §3.4). Members
// holds every member except "format", as raw JSON.
type ProprietarySubject struct {
	FormatName SubjectFormat
	Members    map[string]json.RawMessage
}

func (AccountSubject) isSubject()         {}
func (EmailSubject) isSubject()           {}
func (IssSubSubject) isSubject()          {}
func (OpaqueSubject) isSubject()          {}
func (PhoneNumberSubject) isSubject()     {}
func (DIDSubject) isSubject()             {}
func (URISubject) isSubject()             {}
func (AliasesSubject) isSubject()         {}
func (JWTIDSubject) isSubject()           {}
func (SAMLAssertionIDSubject) isSubject() {}
func (IPAddressesSubject) isSubject()     {}
func (ComplexSubject) isSubject()         {}
func (ProprietarySubject) isSubject()     {}

// Format implements Subject.
func (AccountSubject) Format() SubjectFormat { return FormatAccount }

// Format implements Subject.
func (EmailSubject) Format() SubjectFormat { return FormatEmail }

// Format implements Subject.
func (IssSubSubject) Format() SubjectFormat { return FormatIssSub }

// Format implements Subject.
func (OpaqueSubject) Format() SubjectFormat { return FormatOpaque }

// Format implements Subject.
func (PhoneNumberSubject) Format() SubjectFormat { return FormatPhoneNumber }

// Format implements Subject.
func (DIDSubject) Format() SubjectFormat { return FormatDID }

// Format implements Subject.
func (URISubject) Format() SubjectFormat { return FormatURI }

// Format implements Subject.
func (AliasesSubject) Format() SubjectFormat { return FormatAliases }

// Format implements Subject.
func (JWTIDSubject) Format() SubjectFormat { return FormatJWTID }

// Format implements Subject.
func (SAMLAssertionIDSubject) Format() SubjectFormat { return FormatSAMLAssertionID }

// Format implements Subject.
func (IPAddressesSubject) Format() SubjectFormat { return FormatIPAddresses }

// Format implements Subject.
func (ComplexSubject) Format() SubjectFormat { return FormatComplex }

// Format implements Subject.
func (s ProprietarySubject) Format() SubjectFormat { return s.FormatName }

// Validate implements Subject.
func (s AccountSubject) Validate() error {
	if !strings.HasPrefix(s.URI, "acct:") || len(s.URI) == len("acct:") {
		return invalid(FormatAccount, `"uri" must be a non-empty acct URI`)
	}
	return nil
}

// Validate implements Subject. It checks only that the address has a
// non-empty local part and domain; RFC 5322 addr-spec syntax is otherwise
// the Transmitter's responsibility.
func (s EmailSubject) Validate() error {
	at := strings.LastIndexByte(s.Email, '@')
	if at <= 0 || at == len(s.Email)-1 {
		return invalid(FormatEmail, `"email" must be an email address`)
	}
	return nil
}

// Validate implements Subject.
func (s IssSubSubject) Validate() error {
	if s.Issuer == "" || s.Subject == "" {
		return invalid(FormatIssSub, `"iss" and "sub" are required`)
	}
	return nil
}

// Validate implements Subject.
func (s OpaqueSubject) Validate() error {
	if s.ID == "" {
		return invalid(FormatOpaque, `"id" is required`)
	}
	return nil
}

// Validate implements Subject. It requires the international prefix "+"
// (RFC 9493 §3.2.5) but does not otherwise police E.164 formatting.
func (s PhoneNumberSubject) Validate() error {
	if len(s.PhoneNumber) < 2 || s.PhoneNumber[0] != '+' {
		return invalid(FormatPhoneNumber, `"phone_number" must include the international "+" prefix`)
	}
	return nil
}

// Validate implements Subject.
func (s DIDSubject) Validate() error {
	if !strings.HasPrefix(s.URL, "did:") || len(s.URL) == len("did:") {
		return invalid(FormatDID, `"url" must be a DID URL`)
	}
	return nil
}

// Validate implements Subject.
func (s URISubject) Validate() error {
	u, err := url.Parse(s.URI)
	if s.URI == "" || err != nil || !u.IsAbs() {
		return invalid(FormatURI, `"uri" must be an absolute URI`)
	}
	return nil
}

// Validate implements Subject.
func (s AliasesSubject) Validate() error {
	if len(s.Identifiers) == 0 {
		return invalid(FormatAliases, `"identifiers" must not be empty`)
	}
	for i, id := range s.Identifiers {
		if id == nil {
			return invalid(FormatAliases, fmt.Sprintf("identifier %d is nil", i))
		}
		switch id.Format() {
		case FormatAliases, FormatComplex:
			return invalid(FormatAliases, fmt.Sprintf("identifier %d must not be %q", i, id.Format()))
		}
		if err := id.Validate(); err != nil {
			return fmt.Errorf("identifier %d: %w", i, err)
		}
	}
	return nil
}

// Validate implements Subject.
func (s JWTIDSubject) Validate() error {
	if s.Issuer == "" || s.JWTID == "" {
		return invalid(FormatJWTID, `"iss" and "jti" are required`)
	}
	return nil
}

// Validate implements Subject.
func (s SAMLAssertionIDSubject) Validate() error {
	if s.Issuer == "" || s.AssertionID == "" {
		return invalid(FormatSAMLAssertionID, `"issuer" and "assertion_id" are required`)
	}
	return nil
}

// Validate implements Subject.
func (s IPAddressesSubject) Validate() error {
	if len(s.Addresses) == 0 {
		return invalid(FormatIPAddresses, `"ip-addresses" must not be empty`)
	}
	for i, a := range s.Addresses {
		if !a.IsValid() || a.Zone() != "" {
			return invalid(FormatIPAddresses, fmt.Sprintf("address %d is not a valid IP address", i))
		}
	}
	return nil
}

// complexMemberNames lists the member names SSF 1.0 §3.3 defines, in the
// order they are encoded.
var complexMemberNames = []string{"user", "device", "session", "application", "tenant", "org_unit", "group"}

// named returns pointers to s's defined members, in complexMemberNames
// order.
func (s *ComplexSubject) named() []*Subject {
	return []*Subject{&s.User, &s.Device, &s.Session, &s.Application, &s.Tenant, &s.OrgUnit, &s.Group}
}

// members returns every set member keyed by its wire name.
func (s ComplexSubject) members() map[string]Subject {
	out := make(map[string]Subject, len(complexMemberNames)+len(s.Additional))
	for i, p := range s.named() {
		if *p != nil {
			out[complexMemberNames[i]] = *p
		}
	}
	for k, v := range s.Additional {
		out[k] = v
	}
	return out
}

// Validate implements Subject.
func (s ComplexSubject) Validate() error {
	for k := range s.Additional {
		if k == "format" || isComplexMemberName(k) {
			return invalid(FormatComplex, fmt.Sprintf("additional member %q collides with a defined member", k))
		}
	}
	members := s.members()
	if len(members) == 0 {
		return invalid(FormatComplex, "at least one member is required")
	}
	for name, m := range members {
		if m == nil {
			return invalid(FormatComplex, fmt.Sprintf("member %q is nil", name))
		}
		if m.Format() == FormatComplex {
			return invalid(FormatComplex, fmt.Sprintf("member %q must be a simple subject", name))
		}
		if err := m.Validate(); err != nil {
			return fmt.Errorf("member %q: %w", name, err)
		}
	}
	return nil
}

func isComplexMemberName(name string) bool {
	for _, n := range complexMemberNames {
		if n == name {
			return true
		}
	}
	return false
}

// Validate implements Subject.
func (s ProprietarySubject) Validate() error {
	if s.FormatName == "" {
		return fmt.Errorf("%w: proprietary subject has no format", ErrInvalidSubject)
	}
	if isKnownFormat(s.FormatName) {
		return invalid(s.FormatName, "a registered format cannot be carried as a proprietary subject")
	}
	if _, ok := s.Members["format"]; ok {
		return invalid(s.FormatName, `members must not include "format"`)
	}
	for k, v := range s.Members {
		if !json.Valid(v) {
			return invalid(s.FormatName, fmt.Sprintf("member %q is not valid JSON", k))
		}
	}
	return nil
}

func isKnownFormat(f SubjectFormat) bool {
	switch f {
	case FormatAccount, FormatEmail, FormatIssSub, FormatOpaque, FormatPhoneNumber,
		FormatDID, FormatURI, FormatAliases, FormatJWTID, FormatSAMLAssertionID,
		FormatIPAddresses, FormatComplex:
		return true
	default:
		return false
	}
}

// member is one name/value pair of an encoded JSON object.
type member struct {
	name  string
	value any
}

// encodeObject validates s, then writes its members as a JSON object with
// "format" first. encoding/json's struct and map encoders cannot express
// that ordering for the map-shaped subjects, and consistency is worth one
// small helper.
func encodeObject(s Subject, members ...member) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(`{"format":`)
	f, err := json.Marshal(string(s.Format()))
	if err != nil {
		return nil, err
	}
	buf.Write(f)
	for _, m := range members {
		name, err := json.Marshal(m.name)
		if err != nil {
			return nil, err
		}
		value, err := json.Marshal(m.value)
		if err != nil {
			return nil, fmt.Errorf("ssf: encode subject member %q: %w", m.name, err)
		}
		buf.WriteByte(',')
		buf.Write(name)
		buf.WriteByte(':')
		buf.Write(value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// MarshalJSON implements json.Marshaler.
func (s AccountSubject) MarshalJSON() ([]byte, error) {
	return encodeObject(s, member{"uri", s.URI})
}

// MarshalJSON implements json.Marshaler.
func (s EmailSubject) MarshalJSON() ([]byte, error) {
	return encodeObject(s, member{"email", s.Email})
}

// MarshalJSON implements json.Marshaler.
func (s IssSubSubject) MarshalJSON() ([]byte, error) {
	return encodeObject(s, member{"iss", s.Issuer}, member{"sub", s.Subject})
}

// MarshalJSON implements json.Marshaler.
func (s OpaqueSubject) MarshalJSON() ([]byte, error) {
	return encodeObject(s, member{"id", s.ID})
}

// MarshalJSON implements json.Marshaler.
func (s PhoneNumberSubject) MarshalJSON() ([]byte, error) {
	return encodeObject(s, member{"phone_number", s.PhoneNumber})
}

// MarshalJSON implements json.Marshaler.
func (s DIDSubject) MarshalJSON() ([]byte, error) {
	return encodeObject(s, member{"url", s.URL})
}

// MarshalJSON implements json.Marshaler.
func (s URISubject) MarshalJSON() ([]byte, error) {
	return encodeObject(s, member{"uri", s.URI})
}

// MarshalJSON implements json.Marshaler.
func (s AliasesSubject) MarshalJSON() ([]byte, error) {
	return encodeObject(s, member{"identifiers", s.Identifiers})
}

// MarshalJSON implements json.Marshaler.
func (s JWTIDSubject) MarshalJSON() ([]byte, error) {
	return encodeObject(s, member{"iss", s.Issuer}, member{"jti", s.JWTID})
}

// MarshalJSON implements json.Marshaler.
func (s SAMLAssertionIDSubject) MarshalJSON() ([]byte, error) {
	return encodeObject(s, member{"issuer", s.Issuer}, member{"assertion_id", s.AssertionID})
}

// MarshalJSON implements json.Marshaler.
func (s IPAddressesSubject) MarshalJSON() ([]byte, error) {
	addrs := make([]string, len(s.Addresses))
	for i, a := range s.Addresses {
		addrs[i] = a.String()
	}
	return encodeObject(s, member{"ip-addresses", addrs})
}

// MarshalJSON implements json.Marshaler. Defined members are encoded in
// SSF 1.0 §3.3 order, followed by Additional members sorted by name.
func (s ComplexSubject) MarshalJSON() ([]byte, error) {
	var ms []member
	for i, p := range s.named() {
		if *p != nil {
			ms = append(ms, member{complexMemberNames[i], *p})
		}
	}
	extra := make([]string, 0, len(s.Additional))
	for k := range s.Additional {
		extra = append(extra, k)
	}
	sort.Strings(extra)
	for _, k := range extra {
		ms = append(ms, member{k, s.Additional[k]})
	}
	return encodeObject(s, ms...)
}

// MarshalJSON implements json.Marshaler. Members are sorted by name.
func (s ProprietarySubject) MarshalJSON() ([]byte, error) {
	names := make([]string, 0, len(s.Members))
	for k := range s.Members {
		names = append(names, k)
	}
	sort.Strings(names)
	ms := make([]member, len(names))
	for i, k := range names {
		ms[i] = member{k, s.Members[k]}
	}
	return encodeObject(s, ms...)
}

// ParseSubject decodes and validates a Subject Member value.
//
// Members the format does not define are ignored rather than rejected:
// SSF 1.0 §4.2.3 requires Receivers to ignore fields they do not
// understand. A format ParseSubject does not recognize is returned as a
// ProprietarySubject, which the caller may reject.
func ParseSubject(data []byte) (Subject, error) {
	return parseSubject(data, 0)
}

// maxSubjectDepth bounds recursion. The deepest legal nesting is a
// complex subject containing an aliases subject containing simple
// identifiers: depth 2.
const maxSubjectDepth = 2

func parseSubject(data []byte, depth int) (Subject, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, fmt.Errorf("%w: subject must be a JSON object", ErrInvalidSubject)
	}
	rawFormat, ok := obj["format"]
	if !ok {
		return nil, fmt.Errorf("%w: missing \"format\"", ErrInvalidSubject)
	}
	var format SubjectFormat
	if err := json.Unmarshal(rawFormat, &format); err != nil || format == "" {
		return nil, fmt.Errorf("%w: \"format\" must be a non-empty string", ErrInvalidSubject)
	}

	str := func(name string) (string, error) {
		raw, ok := obj[name]
		if !ok {
			return "", nil
		}
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return "", invalid(format, fmt.Sprintf("%q must be a string", name))
		}
		return v, nil
	}
	var s Subject
	var err error
	switch format {
	case FormatAccount:
		var v AccountSubject
		v.URI, err = str("uri")
		s = v
	case FormatEmail:
		var v EmailSubject
		v.Email, err = str("email")
		s = v
	case FormatIssSub:
		var v IssSubSubject
		if v.Issuer, err = str("iss"); err == nil {
			v.Subject, err = str("sub")
		}
		s = v
	case FormatOpaque:
		var v OpaqueSubject
		v.ID, err = str("id")
		s = v
	case FormatPhoneNumber:
		var v PhoneNumberSubject
		v.PhoneNumber, err = str("phone_number")
		s = v
	case FormatDID:
		var v DIDSubject
		v.URL, err = str("url")
		s = v
	case FormatURI:
		var v URISubject
		v.URI, err = str("uri")
		s = v
	case FormatJWTID:
		var v JWTIDSubject
		if v.Issuer, err = str("iss"); err == nil {
			v.JWTID, err = str("jti")
		}
		s = v
	case FormatSAMLAssertionID:
		var v SAMLAssertionIDSubject
		if v.Issuer, err = str("issuer"); err == nil {
			v.AssertionID, err = str("assertion_id")
		}
		s = v
	case FormatIPAddresses:
		s, err = parseIPAddresses(obj["ip-addresses"])
	case FormatAliases:
		s, err = parseAliases(obj["identifiers"], depth)
	case FormatComplex:
		s, err = parseComplex(obj, depth)
	default:
		delete(obj, "format")
		s = ProprietarySubject{FormatName: format, Members: obj}
	}
	if err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

func parseIPAddresses(raw json.RawMessage) (Subject, error) {
	var strs []string
	if raw != nil {
		if err := json.Unmarshal(raw, &strs); err != nil {
			return nil, invalid(FormatIPAddresses, `"ip-addresses" must be an array of strings`)
		}
	}
	v := IPAddressesSubject{Addresses: make([]netip.Addr, 0, len(strs))}
	for i, s := range strs {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, invalid(FormatIPAddresses, fmt.Sprintf("address %d: %v", i, err))
		}
		v.Addresses = append(v.Addresses, a)
	}
	return v, nil
}

func parseAliases(raw json.RawMessage, depth int) (Subject, error) {
	if depth >= maxSubjectDepth {
		return nil, invalid(FormatAliases, "nested too deeply")
	}
	var items []json.RawMessage
	if raw != nil {
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, invalid(FormatAliases, `"identifiers" must be an array`)
		}
	}
	v := AliasesSubject{Identifiers: make([]Subject, 0, len(items))}
	for i, item := range items {
		id, err := parseSubject(item, depth+1)
		if err != nil {
			return nil, fmt.Errorf("identifier %d: %w", i, err)
		}
		v.Identifiers = append(v.Identifiers, id)
	}
	return v, nil
}

func parseComplex(obj map[string]json.RawMessage, depth int) (Subject, error) {
	if depth > 0 {
		return nil, invalid(FormatComplex, "a complex subject cannot be nested")
	}
	var v ComplexSubject
	named := v.named()
	for name, raw := range obj {
		if name == "format" {
			continue
		}
		m, err := parseSubject(raw, depth+1)
		if err != nil {
			return nil, fmt.Errorf("member %q: %w", name, err)
		}
		placed := false
		for i, n := range complexMemberNames {
			if n == name {
				*named[i] = m
				placed = true
				break
			}
		}
		if !placed {
			if v.Additional == nil {
				v.Additional = make(map[string]Subject)
			}
			v.Additional[name] = m
		}
	}
	return v, nil
}

// SubjectsMatch reports whether a and b match under SSF 1.0 §8.1.3.1.
// Simple subjects match when they are identical. Two complex subjects
// match when every member defined in both is identical; a member defined
// in only one of them acts as a wildcard. A simple subject never matches a
// complex one.
func SubjectsMatch(a, b Subject) bool {
	ca, aComplex := a.(ComplexSubject)
	cb, bComplex := b.(ComplexSubject)
	switch {
	case aComplex && bComplex:
		ma, mb := ca.members(), cb.members()
		for name, x := range ma {
			if y, ok := mb[name]; ok && !SubjectsEqual(x, y) {
				return false
			}
		}
		return true
	case aComplex || bComplex:
		return false
	default:
		return SubjectsEqual(a, b)
	}
}

// SubjectsEqual reports whether a and b are identical: the same format and
// the same member values. Aliases compare their identifiers in order.
func SubjectsEqual(a, b Subject) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Format() != b.Format() {
		return false
	}
	switch x := a.(type) {
	case AliasesSubject:
		y := b.(AliasesSubject)
		if len(x.Identifiers) != len(y.Identifiers) {
			return false
		}
		for i := range x.Identifiers {
			if !SubjectsEqual(x.Identifiers[i], y.Identifiers[i]) {
				return false
			}
		}
		return true
	case IPAddressesSubject:
		y := b.(IPAddressesSubject)
		if len(x.Addresses) != len(y.Addresses) {
			return false
		}
		for i := range x.Addresses {
			if x.Addresses[i] != y.Addresses[i] {
				return false
			}
		}
		return true
	case ComplexSubject:
		ma, mb := x.members(), b.(ComplexSubject).members()
		if len(ma) != len(mb) {
			return false
		}
		for name, m := range ma {
			if !SubjectsEqual(m, mb[name]) {
				return false
			}
		}
		return true
	case ProprietarySubject:
		y := b.(ProprietarySubject)
		if len(x.Members) != len(y.Members) {
			return false
		}
		for k, v := range x.Members {
			w, ok := y.Members[k]
			if !ok || !jsonEqual(v, w) {
				return false
			}
		}
		return true
	default:
		// Every remaining type is a comparable struct of strings.
		return a == b
	}
}

// jsonEqual reports whether a and b encode the same JSON value. It compares
// decoded values rather than bytes, since equivalent JSON can differ in
// whitespace and string escaping (encoding/json writes "&" as "\u0026").
// Numbers compare by their literal text.
func jsonEqual(a, b json.RawMessage) bool {
	va, errA := decodeJSONValue(a)
	vb, errB := decodeJSONValue(b)
	return errA == nil && errB == nil && reflect.DeepEqual(va, vb)
}

func decodeJSONValue(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	err := dec.Decode(&v)
	return v, err
}
