// Package setcodec signs and verifies Security Event Tokens as profiled by
// SSF 1.0 §4. It is the only place in SSFgo that turns an ssf.SET into a
// JWS or back.
//
// Encoding is used by the Transmitter and decoding by the Receiver; the
// two directions share only the claim names. Decode never trusts the token
// to choose its own verification policy: the caller states the issuer,
// audience, acceptable algorithms, keys and event types up front.
package setcodec

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/jose"
)

// TypeHeader is the JOSE "typ" header value every SSF SET carries
// (SSF 1.0 §4.1.1, RFC 8417 §2.3).
const TypeHeader = "secevent+jwt"

// Signer signs SETs with one key.
type Signer struct {
	Key       crypto.Signer
	Algorithm ssf.SignatureAlgorithm
	// KeyID is the "kid" header value. It should match the key's entry in
	// the Transmitter's JWKS.
	KeyID string
}

type claims struct {
	Iss    string                      `json:"iss"`
	Jti    string                      `json:"jti"`
	Iat    ssf.NumericDate             `json:"iat"`
	Aud    any                         `json:"aud"`
	Txn    string                      `json:"txn,omitempty"`
	SubID  ssf.Subject                 `json:"sub_id"`
	Events map[ssf.EventType]ssf.Event `json:"events"`
}

// Encode validates set and signs it. A single audience is encoded as a
// string and several as an array (SSF 1.0 §4.1.8).
func Encode(s Signer, set ssf.SET) (string, error) {
	if err := set.Validate(); err != nil {
		return "", err
	}
	c := claims{
		Iss:    set.Issuer,
		Jti:    set.JWTID,
		Iat:    ssf.NewNumericDate(set.IssuedAt),
		Txn:    set.TransactionID,
		SubID:  set.Subject,
		Events: map[ssf.EventType]ssf.Event{set.Event.EventType(): set.Event},
	}
	if len(set.Audience) == 1 {
		c.Aud = set.Audience[0]
	} else {
		c.Aud = set.Audience
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("setcodec: encode claims: %w", err)
	}
	return jose.Sign(s.Key, jose.Header{Algorithm: s.Algorithm, Type: TypeHeader, KeyID: s.KeyID}, payload)
}

// Error codes a Receiver reports for a SET it rejects (RFC 8935 §2.4,
// RFC 8936 §2.4.4).
const (
	CodeInvalidRequest  = "invalid_request"
	CodeInvalidKey      = "invalid_key"
	CodeInvalidIssuer   = "invalid_issuer"
	CodeInvalidAudience = "invalid_audience"
)

// DecodeError reports why Decode rejected a SET, with the RFC 8935 error
// code a Receiver should return for it.
type DecodeError struct {
	Code string
	Err  error
}

func (e *DecodeError) Error() string { return "setcodec: " + e.Code + ": " + e.Err.Error() }

func (e *DecodeError) Unwrap() error { return e.Err }

func reject(code string, format string, args ...any) error {
	return &DecodeError{Code: code, Err: fmt.Errorf(format, args...)}
}

// VerifyOptions is the policy Decode enforces. Every field except Now and
// MaxClockSkew is required.
type VerifyOptions struct {
	// Issuer must equal the SET's "iss" exactly (SSF 1.0 §4.1.6).
	Issuer string
	// Audience must be one of the SET's "aud" values, unless
	// AudienceMatch accepts another.
	Audience string
	// AudienceMatch, if set, also accepts a SET with an "aud" value for
	// which it returns true. Optional.
	AudienceMatch func(aud string) bool
	// Algorithms lists the signature algorithms accepted.
	Algorithms []ssf.SignatureAlgorithm
	// Keys are the Transmitter's signing keys, from its JWKS.
	Keys []jose.SetKey
	// Registry decodes the event. An event type it does not hold is
	// rejected.
	Registry *ssf.Registry
	// Now returns the current time. It defaults to time.Now.
	Now func() time.Time
	// MaxClockSkew is how far in the future "iat" and "nbf" may be. It defaults to
	// one minute.
	MaxClockSkew time.Duration

	// LegacyEventSubject accepts a SET without "sub_id" whose event
	// object carries a "subject" member instead, as CAEP and RISC events
	// did before SSF 1.0 (SSF 1.0 §3.1.1 lets those event types keep the
	// member, but requires "sub_id" too).
	LegacyEventSubject bool
	// LegacySubjectType accepts a subject identifier that names its format
	// in "subject_type" rather than "format", as Google's RISC Transmitter
	// does (RISC 1.0 §3.1), mapping Google's "iss-sub" and "phone" to
	// "iss_sub" and "phone_number".
	LegacySubjectType bool
}

// Decode verifies token against opts and returns its content. Every
// failure is a *DecodeError.
func Decode(token string, opts VerifyOptions) (ssf.SET, error) {
	if opts.Issuer == "" || opts.Audience == "" || len(opts.Algorithms) == 0 || opts.Registry == nil {
		return ssf.SET{}, fmt.Errorf("setcodec: VerifyOptions requires Issuer, Audience, Algorithms and Registry")
	}
	compact, err := jose.ParseCompact(token)
	if err != nil {
		return ssf.SET{}, &DecodeError{Code: CodeInvalidRequest, Err: err}
	}
	if !isSETType(compact.Header.Type) {
		return ssf.SET{}, reject(CodeInvalidRequest, "typ header %q is not %q", compact.Header.Type, TypeHeader)
	}
	if err := verifySignature(compact, opts); err != nil {
		return ssf.SET{}, err
	}
	return decodeClaims(compact.Payload, opts)
}

// isSETType accepts "secevent+jwt" and its full media type form
// "application/secevent+jwt", case-insensitively (RFC 7515 §4.1.9).
func isSETType(typ string) bool {
	typ = strings.ToLower(typ)
	return typ == TypeHeader || typ == "application/"+TypeHeader
}

func verifySignature(c jose.Compact, opts VerifyOptions) error {
	alg := c.Header.Algorithm
	if !slices.Contains(opts.Algorithms, alg) {
		return reject(CodeInvalidKey, "signature algorithm %s is not accepted", alg)
	}
	tried := 0
	for _, k := range opts.Keys {
		if c.Header.KeyID != "" && k.KeyID != c.Header.KeyID {
			continue
		}
		if !k.UsableWith(alg) {
			continue
		}
		tried++
		if c.Verify(k.PublicKey, alg) == nil {
			return nil
		}
	}
	if tried == 0 {
		return reject(CodeInvalidKey, "no %s key matches kid %q", alg, c.Header.KeyID)
	}
	return &DecodeError{Code: CodeInvalidKey, Err: jose.ErrInvalidSignature}
}

func decodeClaims(payload []byte, opts VerifyOptions) (ssf.SET, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil || raw == nil {
		return ssf.SET{}, reject(CodeInvalidRequest, "claims are not a JSON object")
	}
	// SSF 1.0 §4.1.3: a SET must not be mistakable for another kind of JWT.
	for _, forbidden := range []string{"sub", "exp"} {
		if _, ok := raw[forbidden]; ok {
			return ssf.SET{}, reject(CodeInvalidRequest, "claim %q must not be present", forbidden)
		}
	}

	var set ssf.SET
	if err := decodeIdentity(raw, opts, &set); err != nil {
		return ssf.SET{}, err
	}
	iat, err := decodeIssuedAt(raw, opts)
	if err != nil {
		return ssf.SET{}, err
	}
	set.IssuedAt = iat
	if err := checkNotBefore(raw, opts); err != nil {
		return ssf.SET{}, err
	}
	if err := decodeEvent(raw, opts, &set); err != nil {
		return ssf.SET{}, err
	}
	if err := set.Validate(); err != nil {
		return ssf.SET{}, &DecodeError{Code: CodeInvalidRequest, Err: err}
	}
	return set, nil
}

// decodeIdentity decodes "iss", "aud", "jti" and "txn", requiring the
// issuer to match and the audience to include the Receiver's.
func decodeIdentity(raw map[string]json.RawMessage, opts VerifyOptions, set *ssf.SET) error {
	var err error
	if set.Issuer, err = stringClaim(raw, "iss", true); err != nil {
		return err
	}
	if set.Issuer != opts.Issuer {
		return reject(CodeInvalidIssuer, "iss %q does not match %q", set.Issuer, opts.Issuer)
	}
	if set.Audience, err = audienceClaim(raw["aud"]); err != nil {
		return err
	}
	if !slices.Contains(set.Audience, opts.Audience) &&
		(opts.AudienceMatch == nil || !slices.ContainsFunc(set.Audience, opts.AudienceMatch)) {
		return reject(CodeInvalidAudience, "aud does not contain %q", opts.Audience)
	}
	if set.JWTID, err = stringClaim(raw, "jti", true); err != nil {
		return err
	}
	set.TransactionID, err = stringClaim(raw, "txn", false)
	return err
}

// decodeIssuedAt decodes the required "iat", refusing one further in the
// future than the allowed clock skew.
func decodeIssuedAt(raw map[string]json.RawMessage, opts VerifyOptions) (time.Time, error) {
	rawIat, ok := raw["iat"]
	if !ok {
		return time.Time{}, reject(CodeInvalidRequest, "claim \"iat\" is required")
	}
	var iat ssf.NumericDate
	if err := json.Unmarshal(rawIat, &iat); err != nil {
		return time.Time{}, reject(CodeInvalidRequest, "iat: %w", err)
	}
	if iat.After(latestAcceptable(opts)) {
		return time.Time{}, reject(CodeInvalidRequest, "iat is in the future")
	}
	return iat.Time, nil
}

// checkNotBefore enforces an optional "nbf": RFC 7519 §4.1.5 forbids
// accepting a JWT before that time. SETs need not carry it, but some
// Transmitters' JWT libraries add it.
func checkNotBefore(raw map[string]json.RawMessage, opts VerifyOptions) error {
	rawNbf, ok := raw["nbf"]
	if !ok {
		return nil
	}
	var nbf ssf.NumericDate
	if err := json.Unmarshal(rawNbf, &nbf); err != nil {
		return reject(CodeInvalidRequest, "claim \"nbf\": %v", err)
	}
	if nbf.After(latestAcceptable(opts)) {
		return reject(CodeInvalidRequest, "the SET is not valid before its nbf")
	}
	return nil
}

// latestAcceptable is the latest time "iat" or "nbf" may name: now, plus
// the clock skew allowed.
func latestAcceptable(opts VerifyOptions) time.Time {
	now, skew := time.Now, time.Minute
	if opts.Now != nil {
		now = opts.Now
	}
	if opts.MaxClockSkew > 0 {
		skew = opts.MaxClockSkew
	}
	return now().Add(skew)
}

// decodeEvent decodes the single event in "events" and the subject, from
// "sub_id" or, for legacy Transmitters when allowed, the event itself.
func decodeEvent(raw map[string]json.RawMessage, opts VerifyOptions, set *ssf.SET) error {
	var events map[ssf.EventType]json.RawMessage
	if err := json.Unmarshal(raw["events"], &events); err != nil || events == nil {
		return reject(CodeInvalidRequest, "claim \"events\" must be a JSON object")
	}
	if len(events) != 1 {
		return reject(CodeInvalidRequest, "events must hold exactly one event, got %d", len(events))
	}

	rawSub, ok := raw["sub_id"]
	if !ok && opts.LegacyEventSubject {
		rawSub, ok = eventSubject(events)
	}
	if !ok {
		return reject(CodeInvalidRequest, "claim \"sub_id\" is required")
	}
	if opts.LegacySubjectType {
		rawSub = normalizeSubjectType(rawSub)
	}
	var err error
	if set.Subject, err = ssf.ParseSubject(rawSub); err != nil {
		return reject(CodeInvalidRequest, "sub_id: %w", err)
	}
	for typ, payload := range events {
		if set.Event, err = opts.Registry.Decode(typ, payload); err != nil {
			return &DecodeError{Code: CodeInvalidRequest, Err: err}
		}
	}
	return nil
}

// eventSubject returns the "subject" member of the single event object.
func eventSubject(events map[ssf.EventType]json.RawMessage) (json.RawMessage, bool) {
	for _, payload := range events {
		var obj map[string]json.RawMessage
		if json.Unmarshal(payload, &obj) != nil {
			return nil, false
		}
		s, ok := obj["subject"]
		return s, ok
	}
	return nil, false
}

// legacySubjectTypes maps Google's subject_type values to RFC 9493
// formats; others are used as they are.
var legacySubjectTypes = map[string]string{"iss-sub": "iss_sub", "phone": "phone_number"}

// normalizeSubjectType rewrites a subject identifier that uses
// "subject_type" and no "format" to the RFC 9493 form. Anything else is
// returned unchanged.
func normalizeSubjectType(raw json.RawMessage) json.RawMessage {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return raw
	}
	if _, has := obj["format"]; has {
		return raw
	}
	var typ string
	if json.Unmarshal(obj["subject_type"], &typ) != nil || typ == "" {
		return raw
	}
	if mapped, ok := legacySubjectTypes[typ]; ok {
		typ = mapped
	}
	format, _ := json.Marshal(typ)
	obj["format"] = format
	delete(obj, "subject_type")
	out, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return out
}

func stringClaim(raw map[string]json.RawMessage, name string, required bool) (string, error) {
	v, ok := raw[name]
	if !ok {
		if required {
			return "", reject(CodeInvalidRequest, "claim %q is required", name)
		}
		return "", nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil || (required && s == "") || string(v) == "null" {
		return "", reject(CodeInvalidRequest, "claim %q must be a non-empty string", name)
	}
	return s, nil
}

func audienceClaim(v json.RawMessage) ([]string, error) {
	if v == nil {
		return nil, reject(CodeInvalidRequest, "claim \"aud\" is required")
	}
	var one string
	if err := json.Unmarshal(v, &one); err == nil && string(v) != "null" {
		if one == "" {
			return nil, reject(CodeInvalidRequest, "aud must not be empty")
		}
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(v, &many); err != nil || len(many) == 0 || slices.Contains(many, "") {
		return nil, reject(CodeInvalidRequest, "aud must be a string or a non-empty array of strings")
	}
	return many, nil
}

// IsDecodeError reports whether err is a *DecodeError and returns it.
func IsDecodeError(err error) (*DecodeError, bool) {
	var de *DecodeError
	ok := errors.As(err, &de)
	return de, ok
}
