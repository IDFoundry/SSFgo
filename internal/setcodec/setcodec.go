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
	// Audience must be one of the SET's "aud" values.
	Audience string
	// Algorithms lists the signature algorithms accepted.
	Algorithms []ssf.SignatureAlgorithm
	// Keys are the Transmitter's signing keys, from its JWKS.
	Keys []jose.SetKey
	// Registry decodes the event. An event type it does not hold is
	// rejected.
	Registry *ssf.Registry
	// Now returns the current time. It defaults to time.Now.
	Now func() time.Time
	// MaxClockSkew is how far in the future "iat" may be. It defaults to
	// one minute.
	MaxClockSkew time.Duration
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
	var err error
	if set.Issuer, err = stringClaim(raw, "iss", true); err != nil {
		return ssf.SET{}, err
	}
	if set.Issuer != opts.Issuer {
		return ssf.SET{}, reject(CodeInvalidIssuer, "iss %q does not match %q", set.Issuer, opts.Issuer)
	}
	if set.Audience, err = audienceClaim(raw["aud"]); err != nil {
		return ssf.SET{}, err
	}
	if !slices.Contains(set.Audience, opts.Audience) {
		return ssf.SET{}, reject(CodeInvalidAudience, "aud does not contain %q", opts.Audience)
	}
	if set.JWTID, err = stringClaim(raw, "jti", true); err != nil {
		return ssf.SET{}, err
	}
	if set.TransactionID, err = stringClaim(raw, "txn", false); err != nil {
		return ssf.SET{}, err
	}

	rawIat, ok := raw["iat"]
	if !ok {
		return ssf.SET{}, reject(CodeInvalidRequest, "claim \"iat\" is required")
	}
	var iat ssf.NumericDate
	if err := json.Unmarshal(rawIat, &iat); err != nil {
		return ssf.SET{}, reject(CodeInvalidRequest, "iat: %w", err)
	}
	now, skew := time.Now, time.Minute
	if opts.Now != nil {
		now = opts.Now
	}
	if opts.MaxClockSkew > 0 {
		skew = opts.MaxClockSkew
	}
	if iat.After(now().Add(skew)) {
		return ssf.SET{}, reject(CodeInvalidRequest, "iat is in the future")
	}
	set.IssuedAt = iat.Time

	rawSub, ok := raw["sub_id"]
	if !ok {
		return ssf.SET{}, reject(CodeInvalidRequest, "claim \"sub_id\" is required")
	}
	if set.Subject, err = ssf.ParseSubject(rawSub); err != nil {
		return ssf.SET{}, reject(CodeInvalidRequest, "sub_id: %w", err)
	}

	var events map[ssf.EventType]json.RawMessage
	if err := json.Unmarshal(raw["events"], &events); err != nil || events == nil {
		return ssf.SET{}, reject(CodeInvalidRequest, "claim \"events\" must be a JSON object")
	}
	if len(events) != 1 {
		return ssf.SET{}, reject(CodeInvalidRequest, "events must hold exactly one event, got %d", len(events))
	}
	for typ, payload := range events {
		if set.Event, err = opts.Registry.Decode(typ, payload); err != nil {
			return ssf.SET{}, &DecodeError{Code: CodeInvalidRequest, Err: err}
		}
	}

	if err := set.Validate(); err != nil {
		return ssf.SET{}, &DecodeError{Code: CodeInvalidRequest, Err: err}
	}
	return set, nil
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
