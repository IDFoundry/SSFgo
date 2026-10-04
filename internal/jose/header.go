package jose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	ssf "github.com/idfoundry/ssfgo"
	"github.com/idfoundry/ssfgo/internal/critical"
)

// Header is a JWS protected header. Only the members SSFgo acts on are
// modeled. Every other member is ignored, as RFC 7515 §4.2/§4.3 require,
// except that "crit" (RFC 7515 §4.1.11) may only name members this
// package understands.
type Header struct {
	Algorithm ssf.SignatureAlgorithm
	Type      string // "typ", optional
	KeyID     string // "kid", optional
}

type rawHeader struct {
	Alg  string   `json:"alg"`
	Typ  string   `json:"typ,omitempty"`
	Kid  string   `json:"kid,omitempty"`
	Crit []string `json:"crit,omitempty"`
}

// understoodHeaderParams is every header member this package processes —
// the set a "crit" list is checked against.
var understoodHeaderParams = map[string]bool{
	"alg": true, "typ": true, "kid": true, "crit": true,
}

func marshalHeader(h Header) ([]byte, error) {
	if !h.Algorithm.IsValid() {
		return nil, fmt.Errorf("jose: invalid algorithm %v", h.Algorithm)
	}
	return json.Marshal(rawHeader{Alg: h.Algorithm.String(), Typ: h.Type, Kid: h.KeyID})
}

// parseHeader reads the header's members by their exact names. A header
// that repeats a member, or whose "crit" is empty, is refused: JSON parsers
// disagree on such input, and encoding/json would also match "ALG" to
// "alg" and let a later duplicate override an earlier one.
func parseHeader(data []byte) (Header, error) {
	members, err := uniqueMembers(data)
	if err != nil {
		return Header{}, fmt.Errorf("jose: parse header: %w", err)
	}
	var raw rawHeader
	for name, dst := range map[string]any{"alg": &raw.Alg, "typ": &raw.Typ, "kid": &raw.Kid, "crit": &raw.Crit} {
		if v, ok := members[name]; ok {
			if err := json.Unmarshal(v, dst); err != nil {
				return Header{}, fmt.Errorf("jose: parse header: %s: %w", name, err)
			}
		}
	}
	if _, ok := members["crit"]; ok && len(raw.Crit) == 0 {
		return Header{}, errors.New("jose: parse header: crit must not be empty (RFC 7515 §4.1.11)")
	}
	if err := critical.Check(raw.Crit, understoodHeaderParams); err != nil {
		return Header{}, fmt.Errorf("jose: parse header: %w", err)
	}
	alg, err := ssf.ParseSignatureAlgorithm(raw.Alg)
	if err != nil {
		return Header{}, fmt.Errorf("jose: parse header: %w", err)
	}
	return Header{Algorithm: alg, Type: raw.Typ, KeyID: raw.Kid}, nil
}

// uniqueMembers returns the members of the JSON object data, refusing one
// that names a member twice.
func uniqueMembers(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	members := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, _ := tok.(string)
		if _, dup := members[name]; dup {
			return nil, fmt.Errorf("member %q appears more than once", name)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		members[name] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if dec.More() || dec.InputOffset() != int64(len(bytes.TrimRight(data, " \t\r\n"))) {
		return nil, errors.New("trailing data after the JSON object")
	}
	return members, nil
}
