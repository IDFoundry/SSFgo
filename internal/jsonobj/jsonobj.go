// Package jsonobj decodes a JSON object strictly: a member named twice is
// an error, not a value the last occurrence silently wins. JSON parsers
// disagree on such input, so accepting it lets two parties read one
// document differently.
package jsonobj

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Members returns the members of the JSON object data, refusing anything
// but one object — including one that names a member twice.
func Members(data []byte) (map[string]json.RawMessage, error) {
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
