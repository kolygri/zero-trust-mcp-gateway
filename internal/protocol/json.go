// Package protocol implements the deliberately narrow MCP 2026-07-28 boundary.
package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

const MaxDepth = 32

// StrictJSON rejects ambiguous encodings before decoding. Unknown Go struct
// fields are rejected; callers needing extensible objects can use a map.
func StrictJSON(data []byte, dst any) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	if err := validSurrogates(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walk(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	dec = json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("JSON does not match the supported shape")
	}
	return nil
}

func walk(dec *json.Decoder, depth int) error {
	if depth > MaxDepth {
		return errors.New("JSON nesting exceeds limit")
	}
	tok, err := dec.Token()
	if err != nil {
		return errors.New("invalid JSON")
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return errors.New("invalid object")
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if seen[name] {
				return errors.New("duplicate JSON key")
			}
			seen[name] = true
			if err := walk(dec, depth+1); err != nil {
				return err
			}
		}
		if end, err := dec.Token(); err != nil || end != json.Delim('}') {
			return errors.New("invalid object")
		}
	case '[':
		for dec.More() {
			if err := walk(dec, depth+1); err != nil {
				return err
			}
		}
		if end, err := dec.Token(); err != nil || end != json.Delim(']') {
			return errors.New("invalid array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

// encoding/json replaces invalid UTF-16 escapes. Reject them instead so that
// the canonical interpretation cannot differ from a downstream implementation.
func validSurrogates(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return errors.New("invalid JSON escape")
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return errors.New("invalid Unicode escape")
		}
		n, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return errors.New("invalid Unicode escape")
		}
		i += 4
		if n >= 0xDC00 && n <= 0xDFFF {
			return errors.New("unpaired Unicode surrogate")
		}
		if n < 0xD800 || n > 0xDBFF {
			continue
		}
		if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
			return errors.New("unpaired Unicode surrogate")
		}
		low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
		if err != nil || low < 0xDC00 || low > 0xDFFF {
			return errors.New("unpaired Unicode surrogate")
		}
		i += 6
	}
	return nil
}

// CanonicalJSON sorts object keys and normalises JSON whitespace and string
// escapes. Number spellings remain exact: 1 and 1.0 conservatively have distinct
// candidate bindings. This is an application encoding, not RFC 8785 JCS.
func CanonicalJSON(data []byte) ([]byte, error) {
	var value any
	if err := StrictJSON(data, &value); err != nil {
		return nil, err
	}
	result, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonical JSON: %w", err)
	}
	return result, nil
}
