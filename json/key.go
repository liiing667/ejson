package json

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// PublicKeyField is the key name at which the public key should be
	// stored in an EJSON document.
	PublicKeyField = "_public_key"
)

// ErrPublicKeyMissing indicates that the PublicKeyField key was not found
// at the top level of the JSON document provided.
var ErrPublicKeyMissing = errors.New("public key not present in EJSON file")

// ErrPublicKeyInvalid means that the PublicKeyField key was found, but the
// value could not be parsed into a valid key.
var ErrPublicKeyInvalid = errors.New("public key has invalid format")

// ErrPublicKeyDuplicate means that the PublicKeyField key appeared more than
// once at the top level of the JSON document. Rather than silently letting
// one value overwrite the other, extraction fails closed and reports the
// position of the offending duplicate.
var ErrPublicKeyDuplicate = errors.New("duplicate public key in EJSON file")

// ExtractPublicKey finds the _public_key value in an EJSON document and
// parses it into a key usable with the crypto library.
func ExtractPublicKey(data []byte) (key [32]byte, err error) {
	raw, err := extractPublicKeyValue(data)
	if err != nil {
		return key, err
	}
	var ks string
	if err := json.Unmarshal(raw, &ks); err != nil {
		return key, ErrPublicKeyInvalid
	}
	if len(ks) != 64 {
		return key, ErrPublicKeyInvalid
	}
	bs, err := hex.DecodeString(ks)
	if err != nil {
		return key, ErrPublicKeyInvalid
	}
	if len(bs) != 32 {
		return key, ErrPublicKeyInvalid
	}
	copy(key[:], bs)
	return key, nil
}

// extractPublicKeyValue scans the top-level object of an EJSON document and
// returns the raw value of the PublicKeyField key. A duplicate PublicKeyField
// key is rejected with a position-annotated error instead of being resolved
// by last-write-wins.
func extractPublicKeyValue(data []byte) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("invalid json: top-level value must be an object")
	}
	var value json.RawMessage
	found := false
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("invalid json: object key must be a string")
		}
		keyOffset := dec.InputOffset()
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		if name != PublicKeyField {
			continue
		}
		if found {
			line, col := lineCol(data, keyOffset)
			return nil, fmt.Errorf("%w at line %d, column %d", ErrPublicKeyDuplicate, line, col)
		}
		found = true
		value = raw
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("invalid json: unexpected data after top-level object")
	}
	if !found {
		return nil, ErrPublicKeyMissing
	}
	return value, nil
}

// lineCol converts a byte offset into a 1-based line and column.
func lineCol(data []byte, offset int64) (line, col int) {
	line, col = 1, 1
	for i := int64(0); i < offset && i < int64(len(data)); i++ {
		if data[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}
