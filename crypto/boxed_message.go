package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// SchemaVersion is the only boxed-message schema version this implementation
// knows how to read and write.
const SchemaVersion = 1

// ErrUnknownSchemaVersion indicates that a boxed message declares a schema
// version this implementation does not understand.
var ErrUnknownSchemaVersion = errors.New("unknown schema version")

// envelopePrefix and envelopeSuffix delimit the wire format of a boxed
// message.
const (
	envelopePrefix = "EJ["
	envelopeSuffix = "]"
)

// boxedMessage dumps and loads the wire format for encrypted messages. The
// schema is fairly simple:
//
//	"EJ["
//	SchemaVersion ( "1" )
//	":"
//	EncrypterPublic :: base64-encoded 32-byte key
//	":"
//	Nonce :: base64-encoded 24-byte nonce
//	":"
//	Box :: base64-encoded encrypted message
//	"]"
type boxedMessage struct {
	SchemaVersion   int
	EncrypterPublic [32]byte
	Nonce           [24]byte
	Box             []byte
}

// LooksLikeBoxedMessage reports whether data has the outer EJ[...] envelope
// shape, regardless of whether its contents are valid. Anything matching
// this shape must parse strictly via Load; callers must not treat a
// malformed envelope as plaintext.
func LooksLikeBoxedMessage(data []byte) bool {
	return bytes.HasPrefix(data, []byte(envelopePrefix)) &&
		bytes.HasSuffix(data, []byte(envelopeSuffix))
}

// IsBoxedMessage tests whether a value is a well-formed boxedMessage. This
// can be used to determine whether a string value requires encryption or is
// already encrypted.
func IsBoxedMessage(data []byte) bool {
	var bm boxedMessage
	return bm.Load(data) == nil
}

// Dump dumps to the wire format
func (b *boxedMessage) Dump() []byte {
	pub := base64.StdEncoding.EncodeToString(b.EncrypterPublic[:])
	nonce := base64.StdEncoding.EncodeToString(b.Nonce[:])
	box := base64.StdEncoding.EncodeToString(b.Box)

	str := fmt.Sprintf("EJ[%d:%s:%s:%s]",
		b.SchemaVersion, pub, nonce, box)
	return []byte(str)
}

// Load restores from the wire format.
func (b *boxedMessage) Load(from []byte) error {
	if !LooksLikeBoxedMessage(from) {
		return fmt.Errorf("invalid message format: missing %s...%s envelope", envelopePrefix, envelopeSuffix)
	}
	body := string(from[len(envelopePrefix) : len(from)-len(envelopeSuffix)])
	// The base64 alphabet contains no colons, so the four fields always split
	// cleanly on ':'.
	parts := strings.Split(body, ":")
	if len(parts) != 4 {
		return fmt.Errorf("invalid message format: expected 4 colon-separated fields, found %d", len(parts))
	}

	version, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("invalid schema version %q: %v", parts[0], err)
	}
	if version != SchemaVersion {
		return fmt.Errorf("%w: %d", ErrUnknownSchemaVersion, version)
	}
	b.SchemaVersion = version

	pub, err := decodeField("public key", parts[1], 32)
	if err != nil {
		return err
	}
	copy(b.EncrypterPublic[:], pub)

	nonce, err := decodeField("nonce", parts[2], 24)
	if err != nil {
		return err
	}
	copy(b.Nonce[:], nonce)

	box, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return fmt.Errorf("invalid base64 in box: %v", err)
	}
	if len(box) == 0 {
		return fmt.Errorf("invalid box: empty")
	}
	b.Box = box

	return nil
}

// decodeField decodes a base64 field of the wire format, requiring the
// decoded value to be exactly want bytes long.
func decodeField(name, value string, want int) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in %s: %v", name, err)
	}
	if len(decoded) != want {
		return nil, fmt.Errorf("invalid %s: decoded to %d bytes, expected %d", name, len(decoded), want)
	}
	return decoded, nil
}
