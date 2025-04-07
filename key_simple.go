package cryptography

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

// SimpleLength defines the length of the key in bytes.
type SimpleLength int

// Predefined key lengths for convenience.
const (
	Simple16 SimpleLength = 16 // 128-bit key
	Simple24 SimpleLength = 24 // 192-bit key
	Simple32 SimpleLength = 32 // 256-bit key
)

// SimpleKey represents a cryptographic key as a byte slice.
type SimpleKey []byte

// NewSimpleKey generates a new random key of the specified length.
// Returns an error if the random number generation fails.
func NewSimpleKey(length SimpleLength) (SimpleKey, error) {
	key := make(SimpleKey, length)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Bytes returns the key as a byte slice.
func (k SimpleKey) Bytes() []byte {
	return k
}

// Hex returns the key as a hexadecimal string.
func (k SimpleKey) Hex() string {
	return hex.EncodeToString(k)
}

// Base64 returns the key as a Base64-encoded string.
func (k SimpleKey) Base64() string {
	return base64.StdEncoding.EncodeToString(k)
}

// String implements the fmt.Stringer interface.
// By default, it returns the key as a hexadecimal string.
func (k SimpleKey) String() string {
	return k.Hex()
}
