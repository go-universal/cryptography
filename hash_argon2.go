package cryptography

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2Hasher is a struct that holds configuration parameters for Argon2 hashing.
type argon2Hasher struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  SimpleLength
	keyLength   uint32
}

// NewArgon2Hasher creates a new Argon2 hasher with the specified parameters (recommended for password).
// If a parameter is 0, a default value is used.
func NewArgon2Hasher(
	saltLength SimpleLength, keyLength uint32,
	memory uint32, iterations uint32, parallelism uint8,
) Hasher {
	return &argon2Hasher{
		memory:      valueOf(memory, 64*1024),
		iterations:  valueOf(iterations, 1),
		parallelism: valueOf(parallelism, uint8(runtime.NumCPU())),
		saltLength:  valueOf(saltLength, Simple16),
		keyLength:   valueOf(keyLength, 32),
	}
}

func (a *argon2Hasher) Hash(data []byte) ([]byte, error) {
	// Generate a random salt
	salt, err := NewSimpleKey(a.saltLength)
	if err != nil {
		return nil, err
	}

	// Derive the key using Argon2
	key := argon2.IDKey(data, salt, a.iterations, a.memory, a.parallelism, a.keyLength)

	// Encode the salt and key in base64
	encodedSalt, _ := base64Encode(salt)
	encodedKey, _ := base64Encode(key)

	// Format the hash as a string and encode it in base64
	hash := fmt.Sprintf(
		"%s#%d$%d$%d$%d#%s",
		string(encodedSalt), argon2.Version, a.memory,
		a.iterations, a.parallelism, string(encodedKey),
	)
	return base64Encode([]byte(hash))
}

func (a *argon2Hasher) Validate(hash, data []byte) (bool, error) {
	// Decode the hash to extract its components
	salt, key, _, _, _, _, err := a.decodeHash(hash)
	if err != nil {
		return false, err
	}

	// Derive the key from the input data and extracted salt
	otherKey := argon2.IDKey(data, salt, a.iterations, a.memory, a.parallelism, a.keyLength)

	// Check that the contents of the hashed passwords are identical. Note
	// that we are using the subtle.ConstantTimeCompare() function for this
	// to help prevent timing attacks.
	return subtle.ConstantTimeCompare(key, otherKey) == 1, nil
}

func (a *argon2Hasher) decodeHash(hash []byte) ([]byte, []byte, int, uint32, uint32, uint8, error) {
	// Decode the base64-encoded hash
	raw, err := base64Decode(hash)
	if err != nil {
		return nil, nil, 0, 0, 0, 0, errors.New("invalid password hash")
	}

	// Split the hash into parts
	parts := strings.Split(string(raw), "#")
	if len(parts) != 3 {
		return nil, nil, 0, 0, 0, 0, errors.New("invalid password hash")
	}

	// Decode the salt
	salt, err := base64Decode([]byte(parts[0]))
	if err != nil {
		return nil, nil, 0, 0, 0, 0, errors.New("invalid password hash")
	}

	// Parse and validate the version, memory, iterations, and parallelism
	var version, memory, iterations, parallelism int
	_, err = fmt.Sscanf(parts[1], "%d$%d$%d$%d", &version, &memory, &iterations, &parallelism)
	if err != nil || version != argon2.Version {
		return nil, nil, 0, 0, 0, 0, errors.New("incompatible or invalid password hash")
	}

	// Decode the key
	key, err := base64Decode([]byte(parts[2]))
	if err != nil {
		return nil, nil, 0, 0, 0, 0, errors.New("invalid password hash")
	}

	// Return the extracted components
	return salt, key, version, uint32(memory), uint32(iterations), uint8(parallelism), nil
}
