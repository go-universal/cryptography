package cryptography

import (
	"crypto/hmac"
	"fmt"
)

// hmacHasher is a struct that holds the key and hashing algorithm for HMAC operations.
type hmacHasher struct {
	key  []byte
	algo HashingAlgo
}

// HMacHasher creates a new HMAC hasher instance (recommended for message signing).
func HMacHasher(key []byte, algo HashingAlgo) Hasher {
	return &hmacHasher{
		key:  key,
		algo: algo,
	}
}

func (h *hmacHasher) Hash(data []byte) ([]byte, error) {
	// Validate the key
	if len(h.key) == 0 {
		return nil, fmt.Errorf("empty key passed to hasher")
	}

	// Get the hashing algorithm constructor
	constructor := HashingInstance(h.algo)
	if constructor == nil {
		return nil, fmt.Errorf("invalid hash algorithm passed to hasher")
	}

	// Create a new HMAC hasher and write the data
	hasher := hmac.New(constructor, h.key)
	if _, err := hasher.Write(data); err != nil {
		return nil, err
	}

	// Return the base64-encoded hash
	return base64Encode(hasher.Sum(nil))
}

func (h *hmacHasher) Validate(hash, data []byte) (bool, error) {
	// Generate a new hash for the data
	newHash, err := h.Hash(data)
	if err != nil {
		return false, err
	}

	// Compare the provided hash with the newly generated hash
	return hmac.Equal(hash, newHash), nil
}
