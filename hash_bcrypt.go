package cryptography

import (
	"golang.org/x/crypto/bcrypt"
)

// bcryptHasher is a struct that holds the cost parameter for bcrypt hashing.
type bcryptHasher struct {
	cost int
}

// NewBcryptHasher creates a new bcrypt hasher (alternative for password).
// If a parameter is 0, a default value is used.
func NewBcryptHasher(cost int) Hasher {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}
	return &bcryptHasher{cost: cost}
}

func (b *bcryptHasher) Hash(data []byte) ([]byte, error) {
	encrypted, err := bcrypt.GenerateFromPassword(data, b.cost)
	if err != nil {
		return nil, err
	}
	return base64Encode(encrypted)
}

func (b *bcryptHasher) Validate(hash, data []byte) (bool, error) {
	raw, err := base64Decode(hash)
	if err != nil {
		return false, err
	}
	err = bcrypt.CompareHashAndPassword(raw, data)
	return err == nil, nil
}
