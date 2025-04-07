package cryptography

// Hasher generate and validate hash from data.
// It is recommended to use secure hashing algorithms like Argon2 or bcrypt
// for sensitive use cases such as password hashing.
type Hasher interface {
	// Hash generates a hash from the provided data.
	// Returns the hashed data or an error if the hashing process fails.
	Hash(data []byte) ([]byte, error)

	// Validate compares a hashed value with its possible plaintext equivalent.
	// Returns true if the hash matches the data, otherwise false.
	// An error is returned if the validation process fails.
	Validate(hash, data []byte) (bool, error)
}
