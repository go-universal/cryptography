package cryptography

// Cryptography provides signing, validating, encrypting, and decrypting data.
// It provides support for both raw byte operations and base64-encoded string operations.
type Cryptography interface {
	// Sign generates a cryptographic signature for the given data.
	// Returns the signature as a byte slice or an error if signing fails.
	Sign(data []byte) ([]byte, error)

	// ValidateSignature checks if the provided signature is valid for the given data.
	// Returns true if the signature is valid, false otherwise, along with any error encountered.
	ValidateSignature(data []byte, signature []byte) (bool, error)

	// Encrypt encrypts the given data and returns the encrypted result as a byte slice.
	// Returns an error if encryption fails.
	Encrypt(data []byte) ([]byte, error)

	// Decrypt decrypts the given encrypted data and returns the original data as a byte slice.
	// Returns an error if decryption fails.
	Decrypt(data []byte) ([]byte, error)

	// EncryptBase64 encrypts the given data and encodes the result as a base64 string.
	// Returns the base64-encoded encrypted string or an error if encryption fails.
	EncryptBase64(data []byte) (string, error)

	// DecryptBase64 decodes the given base64-encoded string and decrypts it.
	// Returns the original data as a byte slice or an error if decryption fails.
	DecryptBase64(encrypted string) ([]byte, error)
}
