package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"io"
)

// symmetric struct represents a symmetric encryption driver.
type symmetric struct {
	key    SimpleKey
	signer HashingAlgo
}

// NewSymmetric creates a new symmetric encryption driver.
func NewSymmetric(key SimpleKey, signer HashingAlgo) Cryptography {
	return &symmetric{
		key:    key,
		signer: signer,
	}
}

func (s *symmetric) Sign(data []byte) ([]byte, error) {
	constructor := HashingInstance(s.signer)
	if constructor == nil {
		return nil, fmt.Errorf("invalid hash algorithm passed to driver")
	}

	hasher := hmac.New(constructor, s.key)
	if _, err := hasher.Write(data); err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}

func (s *symmetric) ValidateSignature(data, signature []byte) (bool, error) {
	constructor := HashingInstance(s.signer)
	if constructor == nil {
		return false, fmt.Errorf("invalid hash algorithm passed to driver")
	}

	hasher := hmac.New(constructor, s.key)
	if _, err := hasher.Write(data); err != nil {
		return false, err
	}

	return hmac.Equal(signature, hasher.Sum(nil)), nil
}

func (s *symmetric) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Prepend the nonce to the ciphertext
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (s *symmetric) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (s *symmetric) EncryptBase64(data []byte) (string, error) {
	encrypted, err := s.Encrypt(data)
	if err != nil {
		return "", err
	}

	encoded, err := base64Encode(encrypted)
	return string(encoded), err
}

func (s *symmetric) DecryptBase64(encrypted string) ([]byte, error) {
	raw, err := base64Decode([]byte(encrypted))
	if err != nil {
		return nil, err
	}

	return s.Decrypt(raw)
}
