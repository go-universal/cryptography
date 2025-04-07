package cryptography_test

import (
	"bytes"
	"testing"

	"github.com/go-universal/cryptography"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSymmetric(t *testing.T) {
	data := []byte("my name is John doe")

	key, err := cryptography.NewSimpleKey(cryptography.Simple32)
	require.NoError(t, err)

	driver := cryptography.NewSymmetric(key, cryptography.SHA256)

	// Encrypt
	encrypted, err := driver.EncryptBase64(data)
	require.NoError(t, err)

	// Decrypt
	raw, err := driver.DecryptBase64(encrypted)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(raw, data), "decrypted data should match original")
}

func TestAsymmetric(t *testing.T) {
	data := []byte("my name is John doe")

	key, err := cryptography.NewRSAKey(cryptography.RSA2048)
	require.NoError(t, err)

	driver := cryptography.NewAsymmetric(*key, cryptography.SHA256)

	// Encrypt
	encrypted, err := driver.EncryptBase64(data)
	require.NoError(t, err)

	// Decrypt
	raw, err := driver.DecryptBase64(encrypted)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(raw, data), "decrypted data should match original")
}
