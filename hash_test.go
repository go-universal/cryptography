package cryptography_test

import (
	"testing"

	"github.com/go-universal/cryptography"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArgon2(t *testing.T) {
	password := []byte("pass12341fadsfasf@!#@$")

	hasher := cryptography.NewArgon2Hasher(0, 0, 0, 0, 0)
	hashed, err := hasher.Hash(password)
	require.NoError(t, err)

	same, err := hasher.Validate(hashed, password)
	require.NoError(t, err)
	assert.True(t, same, "validate failed")
}

func TestBCrypt(t *testing.T) {
	password := []byte("pass12341fadsfasf@!#@$")

	hasher := cryptography.NewBcryptHasher(0)
	hashed, err := hasher.Hash(password)
	require.NoError(t, err)

	same, err := hasher.Validate(hashed, password)
	require.NoError(t, err)
	assert.True(t, same, "validate failed")
}

func TestHMac(t *testing.T) {
	password := []byte("pass12341fadsfasf@!#@$")
	algos := []cryptography.HashingAlgo{
		cryptography.MD5, cryptography.SHA1,

		cryptography.SHA224, cryptography.SHA256,
		cryptography.SHA384, cryptography.SHA512,

		cryptography.SHA3224, cryptography.SHA3256,
		cryptography.SHA3384, cryptography.SHA3512,
	}

	// Generate random key
	key, err := cryptography.NewSimpleKey(cryptography.Simple32)
	require.NoError(t, err)

	// Test all algos
	for _, algo := range algos {
		t.Run(string(algo), func(t *testing.T) {
			hasher := cryptography.HMacHasher(key, algo)
			hashed, err := hasher.Hash(password)
			require.NoError(t, err)

			same, err := hasher.Validate(hashed, password)
			require.NoError(t, err)
			assert.True(t, same, "validate failed")
		})
	}
}
