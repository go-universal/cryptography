package cryptography

import (
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/sha3"
)

// HashingAlgo represents the hashing algorithm.
type HashingAlgo string

// Supported hashing algorithms.
const (
	MD5  HashingAlgo = "MD5"  // MD5 algorithm (not recommended for security)
	SHA1 HashingAlgo = "SHA1" // SHA1 algorithm (not recommended for security)

	SHA224 HashingAlgo = "SHA224" // SHA2 224 algorithm
	SHA256 HashingAlgo = "SHA256" // SHA2 256 algorithm (recommended)
	SHA384 HashingAlgo = "SHA384" // SHA2 384 algorithm
	SHA512 HashingAlgo = "SHA512" // SHA2 512 algorithm

	SHA3224 HashingAlgo = "SHA3224" // SHA3 224 algorithm
	SHA3256 HashingAlgo = "SHA3256" // SHA3 256 algorithm
	SHA3384 HashingAlgo = "SHA3384" // SHA3 384 algorithm
	SHA3512 HashingAlgo = "SHA3512" // SHA3 512 algorithm
)

// HashingInstance returns a new hash.Hash instance for the given algorithm.
// Returns nil if the algorithm is not supported.
func HashingInstance(algo HashingAlgo) func() hash.Hash {
	switch algo {
	case MD5:
		return md5.New
	case SHA1:
		return sha1.New

	case SHA224:
		return sha256.New224
	case SHA256:
		return sha256.New
	case SHA384:
		return sha512.New384
	case SHA512:
		return sha512.New

	case SHA3224:
		return sha3.New224
	case SHA3256:
		return sha3.New256
	case SHA3384:
		return sha3.New384
	case SHA3512:
		return sha3.New512

	default:
		return nil
	}
}

// HashingSize returns the size of the hash output for the given algorithm in bytes.
// Returns 0 if the algorithm is not supported.
func HashingSize(algo HashingAlgo) int {
	switch algo {
	case MD5:
		return md5.Size
	case SHA1:
		return sha1.Size

	case SHA224:
		return sha256.Size224
	case SHA256:
		return sha256.Size
	case SHA384:
		return sha512.Size384
	case SHA512:
		return sha512.Size

	case SHA3224:
		return sha3.New224().Size()
	case SHA3256:
		return sha3.New256().Size()
	case SHA3384:
		return sha3.New384().Size()
	case SHA3512:
		return sha3.New512().Size()

	default:
		return 0
	}
}

// HashingAlg maps the hashing algorithm to its corresponding crypto.Hash value.
// Returns 0 if the algorithm is not supported.
func HashingAlg(algo HashingAlgo) crypto.Hash {
	switch algo {
	case MD5:
		return crypto.MD5
	case SHA1:
		return crypto.SHA1

	case SHA224:
		return crypto.SHA224
	case SHA256:
		return crypto.SHA256
	case SHA384:
		return crypto.SHA384
	case SHA512:
		return crypto.SHA512

	case SHA3224:
		return crypto.SHA3_224
	case SHA3256:
		return crypto.SHA3_256
	case SHA3384:
		return crypto.SHA3_384
	case SHA3512:
		return crypto.SHA3_512

	default:
		return 0
	}
}
