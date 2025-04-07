# Cryptography Library

![GitHub Tag](https://img.shields.io/github/v/tag/go-universal/cryptography?sort=semver&label=version)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-universal/cryptography.svg)](https://pkg.go.dev/github.com/go-universal/cryptography)
[![License](https://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/go-universal/cryptography/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/go-universal/cryptography)](https://goreportcard.com/report/github.com/go-universal/cryptography)
![Contributors](https://img.shields.io/github/contributors/go-universal/cryptography)
![Issues](https://img.shields.io/github/issues/go-universal/cryptography)

This library provides a comprehensive set of cryptographic utilities for hashing, encryption, and key management. It supports both symmetric and asymmetric cryptography, as well as various hashing algorithms.

## Features

- Symmetric encryption using AES-GCM.
- Asymmetric encryption using RSA.
- Hashing with Argon2, bcrypt, and HMAC.
- Key generation and parsing utilities.

## Installation

To use this library, add it to your Go project:

```bash
go get github.com/go-universal/cryptography
```

## API Documentation

### Symmetric Encryption

Creates a new symmetric encryption driver.

```go
func NewSymmetric(key SimpleKey, signer HashingAlgo) Cryptography
```

```go
key, _ := cryptography.NewSimpleKey(cryptography.Simple32)
driver := cryptography.NewSymmetric(key, cryptography.SHA256)

data := []byte("my secret data")

// Encrypt
encrypted, _ := driver.EncryptBase64(data)

// Decrypt
decrypted, _ := driver.DecryptBase64(encrypted)
fmt.Println(string(decrypted)) // Output: my secret data
```

### Asymmetric Encryption

Creates a new asymmetric encryption driver with a private key.

```go
func NewAsymmetric(key RSAKey, signer HashingAlgo) Cryptography
```

#### `NewAsymmetricClient`

Creates a new asymmetric encryption driver with a public key.

```go
func NewAsymmetricClient(public *rsa.PublicKey, signer HashingAlgo) Cryptography
```

```go
key, _ := cryptography.NewRSAKey(cryptography.RSA2048)
driver := cryptography.NewAsymmetric(*key, cryptography.SHA256)

data := []byte("my secret data")

// Encrypt
encrypted, _ := driver.EncryptBase64(data)

// Decrypt
decrypted, _ := driver.DecryptBase64(encrypted)
fmt.Println(string(decrypted)) // Output: my secret data
```

### Hashing

Creates a new Argon2 hasher.

```go
func NewArgon2Hasher(
    saltLength SimpleLength, keyLength uint32,
    memory uint32, iterations uint32, parallelism uint8,
) Hasher
```

Creates a new bcrypt hasher.

```go
func NewBcryptHasher(cost int) Hasher
```

Creates a new HMAC hasher.

```go
func HMacHasher(key []byte, algo HashingAlgo) Hasher
```

```go
password := []byte("my_password")

// Argon2
argon2Hasher := cryptography.NewArgon2Hasher(0, 0, 0, 0, 0)
hashed, _ := argon2Hasher.Hash(password)
valid, _ := argon2Hasher.Validate(hashed, password)
fmt.Println(valid) // Output: true

// bcrypt
bcryptHasher := cryptography.NewBcryptHasher(0)
hashed, _ = bcryptHasher.Hash(password)
valid, _ = bcryptHasher.Validate(hashed, password)
fmt.Println(valid) // Output: true
```

### Key Management

#### Simple Key

Generates a new random key of the specified length.

```go
func NewSimpleKey(length SimpleLength) (SimpleKey, error)
```

#### RSA Key

Generates a new RSA private key of the specified length.

```go
func NewRSAKey(length RSALength) (*RSAKey, error)
```

#### Parse Private Key

Parses an RSA private key from PKCS#1 or PKCS#8 format.

```go
func ParsePrivateKey(key []byte, isPEM bool) (*RSAKey, error)
```

#### Parse Public Key

Parses an RSA public key from PKIX or PKCS#1 format.

```go
func ParsePublicKey(key []byte, isPEM bool) (*rsa.PublicKey, error)
```

```go
// Generate a new RSA key
rsaKey, _ := cryptography.NewRSAKey(cryptography.RSA2048)

// Export and parse the private key
privateKeyPEM, _ := rsaKey.PrivateKeyPEM(true)
parsedKey, _ := cryptography.ParsePrivateKey(privateKeyPEM, true)

// Export and parse the public key
publicKeyPEM, _ := rsaKey.PublicKeyPEM(true)
parsedPublicKey, _ := cryptography.ParsePublicKey(publicKeyPEM, true)
```

## License

This project is licensed under the ISC License. See the [LICENSE](LICENSE) file for details.
