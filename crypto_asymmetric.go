package cryptography

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// asymmetric represents an asymmetric cryptography driver.
type asymmetric struct {
	key       *RSAKey
	publicKey *rsa.PublicKey
	signer    HashingAlgo
}

// NewAsymmetric creates a new asymmetric encryption driver with a private key.
func NewAsymmetric(key RSAKey, signer HashingAlgo) Cryptography {
	return &asymmetric{
		key:    &key,
		signer: signer,
	}
}

// NewAsymmetricClient creates a new asymmetric encryption driver with a public key.
func NewAsymmetricClient(public *rsa.PublicKey, signer HashingAlgo) Cryptography {
	return &asymmetric{
		publicKey: public,
		signer:    signer,
	}
}

// PublicKey returns the public key associated with the driver.
func (a *asymmetric) PublicKey() *rsa.PublicKey {
	if a.publicKey != nil {
		return a.publicKey
	}
	if a.key != nil {
		return a.key.PublicKey()
	}
	return nil
}

func (a *asymmetric) Sign(data []byte) ([]byte, error) {
	if a.key == nil {
		return nil, fmt.Errorf("no private key provided")
	}

	constructor := HashingInstance(a.signer)
	if constructor == nil {
		return nil, fmt.Errorf("invalid hashing algorithm")
	}

	hasher := constructor()
	if _, err := hasher.Write(data); err != nil {
		return nil, err
	}

	return rsa.SignPKCS1v15(
		rand.Reader, a.key.PrivateKey(),
		HashingAlg(a.signer), hasher.Sum(nil),
	)
}

func (a *asymmetric) ValidateSignature(data []byte, signature []byte) (bool, error) {
	constructor := HashingInstance(a.signer)
	if constructor == nil {
		return false, fmt.Errorf("invalid hashing algorithm")
	}

	hasher := constructor()
	if _, err := hasher.Write(data); err != nil {
		return false, err
	}

	err := rsa.VerifyPKCS1v15(
		a.PublicKey(), HashingAlg(a.signer),
		hasher.Sum(nil), signature,
	)
	return err == nil, err
}

func (a *asymmetric) Encrypt(data []byte) ([]byte, error) {
	constructor := HashingInstance(a.signer)
	if constructor == nil {
		return nil, fmt.Errorf("invalid hashing algorithm")
	}

	return rsa.EncryptOAEP(
		constructor(), rand.Reader,
		a.PublicKey(), data, nil,
	)
}

func (a *asymmetric) Decrypt(data []byte) ([]byte, error) {
	if a.key == nil {
		return nil, fmt.Errorf("no private key provided")
	}

	constructor := HashingInstance(a.signer)
	if constructor == nil {
		return nil, fmt.Errorf("invalid hashing algorithm")
	}

	return rsa.DecryptOAEP(
		constructor(), rand.Reader,
		a.key.PrivateKey(), data, nil,
	)
}

func (a *asymmetric) EncryptBase64(data []byte) (string, error) {
	encrypted, err := a.Encrypt(data)
	if err != nil {
		return "", err
	}

	encoded, err := base64Encode(encrypted)
	return string(encoded), err
}

func (a *asymmetric) DecryptBase64(encrypted string) ([]byte, error) {
	raw, err := base64Decode([]byte(encrypted))
	if err != nil {
		return nil, err
	}

	return a.Decrypt(raw)
}
