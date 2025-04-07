package cryptography

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

// RSALength defines the bit length of RSA keys.
type RSALength int

const (
	RSA1024 RSALength = 1024 // Weak and not recommended for modern security.
	RSA2048 RSALength = 2048 // Minimum recommended size for modern applications.
	RSA3072 RSALength = 3072 // Stronger security for long-term protection.
	RSA4096 RSALength = 4096 // Highly secure but slower performance.
)

// RSAKey wraps an RSA private key and provides utility methods.
type RSAKey struct {
	key *rsa.PrivateKey
}

// NewRSAKey generates a new RSA private key of the specified length.
func NewRSAKey(length RSALength) (*RSAKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, int(length))
	if err != nil {
		return nil, err
	}
	return &RSAKey{key: key}, nil
}

// PrivateKey returns the RSA private key.
func (k *RSAKey) PrivateKey() *rsa.PrivateKey {
	return k.key
}

// PrivateKeyBytes returns the private key in PKCS#1 or PKCS#8 format.
// PKCS #1 is not recommended for security as it's considered weak and
// can potentially be broken by modern computational capabilities.
func (k *RSAKey) PrivateKeyBytes(usePKCS8 bool) ([]byte, error) {
	if usePKCS8 {
		return x509.MarshalPKCS8PrivateKey(k.key)
	}
	return x509.MarshalPKCS1PrivateKey(k.key), nil
}

// PrivateKeyPEM returns the private key in PEM-encoded format (PKCS#1 or PKCS#8).
// PKCS #1 is not recommended for security as it's considered weak and
// can potentially be broken by modern computational capabilities.
func (k *RSAKey) PrivateKeyPEM(usePKCS8 bool) ([]byte, error) {
	keyBytes, err := k.PrivateKeyBytes(usePKCS8)
	if err != nil {
		return nil, err
	}

	blockType := "PRIVATE KEY"
	if !usePKCS8 {
		blockType = "RSA PRIVATE KEY"
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: keyBytes}), nil
}

// PublicKey returns the RSA public key.
func (k *RSAKey) PublicKey() *rsa.PublicKey {
	return &k.key.PublicKey
}

// PublicKeyBytes returns the public key in PKIX or PKCS#1 format.
// PKCS #1 is not recommended for security as it's considered weak and
// can potentially be broken by modern computational capabilities.
func (k *RSAKey) PublicKeyBytes(usePKCS8 bool) ([]byte, error) {
	if usePKCS8 {
		return x509.MarshalPKIXPublicKey(&k.key.PublicKey)
	}
	return x509.MarshalPKCS1PublicKey(&k.key.PublicKey), nil
}

// PublicKeyPEM returns the public key in PEM-encoded format (PKIX or PKCS#1).
// PKCS #1 is not recommended for security as it's considered weak and
// can potentially be broken by modern computational capabilities.
func (k *RSAKey) PublicKeyPEM(usePKCS8 bool) ([]byte, error) {
	keyBytes, err := k.PublicKeyBytes(usePKCS8)
	if err != nil {
		return nil, err
	}

	blockType := "PUBLIC KEY"
	if !usePKCS8 {
		blockType = "RSA PUBLIC KEY"
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: keyBytes}), nil
}

// IssueCertificateBytes generates a self-signed certificate in DER format.
func (k *RSAKey) IssueCertificateBytes(subject pkix.Name, algo x509.SignatureAlgorithm, options *x509.Certificate) ([]byte, error) {
	if options == nil {
		options = &x509.Certificate{}
	}
	options.Subject = subject
	options.SignatureAlgorithm = algo

	// Self-sign the certificate
	return x509.CreateCertificate(rand.Reader, options, options, &k.key.PublicKey, k.key)
}

// IssueCertificatePEM generates a self-signed certificate in PEM format.
func (k *RSAKey) IssueCertificatePEM(subject pkix.Name, algo x509.SignatureAlgorithm, options *x509.Certificate) ([]byte, error) {
	certDER, err := k.IssueCertificateBytes(subject, algo, options)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}
