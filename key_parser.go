package cryptography

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// decodePEMBlock decodes a PEM block if isPEM is true, otherwise returns the raw input.
func decodePEMBlock(data []byte, isPEM bool) ([]byte, error) {
	if isPEM {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}
		return block.Bytes, nil
	}
	return data, nil
}

// ParsePrivateKey parses an RSA private key from PKCS #1 or PKCS #8 format.
func ParsePrivateKey(key []byte, isPEM bool) (*RSAKey, error) {
	raw, err := decodePEMBlock(key, isPEM)
	if err != nil {
		return nil, err
	}

	// Try parsing as PKCS #1
	private, err := x509.ParsePKCS1PrivateKey(raw)
	if err == nil {
		return &RSAKey{key: private}, nil
	}

	// If not PKCS #1, try parsing as PKCS #8
	parsed, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return nil, err
	}

	// Ensure the parsed key is an RSA private key
	if private, ok := parsed.(*rsa.PrivateKey); ok {
		return &RSAKey{key: private}, nil
	}

	return nil, fmt.Errorf("failed to parse RSA private key")
}

// ParsePublicKey parses an RSA public key from PKIX or PKCS #1 format.
func ParsePublicKey(key []byte, isPEM bool) (*rsa.PublicKey, error) {
	raw, err := decodePEMBlock(key, isPEM)
	if err != nil {
		return nil, err
	}

	// Try parsing as PKCS #1
	public, err := x509.ParsePKCS1PublicKey(raw)
	if err == nil {
		return public, nil
	}

	// Try parsing as PKIX
	parsed, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, err
	}

	// Ensure the parsed key is an RSA public key
	if public, ok := parsed.(*rsa.PublicKey); ok {
		return public, nil
	}

	return nil, fmt.Errorf("failed to parse RSA public key")
}

// ParseCertificateRequest parses an x509 certificate request (CSR).
func ParseCertificateRequest(csr []byte, isPEM bool) (*x509.CertificateRequest, error) {
	raw, err := decodePEMBlock(csr, isPEM)
	if err != nil {
		return nil, err
	}

	// Parse the CSR
	request, err := x509.ParseCertificateRequest(raw)
	if err != nil {
		return nil, err
	}
	return request, nil
}

// ParseCertificate parses an x509 certificate.
func ParseCertificate(cert []byte, isPEM bool) (*x509.Certificate, error) {
	raw, err := decodePEMBlock(cert, isPEM)
	if err != nil {
		return nil, err
	}

	// Parse the certificate
	parsedCert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}
	return parsedCert, nil
}
