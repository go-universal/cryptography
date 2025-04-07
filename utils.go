package cryptography

import "encoding/base64"

// valueOf returns the value if it is not the zero value for its type,
// otherwise it returns the fallback value.
func valueOf[T comparable](value, fallback T) T {
	var zero T
	if value == zero {
		return fallback
	}
	return value
}

// base64Encode encodes the input data to a base64-encoded byte slice.
func base64Encode(data []byte) ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(data)
	return []byte(encoded), nil
}

// base64Decode decodes a base64-encoded byte slice back to its original form.
func base64Decode(data []byte) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	return decoded, nil
}
