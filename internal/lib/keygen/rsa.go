package keygen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// KeyPair represents an RSA key pair
type KeyPair struct {
	PrivateKey string // PEM-encoded private key
	PublicKey  string // PEM-encoded public key
}

// GenerateRSAKeyPair generates a new RSA key pair with the specified bit size
func GenerateRSAKeyPair(bits int) (*KeyPair, error) {
	const op = "lib.keygen.GenerateRSAKeyPair"
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Encode private key to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Extract public key from private key
	publicKey := &privateKey.PublicKey

	// Encode public key to PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return &KeyPair{
		PrivateKey: string(privateKeyPEM),
		PublicKey:  string(publicKeyPEM),
	}, nil
}

// ParseRSAPrivateKey parses a PEM-encoded RSA private key
func ParseRSAPrivateKey(pemKey string) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected data after PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

// ParseRSAPublicKey parses a PEM-encoded RSA public key
func ParseRSAPublicKey(pemKey string) (*rsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected data after PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPublicKey, nil
}
