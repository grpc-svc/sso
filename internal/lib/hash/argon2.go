package hash

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	timeCost    = 1
	memoryCost  = 64 * 1024
	parallelism = 4
	keyLength   = 32
	saltLength  = 16
)

type PasswordData struct {
	Hash []byte
	Salt []byte
}

// HashPassword hashes the given password using Argon2id and returns the hash and salt.
func HashPassword(password string) (*PasswordData, error) {
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}

	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, parallelism, keyLength)

	return &PasswordData{
		Hash: hash,
		Salt: salt,
	}, nil
}

// ComparePassword compares the given password with the original hash using the provided salt.
func ComparePassword(password string, salt, originalHash []byte) error {
	if len(salt) != saltLength {
		return fmt.Errorf("invalid salt length: expected %d, got %d", saltLength, len(salt))
	}

	if len(originalHash) != keyLength {
		return fmt.Errorf("invalid hash length: expected %d, got %d", keyLength, len(originalHash))
	}

	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	newHash := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, parallelism, keyLength)

	if subtle.ConstantTimeCompare(originalHash, newHash) != 1 {
		return fmt.Errorf("passwords do not match")
	}
	return nil
}
