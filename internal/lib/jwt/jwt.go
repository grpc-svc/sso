package jwt

import (
	"fmt"
	"sso/internal/domain/models"
	"sso/internal/lib/keygen"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// NewToken creates a new JWT token for the given user and app with the specified duration.
// Tokens are signed using RS256 (asymmetric RSA) with the app's RSA private key, and clients
// must use the corresponding app public key to verify them (this differs from HS256/HMAC).
func NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["uid"] = user.ID
	claims["email"] = user.Email
	claims["app_id"] = app.ID
	claims["exp"] = time.Now().Add(duration).Unix()

	// Parse the private key from PEM format
	privateKey, err := keygen.ParseRSAPrivateKey(app.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Sign the token with the private key
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}
