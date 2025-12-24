package jwt

import (
	"fmt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/keygen"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWT is a token provider that generates JWT tokens.
type JWT struct {
	log *slog.Logger
}

// New creates a new JWT token provider.
func New(log *slog.Logger) *JWT {
	return &JWT{
		log: log,
	}
}

// NewToken creates a new JWT token for the given user and app with the specified duration.
// Tokens are signed using RS256 (asymmetric RSA) with the app's RSA private key, and clients
// must use the corresponding app public key to verify them (this differs from HS256/HMAC).
func (j *JWT) NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	const op = "jwt.NewToken"

	log := j.log.With(
		slog.String("op", op),
		slog.Int64("user_id", user.ID),
		slog.Int("app_id", app.ID),
	)

	token := jwt.New(jwt.SigningMethodRS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["uid"] = user.ID
	claims["email"] = user.Email
	claims["app_id"] = app.ID
	claims["exp"] = time.Now().Add(duration).Unix()

	// Parse the private key from PEM format
	privateKey, err := keygen.ParseRSAPrivateKey(app.PrivateKey)
	if err != nil {
		log.Error("failed to parse private key", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: failed to parse private key: %w", op, err)
	}

	// Sign the token with the private key
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		log.Error("failed to sign token", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: failed to sign token: %w", op, err)
	}

	log.Info("token generated successfully")

	return tokenString, nil
}
