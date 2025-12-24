package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/hash"
	"sso/internal/storage"
	"time"
)

// Service defines the interface for authentication operations.
type Service interface {
	Login(ctx context.Context, email string, password string, appID int) (token string, err error)
	Register(ctx context.Context, email string, password string) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (isAdmin bool, err error)
}

type TokenProvider interface {
	NewToken(user models.User, app models.App, duration time.Duration) (string, error)
}

type Auth struct {
	log           *slog.Logger
	storage       storage.Storage
	tokenProvider TokenProvider
	tokenTTL      time.Duration
}

// Compile-time check that Auth implements Service interface.
var _ Service = (*Auth)(nil)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidAppID       = errors.New("invalid app ID")
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
)

// New creates a new instance of the Auth service.
func New(
	log *slog.Logger,
	storage storage.Storage,
	tokenProvider TokenProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		log:           log,
		storage:       storage,
		tokenProvider: tokenProvider,
		tokenTTL:      tokenTTL,
	}
}

// Login authenticates a user and returns a token.
func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	appID int,
) (token string, err error) {
	const op = "Auth.Login"

	log := a.log.With(slog.String("op", op), slog.String("username", email))

	log.Info("attempting to log in user")

	user, err := a.storage.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.String("error", err.Error()))
			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		log.Error("failed to get user", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err = hash.ComparePassword(password, user.PasswordSalt, user.PasswordHash); err != nil {
		log.Info("invalid credentials", slog.String("error", err.Error()))

		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}
	app, err := a.storage.App(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("app not found", slog.String("error", err.Error()))
			return "", fmt.Errorf("%s: %w", op, ErrInvalidAppID)
		}

		log.Error("failed to get app", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully", slog.Int64("user_id", user.ID), slog.Int("app_id", app.ID))

	token, err = a.tokenProvider.NewToken(user, app, a.tokenTTL)
	if err != nil {
		log.Error("failed to create token", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

// Register creates a new user account.
func (a *Auth) Register(
	ctx context.Context,
	email string,
	password string,
) (userID int64, err error) {
	const op = "Auth.Register"

	log := a.log.With(slog.String("op", op), slog.String("email", email))

	log.Info("Registering new user")

	passData, err := hash.HashPassword(password)
	if err != nil {
		log.Error("Failed to hash password", slog.String("error", err.Error()))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	userID, err = a.storage.SaveUser(ctx, email, passData.Hash, passData.Salt)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("User already exists", slog.String("error", err.Error()))
			return 0, fmt.Errorf("%s: %w", op, ErrUserExists)
		}
		log.Error("Failed to save user", slog.String("error", err.Error()))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("User registered", slog.Int64("user_id", userID))

	return userID, nil
}

// IsAdmin checks if a user has administrative privileges.
func (a *Auth) IsAdmin(
	ctx context.Context,
	userID int64,
) (isAdmin bool, err error) {
	const op = "Auth.IsAdmin"

	log := a.log.With(slog.String("op", op), slog.Int64("user_id", userID))

	log.Info("Checking if user is admin")

	isAdmin, err = a.storage.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("User not found", slog.String("error", err.Error()))
			return false, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("Checked admin status", slog.Int64("user_id", userID), slog.Bool("is_admin", isAdmin))

	return isAdmin, nil
}
