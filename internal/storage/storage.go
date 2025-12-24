package storage

import (
	"context"
	"errors"
	"sso/internal/domain/models"
)

var (
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")
	ErrAppNotFound  = errors.New("app not found")
)

// Storage defines the interface for user and application storage operations.
type Storage interface {
	SaveUser(ctx context.Context, email string, passwordHash []byte, passwordSalt []byte) (int64, error)
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
	App(ctx context.Context, appID int) (models.App, error)
	Close() error
}
