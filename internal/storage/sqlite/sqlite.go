package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sso/internal/domain/models"
	"sso/internal/storage"
	"time"

	"github.com/mattn/go-sqlite3"
)

// Storage implements the storage.Storage interface using SQLite as the backend.
type Storage struct {
	db *sql.DB
}

// New creates a new instance of SQLite storage.
func New(storagePath string) (*Storage, error) {
	const op = "storage.sqlite.New"

	// Add SQLite pragmas for better performance and reliability
	// _journal_mode=WAL: Write-Ahead Logging for better concurrency
	// _busy_timeout=5000: Wait up to 5 seconds if database is locked
	// _synchronous=NORMAL: Balance between safety and performance
	// _foreign_keys=ON: Enable foreign key constraints
	dsn := storagePath + "?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_foreign_keys=ON"

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Configure connection pool to prevent resource exhaustion
	db.SetMaxOpenConns(25)                 // Maximum number of open connections
	db.SetMaxIdleConns(5)                  // Maximum number of idle connections
	db.SetConnMaxLifetime(5 * time.Minute) // Maximum connection lifetime

	// Verify connection is working
	if pingErr := db.Ping(); pingErr != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("%s: failed to ping database: %w", op, errors.Join(pingErr, closeErr))
		}

		return nil, fmt.Errorf("%s: failed to ping database: %w", op, pingErr)
	}

	return &Storage{db: db}, nil
}

// Close closes the database connection.
func (s *Storage) Close() error {
	return s.db.Close()
}

// SaveUser saves a new user and returns its ID.
func (s *Storage) SaveUser(ctx context.Context, email string, passwordHash []byte, passwordSalt []byte) (int64, error) {
	const op = "storage.sqlite.SaveUser"

	stmt, err := s.db.PrepareContext(ctx, `INSERT INTO users (email, password_hash, password_salt) VALUES (?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = stmt.Close() }()

	res, err := stmt.ExecContext(ctx, email, passwordHash, passwordSalt)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

// User returns user by email.
func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.sqlite.User"

	stmt, err := s.db.PrepareContext(ctx, `SELECT id, email, password_hash, password_salt FROM users WHERE email = ?`)
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = stmt.Close() }()

	row := stmt.QueryRowContext(ctx, email)

	var user models.User
	err = row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.PasswordSalt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return user, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

func (s *Storage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "storage.sqlite.IsAdmin"

	stmt, err := s.db.PrepareContext(ctx, `SELECT is_admin FROM users WHERE id = ?`)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = stmt.Close() }()

	row := stmt.QueryRowContext(ctx, userID)

	var isAdmin bool
	err = row.Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}

func (s *Storage) App(ctx context.Context, appID int) (models.App, error) {
	const op = "storage.sqlite.App"

	stmt, err := s.db.PrepareContext(ctx, `SELECT id, name, private_key, public_key FROM apps WHERE id = ?`)
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = stmt.Close() }()

	row := stmt.QueryRowContext(ctx, appID)

	var app models.App
	err = row.Scan(&app.ID, &app.Name, &app.PrivateKey, &app.PublicKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return app, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}
		return app, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}
