CREATE TABLE IF NOT EXISTS users
(
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash BLOB NOT NULL,
    password_salt BLOB NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS apps
(
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    secret TEXT NOT NULL
);
