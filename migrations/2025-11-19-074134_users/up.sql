-- Your SQL goes here
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT UUIDV7(),
    customer_name VARCHAR NOT NULL,
    email CITEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Index for active users
CREATE INDEX users_is_active_idx ON users (is_active);

-- Composite index for active users + email lookup
CREATE INDEX users_is_active_email_idx ON users (is_active, email);
