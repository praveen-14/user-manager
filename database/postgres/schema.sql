-- PostgreSQL schema for user-manager application
-- Create users table

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT,
    name TEXT,
    mobile_number TEXT,
    role TEXT,
    email_verified BOOLEAN DEFAULT FALSE,
    user_verified BOOLEAN DEFAULT FALSE,
    email_verification_code TEXT,
    password_reset_code TEXT,
    password_reset_requested BOOLEAN DEFAULT FALSE,
    created_at BIGINT,
    updated_at BIGINT,
    last_logged_in_at BIGINT,
    deleted BOOLEAN DEFAULT FALSE,
    token TEXT,
    tags TEXT[] DEFAULT '{}',
    data JSONB
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_name ON users (name);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users (created_at);
CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);
CREATE INDEX IF NOT EXISTS idx_users_deleted ON users (deleted);
CREATE INDEX IF NOT EXISTS idx_users_user_verified ON users (user_verified);
CREATE INDEX IF NOT EXISTS idx_users_tags ON users USING GIN (tags);
