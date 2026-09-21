-- Enable pgcrypto extension for pgp_sym_encrypt / pgp_sym_decrypt / hmac
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create application user (password from .env, set via psql in entrypoint)
-- We create the user here with a placeholder; password is set by docker-entrypoint-initdb.d script

-- Create users table with encrypted fields + HMAC index for searchable encryption
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    name_encrypted  bytea         NOT NULL,
    email_encrypted bytea         NOT NULL,
    phone_encrypted bytea         NOT NULL,
    email_hmac      bytea         NOT NULL,
    phone_hmac      bytea         NOT NULL,
    profile_picture_encrypted bytea,   -- รูปโปรไฟล์เข้ารหัสด้วย pgp_sym_encrypt (AES-256)
    profile_picture_mime      text,    -- MIME type ของรูปโปรไฟล์
    created_at      TIMESTAMPTZ   DEFAULT now()
);

-- Create index on HMAC columns for fast exact-match search
CREATE INDEX idx_users_email_hmac ON users (email_hmac);
CREATE INDEX idx_users_phone_hmac ON users (phone_hmac);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id          SERIAL PRIMARY KEY,
    action      VARCHAR(50)  NOT NULL,
    table_name  VARCHAR(50)  NOT NULL DEFAULT 'users',
    record_id   INTEGER,
    detail      TEXT,
    ip_address  VARCHAR(45),
    created_at  TIMESTAMPTZ  DEFAULT now()
);

-- Key rotation history table
CREATE TABLE IF NOT EXISTS key_history (
    id          SERIAL PRIMARY KEY,
    key_label   VARCHAR(100) NOT NULL,
    key_hash    VARCHAR(64)  NOT NULL,
    rotated_at  TIMESTAMPTZ  DEFAULT now(),
    rotated_by  VARCHAR(50)
);

-- API tokens table
CREATE TABLE IF NOT EXISTS api_tokens (
    id          SERIAL PRIMARY KEY,
    token_hash  VARCHAR(64)  NOT NULL UNIQUE,
    label       VARCHAR(100) NOT NULL,
    is_active   BOOLEAN      DEFAULT true,
    created_at  TIMESTAMPTZ  DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    used_at     TIMESTAMPTZ
);

-- Application settings table (replaces .env for app-level config)
CREATE TABLE IF NOT EXISTS app_settings (
    key         VARCHAR(100) PRIMARY KEY,
    value       TEXT         NOT NULL,
    description TEXT,
    is_secret   BOOLEAN      DEFAULT true,
    updated_at  TIMESTAMPTZ  DEFAULT now()
);

-- File storage metadata (files stored in S3 with SSE-C)
CREATE TABLE IF NOT EXISTS file_storage (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
    original_name   VARCHAR(255) NOT NULL,
    s3_key          VARCHAR(255) NOT NULL UNIQUE,
    mime_type       VARCHAR(100) NOT NULL,
    file_size       BIGINT       NOT NULL,
    sse_c_key_hash  VARCHAR(64)  NOT NULL,
    attachment_type VARCHAR(50)  DEFAULT 'general',
    uploaded_by     VARCHAR(50),
    created_at      TIMESTAMPTZ  DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_file_storage_user_id ON file_storage(user_id);

-- Login attempts table for DB-based rate limiting (not session-based)
CREATE TABLE IF NOT EXISTS login_attempts (
    id          SERIAL PRIMARY KEY,
    ip_address  VARCHAR(45)  NOT NULL,
    attempted_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_login_attempts_ip ON login_attempts (ip_address, attempted_at);

-- Grant permissions to appuser
GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO appuser;
GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO appuser;
GRANT USAGE, SELECT ON SEQUENCE key_history_id_seq TO appuser;
GRANT USAGE, SELECT ON SEQUENCE api_tokens_id_seq TO appuser;
GRANT USAGE, SELECT ON SEQUENCE file_storage_id_seq TO appuser;
GRANT USAGE, SELECT ON SEQUENCE login_attempts_id_seq TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO appuser;
GRANT SELECT, INSERT ON audit_log TO appuser;
GRANT SELECT, INSERT ON key_history TO appuser;
GRANT SELECT, INSERT, UPDATE ON api_tokens TO appuser;
GRANT SELECT, INSERT, UPDATE ON app_settings TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON file_storage TO appuser;
GRANT SELECT, INSERT, DELETE ON login_attempts TO appuser;
