-- jardissupport/auth: token table for DbTokenStore (SQLite)
-- Only the SHA-256 hash of a token is stored, never the plain value.
-- Timestamps are UTC text ('Y-m-d H:i:s.u'), which sorts chronologically.
-- Default table name: auth_tokens.
CREATE TABLE IF NOT EXISTS auth_tokens (
    token_hash TEXT    NOT NULL PRIMARY KEY,
    token_type TEXT    NOT NULL,
    subject    TEXT    NULL,
    claims     TEXT    NOT NULL,
    expires_at TEXT    NULL,
    created_at TEXT    NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_subject ON auth_tokens (subject);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires_at ON auth_tokens (expires_at);
