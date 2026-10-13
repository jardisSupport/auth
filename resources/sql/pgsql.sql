-- jardissupport/auth: token table for DbTokenStore (PostgreSQL)
-- Only the SHA-256 hash of a token is stored, never the plain value.
-- Timestamps are UTC. Default table name: auth_tokens.
CREATE TABLE IF NOT EXISTS auth_tokens (
    token_hash CHAR(64)     NOT NULL,
    token_type VARCHAR(32)  NOT NULL,
    subject    VARCHAR(255) NULL,
    claims     TEXT         NOT NULL,
    expires_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL,
    revoked    SMALLINT     NOT NULL DEFAULT 0,
    PRIMARY KEY (token_hash)
);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_subject ON auth_tokens (subject);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires_at ON auth_tokens (expires_at);
