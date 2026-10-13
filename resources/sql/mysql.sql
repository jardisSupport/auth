-- jardissupport/auth: token table for DbTokenStore (MySQL / MariaDB)
-- Only the SHA-256 hash of a token is stored, never the plain value.
-- Timestamps are UTC. Default table name: auth_tokens.
CREATE TABLE IF NOT EXISTS auth_tokens (
    token_hash CHAR(64)     NOT NULL,
    token_type VARCHAR(32)  NOT NULL,
    subject    VARCHAR(255) NULL,
    claims     TEXT         NOT NULL,
    expires_at DATETIME(6)  NULL,
    created_at DATETIME(6)  NOT NULL,
    revoked    TINYINT(1)   NOT NULL DEFAULT 0,
    PRIMARY KEY (token_hash),
    KEY idx_auth_tokens_subject (subject),
    KEY idx_auth_tokens_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
