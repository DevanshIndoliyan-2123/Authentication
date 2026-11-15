-- Baseline schema for tbl_users (matches UserEntity).
-- IF NOT EXISTS makes this safe on databases that Hibernate already created.

CREATE TABLE IF NOT EXISTS tbl_users (
    id                   BIGSERIAL PRIMARY KEY,
    user_id              VARCHAR(255) NOT NULL UNIQUE,
    name                 VARCHAR(255),
    email                VARCHAR(255) UNIQUE,
    password             VARCHAR(255),
    verify_otp           VARCHAR(255),
    verify_otp_expire_at BIGINT,
    is_account_verified  BOOLEAN,
    reset_otp            VARCHAR(255),
    reset_otp_expire_at  BIGINT,
    created_at           TIMESTAMP(6) NOT NULL DEFAULT now(),
    updated_at           TIMESTAMP(6) NOT NULL DEFAULT now()
);

-- Wrong-OTP counters. OTP columns now hold HMAC hashes (64 hex chars).
ALTER TABLE tbl_users ADD COLUMN IF NOT EXISTS verify_otp_attempts INTEGER DEFAULT 0;
ALTER TABLE tbl_users ADD COLUMN IF NOT EXISTS reset_otp_attempts  INTEGER DEFAULT 0;

-- Plain-text OTPs from older versions can no longer be matched; drop them.
UPDATE tbl_users SET verify_otp = NULL, verify_otp_expire_at = 0
 WHERE verify_otp IS NOT NULL AND length(verify_otp) <> 64;
UPDATE tbl_users SET reset_otp = NULL, reset_otp_expire_at = 0
 WHERE reset_otp IS NOT NULL AND length(reset_otp) <> 64;
