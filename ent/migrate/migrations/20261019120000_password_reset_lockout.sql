-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ADD COLUMN "password_reset_ttl_minutes" bigint NOT NULL DEFAULT 30, ADD COLUMN "suspicious_login_email_enabled" boolean NOT NULL DEFAULT false;
-- Modify "users" table
ALTER TABLE "users" ADD COLUMN "failed_login_count" bigint NOT NULL DEFAULT 0, ADD COLUMN "last_failed_login_at" timestamptz NULL, ADD COLUMN "locked_until" timestamptz NULL, ADD COLUMN "lockout_count" bigint NOT NULL DEFAULT 0, ADD COLUMN "last_locked_at" timestamptz NULL;
