-- Password history and expiry.
-- Existing passwords count as changed now: turning the expiry on must not
-- expire every account at once.
ALTER TABLE "users" ADD COLUMN "password_changed_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, ADD COLUMN "password_history" jsonb NULL;
ALTER TABLE "users" ALTER COLUMN "password_changed_at" DROP DEFAULT;
ALTER TABLE "instance_settings" ADD COLUMN "password_history_count" bigint NOT NULL DEFAULT 5;
