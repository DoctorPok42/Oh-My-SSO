-- Modify "client_apps" table
ALTER TABLE "client_apps" ADD COLUMN "session_idle_minutes" bigint NULL, ADD COLUMN "session_max_minutes" bigint NULL;
-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ALTER COLUMN "session_idle_minutes" SET DEFAULT 10, ALTER COLUMN "session_max_hours" SET DEFAULT 8;
-- Modify "sessions" table
ALTER TABLE "sessions" ADD COLUMN "token_hash" character varying NOT NULL;
-- Create index "sessions_token_hash_key" to table: "sessions"
CREATE UNIQUE INDEX "sessions_token_hash_key" ON "sessions" ("token_hash");
