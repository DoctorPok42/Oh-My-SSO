-- Modify "client_apps" table
ALTER TABLE "client_apps" ADD COLUMN "subject_type" character varying NOT NULL DEFAULT 'public', ADD COLUMN "sector_identifier" character varying NULL;
-- Modify "realms" table
ALTER TABLE "realms" ADD COLUMN "pairwise_subject_salt" character varying NULL;
-- Modify "sessions" table
ALTER TABLE "sessions" ALTER COLUMN "auth_method" SET DEFAULT 'pwd';
-- Backfill existing sessions: "password" -> RFC 8176 "pwd" (manual addition)
UPDATE "sessions" SET "auth_method" = 'pwd' WHERE "auth_method" = 'password';
