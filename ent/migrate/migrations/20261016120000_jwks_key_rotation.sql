-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ADD COLUMN "key_rotation_grace_hours" bigint NOT NULL DEFAULT 24;
-- Modify "signing_keys" table
ALTER TABLE "signing_keys" ADD COLUMN "retire_after" timestamptz NULL;
-- Create index "signingkey_realm_id_purpose_status" to table: "signing_keys"
CREATE INDEX "signingkey_realm_id_purpose_status" ON "signing_keys" ("realm_id", "purpose", "status");
-- Backfill: keys that were already "rotating" before this migration had no
-- deadline. Give them a full default grace period from now (manual addition).
UPDATE "signing_keys" SET "retire_after" = now() + interval '24 hours' WHERE "status" = 'rotating' AND "retire_after" IS NULL;
