-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ADD COLUMN "account_deletion_enabled" boolean NOT NULL DEFAULT false;
-- Modify "users" table
ALTER TABLE "users" ADD COLUMN "deletion_scheduled_at" timestamptz NULL;
-- Create index "user_deletion_scheduled_at" to table: "users"
CREATE INDEX "user_deletion_scheduled_at" ON "users" ("deletion_scheduled_at");
