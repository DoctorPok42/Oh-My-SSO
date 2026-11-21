-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ADD COLUMN "email_change_allowed" boolean NOT NULL DEFAULT false;
-- Modify "users" table
ALTER TABLE "users" ADD COLUMN "pending_email" character varying NULL;
