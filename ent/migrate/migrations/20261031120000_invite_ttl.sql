-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ADD COLUMN "invite_ttl_hours" bigint NOT NULL DEFAULT 4;
