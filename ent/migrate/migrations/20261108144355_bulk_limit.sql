-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ADD COLUMN "bulk_limit" bigint NOT NULL DEFAULT 100;
