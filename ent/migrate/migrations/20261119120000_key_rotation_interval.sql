-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ADD COLUMN "key_rotation_interval_days" bigint NOT NULL DEFAULT 90, ADD COLUMN "key_rotation_claimed_until" timestamptz NULL;
