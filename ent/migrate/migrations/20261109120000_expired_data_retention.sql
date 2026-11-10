-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ADD COLUMN "expired_data_retention_days" bigint NOT NULL DEFAULT 90;
