-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ADD COLUMN "audit_log_retention_days" bigint NOT NULL DEFAULT 365;
