-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ADD COLUMN "password_breach_check_enabled" boolean NOT NULL DEFAULT true;
