-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ADD COLUMN "mfa_trusted_device_enabled" boolean NOT NULL DEFAULT true, ADD COLUMN "mfa_trusted_device_days" bigint NOT NULL DEFAULT 30;
-- Modify "sessions" table
ALTER TABLE "sessions" ADD COLUMN "trusted_device" boolean NOT NULL DEFAULT false;
-- Create "trusted_devices" table
CREATE TABLE "trusted_devices" ("id" character varying NOT NULL, "device_hash" character varying NOT NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "created_at" timestamptz NOT NULL, "expires_at" timestamptz NOT NULL, "last_used_at" timestamptz NULL, "realm_id" character varying NOT NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "trusted_devices_realms_trusted_devices" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "trusted_devices_users_trusted_devices" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "trusteddevice_device_hash_user_id" to table: "trusted_devices"
CREATE UNIQUE INDEX "trusteddevice_device_hash_user_id" ON "trusted_devices" ("device_hash", "user_id");
-- Create index "trusteddevice_user_id" to table: "trusted_devices"
CREATE INDEX "trusteddevice_user_id" ON "trusted_devices" ("user_id");
