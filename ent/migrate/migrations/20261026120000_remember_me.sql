-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ADD COLUMN "remember_me_enabled" boolean NOT NULL DEFAULT true, ADD COLUMN "remember_me_idle_days" bigint NOT NULL DEFAULT 7, ADD COLUMN "remember_me_max_days" bigint NOT NULL DEFAULT 30;
-- Modify "sessions" table
ALTER TABLE "sessions" ADD COLUMN "remember_me" boolean NOT NULL DEFAULT false;
