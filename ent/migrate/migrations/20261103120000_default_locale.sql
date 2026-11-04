-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ADD COLUMN "default_locale" character varying NOT NULL DEFAULT 'en';
