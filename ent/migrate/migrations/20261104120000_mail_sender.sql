-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ADD COLUMN "mail_from_name" character varying NOT NULL DEFAULT '', ADD COLUMN "mail_from_address" character varying NOT NULL DEFAULT '', ADD COLUMN "mail_reply_to" character varying NOT NULL DEFAULT '', ADD COLUMN "mail_logo_url" character varying NOT NULL DEFAULT '';
