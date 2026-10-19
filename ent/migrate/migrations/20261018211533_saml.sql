-- Modify "signing_keys" table
ALTER TABLE "signing_keys" ADD COLUMN "certificate" text NULL;
-- Modify "tokens" table
ALTER TABLE "tokens" ADD COLUMN "subject" character varying NULL, ADD COLUMN "subject_format" character varying NULL;
