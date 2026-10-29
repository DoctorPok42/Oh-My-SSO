-- Modify "known_accounts" table
ALTER TABLE "known_accounts" ADD COLUMN "last_method" character varying NULL, ADD COLUMN "last_second_factor" character varying NULL;
