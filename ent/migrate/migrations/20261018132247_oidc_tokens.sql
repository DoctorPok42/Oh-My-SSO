-- Modify "client_apps" table
ALTER TABLE "client_apps" ALTER COLUMN "access_token_ttl" SET DEFAULT 300;
-- Modify "tokens" table
ALTER TABLE "tokens" ADD COLUMN "token_hash" character varying NULL, ADD COLUMN "family_id" character varying NULL, ADD COLUMN "used_at" timestamptz NULL;
-- Create index "token_family_id" to table: "tokens"
CREATE INDEX "token_family_id" ON "tokens" ("family_id");
-- Create index "tokens_token_hash_key" to table: "tokens"
CREATE UNIQUE INDEX "tokens_token_hash_key" ON "tokens" ("token_hash");
