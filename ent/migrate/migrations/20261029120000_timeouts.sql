-- Modify "timeouts" table
ALTER TABLE "timeouts" ADD COLUMN "lifted_at" timestamptz NULL, ADD COLUMN "lifted_by" character varying NULL, ADD COLUMN "enforced_at" timestamptz NULL;
-- Create index "timeout_realm_id_starts_at" to table: "timeouts"
CREATE INDEX "timeout_realm_id_starts_at" ON "timeouts" ("realm_id", "starts_at");
-- Create index "timeout_starts_at" to table: "timeouts"
CREATE INDEX "timeout_starts_at" ON "timeouts" ("starts_at") WHERE ((enforced_at IS NULL) AND (lifted_at IS NULL));
