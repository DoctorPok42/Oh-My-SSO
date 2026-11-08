-- Create index "session_realm_id_ip_address" to table: "sessions"
CREATE INDEX "session_realm_id_ip_address" ON "sessions" ("realm_id", "ip_address");
-- Modify "users" table
ALTER TABLE "users" ADD COLUMN "must_change_password" boolean NOT NULL DEFAULT false;
