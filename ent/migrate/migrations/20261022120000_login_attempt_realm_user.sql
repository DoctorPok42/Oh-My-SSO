-- Modify "login_attempts" table
ALTER TABLE "login_attempts" ADD COLUMN "realm_id" character varying NULL, ADD COLUMN "user_id" character varying NULL;
-- Create index "loginattempt_realm_id_created_at" to table: "login_attempts"
CREATE INDEX "loginattempt_realm_id_created_at" ON "login_attempts" ("realm_id", "created_at");
-- Create index "loginattempt_user_id_created_at" to table: "login_attempts"
CREATE INDEX "loginattempt_user_id_created_at" ON "login_attempts" ("user_id", "created_at");
