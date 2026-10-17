-- Modify "client_apps" table
ALTER TABLE "client_apps" ADD COLUMN "mfa_policy" character varying NOT NULL DEFAULT 'inherit', ADD COLUMN "mfa_allowed_methods" jsonb NULL;
-- Modify "instance_settings" table
ALTER TABLE "instance_settings" ADD COLUMN "mfa_step_up_max_age_minutes" bigint NOT NULL DEFAULT 10;
-- Modify "mfa_methods" table
ALTER TABLE "mfa_methods" ADD COLUMN "name" character varying NULL, ADD COLUMN "last_used_counter" bigint NOT NULL DEFAULT 0;
-- Create index "mfamethod_user_id_active_totp" to table: "mfa_methods"
CREATE UNIQUE INDEX "mfamethod_user_id_active_totp" ON "mfa_methods" ("user_id") WHERE (((type)::text = 'totp'::text) AND ((status)::text = 'active'::text));
-- Modify "sessions" table
ALTER TABLE "sessions" ADD COLUMN "mfa_verified_at" timestamptz NULL;
-- Create "mfa_policies" table
CREATE TABLE "mfa_policies" ("id" character varying NOT NULL, "managed_by" character varying NOT NULL DEFAULT 'ui', "required" boolean NOT NULL DEFAULT false, "allowed_methods" jsonb NULL, "enrollment_grace_days" bigint NOT NULL DEFAULT 0, "step_up_for_sensitive_actions" boolean NOT NULL DEFAULT false, "required_since" timestamptz NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "realm_id" character varying NOT NULL, "role_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "mfa_policies_realms_mfa_policies" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "mfa_policies_roles_mfa_policy" FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "mfa_policies_role_id_key" to table: "mfa_policies"
CREATE UNIQUE INDEX "mfa_policies_role_id_key" ON "mfa_policies" ("role_id");
-- Create index "mfapolicy_realm_id" to table: "mfa_policies"
CREATE INDEX "mfapolicy_realm_id" ON "mfa_policies" ("realm_id");
