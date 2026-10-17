-- Modify "mfa_methods" table
ALTER TABLE "mfa_methods" ADD COLUMN "webauthn_credential" text NULL;
-- Create index "mfamethod_credential_id" to table: "mfa_methods"
CREATE UNIQUE INDEX "mfamethod_credential_id" ON "mfa_methods" ("credential_id");
