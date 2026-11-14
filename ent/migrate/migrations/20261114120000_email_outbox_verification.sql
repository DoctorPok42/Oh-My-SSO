-- Lot E of the audit (B-12, B-13): the e-mail outbox, the verified state of
-- an address, and the links of the address verification e-mails.
-- Modify "password_reset_tokens" table
ALTER TABLE "password_reset_tokens" ADD COLUMN "emailed_to" character varying NULL;
-- Modify "users" table
ALTER TABLE "users" ADD COLUMN "email_verified_at" timestamptz NULL;
-- Create "email_outbox" table
CREATE TABLE "email_outbox" (
  "id" character varying NOT NULL,
  "realm_id" character varying NOT NULL,
  "kind" character varying NOT NULL,
  "event" text NOT NULL,
  "sealed_token" text NULL,
  "status" character varying NOT NULL DEFAULT 'pending',
  "attempts" bigint NOT NULL DEFAULT 0,
  "next_attempt_at" timestamptz NOT NULL,
  "deadline" timestamptz NOT NULL,
  "locked_until" timestamptz NULL,
  "claim" character varying NULL,
  "last_error" character varying NULL,
  "recipient" character varying NULL,
  "template" character varying NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "sent_at" timestamptz NULL,
  "user_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "email_outbox_users_email_outbox" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "emailoutbox_realm_id_updated_at" to table: "email_outbox"
CREATE INDEX "emailoutbox_realm_id_updated_at" ON "email_outbox" ("realm_id", "updated_at");
-- Create index "emailoutbox_status_next_attempt_at" to table: "email_outbox"
CREATE INDEX "emailoutbox_status_next_attempt_at" ON "email_outbox" ("status", "next_attempt_at");
-- Create index "emailoutbox_user_id_created_at" to table: "email_outbox"
CREATE INDEX "emailoutbox_user_id_created_at" ON "email_outbox" ("user_id", "created_at");
-- Create "email_verification_tokens" table
CREATE TABLE "email_verification_tokens" (
  "id" character varying NOT NULL,
  "email" character varying NOT NULL,
  "token_hash" character varying NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "used_at" timestamptz NULL,
  "created_at" timestamptz NOT NULL,
  "user_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "email_verification_tokens_users_email_verification_tokens" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "email_verification_tokens_token_hash_key" to table: "email_verification_tokens"
CREATE UNIQUE INDEX "email_verification_tokens_token_hash_key" ON "email_verification_tokens" ("token_hash");
-- The verified state used to be a profile key, written by hand by an
-- administrator: an address so marked keeps it, from now on in its column.
-- The key leaves the profile (it is no longer read).
UPDATE "users" SET "email_verified_at" = now() WHERE "profile" -> 'email_verified' = 'true'::jsonb;
UPDATE "users" SET "profile" = "profile" - 'email_verified' WHERE "profile" ? 'email_verified';
