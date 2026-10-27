-- Create "known_accounts" table
CREATE TABLE "known_accounts" ("id" character varying NOT NULL, "device_hash" character varying NOT NULL, "created_at" timestamptz NOT NULL, "last_used_at" timestamptz NOT NULL, "realm_id" character varying NOT NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "known_accounts_realms_known_accounts" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "known_accounts_users_known_accounts" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "knownaccount_device_hash_user_id" to table: "known_accounts"
CREATE UNIQUE INDEX "knownaccount_device_hash_user_id" ON "known_accounts" ("device_hash", "user_id");
