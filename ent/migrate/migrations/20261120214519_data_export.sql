-- Create "data_exports" table
CREATE TABLE "data_exports" (
  "id" character varying NOT NULL,
  "realm_id" character varying NOT NULL,
  "status" character varying NOT NULL DEFAULT 'running',
  "data" bytea NULL,
  "created_at" timestamptz NOT NULL,
  "finished_at" timestamptz NULL,
  "expires_at" timestamptz NOT NULL,
  "user_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "data_exports_users_data_exports" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "dataexport_expires_at" to table: "data_exports"
CREATE INDEX "dataexport_expires_at" ON "data_exports" ("expires_at");
-- Create index "dataexport_user_id" to table: "data_exports"
CREATE UNIQUE INDEX "dataexport_user_id" ON "data_exports" ("user_id");
