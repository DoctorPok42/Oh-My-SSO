-- Modify "client_apps" table
ALTER TABLE "client_apps" ADD COLUMN "jwks" text NULL, ADD COLUMN "jwks_uri" character varying NULL;
-- Modify "tokens" table
ALTER TABLE "tokens" ADD COLUMN "audience" jsonb NULL;
-- Create "api_resources" table
CREATE TABLE "api_resources" (
  "id" character varying NOT NULL,
  "identifier" character varying NOT NULL,
  "name" character varying NOT NULL,
  "description" character varying NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "realm_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "api_resources_realms_api_resources" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT
);
-- Create index "apiresource_realm_id_identifier" to table: "api_resources"
CREATE UNIQUE INDEX "apiresource_realm_id_identifier" ON "api_resources" ("realm_id", "identifier");
-- Create "api_resource_scopes" table
CREATE TABLE "api_resource_scopes" (
  "api_resource_id" character varying NOT NULL,
  "client_scope_id" character varying NOT NULL,
  PRIMARY KEY ("api_resource_id", "client_scope_id"),
  CONSTRAINT "api_resource_scopes_api_resource_id" FOREIGN KEY ("api_resource_id") REFERENCES "api_resources" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "api_resource_scopes_client_scope_id" FOREIGN KEY ("client_scope_id") REFERENCES "client_scopes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
