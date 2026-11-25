-- Modify "tokens" table
ALTER TABLE "public"."tokens" ALTER COLUMN "session_id" DROP NOT NULL;
-- Create "client_app_service_roles" table
CREATE TABLE "public"."client_app_service_roles" (
  "client_app_id" character varying NOT NULL,
  "role_id" character varying NOT NULL,
  PRIMARY KEY ("client_app_id", "role_id"),
  CONSTRAINT "client_app_service_roles_client_app_id" FOREIGN KEY ("client_app_id") REFERENCES "public"."client_apps" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "client_app_service_roles_role_id" FOREIGN KEY ("role_id") REFERENCES "public"."roles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
