-- Create "user_import_jobs" table
CREATE TABLE "user_import_jobs" ("id" character varying NOT NULL, "status" character varying NOT NULL DEFAULT 'running', "file_name" character varying NOT NULL DEFAULT '', "requested_by" character varying NOT NULL, "requested_by_name" character varying NOT NULL, "requested_by_realm" character varying NOT NULL, "send_email" boolean NOT NULL DEFAULT false, "notify_when_done" boolean NOT NULL DEFAULT false, "total" bigint NOT NULL DEFAULT 0, "processed" bigint NOT NULL DEFAULT 0, "created_count" bigint NOT NULL DEFAULT 0, "failed_count" bigint NOT NULL DEFAULT 0, "ignored_columns" jsonb NULL, "rows" jsonb NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "finished_at" timestamptz NULL, "realm_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "user_import_jobs_realms_user_import_jobs" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "userimportjob_realm_id" to table: "user_import_jobs"
CREATE UNIQUE INDEX "userimportjob_realm_id" ON "user_import_jobs" ("realm_id") WHERE (status = 'running');
-- Create index "userimportjob_realm_id_created_at" to table: "user_import_jobs"
CREATE INDEX "userimportjob_realm_id_created_at" ON "user_import_jobs" ("realm_id", "created_at");
-- Create index "userimportjob_status_updated_at" to table: "user_import_jobs"
CREATE INDEX "userimportjob_status_updated_at" ON "user_import_jobs" ("status", "updated_at");
