-- Create "bulk_jobs" table
CREATE TABLE "bulk_jobs" ("id" character varying NOT NULL, "action" character varying NOT NULL, "operation_id" character varying NOT NULL, "status" character varying NOT NULL DEFAULT 'running', "requested_by" character varying NOT NULL, "requested_by_name" character varying NOT NULL, "requested_by_realm" character varying NOT NULL, "ids" jsonb NOT NULL, "total" bigint NOT NULL DEFAULT 0, "processed" bigint NOT NULL DEFAULT 0, "done_count" bigint NOT NULL DEFAULT 0, "skipped_count" bigint NOT NULL DEFAULT 0, "failed_count" bigint NOT NULL DEFAULT 0, "items" jsonb NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "finished_at" timestamptz NULL, "realm_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "bulk_jobs_realms_bulk_jobs" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "bulkjob_realm_id" to table: "bulk_jobs"
CREATE UNIQUE INDEX "bulkjob_realm_id" ON "bulk_jobs" ("realm_id") WHERE (status = 'running');
-- Create index "bulkjob_status_updated_at" to table: "bulk_jobs"
CREATE INDEX "bulkjob_status_updated_at" ON "bulk_jobs" ("status", "updated_at");
