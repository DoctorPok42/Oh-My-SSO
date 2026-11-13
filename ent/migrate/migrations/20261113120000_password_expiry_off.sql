-- password_expiry_days is not enforced yet (audit B-05): 0 (never) by default.
-- The former default, 90, was never acted on: back to 0, so that the day the
-- expiry is enforced, no realm starts expiring passwords nobody asked for.
ALTER TABLE "instance_settings" ALTER COLUMN "password_expiry_days" SET DEFAULT 0;
UPDATE "instance_settings" SET "password_expiry_days" = 0 WHERE "password_expiry_days" = 90;
