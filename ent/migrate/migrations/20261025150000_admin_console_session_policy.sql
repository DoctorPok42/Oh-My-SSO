-- Keep the master admin console's sensitive changes unlocked for one hour.
UPDATE "instance_settings"
SET "mfa_step_up_max_age_minutes" = 60
WHERE "realm_id" = (
  SELECT "id" FROM "realms" WHERE "name" = 'master' AND "is_system_realm" = true
);
