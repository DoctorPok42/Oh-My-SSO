-- "Don't ask again on this device" stays off in the master realm: its
-- accounts administer the whole instance, they always give a second factor.
UPDATE "instance_settings"
SET "mfa_trusted_device_enabled" = false
WHERE "realm_id" = (
  SELECT "id" FROM "realms" WHERE "name" = 'master' AND "is_system_realm" = true
);
