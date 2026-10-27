-- "Keep me signed in" stays off in the master realm: its accounts administer
-- the whole instance, a remembered session there is not worth the risk.
UPDATE "instance_settings"
SET "remember_me_enabled" = false
WHERE "realm_id" = (
  SELECT "id" FROM "realms" WHERE "name" = 'master' AND "is_system_realm" = true
);
