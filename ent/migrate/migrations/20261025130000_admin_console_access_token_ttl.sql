-- Keep the internal admin console client usable for one hour between refreshes.
UPDATE "client_apps"
SET "access_token_ttl" = 3600
WHERE "client_id" = 'sso-admin'
  AND "realm_id" = (
    SELECT "id" FROM "realms" WHERE "name" = 'master' AND "is_system_realm" = true
  );
