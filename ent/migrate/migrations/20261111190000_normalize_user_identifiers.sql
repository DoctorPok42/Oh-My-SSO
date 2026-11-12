-- Usernames and e-mail addresses are stored in lower case (domain.NormalizeIdentifier).
-- Two accounts of a realm that differ only by case would become one: stop before changing anything.
DO $$
DECLARE
  clashes text;
BEGIN
  SELECT string_agg(format('%s in realm %s', ident, realm_id), ', ') INTO clashes
  FROM (
    SELECT "realm_id", lower("username") AS ident FROM "users" GROUP BY 1, 2 HAVING count(*) > 1
    UNION
    SELECT "realm_id", lower("email") FROM "users" GROUP BY 1, 2 HAVING count(*) > 1
  ) AS c;
  IF clashes IS NOT NULL THEN
    RAISE EXCEPTION 'users that differ only by case: %. Rename or delete the duplicates, then apply the migrations again', clashes;
  END IF;
END $$;
-- Modify "users" rows
UPDATE "users" SET "username" = lower("username"), "email" = lower("email") WHERE "username" <> lower("username") OR "email" <> lower("email");
