-- Modify "audit_logs" table
ALTER TABLE "audit_logs" ADD COLUMN "actor_type" character varying NOT NULL DEFAULT 'system', ADD COLUMN "target_user_id" character varying NULL;
-- Create index "auditlog_target_user_id_timestamp" to table: "audit_logs"
CREATE INDEX "auditlog_target_user_id_timestamp" ON "audit_logs" ("target_user_id", "timestamp");
-- Create index "auditlog_realm_id_action_timestamp" to table: "audit_logs"
CREATE INDEX "auditlog_realm_id_action_timestamp" ON "audit_logs" ("realm_id", "action", "timestamp");

-- Backfill: who did it (actor_type) and whom it is about (target_user_id).
-- Until now user_id held the actor for most entries, but the target for the
-- server's own events: those move to target_user_id.
UPDATE "audit_logs" SET "target_user_id" = "user_id", "user_id" = NULL
  WHERE "action" IN ('account_locked', 'notification_sent', 'refresh_token_reuse_detected');
UPDATE "audit_logs" SET "actor_type" = 'cli'
  WHERE "action" IN ('admin.bootstrap', 'admin.recovery_admin', 'admin.recovery_client_secret', 'admin.recovery_timeout_lift')
     OR ("user_id" IS NULL AND "details" ->> 'triggered_by' LIKE 'cli:%');
UPDATE "audit_logs" SET "actor_type" = 'admin'
  WHERE "user_id" IS NOT NULL AND "action" LIKE 'admin.%';
-- Entries written by a service on behalf of "user:<id>": an administrator,
-- unless the id is the user the entry is about.
UPDATE "audit_logs" SET "actor_type" = 'admin'
  WHERE "user_id" IS NOT NULL
    AND "action" IN ('mfa_reset', 'mfa_policy_changed', 'consent_policy_changed');
UPDATE "audit_logs" SET "target_user_id" = "details" ->> 'user_id'
  WHERE "action" = 'consent_revoked' AND "details" ->> 'user_id' IS NOT NULL;
UPDATE "audit_logs" SET "actor_type" = CASE WHEN "user_id" = "target_user_id" THEN 'user' ELSE 'admin' END
  WHERE "action" = 'consent_revoked' AND "user_id" IS NOT NULL;
UPDATE "audit_logs" SET "actor_type" = 'user'
  WHERE "user_id" IS NOT NULL AND "actor_type" = 'system';
UPDATE "audit_logs" SET "target_user_id" = "resource_id"
  WHERE "target_user_id" IS NULL AND "resource_type" = 'User';
UPDATE "audit_logs" SET "target_user_id" = "user_id"
  WHERE "target_user_id" IS NULL AND "actor_type" = 'user';

-- Rename the actions to "<domain>.<what happened>" (internal/core/audit).
UPDATE "audit_logs" AS a SET "action" = m."new"
FROM (VALUES
  ('suspicious_login', 'auth.login_suspicious'),
  ('new_device_login', 'auth.login_new_device'),
  ('logout', 'auth.logout'),
  ('mfa_trusted_device_challenged', 'auth.trusted_device_challenged'),
  ('authorization_denied', 'auth.access_denied'),
  ('refresh_token_reuse_detected', 'token.reuse_detected'),
  ('account_locked', 'user.locked'),
  ('account_unlocked', 'user.unlocked'),
  ('admin.user.unlock', 'user.unlocked'),
  ('admin.user.invite', 'user.invited'),
  ('admin.user.activation_link', 'user.activation_link_sent'),
  ('activation_link_issued', 'user.activation_link_sent'),
  ('admin.user.update', 'user.updated'),
  ('account.profile_updated', 'user.profile_updated'),
  ('admin.user.delete', 'user.deleted'),
  ('admin.user.groups', 'user.groups_changed'),
  ('admin.user.roles', 'user.roles_changed'),
  ('account.password_changed', 'user.password_changed'),
  ('password_reset_requested', 'user.password_reset_requested'),
  ('password_reset', 'user.password_reset'),
  ('admin.user.mfa_reset', 'mfa.reset'),
  ('mfa_reset', 'mfa.reset'),
  ('mfa_method_enrolled', 'mfa.method_enrolled'),
  ('mfa_method_removed', 'mfa.method_removed'),
  ('mfa_backup_codes_regenerated', 'mfa.backup_codes_regenerated'),
  ('mfa_passkey_clone_warning', 'mfa.passkey_clone_detected'),
  ('mfa_policy_changed', 'mfa.policy_changed'),
  ('mfa_device_trusted', 'trusted_device.added'),
  ('mfa_device_trust_revoked', 'trusted_device.revoked'),
  ('account.trusted_device_revoked', 'trusted_device.revoked'),
  ('admin.trusted_device.revoke', 'trusted_device.revoked'),
  ('account.trusted_devices_revoked', 'trusted_device.revoked_all'),
  ('admin.trusted_device.revoke_all', 'trusted_device.revoked_all'),
  ('account.session_revoked', 'session.revoked'),
  ('admin.session.revoke', 'session.revoked'),
  ('account.sessions_revoked', 'session.revoked_all'),
  ('admin.session.revoke_all', 'session.revoked_all'),
  ('consent_granted', 'consent.granted'),
  ('consent_denied', 'consent.denied'),
  ('consent_revoked', 'consent.revoked'),
  ('account.app_access_revoked', 'consent.app_access_revoked'),
  ('consent_policy_changed', 'consent.policy_changed'),
  ('known_account.forget', 'known_account.forgotten'),
  ('admin.client.create', 'client.created'),
  ('admin.client.update', 'client.updated'),
  ('admin.client.delete', 'client.deleted'),
  ('admin.client.secret_rotate', 'client.secret_rotated'),
  ('admin.client.certificate_add', 'client.certificate_added'),
  ('admin.client.certificate_remove', 'client.certificate_removed'),
  ('admin.client_scope.create', 'client_scope.created'),
  ('admin.client_scope.update', 'client_scope.updated'),
  ('admin.client_scope.delete', 'client_scope.deleted'),
  ('admin.role.create', 'role.created'),
  ('admin.role.update', 'role.updated'),
  ('admin.role.delete', 'role.deleted'),
  ('admin.group.create', 'group.created'),
  ('admin.group.update', 'group.updated'),
  ('admin.group.delete', 'group.deleted'),
  ('admin.permission.create', 'permission.created'),
  ('admin.permission.delete', 'permission.deleted'),
  ('admin.timeout.create', 'timeout.created'),
  ('admin.timeout.update', 'timeout.updated'),
  ('admin.timeout.lift', 'timeout.lifted'),
  ('timeout_created', 'timeout.created'),
  ('timeout_updated', 'timeout.updated'),
  ('timeout_lifted', 'timeout.lifted'),
  ('timeout_enforced', 'timeout.enforced'),
  ('admin.realm.create', 'realm.created'),
  ('admin.realm.update', 'realm.updated'),
  ('admin.settings.update', 'settings.updated'),
  ('admin.bootstrap', 'instance.bootstrapped'),
  ('admin.recovery_admin', 'recovery.admin'),
  ('admin.recovery_client_secret', 'recovery.client_secret'),
  ('admin.recovery_timeout_lift', 'recovery.timeout_lifted'),
  ('notification_sent', 'notification.sent')
) AS m("old", "new")
WHERE a."action" = m."old";
