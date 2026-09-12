-- Create "login_attempts" table
CREATE TABLE "login_attempts" (
  "id" character varying NOT NULL,
  "identifier" character varying NOT NULL,
  "ip_address" character varying NULL,
  "user_agent" character varying NULL,
  "status" character varying NOT NULL,
  "failure_reason" character varying NULL,
  "created_at" timestamptz NOT NULL,
  PRIMARY KEY ("id")
);
-- Create index "loginattempt_identifier_created_at" to table: "login_attempts"
CREATE INDEX "loginattempt_identifier_created_at" ON "login_attempts" ("identifier", "created_at");
-- Create index "loginattempt_ip_address_created_at" to table: "login_attempts"
CREATE INDEX "loginattempt_ip_address_created_at" ON "login_attempts" ("ip_address", "created_at");
-- Create "realms" table
CREATE TABLE "realms" (
  "id" character varying NOT NULL,
  "name" character varying NOT NULL,
  "is_system_realm" boolean NOT NULL DEFAULT false,
  "display_name" character varying NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "status" character varying NOT NULL DEFAULT 'active',
  PRIMARY KEY ("id")
);
-- Create index "realms_name_key" to table: "realms"
CREATE UNIQUE INDEX "realms_name_key" ON "realms" ("name");
-- Create "audit_logs" table
CREATE TABLE "audit_logs" (
  "id" character varying NOT NULL,
  "user_id" character varying NULL,
  "action" character varying NOT NULL,
  "resource_type" character varying NULL,
  "resource_id" character varying NULL,
  "timestamp" timestamptz NOT NULL,
  "ip_address" character varying NULL,
  "user_agent" character varying NULL,
  "level" character varying NOT NULL DEFAULT 'info',
  "status" character varying NOT NULL DEFAULT 'success',
  "details" jsonb NULL,
  "realm_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "audit_logs_realms_audit_logs" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT
);
-- Create index "auditlog_realm_id_timestamp" to table: "audit_logs"
CREATE INDEX "auditlog_realm_id_timestamp" ON "audit_logs" ("realm_id", "timestamp");
-- Create index "auditlog_resource_type_resource_id" to table: "audit_logs"
CREATE INDEX "auditlog_resource_type_resource_id" ON "audit_logs" ("resource_type", "resource_id");
-- Create index "auditlog_user_id_timestamp" to table: "audit_logs"
CREATE INDEX "auditlog_user_id_timestamp" ON "audit_logs" ("user_id", "timestamp");
-- Create "client_apps" table
CREATE TABLE "client_apps" (
  "id" character varying NOT NULL,
  "managed_by" character varying NOT NULL DEFAULT 'ui',
  "name" character varying NOT NULL,
  "protocol" character varying NOT NULL,
  "status" character varying NOT NULL DEFAULT 'active',
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "deleted_at" timestamptz NULL,
  "owner_admin_id" character varying NULL,
  "client_id" character varying NULL,
  "client_secret_hash" character varying NULL,
  "client_type" character varying NULL,
  "redirect_uris" jsonb NULL,
  "post_logout_redirect_uris" jsonb NULL,
  "allowed_grant_types" jsonb NULL,
  "allowed_scopes" jsonb NULL,
  "token_endpoint_auth_method" character varying NULL,
  "id_token_signed_alg" character varying NULL,
  "access_token_ttl" bigint NOT NULL DEFAULT 3600,
  "refresh_token_ttl" bigint NOT NULL DEFAULT 2592000,
  "id_token_ttl" bigint NOT NULL DEFAULT 3600,
  "require_pkce" boolean NOT NULL DEFAULT true,
  "entity_id" character varying NULL,
  "acs_url" character varying NULL,
  "slo_url" character varying NULL,
  "client_certificates" jsonb NULL,
  "name_id_format" character varying NULL,
  "want_assertion_signed" boolean NOT NULL DEFAULT true,
  "want_response_signed" boolean NOT NULL DEFAULT false,
  "default_relay_state" character varying NULL,
  "attribute_mappings" jsonb NULL,
  "require_consent" boolean NOT NULL DEFAULT false,
  "metadata_url" character varying NULL,
  "realm_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "client_apps_realms_client_apps" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT
);
-- Create index "clientapp_realm_id_client_id" to table: "client_apps"
CREATE UNIQUE INDEX "clientapp_realm_id_client_id" ON "client_apps" ("realm_id", "client_id");
-- Create index "clientapp_realm_id_entity_id" to table: "client_apps"
CREATE UNIQUE INDEX "clientapp_realm_id_entity_id" ON "client_apps" ("realm_id", "entity_id");
-- Create "groups" table
CREATE TABLE "groups" (
  "id" character varying NOT NULL,
  "managed_by" character varying NOT NULL DEFAULT 'ui',
  "name" character varying NOT NULL,
  "description" character varying NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "status" character varying NOT NULL DEFAULT 'active',
  "realm_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "groups_realms_groups" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT
);
-- Create index "group_realm_id_name" to table: "groups"
CREATE UNIQUE INDEX "group_realm_id_name" ON "groups" ("realm_id", "name");
-- Create "client_groups" table
CREATE TABLE "client_groups" (
  "id" character varying NOT NULL,
  "granted_at" timestamptz NOT NULL,
  "granted_by" character varying NULL,
  "client_app_id" character varying NOT NULL,
  "group_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "client_groups_client_apps_client_app" FOREIGN KEY ("client_app_id") REFERENCES "client_apps" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "client_groups_groups_group" FOREIGN KEY ("group_id") REFERENCES "groups" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "clientgroup_group_id_client_app_id" to table: "client_groups"
CREATE UNIQUE INDEX "clientgroup_group_id_client_app_id" ON "client_groups" ("group_id", "client_app_id");
-- Create "roles" table
CREATE TABLE "roles" (
  "id" character varying NOT NULL,
  "managed_by" character varying NOT NULL DEFAULT 'ui',
  "name" character varying NOT NULL,
  "description" character varying NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "status" character varying NOT NULL DEFAULT 'active',
  "realm_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "roles_realms_roles" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT
);
-- Create index "role_realm_id_name" to table: "roles"
CREATE UNIQUE INDEX "role_realm_id_name" ON "roles" ("realm_id", "name");
-- Create "client_roles" table
CREATE TABLE "client_roles" (
  "id" character varying NOT NULL,
  "granted_at" timestamptz NOT NULL,
  "granted_by" character varying NULL,
  "client_app_id" character varying NOT NULL,
  "role_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "client_roles_client_apps_client_app" FOREIGN KEY ("client_app_id") REFERENCES "client_apps" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "client_roles_roles_role" FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "clientrole_role_id_client_app_id" to table: "client_roles"
CREATE UNIQUE INDEX "clientrole_role_id_client_app_id" ON "client_roles" ("role_id", "client_app_id");
-- Create "client_scopes" table
CREATE TABLE "client_scopes" (
  "id" character varying NOT NULL,
  "name" character varying NOT NULL,
  "description" character varying NULL,
  "protocol" character varying NOT NULL DEFAULT 'oidc',
  "is_default" boolean NOT NULL DEFAULT false,
  "claim_mappers" jsonb NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "realm_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "client_scopes_realms_client_scopes" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT
);
-- Create index "clientscope_realm_id_name" to table: "client_scopes"
CREATE UNIQUE INDEX "clientscope_realm_id_name" ON "client_scopes" ("realm_id", "name");
-- Create "client_scope_mappings" table
CREATE TABLE "client_scope_mappings" (
  "id" character varying NOT NULL,
  "required" boolean NOT NULL DEFAULT false,
  "client_app_id" character varying NOT NULL,
  "client_scope_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "client_scope_mappings_client_apps_client_app" FOREIGN KEY ("client_app_id") REFERENCES "client_apps" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "client_scope_mappings_client_scopes_client_scope" FOREIGN KEY ("client_scope_id") REFERENCES "client_scopes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "clientscopemapping_client_app_id_client_scope_id" to table: "client_scope_mappings"
CREATE UNIQUE INDEX "clientscopemapping_client_app_id_client_scope_id" ON "client_scope_mappings" ("client_app_id", "client_scope_id");
-- Create "users" table
CREATE TABLE "users" (
  "id" character varying NOT NULL,
  "username" character varying NOT NULL,
  "password_hash" character varying NULL,
  "email" character varying NOT NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "deleted_at" timestamptz NULL,
  "status" character varying NOT NULL DEFAULT 'active',
  "last_login_at" timestamptz NULL,
  "profile" jsonb NULL,
  "realm_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "users_realms_users" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT
);
-- Create index "user_realm_id_email" to table: "users"
CREATE UNIQUE INDEX "user_realm_id_email" ON "users" ("realm_id", "email");
-- Create index "user_realm_id_username" to table: "users"
CREATE UNIQUE INDEX "user_realm_id_username" ON "users" ("realm_id", "username");
-- Create "consents" table
CREATE TABLE "consents" (
  "id" character varying NOT NULL,
  "scopes" jsonb NULL,
  "status" character varying NOT NULL DEFAULT 'granted',
  "granted_at" timestamptz NOT NULL,
  "revoked_at" timestamptz NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "client_ref_id" character varying NOT NULL,
  "user_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "consents_client_apps_consents" FOREIGN KEY ("client_ref_id") REFERENCES "client_apps" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "consents_users_consents" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "consent_user_id_client_ref_id" to table: "consents"
CREATE UNIQUE INDEX "consent_user_id_client_ref_id" ON "consents" ("user_id", "client_ref_id");
-- Create "identity_providers" table
CREATE TABLE "identity_providers" (
  "id" character varying NOT NULL,
  "managed_by" character varying NOT NULL DEFAULT 'ui',
  "name" character varying NOT NULL,
  "protocol" character varying NOT NULL,
  "status" character varying NOT NULL DEFAULT 'active',
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "issuer_url" character varying NULL,
  "client_id" character varying NULL,
  "client_secret_hash" character varying NULL,
  "authorization_endpoint" character varying NULL,
  "token_endpoint" character varying NULL,
  "userinfo_endpoint" character varying NULL,
  "jwks_uri" character varying NULL,
  "scopes_requested" jsonb NULL,
  "idp_entity_id" character varying NULL,
  "idp_sso_url" character varying NULL,
  "idp_certificate" text NULL,
  "attribute_mapping" jsonb NULL,
  "auto_provisioning" boolean NOT NULL DEFAULT false,
  "default_roles" jsonb NULL,
  "realm_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "identity_providers_realms_identity_providers" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT
);
-- Create index "identityprovider_realm_id_name" to table: "identity_providers"
CREATE UNIQUE INDEX "identityprovider_realm_id_name" ON "identity_providers" ("realm_id", "name");
-- Create "federated_identities" table
CREATE TABLE "federated_identities" (
  "id" character varying NOT NULL,
  "external_subject" character varying NOT NULL,
  "linked_at" timestamptz NOT NULL,
  "last_login_at" timestamptz NULL,
  "identity_provider_id" character varying NOT NULL,
  "user_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "federated_identities_identity_providers_federated_identities" FOREIGN KEY ("identity_provider_id") REFERENCES "identity_providers" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "federated_identities_users_federated_identities" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "federatedidentity_identity_provider_id_external_subject" to table: "federated_identities"
CREATE UNIQUE INDEX "federatedidentity_identity_provider_id_external_subject" ON "federated_identities" ("identity_provider_id", "external_subject");
-- Create "group_client_scopes" table
CREATE TABLE "group_client_scopes" (
  "id" character varying NOT NULL,
  "granted_at" timestamptz NOT NULL,
  "group_id" character varying NOT NULL,
  "client_scope_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "group_client_scopes_client_scopes_client_scope" FOREIGN KEY ("client_scope_id") REFERENCES "client_scopes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "group_client_scopes_groups_group" FOREIGN KEY ("group_id") REFERENCES "groups" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "groupclientscope_group_id_client_scope_id" to table: "group_client_scopes"
CREATE UNIQUE INDEX "groupclientscope_group_id_client_scope_id" ON "group_client_scopes" ("group_id", "client_scope_id");
-- Create "permissions" table
CREATE TABLE "permissions" (
  "id" character varying NOT NULL,
  "name" character varying NOT NULL,
  "description" character varying NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "status" character varying NOT NULL DEFAULT 'active',
  "resource" character varying NOT NULL,
  "action" character varying NOT NULL,
  "scope" character varying NOT NULL,
  "constraints" jsonb NULL,
  "realm_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "permissions_realms_permissions" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT
);
-- Create index "permission_realm_id_name" to table: "permissions"
CREATE UNIQUE INDEX "permission_realm_id_name" ON "permissions" ("realm_id", "name");
-- Create "group_permissions" table
CREATE TABLE "group_permissions" (
  "group_id" character varying NOT NULL,
  "permission_id" character varying NOT NULL,
  PRIMARY KEY ("group_id", "permission_id"),
  CONSTRAINT "group_permissions_group_id" FOREIGN KEY ("group_id") REFERENCES "groups" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "group_permissions_permission_id" FOREIGN KEY ("permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create "instance_settings" table
CREATE TABLE "instance_settings" (
  "id" character varying NOT NULL,
  "managed_by" character varying NOT NULL DEFAULT 'ui',
  "min_password_length" bigint NOT NULL DEFAULT 12,
  "password_expiry_days" bigint NOT NULL DEFAULT 90,
  "session_idle_minutes" bigint NOT NULL DEFAULT 30,
  "session_max_hours" bigint NOT NULL DEFAULT 12,
  "lockout_threshold" bigint NOT NULL DEFAULT 5,
  "lockout_duration_minutes" bigint NOT NULL DEFAULT 15,
  "ip_allowlist" jsonb NULL,
  "mfa_required_globally" boolean NOT NULL DEFAULT false,
  "notification_email_enabled" boolean NOT NULL DEFAULT false,
  "updated_at" timestamptz NOT NULL,
  "updated_by" character varying NULL,
  "realm_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "instance_settings_realms_instance_settings" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT
);
-- Create index "instance_settings_realm_id_key" to table: "instance_settings"
CREATE UNIQUE INDEX "instance_settings_realm_id_key" ON "instance_settings" ("realm_id");
-- Create "signing_keys" table
CREATE TABLE "signing_keys" (
  "id" character varying NOT NULL,
  "key_type" character varying NOT NULL,
  "purpose" character varying NOT NULL,
  "kms_key_reference" character varying NOT NULL,
  "kms_backend" character varying NOT NULL,
  "public_key" text NULL,
  "kid" character varying NOT NULL,
  "status" character varying NOT NULL DEFAULT 'active',
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "retired_at" timestamptz NULL,
  "realm_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "signing_keys_realms_signing_keys" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT
);
-- Create index "signing_keys_kid_key" to table: "signing_keys"
CREATE UNIQUE INDEX "signing_keys_kid_key" ON "signing_keys" ("kid");
-- Create "key_rotation_logs" table
CREATE TABLE "key_rotation_logs" (
  "id" character varying NOT NULL,
  "action" character varying NOT NULL,
  "triggered_by" character varying NOT NULL,
  "reason" character varying NULL,
  "created_at" timestamptz NOT NULL,
  "signing_key_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "key_rotation_logs_signing_keys_rotation_logs" FOREIGN KEY ("signing_key_id") REFERENCES "signing_keys" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT
);
-- Create "mfa_backup_codes" table
CREATE TABLE "mfa_backup_codes" (
  "id" character varying NOT NULL,
  "batch_id" character varying NOT NULL,
  "code_hash" character varying NOT NULL,
  "used" boolean NOT NULL DEFAULT false,
  "used_at" timestamptz NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "user_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "mfa_backup_codes_users_mfa_backup_codes" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "mfabackupcode_code_hash" to table: "mfa_backup_codes"
CREATE INDEX "mfabackupcode_code_hash" ON "mfa_backup_codes" ("code_hash");
-- Create index "mfabackupcode_user_id_batch_id" to table: "mfa_backup_codes"
CREATE INDEX "mfabackupcode_user_id_batch_id" ON "mfa_backup_codes" ("user_id", "batch_id");
-- Create "mfa_methods" table
CREATE TABLE "mfa_methods" (
  "id" character varying NOT NULL,
  "type" character varying NOT NULL,
  "secret_encrypted" text NULL,
  "credential_id" character varying NULL,
  "public_key" text NULL,
  "is_discoverable" boolean NOT NULL DEFAULT false,
  "status" character varying NOT NULL DEFAULT 'active',
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "last_used_at" timestamptz NULL,
  "user_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "mfa_methods_users_mfa_methods" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "mfamethod_user_id_type" to table: "mfa_methods"
CREATE INDEX "mfamethod_user_id_type" ON "mfa_methods" ("user_id", "type");
-- Create "password_reset_tokens" table
CREATE TABLE "password_reset_tokens" (
  "id" character varying NOT NULL,
  "token_hash" character varying NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "used" boolean NOT NULL DEFAULT false,
  "used_at" timestamptz NULL,
  "requested_ip" character varying NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "user_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "password_reset_tokens_users_password_reset_tokens" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "password_reset_tokens_token_hash_key" to table: "password_reset_tokens"
CREATE UNIQUE INDEX "password_reset_tokens_token_hash_key" ON "password_reset_tokens" ("token_hash");
-- Create "role_client_scopes" table
CREATE TABLE "role_client_scopes" (
  "id" character varying NOT NULL,
  "granted_at" timestamptz NOT NULL,
  "role_id" character varying NOT NULL,
  "client_scope_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "role_client_scopes_client_scopes_client_scope" FOREIGN KEY ("client_scope_id") REFERENCES "client_scopes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "role_client_scopes_roles_role" FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "roleclientscope_role_id_client_scope_id" to table: "role_client_scopes"
CREATE UNIQUE INDEX "roleclientscope_role_id_client_scope_id" ON "role_client_scopes" ("role_id", "client_scope_id");
-- Create "role_permissions" table
CREATE TABLE "role_permissions" (
  "role_id" character varying NOT NULL,
  "permission_id" character varying NOT NULL,
  PRIMARY KEY ("role_id", "permission_id"),
  CONSTRAINT "role_permissions_permission_id" FOREIGN KEY ("permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "role_permissions_role_id" FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create "sessions" table
CREATE TABLE "sessions" (
  "id" character varying NOT NULL,
  "created_at" timestamptz NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "last_activity_at" timestamptz NOT NULL,
  "ip_address" character varying NULL,
  "user_agent" character varying NULL,
  "device_fingerprint" character varying NULL,
  "mfa_verified" boolean NOT NULL DEFAULT false,
  "mfa_method_type" character varying NULL,
  "auth_method" character varying NOT NULL DEFAULT 'password',
  "status" character varying NOT NULL DEFAULT 'active',
  "revoked_reason" character varying NULL,
  "realm_id" character varying NOT NULL,
  "user_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "sessions_realms_sessions" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT,
  CONSTRAINT "sessions_users_sessions" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "session_user_id_status" to table: "sessions"
CREATE INDEX "session_user_id_status" ON "sessions" ("user_id", "status");
-- Create "timeouts" table
CREATE TABLE "timeouts" (
  "id" character varying NOT NULL,
  "target_type" character varying NOT NULL,
  "target_id" character varying NOT NULL,
  "starts_at" timestamptz NOT NULL,
  "ends_at" timestamptz NULL,
  "reason" character varying NOT NULL,
  "created_by" character varying NOT NULL,
  "created_at" timestamptz NOT NULL,
  "realm_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "timeouts_realms_timeouts" FOREIGN KEY ("realm_id") REFERENCES "realms" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT
);
-- Create index "timeout_target_type_target_id_ends_at" to table: "timeouts"
CREATE INDEX "timeout_target_type_target_id_ends_at" ON "timeouts" ("target_type", "target_id", "ends_at");
-- Create "tokens" table
CREATE TABLE "tokens" (
  "id" character varying NOT NULL,
  "type" character varying NOT NULL,
  "jti" character varying NOT NULL,
  "issued_at" timestamptz NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "revoked" boolean NOT NULL DEFAULT false,
  "scopes" jsonb NULL,
  "client_ref_id" character varying NOT NULL,
  "session_id" character varying NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "tokens_client_apps_tokens" FOREIGN KEY ("client_ref_id") REFERENCES "client_apps" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "tokens_sessions_tokens" FOREIGN KEY ("session_id") REFERENCES "sessions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "token_session_id_revoked" to table: "tokens"
CREATE INDEX "token_session_id_revoked" ON "tokens" ("session_id", "revoked");
-- Create index "tokens_jti_key" to table: "tokens"
CREATE UNIQUE INDEX "tokens_jti_key" ON "tokens" ("jti");
-- Create "user_groups" table
CREATE TABLE "user_groups" (
  "user_id" character varying NOT NULL,
  "group_id" character varying NOT NULL,
  PRIMARY KEY ("user_id", "group_id"),
  CONSTRAINT "user_groups_group_id" FOREIGN KEY ("group_id") REFERENCES "groups" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "user_groups_user_id" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create "user_roles" table
CREATE TABLE "user_roles" (
  "user_id" character varying NOT NULL,
  "role_id" character varying NOT NULL,
  PRIMARY KEY ("user_id", "role_id"),
  CONSTRAINT "user_roles_role_id" FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "user_roles_user_id" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
