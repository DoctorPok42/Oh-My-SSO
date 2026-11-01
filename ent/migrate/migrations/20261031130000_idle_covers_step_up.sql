-- An idle session must last at least the MFA step-up window, or the admin
-- console asks to sign in again before the window ends.
UPDATE "instance_settings" SET "session_idle_minutes" = "mfa_step_up_max_age_minutes" WHERE "session_idle_minutes" < "mfa_step_up_max_age_minutes";
