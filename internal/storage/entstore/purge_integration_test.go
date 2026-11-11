package entstore_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/auditlog"
	"sso.internal/sso/ent/knownaccount"
	"sso.internal/sso/ent/loginattempt"
	"sso.internal/sso/ent/passwordresettoken"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/ent/session"
	"sso.internal/sso/ent/token"
	"sso.internal/sso/ent/trusteddevice"
	"sso.internal/sso/internal/storage/entstore"
)

func TestPurgeRepository_Integration(t *testing.T) {
	f := newRBACFixture(t)
	c := f.client
	purge := entstore.NewPurgeRepository(c)
	before := time.Now().Add(-90 * 24 * time.Hour)
	old, recent := before.Add(-time.Hour), before.Add(time.Hour)

	other := &rbacFixture{t: t, ctx: f.ctx, client: c, realm: newTestRealm(t, f.ctx, c)}
	u, otherUser := f.user(), other.user()
	app := f.clientApp("purge")

	newSession := func(fx *rbacFixture, userID string, status entschema.SessionStatus, expires, lastActivity time.Time) *ent.Session {
		s, err := c.Session.Create().SetRealmID(fx.realm.ID).SetUserID(userID).SetTokenHash("h-" + f.suffix()).
			SetStatus(status).SetExpiresAt(expires).SetLastActivityAt(lastActivity).SetCreatedAt(lastActivity.Add(-time.Hour)).
			Save(f.ctx)
		require.NoError(t, err)
		return s
	}
	newToken := func(sessionID string, typ entschema.TokenType, expires time.Time, used bool) *ent.Token {
		b := c.Token.Create().SetSessionID(sessionID).SetClientRefID(app.ID).SetType(typ).SetJti("jti-" + f.suffix()).
			SetIssuedAt(expires.Add(-time.Hour)).SetExpiresAt(expires)
		if used {
			b.SetUsedAt(expires.Add(-time.Minute))
		}
		tok, err := b.Save(f.ctx)
		require.NoError(t, err)
		return tok
	}
	exists := func(n int, err error) bool {
		require.NoError(t, err)
		return n == 1
	}

	t.Run("sessions and tokens", func(t *testing.T) {
		expired := newSession(f, u.ID, entschema.SessionActive, old, old)
		revokedLongAgo := newSession(f, u.ID, entschema.SessionRevoked, recent, old)
		idle := newSession(f, u.ID, entschema.SessionActive, recent, old) // not ended yet
		revokedLately := newSession(f, u.ID, entschema.SessionRevoked, recent, recent)
		otherRealm := newSession(other, otherUser.ID, entschema.SessionActive, old, old)

		onExpired := newToken(expired.ID, entschema.TokenAccessToken, recent, false)
		expiredAccess := newToken(idle.ID, entschema.TokenAccessToken, old, false)
		usedRefreshActive := newToken(idle.ID, entschema.TokenRefreshToken, old, true)
		usedRefreshRevoked := newToken(revokedLately.ID, entschema.TokenRefreshToken, old, true)
		freshAccess := newToken(idle.ID, entschema.TokenAccessToken, recent, false)

		n, err := purge.DeleteExpiredTokens(f.ctx, f.realm.ID, before, 100)
		require.NoError(t, err)
		require.Equal(t, 2, n, "the expired access token and the used refresh token of a revoked session")
		n, err = purge.DeleteEndedSessions(f.ctx, f.realm.ID, before, 100)
		require.NoError(t, err)
		require.Equal(t, 2, n, "the expired session and the one revoked long ago")

		for _, gone := range []string{expired.ID, revokedLongAgo.ID} {
			require.False(t, exists(c.Session.Query().Where(session.ID(gone)).Count(f.ctx)), gone)
		}
		for _, kept := range []string{idle.ID, revokedLately.ID, otherRealm.ID} {
			require.True(t, exists(c.Session.Query().Where(session.ID(kept)).Count(f.ctx)), kept)
		}
		for _, gone := range []string{onExpired.ID, expiredAccess.ID, usedRefreshRevoked.ID} {
			require.False(t, exists(c.Token.Query().Where(token.ID(gone)).Count(f.ctx)), gone)
		}
		require.True(t, exists(c.Token.Query().Where(token.ID(usedRefreshActive.ID)).Count(f.ctx)),
			"a used refresh token of an active session stays: presenting it again is a replay")
		require.True(t, exists(c.Token.Query().Where(token.ID(freshAccess.ID)).Count(f.ctx)))
	})

	t.Run("reset and activation links", func(t *testing.T) {
		mk := func(userID string, expires, updated time.Time, used bool) string {
			l, err := c.PasswordResetToken.Create().SetUserID(userID).SetTokenHash("r-" + f.suffix()).
				SetExpiresAt(expires).SetUsed(used).SetCreatedAt(updated).SetUpdatedAt(updated).Save(f.ctx)
			require.NoError(t, err)
			return l.ID
		}
		expired := mk(u.ID, old, old, false)
		usedLongAgo := mk(u.ID, recent, old, true)
		pending := mk(u.ID, recent, old, false)
		otherRealm := mk(otherUser.ID, old, old, false)

		n, err := purge.DeleteEndedResetLinks(f.ctx, f.realm.ID, before, 100)
		require.NoError(t, err)
		require.Equal(t, 2, n)
		count := func(id string) bool {
			return exists(c.PasswordResetToken.Query().Where(passwordresettoken.ID(id)).Count(f.ctx))
		}
		require.False(t, count(expired))
		require.False(t, count(usedLongAgo))
		require.True(t, count(pending))
		require.True(t, count(otherRealm))
	})

	t.Run("sign-in attempts, in batches", func(t *testing.T) {
		mk := func(realmID string, at time.Time) string {
			b := c.LoginAttempt.Create().SetIdentifier("who").SetStatus(entschema.LoginAttemptFailure).SetCreatedAt(at)
			if realmID != "" {
				b.SetRealmID(realmID)
			}
			a, err := b.Save(f.ctx)
			require.NoError(t, err)
			return a.ID
		}
		olds := []string{mk(f.realm.ID, old), mk(f.realm.ID, old), mk(f.realm.ID, old)}
		kept := []string{mk(f.realm.ID, recent), mk(other.realm.ID, old), mk("", recent)}
		orphans := []string{mk("", old), mk("deleted-realm-"+f.suffix(), old)}

		n, err := purge.DeleteLoginAttempts(f.ctx, f.realm.ID, before, 2)
		require.NoError(t, err)
		require.Equal(t, 2, n, "at most limit rows per call")
		n, err = purge.DeleteLoginAttempts(f.ctx, f.realm.ID, before, 2)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		_, err = purge.DeleteLoginAttempts(f.ctx, "", before, 1000)
		require.NoError(t, err)

		count := func(id string) bool { return exists(c.LoginAttempt.Query().Where(loginattempt.ID(id)).Count(f.ctx)) }
		for _, id := range append(olds, orphans...) {
			require.False(t, count(id), id)
		}
		for _, id := range kept {
			require.True(t, count(id), id)
		}
	})

	t.Run("known accounts and trusted devices", func(t *testing.T) {
		known := func(at time.Time) string {
			k, err := c.KnownAccount.Create().SetRealmID(f.realm.ID).SetUserID(u.ID).SetDeviceHash("d-" + f.suffix()).
				SetCreatedAt(at).SetLastUsedAt(at).Save(f.ctx)
			require.NoError(t, err)
			return k.ID
		}
		trusted := func(expires time.Time) string {
			d, err := c.TrustedDevice.Create().SetRealmID(f.realm.ID).SetUserID(u.ID).SetDeviceHash("d-" + f.suffix()).
				SetCreatedAt(expires.Add(-30 * 24 * time.Hour)).SetExpiresAt(expires).Save(f.ctx)
			require.NoError(t, err)
			return d.ID
		}
		unusedKnown, usedKnown := known(old), known(recent)
		endedTrust, recentTrust := trusted(old), trusted(recent)

		n, err := purge.DeleteUnusedKnownAccounts(f.ctx, f.realm.ID, before, 100)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		n, err = purge.DeleteExpiredTrustedDevices(f.ctx, f.realm.ID, before, 100)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		require.False(t, exists(c.KnownAccount.Query().Where(knownaccount.ID(unusedKnown)).Count(f.ctx)))
		require.True(t, exists(c.KnownAccount.Query().Where(knownaccount.ID(usedKnown)).Count(f.ctx)))
		require.False(t, exists(c.TrustedDevice.Query().Where(trusteddevice.ID(endedTrust)).Count(f.ctx)))
		require.True(t, exists(c.TrustedDevice.Query().Where(trusteddevice.ID(recentTrust)).Count(f.ctx)))
	})

	t.Run("audit log, in batches", func(t *testing.T) {
		mk := func(realmID string, at time.Time) string {
			e, err := c.AuditLog.Create().SetRealmID(realmID).SetAction("auth.login").SetTimestamp(at).Save(f.ctx)
			require.NoError(t, err)
			return e.ID
		}
		olds := []string{mk(f.realm.ID, old), mk(f.realm.ID, old), mk(f.realm.ID, old)}
		kept := []string{mk(f.realm.ID, recent), mk(other.realm.ID, old)}

		n, err := purge.DeleteAuditLogs(f.ctx, f.realm.ID, before, 2)
		require.NoError(t, err)
		require.Equal(t, 2, n, "at most limit rows per call")
		n, err = purge.DeleteAuditLogs(f.ctx, f.realm.ID, before, 2)
		require.NoError(t, err)
		require.Equal(t, 1, n)

		count := func(id string) bool { return exists(c.AuditLog.Query().Where(auditlog.ID(id)).Count(f.ctx)) }
		for _, id := range olds {
			require.False(t, count(id), id)
		}
		for _, id := range kept {
			require.True(t, count(id), "a recent entry, and an old one of another realm, stay: %s", id)
		}
	})

	t.Run("rows another server holds are skipped, not waited for", func(t *testing.T) {
		mk := func() string {
			a, err := c.LoginAttempt.Create().SetIdentifier("locked").SetRealmID(f.realm.ID).
				SetStatus(entschema.LoginAttemptFailure).SetCreatedAt(old).Save(f.ctx)
			require.NoError(t, err)
			return a.ID
		}
		held, free := mk(), mk()

		db, err := sql.Open("pgx", testDSN)
		require.NoError(t, err)
		defer db.Close()
		tx, err := db.BeginTx(f.ctx, nil)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback() }()
		_, err = tx.ExecContext(f.ctx, `SELECT id FROM login_attempts WHERE id = $1 FOR UPDATE`, held)
		require.NoError(t, err)

		start := time.Now()
		n, err := purge.DeleteLoginAttempts(f.ctx, f.realm.ID, before, 100)
		require.NoError(t, err)
		require.Equal(t, 1, n, "only the free row")
		require.Less(t, time.Since(start), 5*time.Second)
		require.False(t, exists(c.LoginAttempt.Query().Where(loginattempt.ID(free)).Count(f.ctx)))

		require.NoError(t, tx.Rollback())
		n, err = purge.DeleteLoginAttempts(f.ctx, f.realm.ID, before, 100)
		require.NoError(t, err)
		require.Equal(t, 1, n, "the next pass takes it")
	})

}
