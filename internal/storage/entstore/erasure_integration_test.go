package entstore_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/loginattempt"
	entschema "sso.internal/sso/ent/schema"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/storage/entstore"
)

// What still names an account once it is deleted (GDPR article 17), and
// what must not be touched: other people's data, and what happened.
func TestErasureRepository_Integration(t *testing.T) {
	f := newRBACFixture(t)
	c := f.client
	repo := entstore.NewErasureRepository(c)
	other := &rbacFixture{t: t, ctx: f.ctx, client: c, realm: newTestRealm(t, f.ctx, c)}

	dana, bob := f.user(), f.user()
	twin := other.user() // another realm, another person
	_, err := c.User.UpdateOneID(twin.ID).SetUsername(dana.Username).Save(f.ctx)
	require.NoError(t, err)
	admin := other.user()

	// --- scheduling ------------------------------------------------------------
	now := time.Now().UTC().Truncate(time.Microsecond)
	at := now.Add(-time.Minute)
	require.NoError(t, repo.ScheduleDeletion(f.ctx, dana.ID, &at))
	due, err := repo.DeletionDue(f.ctx, now, 10)
	require.NoError(t, err)
	require.Len(t, due, 1)
	require.Equal(t, dana.ID, due[0].ID)
	require.NotNil(t, due[0].DeletionScheduledAt)
	require.NoError(t, repo.ScheduleDeletion(f.ctx, dana.ID, nil))
	due, err = repo.DeletionDue(f.ctx, now, 10)
	require.NoError(t, err)
	require.Empty(t, due, "cancelled")
	require.ErrorIs(t, repo.ScheduleDeletion(f.ctx, "no-such-user", &at), repository.ErrNotFound)

	// --- traces ----------------------------------------------------------------
	attempt := func(realmID, userID, identifier string) *ent.LoginAttempt {
		a, err := c.LoginAttempt.Create().SetRealmID(realmID).SetIdentifier(identifier).SetIPAddress("198.51.100.7").
			SetStatus(entschema.LoginAttemptFailure).SetNillableUserID(nilIfEmpty(userID)).Save(f.ctx)
		require.NoError(t, err)
		return a
	}
	attempt(f.realm.ID, dana.ID, dana.Username)
	attempt(f.realm.ID, "", "DANA-typo@"+dana.Email)     // not her name
	attempt(f.realm.ID, "", strings.ToUpper(dana.Email)) // her address, typed in capitals, before the account was found
	keepBob := attempt(f.realm.ID, bob.ID, bob.Username)
	keepTwin := attempt(other.realm.ID, twin.ID, twin.Username)

	entry := func(realmID, userID, target string, actor entschema.AuditLogActorType, details map[string]interface{}) *ent.AuditLog {
		b := c.AuditLog.Create().SetRealmID(realmID).SetAction("test.action").SetActorType(actor).
			SetIPAddress("203.0.113.9").SetUserAgent("Firefox").SetDetails(details)
		if userID != "" {
			b.SetUserID(userID)
		}
		if target != "" {
			b.SetTargetUserID(target)
		}
		e, err := b.Save(f.ctx)
		require.NoError(t, err)
		return e
	}
	byDana := entry(f.realm.ID, dana.ID, dana.ID, entschema.AuditActorUser, map[string]interface{}{"locale": "fr"})
	failedSignIn := entry(f.realm.ID, "", dana.ID, entschema.AuditActorAnonymous, map[string]interface{}{"identifier": dana.Username})
	byAdmin := entry(f.realm.ID, admin.ID, dana.ID, entschema.AuditActorAdmin, map[string]interface{}{
		"admin_username": admin.Username, "username": dana.Username, "email": dana.Email, "note": "about " + strings.ToUpper(dana.Email),
	})
	imported := entry(f.realm.ID, admin.ID, "", entschema.AuditActorAdmin, map[string]interface{}{
		"created_users": []interface{}{
			map[string]interface{}{"username": dana.Username, "email": dana.Email},
			map[string]interface{}{"username": bob.Username, "email": bob.Email},
		},
		"items": []interface{}{map[string]interface{}{"id": dana.ID, "label": "Dana S."}},
		"role":  dana.Username, // a word equal to her name, not about her
	})
	twinEntry := entry(other.realm.ID, twin.ID, twin.ID, entschema.AuditActorUser, map[string]interface{}{"username": twin.Username})
	// Addresses she had or asked for: nothing in them says it is her, but
	// the entries are about her (an e-mail change).
	toOldAddress := entry(f.realm.ID, "", dana.ID, entschema.AuditActorSystem, map[string]interface{}{"kind": "email_changed", "to": "dana.old@example.test"})
	askedFor := entry(f.realm.ID, dana.ID, dana.ID, entschema.AuditActorUser, map[string]interface{}{"email": "dana.never@example.test"})
	// A name she had (renamed since), by an administrator who keeps his.
	formerName := entry(f.realm.ID, admin.ID, dana.ID, entschema.AuditActorAdmin, map[string]interface{}{
		"username": "dana.former", "admin_username": admin.Username,
	})
	// An import listed her under her first name and address, with her id.
	importedFirst := entry(f.realm.ID, admin.ID, "", entschema.AuditActorAdmin, map[string]interface{}{
		"created_users": []interface{}{
			map[string]interface{}{"id": dana.ID, "username": "dana.former", "email": "dana.first@example.test"},
			map[string]interface{}{"id": bob.ID, "username": bob.Username, "email": bob.Email},
		},
	})

	bulk, err := c.BulkJob.Create().SetRealmID(f.realm.ID).SetAction("users.suspend").SetOperationID("op-1").
		SetStatus(entschema.BulkJobCompleted).SetRequestedBy(admin.ID).SetRequestedByName(admin.Username).
		SetRequestedByRealm(other.realm.ID).SetIds([]string{dana.ID, bob.ID}).SetTotal(2).
		SetItems([]entschema.BulkJobItem{{ID: dana.ID, Label: dana.Username, Status: "done"}, {ID: bob.ID, Label: bob.Username, Status: "done"}}).
		Save(f.ctx)
	require.NoError(t, err)
	imp, err := c.UserImportJob.Create().SetRealmID(f.realm.ID).SetStatus(entschema.UserImportCompleted).
		SetRequestedBy(admin.ID).SetRequestedByName(admin.Username).SetRequestedByRealm(other.realm.ID).SetTotal(2).
		SetRows([]entschema.UserImportRow{
			{Line: 2, Email: dana.Email, Username: dana.Username, Status: "created", UserID: dana.ID},
			{Line: 3, Email: bob.Email, Username: bob.Username, Status: "created", UserID: bob.ID},
		}).Save(f.ctx)
	require.NoError(t, err)

	// Her deletion was cancelled (above): the hourly pass changes nothing,
	// in one transaction, traces included.
	dueBy := time.Now()
	erased, err := repo.EraseAccount(f.ctx, dana, &dueBy)
	require.NoError(t, err)
	require.False(t, erased, "no longer due")
	kept, err := c.AuditLog.Get(f.ctx, byDana.ID)
	require.NoError(t, err)
	require.Equal(t, "203.0.113.9", kept.IPAddress, "her traces are untouched")

	erased, err = repo.EraseAccount(f.ctx, dana, nil) // an administrator, now
	require.NoError(t, err)
	require.True(t, erased)
	_, err = c.User.Get(f.ctx, dana.ID)
	require.True(t, ent.IsNotFound(err), "the account is gone with its traces")
	erased, err = repo.EraseAccount(f.ctx, dana, nil)
	require.NoError(t, err)
	require.False(t, erased, "already gone: another server was first")
	require.ErrorIs(t, entstore.NewUserRepository(c).Delete(f.ctx, dana.ID), repository.ErrNotFound)

	attempts, err := c.LoginAttempt.Query().Where(loginattempt.RealmIDIn(f.realm.ID, other.realm.ID)).All(f.ctx)
	require.NoError(t, err)
	ids := []string{}
	for _, a := range attempts {
		ids = append(ids, a.ID)
	}
	require.Len(t, attempts, 3, "hers are gone, by account and by name typed")
	require.Contains(t, ids, keepBob.ID)
	require.Contains(t, ids, keepTwin.ID)

	get := func(e *ent.AuditLog) *ent.AuditLog {
		got, err := c.AuditLog.Get(f.ctx, e.ID)
		require.NoError(t, err)
		return got
	}
	got := get(byDana)
	require.Empty(t, got.IPAddress, "her address")
	require.Empty(t, got.UserAgent)
	require.Equal(t, dana.ID, got.UserID, "the id stays: what happened stays visible")
	require.Equal(t, "test.action", got.Action)
	require.Equal(t, "fr", got.Details["locale"])

	got = get(failedSignIn)
	require.Empty(t, got.IPAddress, "a sign-in with her name: her address, or an attacker's")
	require.Equal(t, repository.Erased, got.Details["identifier"])

	got = get(byAdmin)
	require.Equal(t, "203.0.113.9", got.IPAddress, "the administrator's address is the administrator's")
	require.Equal(t, admin.Username, got.Details["admin_username"])
	require.Equal(t, repository.Erased, got.Details["username"])
	require.Equal(t, repository.Erased, got.Details["email"])
	require.Equal(t, "about "+repository.Erased, got.Details["note"])

	got = get(imported)
	users := got.Details["created_users"].([]interface{})
	require.Equal(t, map[string]interface{}{"username": repository.Erased, "email": repository.Erased}, users[0])
	require.Equal(t, map[string]interface{}{"username": bob.Username, "email": bob.Email}, users[1], "bob stays")
	items := got.Details["items"].([]interface{})
	require.Equal(t, repository.Erased, items[0].(map[string]interface{})["label"])
	require.Equal(t, dana.Username, got.Details["role"], "not her: a word that happens to be her name")

	got = get(twinEntry)
	require.Equal(t, "203.0.113.9", got.IPAddress, "another realm's account with the same name is someone else")
	require.Equal(t, twin.Username, got.Details["username"])

	got = get(toOldAddress)
	require.Equal(t, repository.Erased, got.Details["to"], "an address she no longer had")
	require.Equal(t, "email_changed", got.Details["kind"])
	require.Equal(t, repository.Erased, get(askedFor).Details["email"], "an address she asked for")

	got = get(formerName)
	require.Equal(t, repository.Erased, got.Details["username"], "a name she no longer had")
	require.Equal(t, admin.Username, got.Details["admin_username"], "the administrator's stays")
	listed := get(importedFirst).Details["created_users"].([]interface{})
	require.Equal(t, map[string]interface{}{"id": dana.ID, "username": repository.Erased, "email": repository.Erased}, listed[0])
	require.Equal(t, map[string]interface{}{"id": bob.ID, "username": bob.Username, "email": bob.Email}, listed[1], "bob stays")

	b, err := c.BulkJob.Get(f.ctx, bulk.ID)
	require.NoError(t, err)
	require.Equal(t, repository.Erased, b.Items[0].Label)
	require.Equal(t, bob.Username, b.Items[1].Label)
	require.Equal(t, admin.Username, b.RequestedByName)
	i, err := c.UserImportJob.Get(f.ctx, imp.ID)
	require.NoError(t, err)
	require.Equal(t, repository.Erased, i.Rows[0].Email)
	require.Equal(t, repository.Erased, i.Rows[0].Username)
	require.Equal(t, bob.Email, i.Rows[1].Email)

	// An administrator deleted in turn: their name goes from the jobs they ran.
	erased, err = repo.EraseAccount(f.ctx, admin, nil)
	require.NoError(t, err)
	require.True(t, erased)
	b, err = c.BulkJob.Get(f.ctx, bulk.ID)
	require.NoError(t, err)
	require.Equal(t, repository.Erased, b.RequestedByName)
	// What he wrote about nobody keeps the accounts he listed.
	listed = get(importedFirst).Details["created_users"].([]interface{})
	require.Equal(t, bob.Username, listed[1].(map[string]interface{})["username"], "bob stays")
	got = get(byAdmin)
	require.Equal(t, repository.Erased, got.Details["admin_username"])
	require.Empty(t, got.IPAddress, "what they did, from their browser")
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
