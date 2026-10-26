package httpserver_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/ent"
	valkeycache "sso.internal/sso/internal/cache/valkey"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/httpserver"
	"sso.internal/sso/internal/notify"
	"sso.internal/sso/internal/storage/entstore"
)


type captureSender struct {
	mu   sync.Mutex
	sent []capturedMail
}

type capturedMail struct {
	to   string
	tmpl notify.Template
	data notify.Data
}

func (c *captureSender) Send(_ context.Context, to string, tmpl notify.Template, data notify.Data) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, capturedMail{to, tmpl, data})
	return nil
}

func (c *captureSender) mails(tmpl notify.Template) []capturedMail {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []capturedMail
	for _, m := range c.sent {
		if m.tmpl == tmpl {
			out = append(out, m)
		}
	}
	return out
}

// waitMails waits until n e-mails of this template were sent (the reset
// request and the dispatcher both run in the background).
func (c *captureSender) waitMails(t *testing.T, tmpl notify.Template, n int) []capturedMail {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.mails(tmpl); len(got) >= n {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout: wanted %d %s e-mail(s), got %d", n, tmpl, len(c.mails(tmpl)))
	return nil
}

type resetEnv struct {
	ts     *httptest.Server
	realms repository.RealmRepository
	users  repository.UserRepository
	audit  repository.AuditLogRepository
	mail   *captureSender
	clock  *fakeClock
}

func setupResetEnv(t *testing.T) *resetEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}
	ctx := context.Background()

	db, err := sql.Open("pgx", startTestPostgres(t, ctx))
	require.NoError(t, err)
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Schema.Create(ctx))

	valkeyClient, err := valkeycache.New(startTestValkey(t, ctx))
	require.NoError(t, err)
	t.Cleanup(valkeyClient.Close)

	clock := &fakeClock{}
	realms := entstore.NewRealmRepository(client)
	users := entstore.NewUserRepository(client)
	settings := entstore.NewInstanceSettingsRepository(client)
	audit := entstore.NewAuditLogRepository(client)
	mail := &captureSender{}

	dispatcher := notify.NewDispatcher(notify.DispatcherConfig{PublicURL: "https://sso.example.com"}, notify.DispatcherDeps{
		Sender: mail, Users: users, Realms: realms, Settings: settings, Audit: audit,
	})
	dispatcher.Start()
	t.Cleanup(func() { dispatcher.Close(context.Background()) })

	lockout := service.NewLockoutService(service.LockoutDeps{
		Users: users, Unknown: valkeycache.NewLockoutStore(valkeyClient), Settings: settings, Notifier: dispatcher, Audit: audit,
	})
	auth := service.NewAuthService(users, entstore.NewLoginAttemptRepository(client), service.WithLockout(lockout))
	sessions := service.NewSessionService(entstore.NewSessionRepository(client), settings,
		entstore.NewTokenRepository(client), valkeycache.NewSessionCache(valkeyClient), service.WithClock(clock.Now))
	reset := service.NewPasswordResetService(service.PasswordResetDeps{
		Users: users, Tokens: entstore.NewPasswordResetTokenRepository(client), Sessions: sessions,
		Settings: settings, Lockout: lockout, Notifier: dispatcher, Audit: audit, Now: clock.Now,
	})
	srv := httpserver.New(auth, sessions,
		service.NewRBACService(entstore.NewAccessRepository(client), audit),
		realms, entstore.NewClientRepository(client), valkeycache.NewRateLimiter(valkeyClient),
		httpserver.WithPasswordReset(reset), httpserver.WithForgotPassword(true),
	)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)
	return &resetEnv{ts: ts, realms: realms, users: users, audit: audit, mail: mail, clock: clock}
}

func (e *resetEnv) post(t *testing.T, path string, body any, cookies ...*http.Cookie) (int, map[string]any, []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+path, bytes.NewReader(b))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, raw
}

func (e *resetEnv) login(t *testing.T, realm, user, password string) (int, *http.Cookie) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"identifier": user, "password": password})
	resp, err := http.Post(e.ts.URL+"/r/"+realm+"/auth/login", "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == httpserver.SessionCookieName {
			return resp.StatusCode, c
		}
	}
	return resp.StatusCode, nil
}

func tokenFrom(t *testing.T, m capturedMail) string {
	t.Helper()
	i := strings.Index(m.data.ResetURL, "#token=")
	require.True(t, i > 0, "the token is in the URL fragment: %s", m.data.ResetURL)
	return m.data.ResetURL[i+len("#token="):]
}

func TestPasswordReset_Integration(t *testing.T) {
	env := setupResetEnv(t)
	ctx := context.Background()
	realm, err := env.realms.Create(ctx, repository.CreateRealmParams{Name: "reset", DisplayName: "Reset Inc"})
	require.NoError(t, err)
	hash, err := service.HashPassword("the old password")
	require.NoError(t, err)
	user, err := env.users.Create(ctx, repository.CreateUserParams{
		RealmID: realm.ID, Username: "erin", Email: "erin@example.test", PasswordHash: hash, Status: domain.UserActive,
	})
	require.NoError(t, err)
	base := "/r/" + realm.Name + "/auth"

	t.Run("same answer for an existing and an unknown e-mail", func(t *testing.T) {
		st1, _, body1 := env.post(t, base+"/forgot-password", map[string]string{"identifier": "erin@example.test"})
		st2, _, body2 := env.post(t, base+"/forgot-password", map[string]string{"identifier": "nobody@example.test"})
		require.Equal(t, http.StatusAccepted, st1)
		require.Equal(t, st1, st2)
		require.Equal(t, string(body1), string(body2), "byte for byte")

		mails := env.mail.waitMails(t, notify.TemplatePasswordReset, 1)
		time.Sleep(200 * time.Millisecond) // the unknown e-mail would have had time to go too
		require.Len(t, env.mail.mails(notify.TemplatePasswordReset), 1, "only the real account gets an e-mail")
		require.Equal(t, "erin@example.test", mails[0].to)
	})

	t.Run("valid token: new password, all sessions revoked, notification audited", func(t *testing.T) {
		status, sessionCookie := env.login(t, realm.Name, "erin", "the old password")
		require.Equal(t, http.StatusOK, status)
		require.NotNil(t, sessionCookie)

		token := tokenFrom(t, env.mail.mails(notify.TemplatePasswordReset)[0])

		// The page itself never contains the token (it stays in the fragment).
		resp, err := http.Get(env.ts.URL + base + "/reset-password")
		require.NoError(t, err)
		page, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Contains(t, string(page), "Choose a new password")
		require.Contains(t, resp.Header.Get("Content-Security-Policy"), "default-src 'none'")

		st, body, _ := env.post(t, base+"/reset-password", map[string]string{"token": token, "password": "a brand new passphrase"})
		require.Equal(t, http.StatusOK, st, "%v", body)

		// The session opened before the reset is dead.
		req, _ := http.NewRequest(http.MethodGet, env.ts.URL+base+"/session", nil)
		req.AddCookie(sessionCookie)
		resp, err = http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		status, _ = env.login(t, realm.Name, "erin", "the old password")
		require.Equal(t, http.StatusUnauthorized, status)
		status, _ = env.login(t, realm.Name, "erin", "a brand new passphrase")
		require.Equal(t, http.StatusOK, status)

		// "Password changed" e-mail, and an AuditLog entry per e-mail sent.
		env.mail.waitMails(t, notify.TemplatePasswordChanged, 1)
		require.Eventually(t, func() bool {
			logs, err := env.audit.ListByUser(ctx, user.ID)
			if err != nil {
				return false
			}
			n := 0
			for _, l := range logs {
				if l.Action == "notification_sent" && l.Status == domain.AuditLogSuccess {
					n++
				}
			}
			return n >= 2 // password_reset + password_changed
		}, 10*time.Second, 50*time.Millisecond)
	})

	t.Run("token already used", func(t *testing.T) {
		token := tokenFrom(t, env.mail.mails(notify.TemplatePasswordReset)[0])
		st, body, _ := env.post(t, base+"/reset-password", map[string]string{"token": token, "password": "yet another passphrase"})
		require.Equal(t, http.StatusBadRequest, st)
		require.Equal(t, "invalid_or_expired_token", body["error"])
	})

	t.Run("expired token", func(t *testing.T) {
		st, _, _ := env.post(t, base+"/forgot-password", map[string]string{"identifier": "erin"})
		require.Equal(t, http.StatusAccepted, st)
		mails := env.mail.waitMails(t, notify.TemplatePasswordReset, 2)
		token := tokenFrom(t, mails[1])

		env.clock.Advance(31 * time.Minute)
		defer env.clock.Reset()
		st, body, _ := env.post(t, base+"/reset-password", map[string]string{"token": token, "password": "a fresh new passphrase"})
		require.Equal(t, http.StatusBadRequest, st)
		require.Equal(t, "invalid_or_expired_token", body["error"])
	})

	t.Run("password policy", func(t *testing.T) {
		st, _, _ := env.post(t, base+"/forgot-password", map[string]string{"identifier": "erin"})
		require.Equal(t, http.StatusAccepted, st)
		token := tokenFrom(t, env.mail.waitMails(t, notify.TemplatePasswordReset, 3)[2])

		st, body, _ := env.post(t, base+"/reset-password", map[string]string{"token": token, "password": "short"})
		require.Equal(t, http.StatusBadRequest, st)
		require.Equal(t, "password_too_short", body["error"])
		require.EqualValues(t, 12, body["min_length"])
	})

	t.Run("JSON only (CSRF)", func(t *testing.T) {
		resp, err := http.Post(env.ts.URL+base+"/forgot-password", "application/x-www-form-urlencoded", strings.NewReader("identifier=erin"))
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
	})
}
