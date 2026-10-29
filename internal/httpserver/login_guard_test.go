package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/clientip"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/ratelimit"
)

// denyingLimiter refuses every request and remembers the keys it was asked
// about: POST /auth/login stops at the per-IP limit (429), before anything
// that would need a database, and the test can read which IP was counted.
type denyingLimiter struct{ keys []string }

func (l *denyingLimiter) Allow(_ context.Context, key string, _ int64, _ time.Duration) (bool, error) {
	l.keys = append(l.keys, key)
	return false, nil
}

func newLoginGuardServer(lim ratelimit.Limiter, opts ...Option) *Server {
	realm := &domain.Realm{ID: "realm-1", Name: "acme", Status: domain.RealmActive}
	return New(nil, nil, nil, &fakeRealmByName{realm: realm}, nil, lim, opts...)
}

func postLogin(s *Server, contentType, body string, tweak func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/r/acme/auth/login", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.RemoteAddr = "203.0.113.9:4321"
	if tweak != nil {
		tweak(req)
	}
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	return rec
}

const validLoginBody = `{"identifier":"alice","password":"correct-horse-battery-staple"}`

// Login CSRF: a foreign page can only send a "simple" cross-site request
// (form or text/plain), never Content-Type: application/json.
func TestLogin_RequiresJSON(t *testing.T) {
	lim := &denyingLimiter{}
	s := newLoginGuardServer(lim)

	// What <form enctype="text/plain"> on an attacker's page would send.
	forged := `{"identifier":"attacker","password":"x","pad":"="}`
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"} {
		rec := postLogin(s, ct, forged, nil)
		require.Equal(t, http.StatusUnsupportedMediaType, rec.Code, ct)
	}
	require.Empty(t, lim.keys, "refused before any work")

	rec := postLogin(s, "application/json", validLoginBody, nil)
	require.Equal(t, http.StatusTooManyRequests, rec.Code, "a JSON request goes through to the rate limit")
}

func TestLogin_RefusesHugeBodiesAndPasswords(t *testing.T) {
	lim := &denyingLimiter{}
	s := newLoginGuardServer(lim)

	huge := `{"identifier":"alice","password":"` + strings.Repeat("a", 64<<10) + `"}`
	rec := postLogin(s, "application/json", huge, nil)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	tooLong := `{"identifier":"alice","password":"` + strings.Repeat("a", maxPasswordLen+1) + `"}`
	require.Less(t, len(tooLong), maxLoginRequestBodySize, "fits in the body limit: the length check is what refuses it")
	rec = postLogin(s, "application/json", tooLong, nil)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	require.Empty(t, lim.keys, "refused before any work")
}

// The per-IP rate limit counts the TCP peer: a client cannot pick its own
// address with X-Forwarded-For (it could with chi's middleware.RealIP).
func TestLogin_RateLimitKeyIgnoresForgedHeaders(t *testing.T) {
	lim := &denyingLimiter{}
	s := newLoginGuardServer(lim)

	rec := postLogin(s, "application/json", validLoginBody, func(r *http.Request) {
		r.Header.Set("X-Forwarded-For", "1.2.3.4")
		r.Header.Set("X-Real-IP", "5.6.7.8")
		r.Header.Set("True-Client-IP", "9.9.9.9")
	})
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Equal(t, []string{ratelimit.Key(routeAuthLogin, "realm-1", "ip", "203.0.113.9")}, lim.keys)
}

func TestLogin_RateLimitKeyFromTrustedProxy(t *testing.T) {
	res, err := clientip.Parse("203.0.113.9", "")
	require.NoError(t, err)
	lim := &denyingLimiter{}
	s := newLoginGuardServer(lim, WithClientIP(res))

	rec := postLogin(s, "application/json", validLoginBody, func(r *http.Request) {
		r.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.7") // forged entry, then the real client
	})
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Equal(t, []string{ratelimit.Key(routeAuthLogin, "realm-1", "ip", "198.51.100.7")}, lim.keys)
}
