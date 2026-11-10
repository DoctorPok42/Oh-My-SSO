package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	oidcadapter "sso.internal/sso/internal/adapters/oidc"
	samladapter "sso.internal/sso/internal/adapters/saml"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/ratelimit"
)

// memLimiter: the sliding window of the Valkey limiter, in memory, with the
// same atomic check-and-count.
type memLimiter struct {
	mu   sync.Mutex
	hits map[string][]memHit
	seq  int
	err  error
}

type memHit struct {
	at     time.Time
	member string
}

func newMemLimiter() *memLimiter { return &memLimiter{hits: map[string][]memHit{}} }

func (l *memLimiter) Reserve(_ context.Context, rules ...ratelimit.Rule) (ratelimit.Reservation, error) {
	if l.err != nil {
		return ratelimit.Reservation{}, l.err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	res := ratelimit.Reservation{OK: true}
	for _, r := range rules {
		var kept []memHit
		for _, h := range l.hits[r.Key] {
			if now.Sub(h.at) < r.Window {
				kept = append(kept, h)
			}
		}
		l.hits[r.Key] = kept
		if int64(len(kept)) < r.Limit {
			continue
		}
		res.OK = false
		retry := r.Window
		if r.Limit > 0 {
			retry = kept[int64(len(kept))-r.Limit].at.Add(r.Window).Sub(now)
		}
		res.RetryAfter = max(res.RetryAfter, retry)
	}
	if !res.OK {
		return res, nil
	}
	for _, r := range rules {
		l.seq++
		m := strconv.Itoa(l.seq)
		l.hits[r.Key] = append(l.hits[r.Key], memHit{at: now, member: m})
		res.Hits = append(res.Hits, ratelimit.Hit{Key: r.Key, Member: m})
	}
	return res, nil
}

func (l *memLimiter) Release(_ context.Context, hits ...ratelimit.Hit) error {
	if l.err != nil {
		return l.err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, h := range hits {
		kept := l.hits[h.Key][:0]
		for _, x := range l.hits[h.Key] {
			if x.member != h.Member {
				kept = append(kept, x)
			}
		}
		l.hits[h.Key] = kept
	}
	return nil
}

func (l *memLimiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) (bool, error) {
	res, err := l.Reserve(ctx, ratelimit.Rule{Key: key, Limit: limit, Window: window})
	return res.OK, err
}

func (l *memLimiter) count(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.hits[key])
}

const rightSecret = "right-secret"

// fakeOIDC answers like the library with our storage: a secret is checked
// (wrong: 401; right: 200, reported as an authenticated client); a request
// without one (a public client) is 200, nothing reported. delay: the time
// of the database lookup.
type fakeOIDC struct {
	calls atomic.Int64
	delay time.Duration
}

func (f *fakeOIDC) DiscoveryHandler() http.Handler { return http.NotFoundHandler() }

func (f *fakeOIDC) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		time.Sleep(f.delay)
		id, secret, ok := r.BasicAuth()
		if !ok {
			_ = r.ParseForm()
			id, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
			ok = secret != ""
		}
		if ok && secret != rightSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if ok {
			oidcadapter.ReportClientAuthenticated(r.Context(), id)
		}
		w.WriteHeader(http.StatusOK)
	})
}

type fakeSAML struct{ calls int }

func (f *fakeSAML) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.calls++
		w.WriteHeader(http.StatusOK)
	})
}

func (f *fakeSAML) RenderTooManyRequests(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
}

func newProtocolServer(lim *memLimiter, limits ProtocolLimits, saml SAMLProvider) (*Server, *fakeOIDC) {
	oidc := &fakeOIDC{}
	realm := &domain.Realm{ID: "realm-1", Name: "acme", Status: domain.RealmActive}
	s := New(nil, nil, nil, &fakeRealmByName{realm: realm}, nil, lim, WithOIDC(oidc), WithSAML(saml),
		WithProtocolLimits(limits))
	return s, oidc
}

// generous: no limit is reached unless a test lowers it.
var generous = ProtocolLimits{
	OIDCPerIP:           RateRule{Max: 1000, Window: time.Minute},
	ClientFailuresPerIP: RateRule{Max: 1000, Window: time.Minute},
	SAMLPerIP:           RateRule{Max: 1000, Window: time.Minute},
}

type tokenCall struct {
	path, ip, clientID, secret, origin, method string
	form                                       bool // client_secret_post instead of Basic
}

func callToken(s *Server, c tokenCall) *httptest.ResponseRecorder {
	if c.path == "" {
		c.path = "/oidc/token"
	}
	if c.method == "" {
		c.method = http.MethodPost
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if c.form {
		form.Set("client_id", c.clientID)
		if c.secret != "" {
			form.Set("client_secret", c.secret)
		}
	}
	req := httptest.NewRequest(c.method, "/r/acme"+c.path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !c.form && c.clientID != "" {
		req.SetBasicAuth(url.QueryEscape(c.clientID), url.QueryEscape(c.secret))
	}
	if c.origin != "" {
		req.Header.Set("Origin", c.origin)
	}
	req.RemoteAddr = c.ip + ":4000"
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	return rec
}

func requireTooMany(t *testing.T, rec *httptest.ResponseRecorder, maxWait time.Duration) {
	t.Helper()
	require.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
	secs, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	require.NoError(t, err, "Retry-After")
	require.GreaterOrEqual(t, secs, 1)
	require.LessOrEqual(t, secs, int(maxWait.Seconds()))
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var body oauthError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "rate_limited", body.Error)
}

func TestOIDCClient_WrongSecretsFromOneAddressAreCut(t *testing.T) {
	l := generous
	l.ClientFailuresPerIP = RateRule{Max: 3, Window: time.Minute}
	s, oidc := newProtocolServer(newMemLimiter(), l, &fakeSAML{})

	for i := 0; i < 3; i++ {
		rec := callToken(s, tokenCall{ip: "203.0.113.1", clientID: "app", secret: "guess" + strconv.Itoa(i)})
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	}
	// From there, even the right secret: answering it would tell it is right.
	requireTooMany(t, callToken(s, tokenCall{ip: "203.0.113.1", clientID: "app", secret: rightSecret}), time.Minute)
	require.EqualValues(t, 3, oidc.calls.Load(), "a refused request never reaches the library")

	// The application itself, elsewhere, is not affected.
	require.Equal(t, http.StatusOK, callToken(s, tokenCall{ip: "198.51.100.7", clientID: "app", secret: rightSecret}).Code)
	// Nor another client from the same address.
	require.Equal(t, http.StatusOK, callToken(s, tokenCall{ip: "203.0.113.1", clientID: "other", secret: rightSecret}).Code)
}

// R1: the client_id is public. Failures from any number of addresses never
// lock the application out for the others, and a public client (client_id
// without a secret) is never refused for the failures of its client_id.
func TestOIDCClient_FailuresNeverLockTheClientOut(t *testing.T) {
	l := generous
	l.ClientFailuresPerIP = RateRule{Max: 3, Window: time.Minute}
	s, _ := newProtocolServer(newMemLimiter(), l, &fakeSAML{})

	for a := 0; a < 50; a++ {
		ip := "203.0.113." + strconv.Itoa(a)
		for i := 0; i < 3; i++ {
			require.Equal(t, http.StatusUnauthorized, callToken(s, tokenCall{path: "/oidc/revoke", ip: ip, clientID: "app", secret: "x"}).Code)
		}
	}
	require.Equal(t, http.StatusOK, callToken(s, tokenCall{ip: "198.51.100.7", clientID: "app", secret: rightSecret}).Code)
	require.Equal(t, http.StatusOK, callToken(s, tokenCall{ip: "198.51.100.7", clientID: "app", secret: rightSecret, form: true}).Code)

	// The public client's code exchange from an address that guessed: no secret, not checked.
	require.Equal(t, http.StatusOK, callToken(s, tokenCall{ip: "203.0.113.1", clientID: "app", form: true}).Code)
}

// R2: a client that proves its secret gives its hit back: an application
// server is never limited per address, however many calls it makes.
func TestOIDCClient_AuthenticatedClientsDoNotCountPerAddress(t *testing.T) {
	l := generous
	l.OIDCPerIP = RateRule{Max: 2, Window: time.Minute}
	lim := newMemLimiter()
	s, _ := newProtocolServer(lim, l, &fakeSAML{})

	for i := 0; i < 30; i++ {
		path := []string{"/oidc/token", "/oidc/introspect", "/oidc/revoke"}[i%3]
		rec := callToken(s, tokenCall{path: path, ip: "203.0.113.1", clientID: "api", secret: rightSecret})
		require.Equal(t, http.StatusOK, rec.Code, "call %d", i+1)
	}
	require.Zero(t, lim.count(ratelimit.Key(routeOIDCClient, "realm-1", "ip", "203.0.113.1")))

	// What does not authenticate a client counts: a wrong secret, none.
	require.Equal(t, http.StatusUnauthorized, callToken(s, tokenCall{ip: "203.0.113.1", clientID: "api", secret: "x"}).Code)
	require.Equal(t, http.StatusOK, callToken(s, tokenCall{ip: "203.0.113.1", clientID: "spa", form: true}).Code)
	requireTooMany(t, callToken(s, tokenCall{ip: "203.0.113.1", clientID: "spa", form: true}), time.Minute)
	// Another address: its own count.
	require.Equal(t, http.StatusOK, callToken(s, tokenCall{ip: "198.51.100.7", clientID: "spa", form: true}).Code)
}

// R3: every attempt is counted before it runs. A burst of parallel guesses
// cannot pass the check before any of them is counted.
func TestOIDCClient_ParallelGuessesAreCounted(t *testing.T) {
	l := generous
	l.ClientFailuresPerIP = RateRule{Max: 10, Window: time.Minute}
	s, oidc := newProtocolServer(newMemLimiter(), l, &fakeSAML{})
	oidc.delay = 20 * time.Millisecond

	var wg sync.WaitGroup
	var refused atomic.Int64
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if callToken(s, tokenCall{ip: "203.0.113.1", clientID: "app", secret: "guess"}).Code == http.StatusTooManyRequests {
				refused.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 10, oidc.calls.Load(), "guesses that reached the library")
	require.EqualValues(t, 190, refused.Load())
}

// A refusal counts nothing: the request refused by its client's failures
// does not use the budget of its address.
func TestOIDCClient_RefusalConsumesNothing(t *testing.T) {
	l := generous
	l.ClientFailuresPerIP = RateRule{Max: 1, Window: time.Minute}
	lim := newMemLimiter()
	s, _ := newProtocolServer(lim, l, &fakeSAML{})
	ipKey := ratelimit.Key(routeOIDCClient, "realm-1", "ip", "203.0.113.1")

	require.Equal(t, http.StatusUnauthorized, callToken(s, tokenCall{ip: "203.0.113.1", clientID: "app", secret: "x"}).Code)
	for i := 0; i < 5; i++ {
		requireTooMany(t, callToken(s, tokenCall{ip: "203.0.113.1", clientID: "app", secret: "x"}), time.Minute)
	}
	require.Equal(t, 1, lim.count(ipKey))
	require.Equal(t, 1, lim.count(clientFailureKey("realm-1", "app", "203.0.113.1")))
}

// A browser application must be able to read the 429 (CORS) and its
// Retry-After; a preflight is never counted nor refused.
func TestOIDCClient_RefusalIsReadableCrossOrigin(t *testing.T) {
	l := generous
	l.OIDCPerIP = RateRule{Max: 0, Window: time.Minute}
	s, _ := newProtocolServer(newMemLimiter(), l, &fakeSAML{})

	rec := callToken(s, tokenCall{ip: "203.0.113.1", origin: "https://spa.example.com"})
	requireTooMany(t, rec, time.Minute)
	require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, "Retry-After", rec.Header().Get("Access-Control-Expose-Headers"))

	pre := callToken(s, tokenCall{ip: "203.0.113.1", origin: "https://spa.example.com", method: http.MethodOptions})
	require.Equal(t, http.StatusOK, pre.Code)
}

func TestOIDCClient_OtherEndpointsAreNotLimitedHere(t *testing.T) {
	l := generous
	l.OIDCPerIP = RateRule{Max: 0, Window: time.Minute}
	s, _ := newProtocolServer(newMemLimiter(), l, &fakeSAML{})

	for _, p := range []string{"/oidc/userinfo", "/oidc/authorize", "/oidc/keys"} {
		rec := callToken(s, tokenCall{path: p, method: http.MethodGet, ip: "203.0.113.1"})
		require.Equal(t, http.StatusOK, rec.Code, p)
	}
}

func TestOIDCClient_LimiterDown(t *testing.T) {
	lim := newMemLimiter()
	lim.err = errors.New("valkey down")
	s, oidc := newProtocolServer(lim, generous, &fakeSAML{})

	rec := callToken(s, tokenCall{ip: "203.0.113.1", clientID: "app", secret: rightSecret})
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Contains(t, rec.Body.String(), `"server_error"`)
	require.Zero(t, oidc.calls.Load())
}

func TestOIDCClient_BodyTooLarge(t *testing.T) {
	s, oidc := newProtocolServer(newMemLimiter(), generous, &fakeSAML{})
	req := httptest.NewRequest(http.MethodPost, "/r/acme/oidc/token",
		strings.NewReader("client_id=app&pad="+strings.Repeat("a", maxOIDCClientBody)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Zero(t, oidc.calls.Load())
}

func TestRequestClient(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.SetBasicAuth(url.QueryEscape("my app:1"), "s")
	id, withSecret, err := requestClient(req)
	require.NoError(t, err)
	require.Equal(t, "my app:1", id)
	require.True(t, withSecret)

	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("client_id=web&client_secret=s&code=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	id, withSecret, err = requestClient(req)
	require.NoError(t, err)
	require.Equal(t, "web", id)
	require.True(t, withSecret)
	body, _ := io.ReadAll(req.Body)
	require.Empty(t, body, "the form was read once")
	require.Equal(t, "x", req.Form.Get("code"), "and stays readable by the library")

	// A public client: its client_id, no secret.
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("client_id=spa&code=x&code_verifier=v"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	id, withSecret, err = requestClient(req)
	require.NoError(t, err)
	require.Equal(t, "spa", id)
	require.False(t, withSecret)
}

func TestClientFailureKeyStaysSmall(t *testing.T) {
	long := strings.Repeat("x", 10_000)
	require.Less(t, len(clientFailureKey("r", long, "203.0.113.1")), 200)
	require.NotEqual(t, clientFailureKey("r", long, "203.0.113.1"), clientFailureKey("r", long+"y", "203.0.113.1"))
	require.NotEqual(t, clientFailureKey("r", "app", "203.0.113.1"), clientFailureKey("r", "app", "203.0.113.2"))
}

func callSAML(s *Server, path, ip string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/r/acme"+path, nil)
	req.RemoteAddr = ip + ":4000"
	// The browser's language (else the realm's, which needs a database).
	req.AddCookie(&http.Cookie{Name: "omsso_locale", Value: "fr"})
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	return rec
}

func TestSAML_LimitedPerAddress(t *testing.T) {
	l := generous
	l.SAMLPerIP = RateRule{Max: 2, Window: time.Minute}
	saml := &fakeSAML{}
	s, _ := newProtocolServer(newMemLimiter(), l, saml)

	require.Equal(t, http.StatusOK, callSAML(s, "/saml/sso", "203.0.113.1").Code)
	require.Equal(t, http.StatusOK, callSAML(s, "/saml/login", "203.0.113.1").Code)
	rec := callSAML(s, "/saml/consent", "203.0.113.1")
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.NotEmpty(t, rec.Header().Get("Retry-After"))
	require.Equal(t, 2, saml.calls)

	// Metadata and assets: not limited. Another address: its own count.
	require.Equal(t, http.StatusOK, callSAML(s, "/saml/metadata", "203.0.113.1").Code)
	require.Equal(t, http.StatusOK, callSAML(s, "/saml/slo", "198.51.100.7").Code)
}

// The real page: HTML, translated, 429.
func TestSAML_TooManyRequestsPage(t *testing.T) {
	adapter, err := samladapter.New(samladapter.Config{PublicURL: "https://sso.example.com"}, nil, nil)
	require.NoError(t, err)
	l := generous
	l.SAMLPerIP = RateRule{Max: 0, Window: time.Minute}
	s, _ := newProtocolServer(newMemLimiter(), l, adapter)

	rec := callSAML(s, "/saml/sso", "203.0.113.1")
	require.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
	require.Equal(t, "60", rec.Header().Get("Retry-After"))
	require.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	require.Contains(t, rec.Body.String(), "Trop de demandes")
}
