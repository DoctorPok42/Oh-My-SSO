package adminapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"

	"sso.internal/sso/internal/core/domain"
)

// Reading what authenticate needs, all at once.
//
// Once the token's signature is checked (in memory, no database), the next
// reads do not depend on each other: the token's row (by "jti"), the session
// (by "sid"), the user (by "sub"), the rights epoch (Valkey) and, for routes
// under /realms/{realm}, that realm. Read one after the other they cost five
// round trips of waiting; started together, one (the slowest).
//
// Nothing is decided here: authenticate checks the results in the same order
// as before, and nothing is written (the session's activity is recorded only
// once every check passed). A realm read here is only used by loadRealm,
// after authentication.

type lookups struct {
	token      *domain.Token
	tokenErr   error
	session    *domain.Session
	sessionErr error
	user       *domain.User // by "sub"; authenticate checks it is the session's user
	userErr    error

	rights          []string
	rightsFromToken bool

	realmName string // the {realm} of the URL, "" when the route has none
	realm     *domain.Realm
	realmErr  error
}

var errNoSubject = errors.New("token without subject")

func (s *Server) lookup(ctx context.Context, r *http.Request, c *accessClaims) lookups {
	var (
		l  lookups
		wg sync.WaitGroup
	)
	// Each goroutine writes its own fields of l; they are read after Wait.
	wg.Go(func() { l.token, l.tokenErr = s.d.Tokens.GetByJTI(ctx, c.JTI) })
	wg.Go(func() { l.session, l.sessionErr = s.d.Sessions.GetActive(ctx, c.SessionID) })
	if c.Subject != "" {
		wg.Go(func() { l.user, l.userErr = s.d.Users.GetByID(ctx, c.Subject) })
	} else {
		l.userErr = errNoSubject
	}
	wg.Go(func() { l.rights, l.rightsFromToken = s.tokenRights(ctx, c) })
	if name := realmInPath(r.URL.Path); name != "" {
		l.realmName = name
		wg.Go(func() { l.realm, l.realmErr = s.d.Admin.RealmByName(ctx, name) })
	}
	wg.Wait()
	return l
}

// realmInPath: "demo" for /api/v1/realms/demo and /api/v1/realms/demo/clients/…,
// "" otherwise. loadRealm compares it with the router's {realm} and reads the
// realm itself if they differ.
func realmInPath(p string) string {
	rest, ok := strings.CutPrefix(p, "/api/v1/realms/")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(rest, "/")
	return name
}
