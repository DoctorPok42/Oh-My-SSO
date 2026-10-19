package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)

// Step 11: session participants (who must hear about a Single Logout).

func TestIdentityCore_SessionParticipants(t *testing.T) {
	ctx := context.Background()

	t.Run("one record per session and client, reused", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session

		p := core.SessionParticipant{SessionID: sess.ID, ClientRef: clientSAML,
			Subject: aliceID, SubjectFormat: domain.NameIDFormatPersistent}
		first, err := f.core.RegisterSessionParticipant(ctx, p)
		require.NoError(t, err)
		require.Equal(t, domain.TokenSAMLSession, first.Type)
		require.True(t, strings.HasPrefix(first.JTI, "_") && len(first.JTI) > 20, "SessionIndex: random, xs:ID-like")
		require.Equal(t, sess.ExpiresAt, first.ExpiresAt, "lives as long as the IdP session")
		require.Equal(t, aliceID, first.Subject)
		require.Equal(t, domain.NameIDFormatPersistent, first.SubjectFormat)

		again, err := f.core.RegisterSessionParticipant(ctx, p)
		require.NoError(t, err)
		require.Equal(t, first.JTI, again.JTI, "the provider keeps ONE SessionIndex for the session")

		// The client's configuration changed (another format): a new record.
		p.SubjectFormat, p.Subject = domain.NameIDFormatEmail, "alice@example.com"
		other, err := f.core.RegisterSessionParticipant(ctx, p)
		require.NoError(t, err)
		require.NotEqual(t, first.JTI, other.JTI)

		parts, err := f.core.SessionParticipants(ctx, sess.ID)
		require.NoError(t, err)
		require.Len(t, parts, 2)
	})

	t.Run("a transient NameID stays the same for the whole session", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session
		p := core.SessionParticipant{SessionID: sess.ID, ClientRef: clientSAML,
			Subject: "_random-1", SubjectFormat: domain.NameIDFormatTransient}
		first, err := f.core.RegisterSessionParticipant(ctx, p)
		require.NoError(t, err)
		p.Subject = "_random-2" // the adapter draws a new one each time
		again, err := f.core.RegisterSessionParticipant(ctx, p)
		require.NoError(t, err)
		require.Equal(t, "_random-1", again.Subject)
		require.Equal(t, first.JTI, again.JTI)

		// A new session: a new transient NameID.
		sess2 := f.aliceSession(t).Session
		p.SessionID = sess2.ID
		next, err := f.core.RegisterSessionParticipant(ctx, p)
		require.NoError(t, err)
		require.Equal(t, "_random-2", next.Subject)
	})

	t.Run("revocation of the session revokes its participants", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session
		_, err := f.core.RegisterSessionParticipant(ctx, core.SessionParticipant{SessionID: sess.ID,
			ClientRef: clientSAML, Subject: aliceID, SubjectFormat: domain.NameIDFormatPersistent})
		require.NoError(t, err)
		_, err = f.core.IssueTokens(ctx, core.TokenRequest{SessionID: sess.ID, ClientRef: clientOIDC, Scopes: []string{"openid"}})
		require.NoError(t, err)

		require.NoError(t, f.core.RevokeSession(ctx, sess.ID, domain.SessionRevokedUserLogout))
		parts, err := f.core.SessionParticipants(ctx, sess.ID)
		require.NoError(t, err)
		require.Empty(t, parts)
		toks, _ := f.tokens.ListBySession(ctx, sess.ID)
		for _, tok := range toks {
			require.True(t, tok.Revoked, "%s %s", tok.Type, tok.JTI)
		}

		_, err = f.core.RegisterSessionParticipant(ctx, core.SessionParticipant{SessionID: sess.ID,
			ClientRef: clientSAML, Subject: aliceID, SubjectFormat: domain.NameIDFormatPersistent})
		require.ErrorIs(t, err, core.ErrSessionInvalid, "no participant for a dead session")
	})

	t.Run("refused inputs", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session
		_, err := f.core.RegisterSessionParticipant(ctx, core.SessionParticipant{SessionID: sess.ID, ClientRef: clientSAML})
		require.Error(t, err, "a subject is required")
		_, err = f.core.RegisterSessionParticipant(ctx, core.SessionParticipant{SessionID: sess.ID,
			ClientRef: "unknown", Subject: "x", SubjectFormat: domain.NameIDFormatPersistent})
		require.Error(t, err)

		f.clients.byID["client-elsewhere"] = &domain.ClientApp{ID: "client-elsewhere", RealmID: "realm-b",
			Protocol: domain.ClientAppProtocolSAML2, Status: domain.ClientAppActive, EntityID: "https://b.example"}
		_, err = f.core.RegisterSessionParticipant(ctx, core.SessionParticipant{SessionID: sess.ID,
			ClientRef: "client-elsewhere", Subject: "x", SubjectFormat: domain.NameIDFormatPersistent})
		require.ErrorIs(t, err, core.ErrClientNotFound, "never a participant from another realm")
	})

	t.Run("expired session", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session
		f.advance(9 * time.Hour)
		_, err := f.core.RegisterSessionParticipant(ctx, core.SessionParticipant{SessionID: sess.ID,
			ClientRef: clientSAML, Subject: aliceID, SubjectFormat: domain.NameIDFormatPersistent})
		require.ErrorIs(t, err, core.ErrSessionInvalid)
	})
}

func TestIdentityCore_ClientByRef(t *testing.T) {
	ctx := context.Background()
	f := newCoreFixture(t)

	pc, err := f.core.ClientByRef(ctx, clientSAML)
	require.NoError(t, err)
	require.Equal(t, "https://sp.example.com/metadata", pc.App.EntityID)

	_, err = f.core.ClientByRef(ctx, "nope")
	require.ErrorIs(t, err, core.ErrClientNotFound)
	_, err = f.core.ClientByRef(ctx, "")
	require.ErrorIs(t, err, core.ErrClientNotFound)

	f.clients.byID[clientSAML].Status = domain.ClientAppSuspended
	_, err = f.core.ClientByRef(ctx, clientSAML)
	require.ErrorIs(t, err, core.ErrClientNotFound)
}
