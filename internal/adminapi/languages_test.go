package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/i18n"
)

// The error sentences follow the language the console asks for, and fall
// back to English for any other.
func TestWriteServiceError_Language(t *testing.T) {
	ae := &service.AdminError{Kind: service.AdminRefused, Code: "last_admin",
		Message: "this is the last active administrator: add another one to Admins first",
		Text: i18n.M("admin.error.last_admin",
			"this is the last active administrator: add another one to {group} first", "group", "Admins")}

	serve := func(accept string) errorBody {
		s := &Server{cfg: Config{Languages: i18n.MustDefault()}}
		h := s.languages(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeServiceError(w, r, ae)
		}))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", nil)
		if accept != "" {
			req.Header.Set("Accept-Language", accept)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusConflict, rec.Code)
		var body errorBody
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		return body
	}

	en := serve("")
	require.Equal(t, "last_admin", en.Error)
	require.Equal(t, "this is the last active administrator: add another one to Admins first", en.Message)

	fr := serve("fr-FR,fr;q=0.9,en;q=0.8")
	require.Equal(t, "last_admin", fr.Error, "the code stays stable for the console")
	require.Equal(t, "c'est le dernier administrateur actif : ajoutez-en un autre à Admins d'abord", fr.Message)
}
