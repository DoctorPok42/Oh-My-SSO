package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecurityTxt(t *testing.T) {
	get := func(contact string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		newLoginGuardServer(&denyingLimiter{}, WithSecurityContact(contact)).Router().
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil))
		return rec
	}

	require.Equal(t, http.StatusNotFound, get("").Code, "no contact configured")
	require.Equal(t, http.StatusNotFound, get("a@b.test\nContact: evil").Code, "a line break would forge a field")

	rec := get("security@example.test")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Header().Get("Content-Type"), "text/plain")
	require.Contains(t, rec.Body.String(), "Contact: mailto:security@example.test\n")
	require.Contains(t, rec.Body.String(), "\nExpires: ")
	require.Contains(t, get("https://example.test/security").Body.String(), "Contact: https://example.test/security\n")
}
