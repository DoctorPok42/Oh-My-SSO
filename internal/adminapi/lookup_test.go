package adminapi

import "testing"

func TestRealmInPath(t *testing.T) {
	for path, want := range map[string]string{
		"/api/v1/realms/demo":               "demo",
		"/api/v1/realms/demo/":              "demo",
		"/api/v1/realms/demo/clients/c-123": "demo",
		"/api/v1/realms":                    "",
		"/api/v1/realms/":                   "",
		"/api/v1/me":                        "",
		"/health":                           "",
	} {
		if got := realmInPath(path); got != want {
			t.Errorf("realmInPath(%q) = %q, want %q", path, got, want)
		}
	}
}
