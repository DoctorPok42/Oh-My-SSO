package loginui

import "testing"

func TestAppHome(t *testing.T) {
	for _, c := range []struct {
		urls []string
		want string
	}{
		{[]string{"https://app.example.test/callback?x=1"}, "https://app.example.test/"},
		{[]string{"https://app.example.test:8443/cb"}, "https://app.example.test:8443/"},
		{[]string{"com.example.app:/cb", "http://localhost:3000/cb"}, "http://localhost:3000/"},
		{[]string{"", "http://app.example.test/cb"}, ""}, // plain http outside localhost
		{[]string{"https://user@app.example.test/cb"}, ""},
		{[]string{"javascript:alert(1)"}, ""},
		{nil, ""},
	} {
		if got := AppHome(c.urls...); got != c.want {
			t.Errorf("AppHome(%q) = %q, want %q", c.urls, got, c.want)
		}
	}
	if NewBackLink("", "https://app.example.test/") != nil || NewBackLink("App", "myapp:/cb") != nil {
		t.Error("a back link needs a name and an address")
	}
}
