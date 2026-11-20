// Package pwnedpasswords asks Have I Been Pwned whether a password appeared in
// a data breach. It implements service.PasswordBreachChecker; the core never
// speaks HTTP.
package pwnedpasswords

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // the Pwned Passwords range API is keyed by SHA-1
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultURL is the range API; the 5 first hex digits of the password's SHA-1
// are appended to it.
const DefaultURL = "https://api.pwnedpasswords.com/range/"

type Client struct {
	URL  string // tests point it to an httptest server
	HTTP *http.Client
}

func New() *Client {
	return &Client{URL: DefaultURL, HTTP: &http.Client{Timeout: 3 * time.Second}}
}

// Pwned reports whether password appeared in a breach. Only the 5 first hex
// digits of its SHA-1 leave the server (k-anonymity), and padding hides the
// size of the answer.
func (c *Client) Pwned(ctx context.Context, password string) (bool, error) {
	sum := fmt.Sprintf("%X", sha1.Sum([]byte(password))) //nolint:gosec // see the import
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+sum[:5], nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "Oh-My-SSO") // the API refuses requests without one
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("pwned passwords: HTTP %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 4<<20))
	for sc.Scan() {
		// "SUFFIX:COUNT"; padding lines have a count of 0.
		suffix, count, _ := strings.Cut(sc.Text(), ":")
		if strings.EqualFold(suffix, sum[5:]) {
			return strings.TrimSpace(count) != "0", nil
		}
	}
	return false, sc.Err()
}
