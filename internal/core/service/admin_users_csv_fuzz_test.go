package service

import "testing"

// Run for real with: go test -run=^$ -fuzz=FuzzParseUserCSV -fuzztime=60s ./internal/core/service
// (a plain `go test` only replays the seeds). The property is the absence of
// a panic and of a line number that is not a line of the file.
func FuzzParseUserCSV(f *testing.F) {
	for _, s := range []string{
		"email,username,groups,roles\nalice@acme.example,alice,staff | sales,support\n",
		"email;nom\nbob@acme.example;Bob\n",
		"\xef\xbb\xbfemail\nx@y.example\n",
		"email,username\n\"a,b@c.example\",\"unterminated\n",
		"email\n\n\n",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		file, err := parseUserCSV(data)
		if err != nil {
			return
		}
		for _, r := range file.rows {
			if r.line < 2 {
				t.Fatalf("row at line %d: the header is line 1", r.line)
			}
		}
	})
}
