package service

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func adminCode(t *testing.T, err error) string {
	t.Helper()
	var ae *AdminError
	if !errors.As(err, &ae) {
		t.Fatalf("not an AdminError: %v", err)
	}
	return ae.Code
}

func TestParseUserCSV(t *testing.T) {
	file, err := parseUserCSV("email,username,Family Name,groups,roles\n" +
		"alice@acme.example,alice,Moreau,staff | sales|staff,support\n" +
		"\n" +
		"bob@acme.example,,,,\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(file.rows) != 2 {
		t.Fatalf("rows = %d, want 2 (the blank line is skipped)", len(file.rows))
	}
	alice, bob := file.rows[0], file.rows[1]
	if alice.line != 2 || bob.line != 4 {
		t.Errorf("lines = %d, %d: they must be the lines of the file", alice.line, bob.line)
	}
	if alice.email != "alice@acme.example" || alice.username != "alice" {
		t.Errorf("alice = %+v", alice)
	}
	if got := strings.Join(alice.groups, ","); got != "staff,sales" {
		t.Errorf("groups = %q: trimmed, without duplicates", got)
	}
	if got := strings.Join(alice.roles, ","); got != "support" {
		t.Errorf("roles = %q", got)
	}
	if alice.profile["family_name"] != "Moreau" {
		t.Errorf("profile = %v", alice.profile)
	}
	if bob.profile != nil {
		t.Errorf("an empty cell is not a profile attribute: %v", bob.profile)
	}
	if got := strings.Join(file.profileColumns, ","); got != "family_name" {
		t.Errorf("profile columns = %q", got)
	}
}

// A file from Excel in a French locale: BOM, ";" and CRLF.
func TestParseUserCSV_ExcelFrench(t *testing.T) {
	file, err := parseUserCSV("\xef\xbb\xbfemail;name\r\nalice@acme.example;\"Moreau; Alice\"\r\n")
	if err != nil {
		t.Fatal(err)
	}
	row := file.rows[0]
	if row.email != "alice@acme.example" || row.profile["name"] != "Moreau; Alice" {
		t.Errorf("row = %+v", row)
	}
}

// The value of a password column must not exist anywhere in what the parser
// returns: neither in the profile nor in the columns it reports.
func TestParseUserCSV_PasswordColumnsAreNeverRead(t *testing.T) {
	for _, col := range []string{
		"password", "Password", "PASSWORD", "password_hash", "user-password", "passwd", "pwd",
		"mdp", "Mot de passe", "mot_de_passe", "secret", "totp_secret", "api_token", "salt", "new password",
	} {
		t.Run(col, func(t *testing.T) {
			file, err := parseUserCSV("email," + col + ",name\nalice@acme.example,hunter2-s3cret,Alice\n")
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%+v", file); strings.Contains(got, "hunter2-s3cret") {
				t.Fatalf("the value reached the parsed file: %s", got)
			}
			if got := strings.Join(file.ignoredColumns, ","); got != col {
				t.Errorf("ignored columns = %q, want %q", got, col)
			}
			if file.rows[0].profile["name"] != "Alice" {
				t.Errorf("the other columns are read: %v", file.rows[0].profile)
			}
		})
	}
}

func TestParseUserCSV_ColumnsThatCannotBeProfileKeys(t *testing.T) {
	file, err := parseUserCSV("email,Prénom,2fa,\nalice@acme.example,Alice,x,\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(file.ignoredColumns, ","); got != "Prénom,2fa" {
		t.Errorf("ignored columns = %q", got)
	}
	if len(file.rows[0].profile) != 0 {
		t.Errorf("profile = %v", file.rows[0].profile)
	}
}

// An unquoted separator shifts the cells: a password could land in "email",
// so a line of the wrong width keeps nothing.
func TestParseUserCSV_WrongWidthKeepsNothing(t *testing.T) {
	file, err := parseUserCSV("name,email,password\nMoreau, Alice,hunter2@s3cret.example,x\n")
	if err != nil {
		t.Fatal(err)
	}
	row := file.rows[0]
	if row.err == nil {
		t.Fatal("no error on a line of the wrong width")
	}
	if row.email != "" || row.username != "" || row.profile != nil {
		t.Errorf("the line kept something: %+v", row)
	}
	if strings.Contains(row.err.Error(), "s3cret") {
		t.Errorf("the error quotes a cell: %v", row.err)
	}
}

func TestParseUserCSV_RefusedFiles(t *testing.T) {
	tooMany := "email\n" + strings.Repeat("a@acme.example\n", MaxUserImportRows+1)
	for name, tc := range map[string]struct{ data, code string }{
		"empty":           {"", "import_empty"},
		"header only":     {"email,username\n", "import_empty"},
		"no email column": {"username\nalice\n", "import_header"},
		"column twice":    {"email,Email\na@b.example,c@d.example\n", "import_header"},
		"not UTF-8":       {"email,name\na@b.example,caf\xe9\n", "import_encoding"},
		"broken quotes":   {"email,name\na@b.example,\"caf\n", "import_malformed"},
		"too large":       {"email\n" + strings.Repeat("a", MaxUserImportBytes), "import_too_large"},
		"too many lines":  {tooMany, "import_too_many_rows"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseUserCSV(tc.data)
			if err == nil {
				t.Fatal("accepted")
			}
			if got := adminCode(t, err); got != tc.code {
				t.Errorf("code = %q, want %q", got, tc.code)
			}
		})
	}
}

func TestCleanImportFileName(t *testing.T) {
	for in, want := range map[string]string{
		"users.csv":                "users.csv",
		`C:\Users\alice\users.csv`: "users.csv",
		"../../etc/users.csv":      "users.csv",
		"us\r\nBcc: x@y.example":   "usBcc: x@y.example",
		"  users.csv  ":            "users.csv",
		strings.Repeat("é", 300):   strings.Repeat("é", maxImportFileName),
	} {
		if got := cleanImportFileName(in); got != want {
			t.Errorf("cleanImportFileName(%q) = %q, want %q", in, got, want)
		}
	}
}
