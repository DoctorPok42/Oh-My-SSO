package service

import (
	"encoding/csv"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"sso.internal/sso/internal/i18n"
)

// The CSV file of an import of users.
//
//	email,username,name,department,groups,roles
//	alice@acme.example,alice,Alice Moreau,Sales,staff|sales,support
//
// The first line names the columns, in any order; only "email" is required.
// "username" (default: the part of the e-mail before @), "groups" and "roles"
// (names, separated by |) have their meaning; any other column is a profile
// attribute, like the "Other attributes" of the "+ Invite user" drawer.
//
// A password never comes from a file: an account chooses its own, with its
// activation link. A column that looks like one (or like any other secret)
// is left out when the header is read, so its values are not even copied out
// of the CSV reader's records: they cannot reach the profile, the report or
// a log. It is named in the preview, so the administrator knows.

const (
	// MaxUserImportBytes and MaxUserImportRows bound one file. The Admin API
	// reads it in one request, and the console keeps its report on one page.
	MaxUserImportBytes = 1 << 20
	MaxUserImportRows  = 1000

	importListSeparator = "|"
	maxColumnNameShown  = 64
)

// sensitiveColumnWords: a column whose name holds one of these (once
// lowercased and without separators) is never read.
var sensitiveColumnWords = []string{
	"password", "passwd", "passphrase", "pwd", "motdepasse", "mdp",
	"secret", "hash", "salt", "token", "otp", "apikey", "privatekey",
}

func isSensitiveColumn(normalized string) bool {
	compact := strings.ReplaceAll(normalized, "_", "")
	return slices.ContainsFunc(sensitiveColumnWords, func(w string) bool { return strings.Contains(compact, w) })
}

// importRow is one line of the file.
type importRow struct {
	line     int
	email    string
	username string
	profile  map[string]interface{}
	groups   []string // names
	roles    []string // names
	err      error    // the line cannot be used as it is
}

// parsedImport is a file, read.
type parsedImport struct {
	rows           []importRow
	profileColumns []string
	ignoredColumns []string // as written in the file
}

type importColumn struct {
	index int
	name  string // normalized
}

// parseUserCSV reads the file. An error here is about the file as a whole;
// a problem on one line is left in that row (importRow.err). The messages
// never quote a cell: a line that is cut wrong can put anything in any
// column.
func parseUserCSV(data string) (*parsedImport, error) {
	if len(data) > MaxUserImportBytes {
		return nil, adminText(AdminInvalid, "import_too_large", "file", i18n.M("admin.error.import_too_large", "the file is too large: {max} MB at most", "max", MaxUserImportBytes>>20))
	}
	data = strings.TrimPrefix(data, "\xef\xbb\xbf") // Excel's "CSV UTF-8" starts with a BOM
	if !utf8.ValidString(data) {
		return nil, adminText(AdminInvalid, "import_encoding", "file", i18n.M("admin.error.import_encoding", "the file is not in UTF-8: save it again as \"CSV UTF-8\""))
	}
	r := csv.NewReader(strings.NewReader(data))
	r.Comma = detectSeparator(data)
	r.FieldsPerRecord = -1 // the lines are compared with the header below
	r.TrimLeadingSpace = true
	r.ReuseRecord = true

	header, err := r.Read()
	if errors.Is(err, io.EOF) {
		return nil, importEmpty()
	}
	if err != nil {
		return nil, importMalformed(err)
	}
	out := &parsedImport{}
	columns, err := readImportHeader(header, out)
	if err != nil {
		return nil, err
	}
	width := len(header)

	for {
		record, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, importMalformed(err)
		}
		if blankRecord(record) {
			continue // the empty lines a spreadsheet leaves at the end
		}
		if len(out.rows) == MaxUserImportRows {
			return nil, adminText(AdminInvalid, "import_too_many_rows", "file", i18n.M("admin.error.import_too_many_rows", "the file has too many lines: {max} users at most", "max", MaxUserImportRows))
		}
		line, _ := r.FieldPos(0)
		row := importRow{line: line}
		if len(record) != width {
			// An unquoted comma shifts the cells: what is in "email" could be
			// any other column, so nothing of this line is kept.
			row.err = adminText(AdminInvalid, "import_columns", "file", i18n.M("admin.error.import_columns", "{found} columns instead of {expected}: a value with a separator must be between quotes", "found", len(record), "expected", width))
		} else {
			fillImportRow(&row, record, columns)
		}
		out.rows = append(out.rows, row)
	}
	if len(out.rows) == 0 {
		return nil, importEmpty()
	}
	return out, nil
}

// detectSeparator: a spreadsheet in a French locale writes ";". The header
// holds no free text, so counting on its first line is enough.
func detectSeparator(data string) rune {
	first, _, _ := strings.Cut(data, "\n")
	if strings.Count(first, ";") > strings.Count(first, ",") {
		return ';'
	}
	return ','
}

func readImportHeader(header []string, out *parsedImport) ([]importColumn, error) {
	columns := make([]importColumn, 0, len(header))
	seen := map[string]bool{}
	for i, raw := range header {
		name := normalizeColumn(raw)
		if name == "" {
			continue // the empty column of a trailing separator
		}
		if seen[name] {
			return nil, adminText(AdminInvalid, "import_header", "file", i18n.M("admin.error.import_duplicate_column", "the column \"{column}\" appears twice", "column", shortColumn(raw)))
		}
		seen[name] = true
		switch {
		case isSensitiveColumn(name) || !profileKeyPattern.MatchString(name):
			out.ignoredColumns = append(out.ignoredColumns, shortColumn(raw))
			continue
		case name != "email" && name != "username" && name != "groups" && name != "roles":
			out.profileColumns = append(out.profileColumns, name)
		}
		columns = append(columns, importColumn{index: i, name: name})
	}
	if !seen["email"] {
		return nil, adminText(AdminInvalid, "import_header", "file", i18n.M("admin.error.import_no_email", "the first line must name the columns, and one of them must be \"email\""))
	}
	return columns, nil
}

// normalizeColumn: "Family Name" and "family-name" are family_name.
func normalizeColumn(raw string) string {
	name := strings.ToLower(strings.TrimSpace(raw))
	return strings.NewReplacer(" ", "_", "-", "_").Replace(name)
}

func shortColumn(raw string) string {
	raw = strings.TrimSpace(raw)
	if utf8.RuneCountInString(raw) <= maxColumnNameShown {
		return raw
	}
	return string([]rune(raw)[:maxColumnNameShown]) + "…"
}

// fillImportRow copies the cells of the known columns, and only those.
func fillImportRow(row *importRow, record []string, columns []importColumn) {
	for _, c := range columns {
		value := strings.TrimSpace(record[c.index])
		switch c.name {
		case "email":
			row.email = value
		case "username":
			row.username = value
		case "groups":
			row.groups = splitImportList(value)
		case "roles":
			row.roles = splitImportList(value)
		default:
			if value == "" {
				continue
			}
			if row.profile == nil {
				row.profile = map[string]interface{}{}
			}
			row.profile[c.name] = value
		}
	}
}

func splitImportList(value string) []string {
	var out []string
	for _, v := range strings.Split(value, importListSeparator) {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func blankRecord(record []string) bool {
	return !slices.ContainsFunc(record, func(v string) bool { return strings.TrimSpace(v) != "" })
}

func importEmpty() error {
	return adminText(AdminInvalid, "import_empty", "file", i18n.M("admin.error.import_empty", "the file has no user: a first line with the columns, then one line per user"))
}

func importMalformed(err error) error {
	var pe *csv.ParseError
	line := 0
	if errors.As(err, &pe) {
		line = pe.Line
	}
	return adminText(AdminInvalid, "import_malformed", "file", i18n.M("admin.error.import_malformed", "the file is not valid CSV near line {line}: check the quotes", "line", line))
}
