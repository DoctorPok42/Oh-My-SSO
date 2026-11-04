package i18n

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The texts of the code, found by reading it: every {{t "key" "English"}}
// of the templates, loc.T("key", "English") and i18n.M("key", "English")
// of the Go code, t("key", "English") of the scripts. The tests below check
// the translation files against them, so that a new text cannot be
// forgotten in a language, and a removed one does not linger.
//
// I18N_DUMP=<file> go test ./internal/i18n -run TestCatalog writes the
// English catalog (key -> text) to <file>: the starting point of a new
// language file.

// sources: the directories with texts, from this package.
var sources = []string{"../adapters", "../httpserver", "../notify", "../core/service", "../adminapi", "."}

var (
	// a string literal: "..." (Go, JS and templates), with escapes.
	str = `"((?:[^"\\]|\\.)*)"`
	// {{t "key" "English" ...}} and (t "key" "English"): templates.
	tmplText = regexp.MustCompile(`(?:\{\{-?\s*|\()(?:t|th|tp)\s+"([a-z0-9_.]+)"\s+` + str)
	// {{tn "key" .N "one" "other"}}
	tmplPlural = regexp.MustCompile(`(?:\{\{-?\s*|\()tn\s+"([a-z0-9_.]+)"\s+[^\s"]+\s+` + str + `\s+` + str)
	// loc.T("key", "English", ...), i18n.M(...), .HTML, .Plain, lookup: Go.
	goText = regexp.MustCompile(`(?:\.T|\.HTML|\.Plain|\bM|\.lookup)\(\s*"([a-z0-9_.]+)",\s*` + "(?:" + str + "|([a-zA-Z]+))")
	// loc.N("key", n, "one", "other")
	goPlural = regexp.MustCompile(`\.N\(\s*"([a-z0-9_.]+)",\s*[^,]+,\s*` + str + `,\s*` + str)
	// t("key", "English") and tn("key", n, "one", "other"): scripts.
	jsText   = regexp.MustCompile(`\bt\(\s*"([a-z0-9_.]+)",\s*` + str)
	jsPlural = regexp.MustCompile(`\btn\(\s*"([a-z0-9_.]+)",\s*[^,]+,\s*` + str + `,\s*` + str)
)

type use struct {
	text string
	file string
}

// catalog reads the code: key -> English text and where it was found.
func catalog(t *testing.T) map[string]use {
	t.Helper()
	out := map[string]use{}
	add := func(key, text, file string) {
		if prev, ok := out[key]; ok && prev.text != text {
			t.Errorf("%s: key %q has two English texts:\n  %q (%s)\n  %q", file, key, prev.text, prev.file, text)
			return
		}
		out[key] = use{text: text, file: file}
	}
	unquote := func(s string) string {
		u, err := strconv.Unquote(`"` + s + `"`)
		if err != nil {
			return s
		}
		return u
	}
	for _, dir := range sources {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			ext := filepath.Ext(path)
			if strings.HasSuffix(path, "_test.go") || (ext != ".go" && ext != ".html" && ext != ".tmpl" && ext != ".js") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			src := string(raw)
			switch ext {
			case ".html", ".tmpl":
				for _, m := range tmplText.FindAllStringSubmatch(src, -1) {
					add(m[1], unquote(m[2]), path)
				}
				for _, m := range tmplPlural.FindAllStringSubmatch(src, -1) {
					add(m[1]+".one", unquote(m[2]), path)
					add(m[1]+".other", unquote(m[3]), path)
				}
			case ".go":
				for _, m := range goText.FindAllStringSubmatch(src, -1) {
					if m[3] != "" { // lookup(key, constant): the constant's value
						add(m[1], goConst(t, src, m[3]), path)
						continue
					}
					add(m[1], unquote(m[2]), path)
				}
				for _, m := range goPlural.FindAllStringSubmatch(src, -1) {
					add(m[1]+".one", unquote(m[2]), path)
					add(m[1]+".other", unquote(m[3]), path)
				}
			case ".js":
				prefix := strings.TrimSuffix(filepath.Base(path), ".js") + ".js."
				if filepath.Base(path) == "htmx.min.js" {
					return nil
				}
				check := func(key string) {
					if !strings.HasPrefix(key, prefix) {
						t.Errorf("%s: key %q must start with %q: the page only sends those to the script", path, key, prefix)
					}
				}
				for _, m := range jsText.FindAllStringSubmatch(src, -1) {
					check(m[1])
					add(m[1], unquote(m[2]), path)
				}
				for _, m := range jsPlural.FindAllStringSubmatch(src, -1) {
					check(m[1])
					add(m[1]+".one", unquote(m[2]), path)
					add(m[1]+".other", unquote(m[3]), path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// goConst: the value of a string constant of src (defMonths...).
func goConst(t *testing.T, src, name string) string {
	m := regexp.MustCompile(`\b` + name + `\s*=\s*` + str).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("constant %s not found", name)
	}
	return m[1]
}

var placeholder = regexp.MustCompile(`\{[a-z_]+\}`)

func placeholders(s string) []string {
	out := placeholder.FindAllString(s, -1)
	sort.Strings(out)
	return slices.Compact(out)
}

// Keys of a file that the code does not use but that are still read.
var metaKeys = []string{"language.name"}

func TestCatalog(t *testing.T) {
	cat := catalog(t)
	if len(cat) < 300 {
		t.Fatalf("only %d texts found: the patterns no longer match the code", len(cat))
	}
	if path := os.Getenv("I18N_DUMP"); path != "" {
		en := map[string]string{}
		for k, u := range cat {
			en[k] = u.text
		}
		raw, _ := json.MarshalIndent(en, "", "  ")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	files, err := fs.Glob(embedded, "locales/*.json")
	if err != nil || len(files) == 0 {
		t.Fatal("no translation file")
	}
	for _, f := range files {
		raw, _ := fs.ReadFile(embedded, f)
		var msgs map[string]string
		if err := json.Unmarshal(raw, &msgs); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var missing []string
		for k := range cat {
			if _, ok := msgs[k]; !ok {
				missing = append(missing, k)
			}
		}
		sort.Strings(missing)
		for _, k := range missing {
			t.Errorf("%s: missing %q (English: %q, %s)", f, k, cat[k].text, cat[k].file)
		}
		for k, v := range msgs {
			if slices.Contains(metaKeys, k) {
				continue
			}
			u, ok := cat[k]
			if !ok {
				t.Errorf("%s: %q is not used by the code any more", f, k)
				continue
			}
			if got, want := placeholders(v), placeholders(u.text); !slices.Equal(got, want) {
				t.Errorf("%s: %q has the placeholders %v, the English text %v", f, k, got, want)
			}
		}
	}
}
