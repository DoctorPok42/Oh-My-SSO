package app

import (
	"os"
	"sync"

	"sso.internal/sso/internal/i18n"
	"sso.internal/sso/internal/logging"
)

// Languages returns the languages of the pages and e-mails: the embedded
// translations (internal/i18n/locales), plus the <lang>.json files of
// LOCALES_DIR when it is set, which add languages or change texts without
// a rebuild (package i18n). Read once; a broken file stops the process at
// start-up rather than showing pages in the wrong language.
var Languages = sync.OnceValue(func() *i18n.Bundle {
	b, err := i18n.Load(os.Getenv("LOCALES_DIR"))
	if err != nil {
		logging.Fatal("languages: cannot load", "error", err)
	}
	return b
})
