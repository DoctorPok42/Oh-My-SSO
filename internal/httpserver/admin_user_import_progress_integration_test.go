package httpserver_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
)

// importCSV: a file of n users.
func importCSV(n int) string {
	var b strings.Builder
	b.WriteString("email\n")
	for i := range n {
		fmt.Fprintf(&b, "user%d@example.test\n", i)
	}
	return b.String()
}

// What the console reads while an import runs: the count must move before
// the end, or its progress bar sits at 0 and jumps to the report.
func TestAdmin_Integration_UserImportProgress(t *testing.T) {
	e, at := userImportEnv(t)
	const base = "/api/v1/realms/demo/users/imports"

	// About a second in all: the bar must move on a short file too.
	e.notifier.onNotify = func(ev domain.NotificationEvent) {
		if ev.Kind == domain.NotificationAccountInvite {
			time.Sleep(20 * time.Millisecond)
		}
	}
	status, started := e.call(t, at, http.MethodPost, base, map[string]any{"csv": importCSV(60), "send_email": true})
	require.Equal(t, http.StatusAccepted, status, "%v", started)
	id := started["id"].(string)

	var seen []float64
	require.Eventually(t, func() bool {
		status, job := e.call(t, at, http.MethodGet, base+"/"+id, nil)
		require.Equal(t, http.StatusOK, status, "%v", job)
		if job["status"] != "running" {
			return true
		}
		seen = append(seen, job["processed"].(float64))
		return false
	}, 30*time.Second, 25*time.Millisecond)

	var between []float64
	for _, n := range seen {
		if n > 0 && n < 60 {
			between = append(between, n)
		}
	}
	t.Logf("%d polls, counts seen: %v", len(seen), between)
	require.NotEmpty(t, between, "the count never moved while the import ran")
}
