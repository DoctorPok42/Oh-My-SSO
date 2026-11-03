package adminapi

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// auditSearch reads the filters of the audit log (list and export):
//
//	action=user.locked   one action; "auth.*" every action of a domain
//	actor=admin,cli      kinds of actor (user, admin, cli, system, anonymous)
//	user=<id>            done by or about this user
//	client=<id>          about this client
//	status=failure       success or failure
//	level=warning,error  any of these levels
//	from, to             RFC 3339 or YYYY-MM-DD (to: that whole day)
func auditSearch(r *http.Request) (repository.AuditSearch, string) {
	q := r.URL.Query()
	from, ok1 := timeParam(r, "from")
	to, ok2 := timeParam(r, "to")
	if !ok1 || !ok2 {
		return repository.AuditSearch{}, "from / to: RFC 3339 time or YYYY-MM-DD"
	}
	if len(q.Get("to")) == len("2006-01-02") {
		to = to.Add(24 * time.Hour) // a date means "this whole day"
	}
	f := repository.AuditSearch{UserID: q.Get("user"), ClientRef: q.Get("client"), From: from, To: to}

	action := strings.TrimSpace(q.Get("action"))
	if prefix, ok := strings.CutSuffix(action, "*"); ok {
		f.ActionPrefix = prefix
	} else {
		f.Action = action
	}

	switch status := domain.AuditLogStatus(q.Get("status")); status {
	case "", domain.AuditLogSuccess, domain.AuditLogFailure:
		f.Status = status
	default:
		return repository.AuditSearch{}, "status must be success or failure"
	}
	for _, l := range strings.Split(q.Get("level"), ",") {
		switch lv := domain.AuditLogLevel(strings.TrimSpace(l)); lv {
		case "":
		case domain.AuditLogDebug, domain.AuditLogInfo, domain.AuditLogSuspicious, domain.AuditLogWarning,
			domain.AuditLogError, domain.AuditLogCritical:
			f.Levels = append(f.Levels, lv)
		default:
			return repository.AuditSearch{}, "level must be a comma-separated list of debug, info, suspicious, warning, error, critical"
		}
	}
	for _, a := range strings.Split(q.Get("actor"), ",") {
		t := domain.AuditActorType(strings.TrimSpace(a))
		switch {
		case t == "":
		case t.Valid():
			f.ActorTypes = append(f.ActorTypes, t)
		default:
			return repository.AuditSearch{}, "actor must be a comma-separated list of user, admin, cli, system, anonymous"
		}
	}
	return f, ""
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	f, bad := auditSearch(r)
	if bad != "" {
		writeError(w, http.StatusBadRequest, "invalid_request", bad)
		return
	}
	p := page(r)
	f.Page = p
	v, total, err := s.d.Admin.SearchAudit(r.Context(), realmFrom(r), f)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list[service.AuditView]{Items: items(v), Total: total, Offset: p.Offset, Limit: p.Limit})
}

// handleAuditActions lists every action the log can hold, for the filter.
func (s *Server) handleAuditActions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.d.Admin.AuditActions()})
}

// auditCSVHeader: the columns of a CSV export.
var auditCSVHeader = []string{
	"timestamp", "action", "status", "level", "actor_type", "actor_id", "actor_username",
	"target_user_id", "target_username", "resource_type", "resource_id", "ip_address", "user_agent", "details",
}

// handleAuditExport streams the entries matching the filters (no filter:
// the whole log) as CSV or JSON, newest first, as a file download. Past
// service.AuditExportLimit entries the export stops: the CSV ends with a
// "# truncated" line, the JSON says "truncated": true.
func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	f, bad := auditSearch(r)
	if bad != "" {
		writeError(w, http.StatusBadRequest, "invalid_request", bad)
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		writeError(w, http.StatusBadRequest, "invalid_request", "format must be csv or json")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	realm := realmFrom(r)
	ctx := r.Context()

	name := fmt.Sprintf("audit-%s-%s.%s", realm.Name, time.Now().UTC().Format("20060102-150405"), format)
	h := w.Header()
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")

	var (
		n         int
		truncated bool
		err       error
	)
	switch format {
	case "csv":
		h.Set("Content-Type", "text/csv; charset=utf-8")
		cw := csv.NewWriter(w)
		_ = cw.Write(auditCSVHeader)
		n, truncated, err = s.d.Admin.ExportAudit(ctx, realm, f, limit, func(v service.AuditView) error {
			return cw.Write(auditCSVRow(v))
		})
		cw.Flush()
		if truncated {
			fmt.Fprintf(w, "# truncated: more than %d entries, narrow the period\n", n)
		}
	case "json":
		h.Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"realm":` + jsonString(realm.Name) + `,"items":[`))
		enc := json.NewEncoder(w)
		first := true
		n, truncated, err = s.d.Admin.ExportAudit(ctx, realm, f, limit, func(v service.AuditView) error {
			if !first {
				if _, err := w.Write([]byte(",")); err != nil {
					return err
				}
			}
			first = false
			return enc.Encode(v)
		})
		_, _ = fmt.Fprintf(w, `],"count":%d,"truncated":%t}`, n, truncated)
	}
	if err != nil {
		// The headers are gone: the file is cut short, the log says why.
		slog.WarnContext(ctx, "admin api: audit export failed", "realm", realm.Name, "entries", n, "error", err)
	}
	s.d.Admin.RecordAuditExport(ctx, adminFrom(r).actor, realm, format, n, truncated, r.URL.Query())
}

func auditCSVRow(v service.AuditView) []string {
	var actorID, actorName, targetID, targetName string
	if v.Actor != nil {
		actorID, actorName = v.Actor.ID, v.Actor.Username
	}
	if v.Target != nil {
		targetID, targetName = v.Target.ID, v.Target.Username
	}
	details := ""
	if len(v.Details) > 0 {
		if b, err := json.Marshal(v.Details); err == nil {
			details = string(b)
		}
	}
	row := []string{
		v.Timestamp.UTC().Format(time.RFC3339Nano), v.Action, v.Status, v.Level, string(v.ActorType), actorID, actorName,
		targetID, targetName, v.ResourceType, v.ResourceID, v.IPAddress, v.UserAgent, details,
	}
	for i := range row {
		row[i] = csvSafe(row[i])
	}
	return row
}

// csvSafe keeps a spreadsheet from running a cell as a formula (CSV
// injection: a user agent or a name starting with "=", "+", "-", "@").
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
