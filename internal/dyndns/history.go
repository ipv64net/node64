package dyndns

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Verlauf: jeder Aufruf bei ipv64 (dyn_updates) und jede IP-Pruefung (dyn_checks), mit Filtern.

// Aufbewahrung (Tage, 0 = unbegrenzt)
var (
	KeepChecksOptions  = []int{7, 30, 90, 365}
	KeepUpdatesOptions = []int{90, 365, 0}
	historyDays        = []int{1, 7, 30, 0}
)

const historyLimit = 300

type updateRow struct {
	Time     time.Time
	TargetID int64
	Target   string
	Trigger  string
	Sent4    string
	Sent6    string
	Prefix   string
	HTTP     int
	Status   string
	Info     string
	OK       bool
	Err      string
	Ms       int64
}

type historyData struct {
	Tab      string // updates, checks
	Target   int64
	Fam      string
	Result   string // ok, err (Updates) bzw. changed, err (Pruefungen)
	Days     int
	DaysOpts []int
	Targets  []*Target
	Updates  []updateRow
	Checks   []checkRow
	Limited  bool // mehr als historyLimit Treffer
}

func (m *Module) pageHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	d := historyData{Tab: q.Get("tab"), Fam: q.Get("fam"), Result: q.Get("result"), DaysOpts: historyDays, Days: 7}
	if d.Tab != "checks" {
		d.Tab = "updates"
	}
	if n, err := strconv.Atoi(q.Get("days")); err == nil && in(strconv.Itoa(n), []string{"0", "1", "7", "30"}) {
		d.Days = n
	}
	d.Target, _ = strconv.ParseInt(q.Get("target"), 10, 64)
	if d.Fam != "4" && d.Fam != "6" {
		d.Fam = ""
	}
	d.Targets, _ = m.Targets(ctx)
	var where []string
	var args []any
	if d.Days > 0 {
		where, args = append(where, "time >= ?"), append(args, store.FormatTime(time.Now().AddDate(0, 0, -d.Days)))
	}
	if d.Tab == "updates" {
		if d.Target > 0 {
			where, args = append(where, "target_id = ?"), append(args, d.Target)
		}
		switch d.Result {
		case "ok":
			where = append(where, "ok = 1")
		case "err":
			where = append(where, "ok = 0")
		default:
			d.Result = ""
		}
		d.Updates, d.Limited = m.queryUpdates(ctx, where, args)
	} else {
		if d.Fam != "" {
			where, args = append(where, "family = ?"), append(args, d.Fam)
		}
		switch d.Result {
		case "changed":
			where = append(where, "changed = 1")
		case "err":
			where = append(where, "ip = ''")
		default:
			d.Result = ""
		}
		d.Checks, d.Limited = m.queryChecks(ctx, where, args)
	}
	m.g.Render(w, r, http.StatusOK, Name+"/history", "dyn.history.title", d)
}

func whereSQL(where []string) string {
	if len(where) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(where, " AND ")
}

func (m *Module) queryUpdates(ctx context.Context, where []string, args []any) ([]updateRow, bool) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT time, target_id, target, trigger, sent4, sent6, sent_prefix, http_status, status, info, ok, error, duration_ms
		FROM dyn_updates`+whereSQL(where)+` ORDER BY id DESC LIMIT `+strconv.Itoa(historyLimit+1), args...)
	if err != nil {
		m.log.Error("history", "err", err)
		return nil, false
	}
	defer rows.Close()
	var out []updateRow
	for rows.Next() {
		var u updateRow
		var t string
		var ok int
		if rows.Scan(&t, &u.TargetID, &u.Target, &u.Trigger, &u.Sent4, &u.Sent6, &u.Prefix, &u.HTTP, &u.Status, &u.Info, &ok, &u.Err, &u.Ms) == nil {
			u.Time, u.OK = store.ParseTime(t), ok == 1
			out = append(out, u)
		}
	}
	if len(out) > historyLimit {
		return out[:historyLimit], true
	}
	return out, false
}

func (m *Module) queryChecks(ctx context.Context, where []string, args []any) ([]checkRow, bool) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT time, family, source, ip, error, duration_ms, changed FROM dyn_checks`+whereSQL(where)+
		` ORDER BY id DESC LIMIT `+strconv.Itoa(historyLimit+1), args...)
	if err != nil {
		m.log.Error("history", "err", err)
		return nil, false
	}
	defer rows.Close()
	var out []checkRow
	for rows.Next() {
		var c checkRow
		var t string
		var ch int
		if rows.Scan(&t, &c.Family, &c.Source, &c.IP, &c.Err, &c.Ms, &ch) == nil {
			c.Time, c.Changed = store.ParseTime(t), ch == 1
			out = append(out, c)
		}
	}
	if len(out) > historyLimit {
		return out[:historyLimit], true
	}
	return out, false
}

// callsSince zaehlt die Aufrufe dieser Node bei ipv64 (fuer die Limit-Anzeige).
func (m *Module) callsSince(ctx context.Context, since time.Time) int {
	var n int
	_ = m.core.Reader().QueryRowContext(ctx, `SELECT count(*) FROM dyn_updates WHERE time >= ? AND http_status > 0`, store.FormatTime(since)).Scan(&n)
	return n
}
