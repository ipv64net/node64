package dyndns

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/store"
)

//go:embed templates
var templateFS embed.FS

// Templates liefert die Seiten des Moduls (module.Templater).
func (m *Module) Templates() fs.FS {
	sub, _ := fs.Sub(templateFS, "templates")
	return sub
}

// uiRoutes registriert die Seiten.
func (m *Module) uiRoutes(mux *http.ServeMux, g module.Guards) {
	m.g = g
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /dyndns", page(m.pageOverview))
	mux.Handle("POST /dyndns/check", page(m.pageCheckNow))
	mux.Handle("POST /dyndns/settings", page(m.pageSettings))
	mux.Handle("POST /dyndns/cluster", page(m.pageCluster))
	mux.Handle("GET /dyndns/history", page(m.pageHistory))
	m.targetRoutes(mux, page)
}

// famView ist eine Adressfamilie fuer die Anzeige.
type famView struct {
	Fam       int
	IP        string
	Prefix    string
	Source    string
	CheckedAt time.Time
	ChangedAt time.Time
	Err       string
	NoRoute   bool
	Temporary bool // von aussen gesehene IPv6 ist eine Privacy-Adresse dieses Hosts
}

type checkRow struct {
	Time    time.Time
	Family  string
	Source  string
	IP      string
	Err     string
	Ms      int64
	Changed bool
}

// targetGroup sind die Ziele einer Domain (Domain selbst zuerst, dann die Unterhosts).
type targetGroup struct {
	Domain string
	Items  []*Target
}

func groupTargets(list []*Target) []targetGroup {
	var out []targetGroup
	for _, t := range list { // Targets() ist nach Domain und Host sortiert
		if len(out) == 0 || out[len(out)-1].Domain != t.Domain {
			out = append(out, targetGroup{Domain: t.Domain})
		}
		g := &out[len(out)-1]
		g.Items = append(g.Items, t)
	}
	return out
}

type overviewData struct {
	Idle      bool // kein aktives Ziel: Pruefung ruht
	Targets   int
	List      []*Target
	Groups    []targetGroup
	Limit     limitInfo
	KeepC     int
	KeepU     int
	KeepCOpts []int
	KeepUOpts []int
	NotifyIP  bool
	NotifyErr bool
	NotifyLim bool
	HasKey    bool
	Account   ipv64api.AccountInfo
	V4, V6    famView
	Fams      []famView // V4, V6 fuer die Schleife im Template
	Local     []ifAddr
	Checks    []checkRow
	NextAt    time.Time
	Interval  int
	Intervals []int
	Source4   string
	Source6   string
	Net       netInfo // Anschluss-Analyse (CGNAT/DS-Lite)
	NetHops   string
	Cluster   clusterView // zustaendige Node im Cluster
}

func (m *Module) famView(fam int, local []ifAddr) famView {
	s := m.state(fam)
	v := famView{Fam: fam, Source: s.Source, CheckedAt: s.CheckedAt, ChangedAt: s.ChangedAt, Err: s.Err, NoRoute: s.NoRoute}
	if s.IP.IsValid() {
		v.IP = s.IP.String()
		if fam == 6 {
			v.Prefix = prefix64(s.IP).String()
			for _, l := range local {
				if l.Addr == s.IP && l.Temporary {
					v.Temporary = true
				}
			}
		}
	}
	return v
}

func (m *Module) pageOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := overviewData{Local: localIPv6(), Intervals: IntervalOptions, Interval: int(m.interval() / time.Minute),
		Source4: m.core.SettingOr(ctx, SetSource4, ""), Source6: m.core.SettingOr(ctx, SetSource6, "")}
	d.V4, d.V6 = m.famView(4, d.Local), m.famView(6, d.Local)
	d.Fams = []famView{d.V4, d.V6}
	d.Net = m.lastNetInfo(ctx)
	d.NetHops = strings.Join(d.Net.Hops, " → ")
	last := d.V4.CheckedAt
	if d.V6.CheckedAt.After(last) {
		last = d.V6.CheckedAt
	}
	if !last.IsZero() {
		d.NextAt = last.Add(m.interval())
	}
	d.List, _ = m.Targets(ctx)
	d.Targets, d.Groups = len(d.List), groupTargets(d.List)
	d.Idle = !m.hasActive(ctx)
	d.Cluster = m.clusterView(ctx)
	d.KeepC, d.KeepU = m.keepDays(ctx, SetKeepChecks, 30), m.keepDays(ctx, SetKeepUpdates, 365)
	d.KeepCOpts, d.KeepUOpts = KeepChecksOptions, KeepUpdatesOptions
	d.NotifyIP, d.NotifyErr, d.NotifyLim = m.notifyOn(ctx, SetNotifyIP), m.notifyOn(ctx, SetNotifyFail), m.notifyOn(ctx, SetNotifyLimit)
	if d.HasKey = m.keyOf(ctx) != ""; d.HasKey {
		d.Account = m.key.Info(ctx)
		m.refreshLimit(ctx, limitPage)
		d.Limit = m.limit(ctx)
	}
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT time, family, source, ip, error, duration_ms, changed FROM dyn_checks ORDER BY id DESC LIMIT 12`)
	if err == nil {
		for rows.Next() {
			var c checkRow
			var t string
			var ch int
			if rows.Scan(&t, &c.Family, &c.Source, &c.IP, &c.Err, &c.Ms, &ch) == nil {
				c.Time, c.Changed = store.ParseTime(t), ch == 1
				d.Checks = append(d.Checks, c)
			}
		}
		rows.Close()
	}
	m.g.Render(w, r, http.StatusOK, Name+"/overview", "dyn.title", d)
}

func (m *Module) pageCheckNow(w http.ResponseWriter, r *http.Request) {
	m.audit(r, "dyndns.check", "", "")
	if !m.checkNow(30 * time.Second) {
		m.g.Flash(w, r, "warning", m.g.T(r, "dyn.conn.check_busy"))
	}
	http.Redirect(w, r, "/dyndns", http.StatusSeeOther)
}

func (m *Module) pageSettings(w http.ResponseWriter, r *http.Request) {
	atoi := func(k string) int { n, _ := strconv.Atoi(r.PostFormValue(k)); return n }
	s := moduleSettings{Interval: atoi("interval"), Source4: r.PostFormValue("source4"), Source6: r.PostFormValue("source6"),
		KeepChecks: atoi("keep_checks"), KeepUpdates: atoi("keep_updates"),
		NotifyIP: r.PostFormValue("notify_ip") == "on", NotifyFail: r.PostFormValue("notify_fail") == "on", NotifyLimit: r.PostFormValue("notify_limit") == "on"}
	if err := m.saveSettings(r.Context(), s); err != nil {
		msg := err.Error()
		if errors.Is(err, errSettings) {
			msg = m.g.T(r, "dyn.settings.invalid")
		}
		m.g.Flash(w, r, "danger", msg)
		http.Redirect(w, r, "/dyndns#settings", http.StatusSeeOther)
		return
	}
	m.audit(r, "dyndns.settings", "settings", "interval="+strconv.Itoa(s.Interval)+"m")
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, "/dyndns#settings", http.StatusSeeOther)
}

// pageCluster waehlt die bevorzugte Node im Cluster.
func (m *Module) pageCluster(w http.ResponseWriter, r *http.Request) {
	id := r.PostFormValue("preferred")
	if err := m.setPreferred(r.Context(), id); err != nil {
		m.g.Flash(w, r, "danger", m.g.T(r, "dyn.cluster.invalid"))
		http.Redirect(w, r, "/dyndns", http.StatusSeeOther)
		return
	}
	m.audit(r, "dyndns.cluster", "preferred", id)
	m.g.Flash(w, r, "success", m.g.T(r, "dyn.cluster.saved"))
	http.Redirect(w, r, "/dyndns", http.StatusSeeOther)
}

func itoaList(l []int) []string {
	out := make([]string, len(l))
	for i, n := range l {
		out[i] = strconv.Itoa(n)
	}
	return out
}

// keepDays liest eine Aufbewahrung in Tagen (0 = unbegrenzt).
func (m *Module) keepDays(ctx context.Context, key string, def int) int {
	n, err := strconv.Atoi(m.core.SettingOr(ctx, key, ""))
	if err != nil || n < 0 {
		return def
	}
	return n
}

// audit schreibt ins Audit-Log ueber den Kern (gleiche Benutzer- und IP-Ermittlung); target ist der Name.
func (m *Module) audit(r *http.Request, action, target, details string) {
	if m.g.Audit != nil {
		m.g.Audit(r, action, target, details)
		return
	}
	ip := r.RemoteAddr
	if m.g.ClientIP != nil {
		ip = m.g.ClientIP(r)
	} else if i := strings.LastIndex(ip, ":"); i > 0 {
		ip = strings.Trim(ip[:i], "[]")
	}
	actor := "api"
	if m.g.Actor != nil {
		actor = m.g.Actor(r)
	}
	if err := m.core.Audit(r.Context(), store.AuditEntry{Actor: actor, Action: action, Target: target, Details: details, IP: ip, Origin: "local"}); err != nil {
		m.log.Error("audit", "err", err)
	}
}
