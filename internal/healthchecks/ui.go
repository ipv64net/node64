package healthchecks

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/scheduler"
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
	mux.Handle("GET /healthchecks", page(m.pageList))
	mux.Handle("GET /healthchecks/new", page(m.pageForm))
	mux.Handle("POST /healthchecks/new", page(m.pageFormSubmit))
	mux.Handle("POST /healthchecks/bulk", page(m.pageBulk))
	mux.Handle("GET /healthchecks/{token}", page(m.pageDetail))
	mux.Handle("GET /healthchecks/{token}/edit", page(m.pageForm))
	mux.Handle("POST /healthchecks/{token}/edit", page(m.pageFormSubmit))
	mux.Handle("POST /healthchecks/{token}/action", page(m.pageAction))
	m.maintenanceRoutes(mux, page)
}

// ---------------------------------------------------------------- Darstellung

// Pill ist eine Messung in der Pillenleiste.
type Pill struct {
	Class   string // up, down, maintenance, dependent
	Label   string // Statuswort fuer den Tooltip
	When    string // Zeitpunkt, formatiert
	Latency string // "12.3 ms" oder leer
	Message string // gekuerzte Meldung
}

type row struct {
	Check    *Check
	State    string
	Status   string
	Latency  float64
	Pills    []Pill
	Changed  time.Time
	NextAt   time.Time
	Reason   string
	Message  string
	Maint    bool
	Retrying bool
}

// group ist ein Abschnitt der Liste (eine frei benannte Gruppe).
type group struct {
	Key, Name        string
	Rows             []row
	Up, Down, Others int
}

type listData struct {
	Docker      []row              // Docker-Checks (eigene Tabelle)
	Unwatched   []checks.Container // Container ohne Check
	DockerErr   string
	DockerShown bool
	Groups      []group
	Grouped     bool     // mindestens ein Check hat eine Gruppe
	AllGrps     []string // alle Gruppennamen (Filter, Vorschlaege)
	Rows        []row
	Types       []checks.Type
	Tags        []string
	States      []string
	Filter      map[string]string
	Sort        string
	Dir         string
	Counts      map[string]int
	Total       int
}

var listStates = []string{"up", "down", "stabilizing", "flapping", "dependent", "pending", "paused"}

func (m *Module) liveRuntime(c *Check) scheduler.Runtime {
	if s := m.scheduler(); s != nil {
		if rt, ok := s.Runtime(c.Token); ok {
			return rt
		}
	}
	return c.Runtime
}

func (m *Module) rowOf(ctx context.Context, lang string, c *Check, pills map[string][]Pill) row {
	rt := m.liveRuntime(c)
	r := row{Check: c, State: string(rt.State), Status: string(rt.LastStatus), Latency: msf(rt.LastLatency), Pills: pills[c.Token],
		Changed: rt.Since, NextAt: rt.NextCheck, Reason: string(rt.LastReason), Message: rt.LastMessage,
		Maint: m.st.InMaintenance(ctx, c.Token, time.Now()), Retrying: rt.State == scheduler.StateUp && rt.ConsecutiveFail > 0}
	if r.State == "" {
		r.State = "pending"
	}
	return r
}

// pillsFor liefert die letzten n Messungen je Check als Pillen (aelteste zuerst).
func (m *Module) pillsFor(ctx context.Context, lang string, loc *time.Location, n int) (map[string][]Pill, error) {
	tr := m.translator(lang)
	rows, err := m.st.r.QueryContext(ctx, `SELECT token, time, status, latency_ms, flags, reason, message FROM (
		SELECT token, time, status, latency_ms, flags, reason, message, row_number() OVER (PARTITION BY token ORDER BY node_seq DESC) AS rn FROM hc_measurements
	) WHERE rn <= ? ORDER BY token, time`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]Pill{}
	for rows.Next() {
		var token, t, reason, message string
		var status, flags int
		var lat float64
		if err := rows.Scan(&token, &t, &status, &lat, &flags, &reason, &message); err != nil {
			return nil, err
		}
		class, label := "down", tr("hc.state.down")
		if status == 1 {
			class, label = "up", tr("hc.state.up")
		}
		if flags&FlagMaintenance != 0 {
			class = "maintenance"
			label += " · " + tr("hc.maintenance")
		} else if flags&FlagDependent != 0 {
			class = "dependent"
			label += " · " + tr("hc.state.dependent")
		}
		ts := pt(t)
		if loc != nil {
			ts = ts.In(loc)
		}
		when := ts.Format("02.01.2006 15:04:05")
		if lang != "de" {
			when = ts.Format("2006-01-02 15:04:05")
		}
		pl := Pill{Class: class, Label: label, When: when, Message: message}
		if lat > 0 {
			pl.Latency = fmt.Sprintf("%.1f ms", lat)
		}
		if r := []rune(message); len(r) > 90 {
			pl.Message = string(r[:90]) + "…"
		}
		out[token] = append(out[token], pl)
	}
	return out, rows.Err()
}

func (m *Module) pageList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	lang := m.g.Lang(r)
	list, err := m.st.Checks(ctx)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	pills, err := m.pillsFor(ctx, lang, m.g.Timezone(r), 30)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	f := map[string]string{"state": q.Get("state"), "type": q.Get("type"), "tag": q.Get("tag"), "group": q.Get("group"), "q": strings.TrimSpace(q.Get("q"))}
	d := listData{Types: checks.Types, States: listStates, Filter: f, Sort: q.Get("sort"), Dir: q.Get("dir"), Counts: map[string]int{}}
	tagSet, grpSet := map[string]bool{}, map[string]bool{}
	for _, c := range list {
		for _, t := range c.Tags {
			tagSet[t] = true
		}
		if c.Group != "" {
			grpSet[c.Group] = true
		}
		rw := m.rowOf(ctx, lang, c, pills)
		d.Counts[rw.State]++
		d.Total++
		if f["state"] != "" && rw.State != f["state"] {
			continue
		}
		if f["type"] != "" && string(c.Type) != f["type"] {
			continue
		}
		if f["tag"] != "" && !contains(c.Tags, f["tag"]) {
			continue
		}
		if f["group"] != "" && c.Group != f["group"] {
			continue
		}
		if f["q"] != "" && !strings.Contains(strings.ToLower(c.Name+" "+c.Target+" "+c.Group+" "+strings.Join(c.Tags, " ")), strings.ToLower(f["q"])) {
			continue
		}
		if c.Type == checks.TypeDocker {
			d.Docker = append(d.Docker, rw)
			continue
		}
		d.Rows = append(d.Rows, rw)
	}
	// Container des Hosts, die noch keinen Check haben (nur wenn der Socket da ist)
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	if cs, err := checks.ListContainers(cctx, ""); err == nil {
		watched := map[string]bool{}
		for _, c := range list {
			if c.Type == checks.TypeDocker {
				watched[strings.TrimPrefix(c.Target, "/")] = true
			}
		}
		for _, ct := range cs {
			if !watched[ct.Name] && !watched[ct.ID] {
				d.Unwatched = append(d.Unwatched, ct)
			}
		}
		d.DockerShown = true
	} else if len(d.Docker) > 0 {
		d.DockerErr, d.DockerShown = err.Error(), true
	}
	cancel()
	sortRows(d.Docker, d.Sort, d.Dir == "desc")
	for t := range tagSet {
		d.Tags = append(d.Tags, t)
	}
	sort.Strings(d.Tags)
	for g := range grpSet {
		d.AllGrps = append(d.AllGrps, g)
	}
	sort.Slice(d.AllGrps, func(i, j int) bool { return strings.ToLower(d.AllGrps[i]) < strings.ToLower(d.AllGrps[j]) })
	sortRows(d.Rows, d.Sort, d.Dir == "desc")
	d.Grouped = len(d.AllGrps) > 0
	d.Groups = groupRows(d.Rows, d.AllGrps, m.g.T(r, "hc.group.none"))
	m.g.Render(w, r, http.StatusOK, Name+"/list", "nav.healthchecks", d)
}

// groupRows verteilt die (schon sortierten) Zeilen auf Gruppen; Checks ohne Gruppe kommen zuletzt.
func groupRows(rows []row, names []string, none string) []group {
	idx := map[string]int{}
	var out []group
	for i, n := range names {
		idx[n] = i
		out = append(out, group{Key: "g" + strconv.Itoa(i), Name: n})
	}
	out = append(out, group{Key: "g-none", Name: none})
	for _, r := range rows {
		i, ok := idx[r.Check.Group]
		if !ok {
			i = len(out) - 1
		}
		g := &out[i]
		g.Rows = append(g.Rows, r)
		switch r.State {
		case "up":
			g.Up++
		case "down", "flapping":
			g.Down++
		default:
			g.Others++
		}
	}
	res := out[:0]
	for _, g := range out {
		if len(g.Rows) > 0 {
			res = append(res, g)
		}
	}
	return res
}

var stateOrder = map[string]int{"down": 0, "flapping": 1, "dependent": 2, "stabilizing": 3, "pending": 4, "up": 5, "paused": 6}

func sortRows(rows []row, key string, desc bool) {
	less := func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch key {
		case "state":
			if stateOrder[a.State] != stateOrder[b.State] {
				return stateOrder[a.State] < stateOrder[b.State]
			}
		case "type":
			if a.Check.Type != b.Check.Type {
				return a.Check.Type < b.Check.Type
			}
		case "latency":
			if a.Latency != b.Latency {
				return a.Latency < b.Latency
			}
		case "changed":
			if !a.Changed.Equal(b.Changed) {
				return a.Changed.After(b.Changed)
			}
		}
		return strings.ToLower(a.Check.Name) < strings.ToLower(b.Check.Name)
	}
	if desc {
		sort.SliceStable(rows, func(i, j int) bool { return less(j, i) })
	} else {
		sort.SliceStable(rows, less)
	}
}

// ---------------------------------------------------------------- Detailseite

type rangeStat struct {
	Range     string
	UpPercent float64
	AvgMS     float64
	Count     int
}

type detailData struct {
	Channels   []channelOpt
	Row        row
	JSON       checkJSON
	Pills      []Pill
	Ranges     []rangeStat
	Events     []Event
	Incidents  []Incident
	Last       *Measurement
	LastJSON   string
	Params     map[string]any
	ParentName string
	Children   []*Check
	PushURL    string
}

func (m *Module) loadPage(w http.ResponseWriter, r *http.Request) *Check {
	token := r.PathValue("token")
	if !tokenRe.MatchString(token) {
		m.g.Render(w, r, http.StatusNotFound, Name+"/missing", "hc.missing", nil)
		return nil
	}
	c, err := m.st.Check(r.Context(), token)
	if err != nil {
		m.fail(w, r, err)
		return nil
	}
	if c == nil {
		m.g.Render(w, r, http.StatusNotFound, Name+"/missing", "hc.missing", nil)
		return nil
	}
	return c
}

func (m *Module) pageDetail(w http.ResponseWriter, r *http.Request) {
	c := m.loadPage(w, r)
	if c == nil {
		return
	}
	ctx := r.Context()
	lang := m.g.Lang(r)
	pills, err := m.pillsFor(ctx, lang, m.g.Timezone(r), 60)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	d := detailData{Row: m.rowOf(ctx, lang, c, pills), JSON: m.toJSON(c, r), Pills: pills[c.Token], PushURL: ""}
	now := time.Now().UTC()
	for _, rg := range []string{"24h", "30d", "1y"} {
		st, err := m.st.Stats(ctx, c.Token, rg, now)
		if err == nil {
			d.Ranges = append(d.Ranges, rangeStat{Range: rg, UpPercent: st.UpPercent, AvgMS: st.AvgMS, Count: st.Count})
		}
	}
	d.Events, _ = m.st.Events(ctx, c.Token, 50, 0)
	d.Incidents, _ = m.st.Incidents(ctx, c.Token, 10)
	if ms, err := m.st.Measurements(ctx, c.Token, time.Time{}, time.Time{}, 1, 0); err == nil && len(ms) > 0 {
		d.Last = &ms[0]
		if b, err := json.MarshalIndent(ms[0].Details, "", "  "); err == nil {
			d.LastJSON = string(b)
		}
	}
	_ = json.Unmarshal(c.Params, &d.Params)
	if c.Parent != "" {
		if p, _ := m.st.Check(ctx, c.Parent); p != nil {
			d.ParentName = p.Name
		}
	}
	all, _ := m.st.Checks(ctx)
	for _, x := range all {
		if x.Parent == c.Token {
			d.Children = append(d.Children, x)
		}
	}
	d.PushURL = d.JSON.PushURL
	if chans, err := m.channels(ctx); err == nil {
		for _, ch := range chans {
			sel := false
			for _, id := range c.Channels {
				if id == ch.ID {
					sel = true
				}
			}
			if sel || (len(c.Channels) == 0 && ch.Default) {
				d.Channels = append(d.Channels, channelOpt{ID: ch.ID, Name: ch.Name, Type: string(ch.Type), Default: ch.Default, Selected: sel})
			}
		}
	}
	m.g.Render(w, r, http.StatusOK, Name+"/detail", "nav.healthchecks", d)
}

// ---------------------------------------------------------------- Formular

// Crumb: Name des Checks in den Brotkrumen.
func (d detailData) Crumb() string {
	if d.Row.Check != nil {
		return d.Row.Check.Name
	}
	return ""
}

type formData struct {
	Edit       bool
	Token      string
	Form       map[string]string
	Errors     map[string]string
	Types      []checks.Type
	Parents    []*Check
	Groups     []string           // vorhandene Gruppen (Vorschlaege)
	Containers []checks.Container // Docker: Container des Hosts (Vorschlaege)
	DockerErr  string
	DockerHost string
	IPModes    []string
	Error      string
	Channels   []channelOpt
	// Hybrid-Vorbereitung: Messstellen und Bewertung (aktiv erst mit ipv64-Verknuepfung)
	Policies   []string
	Locations  []string
	Executions []string
	Linked     bool
}

type channelOpt struct {
	ID       int64
	Name     string
	Type     string
	Default  bool
	Selected bool
}

// formDefaults sind die Vorgaben eines neuen Checks.
func formDefaults() map[string]string {
	return map[string]string{
		"type": "http", "interval_seconds": "60", "retry_interval_seconds": "20", "retries": "1", "stabilize": "3",
		"connect_timeout_seconds": "5", "timeout_seconds": "10", "ip_mode": "auto", "notify_down": "on", "notify_up": "on",
		"execution": "local", "policy": PolicyAll, "locations": "nbg,fsn",
		"method": "GET", "accept_status": "200-299", "follow_redirects": "on", "max_redirects": "5",
		"count": "3", "max_loss_percent": "50", "cert_port": "443", "min_days": "14", "port_expect": "open",
		"period_seconds": "3600", "grace_seconds": "600",
	}
}

// formFromCheck fuellt das Formular aus einem Check.
func formFromCheck(c *Check) map[string]string {
	f := formDefaults()
	f["name"], f["type"], f["target"] = c.Name, string(c.Type), c.Target
	f["interval_seconds"] = strconv.Itoa(int(c.Interval.Seconds()))
	f["retry_interval_seconds"] = strconv.Itoa(int(c.RetryInterval.Seconds()))
	f["retries"], f["stabilize"] = strconv.Itoa(c.Retries), strconv.Itoa(c.Stabilize)
	f["connect_timeout_seconds"] = strconv.FormatFloat(c.ConnectTimeout.Seconds(), 'f', -1, 64)
	f["timeout_seconds"] = strconv.FormatFloat(c.TotalTimeout.Seconds(), 'f', -1, 64)
	f["ip_mode"], f["tags"], f["description"], f["parent"] = string(c.IPMode), strings.Join(c.Tags, ", "), c.Description, c.Parent
	f["group"] = c.Group
	f["invert"], f["critical"], f["paused"] = onOff(c.Invert), onOff(c.Critical), onOff(c.Paused)
	f["notify_down"], f["notify_up"] = onOff(c.NotifyDown), onOff(c.NotifyUp)
	f["repeat_minutes"] = strconv.Itoa(c.RepeatMinutes)
	f["execution"], f["policy"], f["notify_degraded"] = c.Execution, c.Policy, onOff(c.NotifyDegraded)
	if len(c.Locations) > 0 {
		f["locations"] = strings.Join(c.Locations, ",")
	}
	ids := make([]string, 0, len(c.Channels))
	for _, id := range c.Channels {
		ids = append(ids, strconv.FormatInt(id, 10))
	}
	f["channels"] = strings.Join(ids, ",")
	var p map[string]any
	_ = json.Unmarshal(c.Params, &p)
	str := func(k string) string {
		if v, ok := p[k]; ok && v != nil {
			switch t := v.(type) {
			case float64:
				return strconv.FormatFloat(t, 'f', -1, 64)
			case bool:
				return onOff(t)
			case string:
				return t
			}
		}
		return ""
	}
	set := func(form, key string) {
		if v := str(key); v != "" {
			f[form] = v
		}
	}
	switch c.Type {
	case checks.TypeHTTP, checks.TypeKeyword:
		set("method", "method")
		set("accept_status", "accept_status")
		if v, ok := p["follow_redirects"]; ok {
			f["follow_redirects"] = onOff(v == true)
		}
		set("max_redirects", "max_redirects")
		f["insecure_tls"] = str("insecure_tls")
		set("body", "body")
		set("basic_user", "basic_user")
		set("basic_password", "basic_password")
		set("keyword", "keyword")
		f["keyword_absent"] = str("keyword_absent")
		if h, ok := p["headers"].(map[string]any); ok {
			var lines []string
			for k, v := range h {
				lines = append(lines, k+": "+fmt.Sprint(v))
			}
			sort.Strings(lines)
			f["headers"] = strings.Join(lines, "\n")
		}
	case checks.TypeICMP:
		set("count", "count")
		set("max_loss_percent", "max_loss_percent")
		set("max_latency_ms", "max_latency_ms")
	case checks.TypeTCP:
		set("tcp_port", "port")
		set("send", "send")
		set("expect", "expect")
		f["tcp_tls"] = str("tls")
	case checks.TypePort:
		set("port_port", "port")
		set("port_expect", "expect")
	case checks.TypeCert:
		set("cert_port", "port")
		set("min_days", "min_days")
		set("server_name", "server_name")
		f["skip_chain"], f["skip_hostname"] = str("skip_chain"), str("skip_hostname")
	case checks.TypePush:
		set("period_seconds", "period_seconds")
		set("grace_seconds", "grace_seconds")
	case checks.TypeDocker:
		set("docker_host", "host")
	}
	return f
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return ""
}

// checkFromForm baut die API-Eingabe aus dem Formular.
func checkFromForm(r *http.Request) (checkJSON, error) {
	v := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	on := func(k string) bool { return r.PostFormValue(k) == "on" }
	intp := func(k string) (*int, error) {
		s := v(k)
		if s == "" {
			return nil, nil
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("%s: not a number", k)
		}
		return &n, nil
	}
	floatp := func(k string) (*float64, error) {
		s := v(k)
		if s == "" {
			return nil, nil
		}
		f, err := strconv.ParseFloat(strings.ReplaceAll(s, ",", "."), 64)
		if err != nil {
			return nil, fmt.Errorf("%s: not a number", k)
		}
		return &f, nil
	}
	var err error
	in := checkJSON{Name: v("name"), Type: v("type"), Target: v("target"), IPMode: v("ip_mode"), Description: v("description"),
		Execution: v("execution"), Policy: v("policy"), Locations: r.Form["locations"]}
	if in.Locations == nil {
		in.Locations = []string{}
	}
	if in.IntervalSeconds, err = intp("interval_seconds"); err != nil {
		return in, err
	}
	if in.RetryIntervalSeconds, err = intp("retry_interval_seconds"); err != nil {
		return in, err
	}
	if in.Retries, err = intp("retries"); err != nil {
		return in, err
	}
	if in.Stabilize, err = intp("stabilize"); err != nil {
		return in, err
	}
	if in.ConnectTimeoutSeconds, err = floatp("connect_timeout_seconds"); err != nil {
		return in, err
	}
	if in.TimeoutSeconds, err = floatp("timeout_seconds"); err != nil {
		return in, err
	}
	if in.RepeatMinutes, err = intp("repeat_minutes"); err != nil {
		return in, err
	}
	b := func(x bool) *bool { return &x }
	in.Invert, in.Critical, in.Paused = b(on("invert")), b(on("critical")), b(on("paused"))
	in.NotifyDown, in.NotifyUp, in.NotifyDegraded = b(on("notify_down")), b(on("notify_up")), b(on("notify_degraded"))
	parent := v("parent")
	in.Parent = &parent
	grp := v("group")
	in.Group = &grp
	in.Tags = []string{}
	for _, t := range strings.Split(v("tags"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			in.Tags = append(in.Tags, t)
		}
	}
	in.Channels = []int64{}
	_ = r.ParseForm()
	for _, id := range r.PostForm["channels"] {
		if n, err := strconv.ParseInt(id, 10, 64); err == nil {
			in.Channels = append(in.Channels, n)
		}
	}
	p := map[string]any{}
	num := func(key, form string) error {
		if s := v(form); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil {
				return fmt.Errorf("%s: not a number", form)
			}
			p[key] = n
		}
		return nil
	}
	switch checks.Type(in.Type) {
	case checks.TypeHTTP, checks.TypeKeyword:
		if s := v("method"); s != "" {
			p["method"] = s
		}
		if s := v("accept_status"); s != "" {
			p["accept_status"] = s
		}
		p["follow_redirects"] = on("follow_redirects")
		if err := num("max_redirects", "max_redirects"); err != nil {
			return in, err
		}
		if on("insecure_tls") {
			p["insecure_tls"] = true
		}
		if s := r.PostFormValue("body"); strings.TrimSpace(s) != "" {
			p["body"] = s
		}
		if s := v("basic_user"); s != "" {
			p["basic_user"] = s
			p["basic_password"] = r.PostFormValue("basic_password")
		}
		if h := strings.TrimSpace(r.PostFormValue("headers")); h != "" {
			hm := map[string]string{}
			for _, line := range strings.Split(h, "\n") {
				if k, val, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) != "" {
					hm[strings.TrimSpace(k)] = strings.TrimSpace(val)
				}
			}
			p["headers"] = hm
		}
		if checks.Type(in.Type) == checks.TypeKeyword {
			p["keyword"] = v("keyword")
			if on("keyword_absent") {
				p["keyword_absent"] = true
			}
		}
	case checks.TypeICMP:
		for _, k := range []string{"count", "max_loss_percent", "max_latency_ms"} {
			if err := num(k, k); err != nil {
				return in, err
			}
		}
	case checks.TypeTCP:
		if err := num("port", "tcp_port"); err != nil {
			return in, err
		}
		if s := v("send"); s != "" {
			p["send"] = s
		}
		if s := v("expect"); s != "" {
			p["expect"] = s
		}
		if on("tcp_tls") {
			p["tls"] = true
		}
	case checks.TypePort:
		if err := num("port", "port_port"); err != nil {
			return in, err
		}
		p["expect"] = v("port_expect")
	case checks.TypeCert:
		if err := num("port", "cert_port"); err != nil {
			return in, err
		}
		if err := num("min_days", "min_days"); err != nil {
			return in, err
		}
		if s := v("server_name"); s != "" {
			p["server_name"] = s
		}
		if on("skip_chain") {
			p["skip_chain"] = true
		}
		if on("skip_hostname") {
			p["skip_hostname"] = true
		}
	case checks.TypeDocker:
		if s := strings.TrimSpace(v("docker_host")); s != "" {
			p["host"] = s
		}
	case checks.TypePush:
		if err := num("period_seconds", "period_seconds"); err != nil {
			return in, err
		}
		if err := num("grace_seconds", "grace_seconds"); err != nil {
			return in, err
		}
	}
	in.Params, _ = json.Marshal(p)
	return in, nil
}

func (m *Module) formPage(w http.ResponseWriter, r *http.Request, status int, d formData) {
	all, _ := m.st.Checks(r.Context())
	seen := map[string]bool{}
	for _, c := range all {
		if c.Token != d.Token {
			d.Parents = append(d.Parents, c)
		}
		if c.Group != "" && !seen[c.Group] {
			seen[c.Group] = true
			d.Groups = append(d.Groups, c.Group)
		}
	}
	sort.Strings(d.Groups)
	d.DockerHost = checks.DefaultDockerHost()
	cctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	var derr error
	if d.Containers, derr = checks.ListContainers(cctx, d.Form["docker_host"]); derr != nil {
		d.DockerErr = derr.Error()
	}
	cancel()
	d.Types = checks.Types
	d.IPModes = []string{"auto", "ipv4", "ipv6", "both"}
	d.Policies, d.Locations, d.Executions = Policies, KnownLocations, []string{"local", "online", "both"}
	d.Linked = m.linked != nil && m.linked()
	if m.dispatcher != nil {
		selected := map[string]bool{}
		for _, id := range strings.Split(d.Form["channels"], ",") {
			selected[strings.TrimSpace(id)] = true
		}
		if chans, err := m.channels(r.Context()); err == nil {
			for _, ch := range chans {
				d.Channels = append(d.Channels, channelOpt{ID: ch.ID, Name: ch.Name, Type: string(ch.Type), Default: ch.Default, Selected: selected[strconv.FormatInt(ch.ID, 10)]})
			}
		}
	}
	if d.Errors == nil {
		d.Errors = map[string]string{}
	}
	title := "hc.new"
	if d.Edit {
		title = "hc.edit"
	}
	m.g.Render(w, r, status, Name+"/form", title, d)
}

func (m *Module) pageForm(w http.ResponseWriter, r *http.Request) {
	d := formData{Form: formDefaults()}
	if r.PathValue("token") != "" {
		c := m.loadPage(w, r)
		if c == nil {
			return
		}
		if c.Foreign() {
			m.g.Flash(w, r, "warning", m.errForeign(r).Error())
			http.Redirect(w, r, "/healthchecks/"+c.Token, http.StatusSeeOther)
			return
		}
		d.Edit, d.Token, d.Form = true, c.Token, formFromCheck(c)
	} else if t := r.URL.Query().Get("type"); t != "" {
		d.Form["type"] = t
		if v := strings.TrimSpace(r.URL.Query().Get("target")); v != "" {
			d.Form["target"] = v
		}
		if v := strings.TrimSpace(r.URL.Query().Get("name")); v != "" {
			d.Form["name"] = v
		}
	}
	m.formPage(w, r, http.StatusOK, d)
}

func (m *Module) pageFormSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var c *Check
	edit := r.PathValue("token") != ""
	if edit {
		if c = m.loadPage(w, r); c == nil {
			return
		}
		if c.Foreign() {
			m.g.Flash(w, r, "warning", m.errForeign(r).Error())
			http.Redirect(w, r, "/healthchecks/"+c.Token, http.StatusSeeOther)
			return
		}
	} else {
		c = &Check{Token: NewToken()}
	}
	d := formData{Edit: edit, Token: c.Token}
	in, err := checkFromForm(r)
	if err == nil {
		c.UpdatedBy = m.g.Actor(r)
		oldType := c.Type
		err = m.apply(c, in, !edit)
		if err == nil && c.Parent != "" {
			if cyc, cerr := m.parentCycle(r, c.Token, c.Parent); cerr != nil || cyc {
				err = fmt.Errorf("parent: %s", errText(cerr, "would create a cycle"))
			}
		}
		if err == nil {
			if edit {
				err = m.st.Update(ctx, c)
			} else {
				err = m.st.Insert(ctx, c)
			}
			if err == nil {
				c, _ = m.st.Check(ctx, c.Token)
				if s := m.scheduler(); s != nil {
					var rt *scheduler.Runtime
					if edit && oldType == c.Type {
						if live, ok := s.Runtime(c.Token); ok {
							rt = &live
						}
					}
					s.Upsert(c.SchedulerCheck(), rt)
				}
				m.audit(r, map[bool]string{true: "check.update", false: "check.create"}[edit], c)
				m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
				http.Redirect(w, r, "/healthchecks/"+c.Token, http.StatusSeeOther)
				return
			}
		}
	}
	// Fehler: Formular mit Eingaben und Meldung erneut zeigen
	_ = r.ParseForm()
	d.Form = formDefaults()
	for k := range r.PostForm {
		d.Form[k] = r.PostFormValue(k)
	}
	for _, k := range []string{"invert", "critical", "paused", "notify_down", "notify_up", "follow_redirects", "insecure_tls", "keyword_absent", "tcp_tls", "skip_chain", "skip_hostname"} {
		if r.PostFormValue(k) != "on" {
			d.Form[k] = ""
		}
	}
	d.Form["channels"] = strings.Join(r.PostForm["channels"], ",")
	d.Error = err.Error()
	m.formPage(w, r, http.StatusUnprocessableEntity, d)
}

// ---------------------------------------------------------------- Aktionen

// Foreign: Check einer anderen Node (hier nur lesbar).
func (c *Check) Foreign() bool { return c.Owner == "other" }

// Runnable: "Jetzt pruefen" ist nur moeglich, wenn diese Node den Check selbst misst.
func (c *Check) Runnable() bool { return c.MeasuredHere() && c.Type != checks.TypePush }

// errForeign: Aenderungen an Checks anderer Nodes sind hier nicht moeglich.
func (m *Module) errForeign(r *http.Request) error {
	return fmt.Errorf("%s", m.g.T(r, "hc.foreign_readonly"))
}

func (m *Module) pageAction(w http.ResponseWriter, r *http.Request) {
	c := m.loadPage(w, r)
	if c == nil {
		return
	}
	action := r.PostFormValue("action")
	back := "/healthchecks/" + c.Token
	if r.PostFormValue("back") == "list" {
		back = "/healthchecks"
	}
	if err := m.doAction(r, c, action); err != nil {
		m.g.Flash(w, r, "danger", err.Error())
	} else {
		m.g.Flash(w, r, "success", m.g.T(r, "hc.done."+action, "name", c.Name))
	}
	if action == "delete" {
		back = "/healthchecks"
	}
	if action == "clone" {
		if last := r.Header.Get("X-Clone-Token"); last != "" {
			back = "/healthchecks/" + last + "/edit"
		}
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (m *Module) doAction(r *http.Request, c *Check, action string) error {
	ctx := r.Context()
	if c.Foreign() && action != "clone" {
		return m.errForeign(r)
	}
	if action == "run" && !c.Runnable() && c.Type != checks.TypePush {
		return fmt.Errorf("%s", m.g.T(r, "hc.run_remote"))
	}
	switch action {
	case "pause", "resume":
		paused := action == "pause"
		if err := m.st.SetPaused(ctx, c.Token, paused, m.g.Actor(r)); err != nil {
			return err
		}
		nc, _ := m.st.Check(ctx, c.Token)
		if s := m.scheduler(); s != nil && nc != nil {
			s.Upsert(nc.SchedulerCheck(), nil)
		}
		m.PushState(c.Token)
		m.audit(r, "check."+action, c)
	case "run":
		if c.Type == checks.TypePush {
			return fmt.Errorf("%s", m.g.T(r, "hc.run_push"))
		}
		if s := m.scheduler(); s == nil || !s.RunNow(c.Token) {
			return fmt.Errorf("scheduler not running")
		}
	case "clone":
		n := *c
		n.Token, n.Name, n.Paused, n.Revision, n.UpdatedBy, n.Runtime = NewToken(), c.Name+" (copy)", true, 0, m.g.Actor(r), scheduler.Runtime{}
		if c.Owner == "other" {
			n.Execution = "local" // Kopie eines Checks einer anderen Node misst diese Node selbst
		}
		n.Owner = "self"
		if err := m.st.Insert(ctx, &n); err != nil {
			return err
		}
		if nc, _ := m.st.Check(ctx, n.Token); nc != nil {
			if s := m.scheduler(); s != nil {
				s.Upsert(nc.SchedulerCheck(), nil)
			}
			m.audit(r, "check.clone", nc)
			r.Header.Set("X-Clone-Token", n.Token)
		}
	case "delete":
		if s := m.scheduler(); s != nil {
			s.Remove(c.Token)
		}
		if err := m.st.Delete(ctx, c.Token); err != nil {
			return err
		}
		m.audit(r, "check.delete", c)
	default:
		return fmt.Errorf("unknown action")
	}
	return nil
}

func (m *Module) pageBulk(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	action := r.PostFormValue("action")
	n := 0
	for _, token := range r.PostForm["tokens"] {
		if !tokenRe.MatchString(token) {
			continue
		}
		c, err := m.st.Check(r.Context(), token)
		if err != nil || c == nil {
			continue
		}
		if action == "clone" {
			continue
		}
		if err := m.doAction(r, c, action); err == nil {
			n++
		}
	}
	m.g.Flash(w, r, "success", m.g.T(r, "hc.bulk.done", "count", n))
	http.Redirect(w, r, "/healthchecks", http.StatusSeeOther)
}

func (m *Module) fail(w http.ResponseWriter, r *http.Request, err error) {
	m.log.Error("page failed", "path", r.URL.Path, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// ---------------------------------------------------------------- Dashboard

func (m *Module) Dashboard(ctx context.Context) (*module.DashboardInfo, error) {
	list, err := m.st.Checks(ctx)
	if err != nil {
		return nil, err
	}
	info := &module.DashboardInfo{Module: Name, TitleKey: "nav.healthchecks", Path: "/healthchecks"}
	names := map[string]string{}
	for _, c := range list {
		names[c.Token] = c.Name
		switch m.liveRuntime(c).State {
		case scheduler.StateUp:
			info.OK++
		case scheduler.StateDown, scheduler.StateFlapping, scheduler.StateDependent:
			info.Down++
		case scheduler.StatePaused:
			info.Paused++
		default:
			info.Other++
		}
	}
	inc, _ := m.st.Incidents(ctx, "", 8)
	for _, i := range inc {
		info.Incidents = append(info.Incidents, module.IncidentInfo{Name: names[i.Token], Path: "/healthchecks/" + i.Token, StartedAt: i.StartedAt, EndedAt: i.EndedAt, Open: i.Open, Message: i.Message})
	}
	return info, nil
}

// channels liefert die Kanaele des Kerns (fuer Formular und Detailseite).
func (m *Module) channels(ctx context.Context) ([]*notify.Channel, error) {
	if m.notifyStore == nil {
		return nil, nil
	}
	return m.notifyStore.Channels(ctx)
}

// translator liefert eine Uebersetzungsfunktion fuer eine feste Sprache.
func (m *Module) translator(lang string) func(key string, args ...any) string {
	return func(key string, args ...any) string {
		if m.g.Translate != nil {
			return m.g.Translate(lang, key, args...)
		}
		return key
	}
}
