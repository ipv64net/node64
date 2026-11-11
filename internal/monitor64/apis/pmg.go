package apis

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Proxmox Mail Gateway (Benutzer mit der Rolle Auditor). PMG kennt keine API-Token (Stand 9.1): die Anmeldung laeuft
// ueber ein Ticket (POST /access/ticket, zwei Stunden gueltig), das als Cookie PMGAuthCookie mitgeht und nach einer
// Stunde bzw. bei 401 erneuert wird. Abgefragt wird die Node hinter der Adresse ("localhost"). Je Runde:
//
//	/nodes/localhost/status            CPU, Load, RAM, Swap, Root-Dateisystem, Version
//	/nodes/localhost/services          Dienste (systemd): pmgproxy, postfix, pmg-smtp-filter, clamav-daemon ...
//	/nodes/localhost/postfix/qshape    Warteschlange (mailq): zurueckgestellt, aktiv, angehalten
//
// Alle 5 min: /statistics/mail (Durchsatz der letzten Stunde), /quarantine/spamstatus und /virusstatus,
// /config/cluster/status (nur im Cluster). Alle 10 min /nodes/localhost/clamav/database (Alter der Signaturen),
// Updates alle 60 min wie bei Proxmox VE.

const (
	pmgNode        = "localhost"
	pmgAPI         = "/api2/json"
	pmgTicketRenew = time.Hour       // Ticket gilt zwei Stunden
	pmgStatEvery   = 5 * time.Minute // Durchsatz, Quarantaene, Cluster
	pmgClamMaxAge  = 3 * 24 * time.Hour
	pmgMaxTicket   = 4096
)

// PMGConfig sind die Verbindungsdaten eines Proxmox Mail Gateway.
type PMGConfig struct {
	Address      string        // https://host:8006
	User         string        // monitor64@pmg
	Password     string        // Passwort (Geheimnis, nie ausgeben)
	Pin          string        // SHA-256 des Zertifikats (hex); leer = System-CA
	Timeout      time.Duration // ganze Runde (0 = DefaultTimeout)
	UpdatesEvery time.Duration
}

// PMG ist der Sammler eines Proxmox Mail Gateway.
type PMG struct {
	cfg PMGConfig
	wc  *webClient
	now func() time.Time
	mu  sync.Mutex // eine Runde zur Zeit

	authMu   sync.Mutex
	ticket   string
	ticketAt time.Time
	role     string

	updates slowUpdates
	statAt  time.Time
	stat    []model.Service // Durchsatz, Quarantaene, Cluster (zwischen den Abfragen)
	clamAt  time.Time
	clam    *model.Service
}

// NewPMG baut den Sammler (prueft Adresse, Benutzer und Pin; fragt noch nichts ab).
func NewPMG(cfg PMGConfig) (*PMG, error) { return newPMG(cfg, nil) }

func newPMG(cfg PMGConfig, roots *x509.CertPool) (*PMG, error) {
	t, err := parseWebAddr(cfg.Address, "https", "8006", false)
	if err != nil {
		return nil, err
	}
	user := strings.TrimSpace(cfg.User)
	if user == "" || strings.ContainsAny(user, "\r\n \t") {
		return nil, errors.New(model.T("monitor64.txt.pmg_user_missing"))
	}
	if cfg.Password == "" {
		return nil, errors.New(model.T("monitor64.txt.pmg_pw_missing"))
	}
	wc, err := newWebClient(t, cfg.Pin, roots)
	if err != nil {
		return nil, err
	}
	p := &PMG{cfg: cfg, wc: wc, now: time.Now}
	wc.header = func(h http.Header) {
		if tk := p.tok(); tk != "" {
			h.Set("Cookie", "PMGAuthCookie="+url.QueryEscape(tk))
		}
	}
	return p, nil
}

func (p *PMG) timeout() time.Duration {
	if p.cfg.Timeout > 0 {
		return p.cfg.Timeout
	}
	return DefaultTimeout
}

func (p *PMG) tok() string {
	p.authMu.Lock()
	defer p.authMu.Unlock()
	return p.ticket
}

func (p *PMG) secrets() []string { return []string{p.cfg.Password, p.tok()} }

// Close gibt Verbindungen frei (ein Ticket laesst sich nicht abmelden, es laeuft ab).
func (p *PMG) Close() { p.wc.close() }

// Queries nennt die Abfragen ("Was wird abgefragt?").
func (p *PMG) Queries() []string {
	return []string{"POST " + pmgAPI + "/access/ticket", "GET " + pmgAPI + "/nodes/localhost/status", "GET " + pmgAPI + "/nodes/localhost/services",
		"GET " + pmgAPI + "/nodes/localhost/postfix/qshape?queue=deferred|active|hold", "GET " + pmgAPI + "/statistics/mail",
		"GET " + pmgAPI + "/quarantine/spamstatus", "GET " + pmgAPI + "/quarantine/virusstatus", "GET " + pmgAPI + "/config/cluster/status",
		"GET " + pmgAPI + "/nodes/localhost/clamav/database", "GET " + pmgAPI + "/nodes/localhost/apt/update"}
}

// login holt ein Ticket; stale ist das Ticket, mit dem die Anfrage scheiterte ("" = es gibt noch keins bzw. es ist
// alt). Hat inzwischen eine andere Anfrage ein neues geholt, gilt das.
func (p *PMG) login(ctx context.Context, stale string) error {
	p.authMu.Lock()
	if p.ticket != "" && p.ticket != stale {
		p.authMu.Unlock()
		return nil
	}
	p.authMu.Unlock()
	var out struct {
		Data struct {
			Ticket string `json:"ticket"`
			Role   string `json:"role"`
		} `json:"data"`
	}
	body := map[string]string{"username": strings.TrimSpace(p.cfg.User), "password": p.cfg.Password}
	// ohne das alte Ticket (eine Anmeldung mit ungueltigem Cookie kann abgelehnt werden)
	_, err := p.wc.do(ctx, http.MethodPost, pmgAPI+"/access/ticket", http.Header{"Cookie": nil}, body, &out)
	tk := out.Data.Ticket
	switch {
	case err != nil:
	case strings.Contains(tk, "!tfa!"):
		err = &webError{Kind: errWebAuth, Detail: model.T("monitor64.txt.pmg_tfa"), Where: "POST access/ticket"}
	case tk == "" || len(tk) > pmgMaxTicket || strings.ContainsAny(tk, "\r\n;"):
		err = &webError{Kind: errWebResp, Detail: model.T("monitor64.txt.pmg_no_ticket"), Where: "POST access/ticket"}
	}
	p.authMu.Lock()
	defer p.authMu.Unlock()
	if err != nil {
		p.ticket = ""
		return err
	}
	p.ticket, p.ticketAt, p.role = tk, p.now(), out.Data.Role
	return nil
}

// Get fragt einen Pfad unter /api2/json ab und legt "data" in out ab (nil = nur pruefen). Meldet sich vorher an bzw.
// erneuert ein altes oder abgelehntes Ticket einmal.
func (p *PMG) Get(ctx context.Context, path string, out any) error {
	p.authMu.Lock()
	tk, old := p.ticket, p.ticket != "" && p.now().Sub(p.ticketAt) >= pmgTicketRenew
	p.authMu.Unlock()
	if tk == "" || old {
		if err := p.login(ctx, tk); err != nil {
			return err
		}
		tk = p.tok()
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	err := p.wc.get(ctx, pmgAPI+path, &env)
	if errors.Is(err, errWebAuth) { // Ticket abgelaufen bzw. PMG neu gestartet
		if lerr := p.login(ctx, tk); lerr != nil {
			return lerr
		}
		env.Data = nil
		err = p.wc.get(ctx, pmgAPI+path, &env)
	}
	if err != nil || out == nil {
		return err
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return &webError{Kind: errWebResp, Detail: model.T("monitor64.txt.resp_json") + ": " + devText(err.Error()), Where: "GET " + path}
	}
	return nil
}

func (p *PMG) hint(err error) error {
	switch {
	case errors.Is(err, errWebAuth):
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.pmg_hint_auth"))
	case errors.Is(err, errWebPerm):
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.pmg_hint_perm"))
	}
	return err
}

// pmgStatus ist /nodes/{node}/status (wie Proxmox VE, dazu Version und Abgleich im Cluster).
type pmgStatus struct {
	nodeStatus
	Version string `json:"pmgversion"`
}

// version kuerzt "pmg-api/9.0.3/abc123 (running kernel: ...)" auf "9.0.3".
func (s pmgStatus) version() string {
	f := strings.Split(strings.TrimSpace(s.Version), "/")
	if len(f) >= 2 {
		return shortText(strings.TrimSpace(f[1]))
	}
	return shortText(s.Version)
}

// Test prueft die Verbindung im Assistenten (Zertifikat, Anmeldung, Rolle).
func (p *PMG) Test(ctx context.Context) TestResult {
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	res, proceed := probeCert(ctx, p.wc.t, p.wc.pin, p.wc.roots)
	if !proceed {
		return res
	}
	var st pmgStatus
	if err := p.Get(ctx, "/nodes/"+pmgNode+"/status", &st); err != nil {
		res.Error = scrub(p.hint(err).Error(), p.secrets()...)
		return res
	}
	res.OK = true
	res.Version, res.Node = st.version(), pmgNode
	var warn []string
	if res.Warning != "" {
		warn = append(warn, res.Warning)
	}
	p.authMu.Lock()
	role := p.role
	p.authMu.Unlock()
	if role == "root" || role == "admin" {
		warn = append(warn, model.T("monitor64.txt.pmg_role_admin"))
	}
	var svcs []pmgService
	if err := p.Get(ctx, "/nodes/"+pmgNode+"/services", &svcs); err != nil {
		warn = append(warn, "services: "+scrub(p.hint(err).Error(), p.secrets()...))
	} else {
		run := 0
		for _, s := range svcs {
			if s.running() {
				run++
			}
		}
		res.Summary = model.T("monitor64.txt.pmg_services_ok", "n", run)
	}
	res.Warning = strings.Join(warn, "; ")
	return res
}

// Collect ist eine Abfragerunde (nicht gleichzeitig mit sich selbst aufrufen).
func (p *PMG) Collect(ctx context.Context) ([]model.Service, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	now := p.now()
	var st pmgStatus
	if err := p.Get(ctx, "/nodes/"+pmgNode+"/status", &st); err != nil {
		return nil, scrubErr(p.hint(err), p.secrets()...)
	}
	part := &partial{secrets: p.secrets()}
	add := func(what string, err error, prefixes ...string) { part.add(what, p.hint(err), prefixes...) }
	out := nodeServices(st.nodeStatus)
	if svc := p.updates.collect(ctx, p, pmgNode, now, p.cfg.UpdatesEvery, part); svc != nil {
		out = append(out, *svc)
	}
	var svcs []pmgService
	if err := p.Get(ctx, "/nodes/"+pmgNode+"/services", &svcs); err != nil {
		add("services", err, "systemd")
	} else {
		out = append(out, pmgServices(svcs))
	}
	if s, err := p.queue(ctx); err != nil {
		add("postfix/qshape", err, "mailq")
	} else {
		out = append(out, s)
	}
	if p.statAt.IsZero() || now.Sub(p.statAt) >= pmgStatEvery {
		p.stat, p.statAt = p.slowStats(ctx, now, add), now
	}
	out = append(out, p.stat...)
	if p.clamAt.IsZero() || now.Sub(p.clamAt) >= slowEvery {
		var db []pmgClamDB
		if err := p.Get(ctx, "/nodes/"+pmgNode+"/clamav/database", &db); err != nil {
			add("clamav/database", err, "clamav")
		} else {
			p.clam, p.clamAt = pmgClamService(db, now), now
		}
	}
	if p.clam != nil {
		out = append(out, *p.clam)
	}
	sortServices(out)
	return out, part.result()
}

// pmgService ist ein Eintrag aus /nodes/{node}/services.
type pmgService struct {
	Service string `json:"service"`
	Name    string `json:"name"`
	State   string `json:"state"`        // running, dead, exited; bei einmaligen Diensten das Ergebnis (success, exit-code)
	Unit    string `json:"unit-state"`   // enabled, disabled, static, masked, not-found
	Active  string `json:"active-state"` // active, inactive, failed, activating
}

func (s pmgService) id() string { return firstNonEmpty(s.Service, s.Name) }

func (s pmgService) running() bool {
	return s.State == "running" || s.Active == "active" || s.Active == "activating" || s.Active == "reloading"
}

// pmgDaemons muessen laufen, wenn sie eingeschaltet sind; alle anderen Dienste (zeitgesteuerte wie pmg-daily, dazu
// fetchmail und die Zeitdienste, von denen nur einer laeuft) zaehlen nur, wenn systemd sie als fehlgeschlagen fuehrt.
var pmgDaemons = map[string]bool{"pmgproxy": true, "pmgdaemon": true, "pmgpolicy": true, "pmg-smtp-filter": true, "pmgtunnel": true,
	"pmgmirror": true, "postfix": true, "postgres": true, "clamav-daemon": true, "clamav-freshclam": true, "ssh": true}

// bad: Dienst ist eingeschaltet und laeuft nicht bzw. ist fehlgeschlagen.
func (s pmgService) bad() bool {
	switch s.Unit {
	case "not-found", "masked", "disabled":
		return false
	}
	if s.Active == "failed" || s.State == "failed" {
		return true
	}
	switch s.State { // Ergebnis eines einmaligen Dienstes
	case "exit-code", "signal", "timeout", "core-dump", "watchdog", "start-limit-hit", "resources", "oom-kill":
		return true
	}
	return pmgDaemons[s.id()] && !s.running()
}

// pmgServices: ein Dienst "systemd" wie beim Agent (Regel "fehlgeschlagene systemd-Dienste").
func pmgServices(list []pmgService) model.Service {
	var failed []string
	run := 0
	for _, s := range list {
		switch {
		case s.bad():
			failed = append(failed, shortText(s.id()))
		case s.running():
			run++
		}
	}
	sort.Strings(failed)
	sv := model.Service{Key: "systemd", Name: model.T("monitor64.svc.systemd"), Kind: "systemd", Default: true,
		Metrics: []model.Metric{{Name: "failed", Value: float64(len(failed))}}}
	if len(failed) > 0 {
		l := model.Raw(strings.Join(limitList(failed, 5), ", "))
		sv.Facts = append(sv.Facts, model.Fact{Code: "systemd_failed", Text: l})
		sv.Text = model.T("monitor64.txt.failed_list", "n", len(failed), "list", l)
	} else {
		sv.Text = model.T("monitor64.txt.pmg_services_ok", "n", run)
	}
	return sv
}

// pmgQRow ist eine Zeile aus qshape (erste Zeile TOTAL, danach je Domain).
type pmgQRow struct {
	Domain string `json:"domain"`
	Total  num    `json:"total"`
}

// queue: Warteschlange von Postfix. Zurueckgestellte Mails tragen die Schwelle; die groessten Ziel-Domains stehen
// im Text.
func (p *PMG) queue(ctx context.Context) (model.Service, error) {
	count := map[string]float64{}
	var top []pmgQRow
	for _, q := range []string{"deferred", "active", "hold"} {
		var rows []pmgQRow
		if err := p.Get(ctx, "/nodes/"+pmgNode+"/postfix/qshape?queue="+q, &rows); err != nil {
			return model.Service{}, err
		}
		for _, r := range rows {
			if r.Domain == "TOTAL" {
				count[q] = float64(r.Total)
			} else if q == "deferred" && r.Total > 0 {
				top = append(top, r)
			}
		}
	}
	s := model.Service{Key: "mailq", Name: model.T("monitor64.svc.mailq"), Kind: "mailq", Default: true,
		Metrics: []model.Metric{{Name: "deferred", Value: count["deferred"], Rule: model.RuleMailQueue},
			{Name: "active", Value: count["active"]}, {Name: "hold", Value: count["hold"]}},
		Text: model.T("monitor64.txt.mailq", "d", int(count["deferred"]), "a", int(count["active"]), "h", int(count["hold"]))}
	if len(top) > 0 {
		sort.SliceStable(top, func(i, j int) bool { return top[i].Total > top[j].Total })
		var names []string
		for _, r := range top {
			names = append(names, shortText(r.Domain)+" "+strconv.Itoa(int(r.Total)))
		}
		s.Text += " (" + model.Raw(strings.Join(limitList(names, 3), ", ")) + ")"
	}
	return s, nil
}

// pmgMailStat ist /statistics/mail (Zaehler eines Zeitraums).
type pmgMailStat struct {
	In       num `json:"count_in"`
	Out      num `json:"count_out"`
	SpamIn   num `json:"spamcount_in"`
	SpamOut  num `json:"spamcount_out"`
	VirusIn  num `json:"viruscount_in"`
	VirusOut num `json:"viruscount_out"`
	RBL      num `json:"rbl_rejects"`
	Pregreet num `json:"pregreet_rejects"`
	AvgTime  num `json:"avptime"`
}

// pmgQuar ist /quarantine/spamstatus bzw. /virusstatus.
type pmgQuar struct {
	Count  num `json:"count"`
	MBytes num `json:"mbytes"`
}

// pmgClusterNode ist ein Eintrag aus /config/cluster/status.
type pmgClusterNode struct {
	Name    string `json:"name"`
	Type    string `json:"type"` // master, node
	ConnErr string `json:"conn_error"`
	InSync  *num   `json:"insync"`
}

// slowStats: Durchsatz der letzten Stunde, Quarantaene und Cluster. Ein Teil, der nicht antwortet, fehlt bis zur
// naechsten Abfrage (kein alter Stand).
func (p *PMG) slowStats(ctx context.Context, now time.Time, add func(string, error, ...string)) []model.Service {
	var out []model.Service
	var ms pmgMailStat
	q := "?starttime=" + strconv.FormatInt(now.Add(-time.Hour).Unix(), 10) + "&endtime=" + strconv.FormatInt(now.Unix(), 10)
	if err := p.Get(ctx, "/statistics/mail"+q, &ms); err != nil {
		add("statistics/mail", err, "mail")
	} else {
		spam, virus, rej := float64(ms.SpamIn+ms.SpamOut), float64(ms.VirusIn+ms.VirusOut), float64(ms.RBL+ms.Pregreet)
		out = append(out, model.Service{Key: "mail", Name: model.T("monitor64.svc.mailflow"), Kind: "mail", Default: true,
			Metrics: []model.Metric{{Name: "in", Value: float64(ms.In)}, {Name: "out", Value: float64(ms.Out)}, {Name: "spam", Value: spam},
				{Name: "virus", Value: virus}, {Name: "rejects", Value: rej}, {Name: "ptime", Value: round2(float64(ms.AvgTime)), Unit: "s"}},
			Text: model.T("monitor64.txt.mailflow", "in", int(ms.In), "out", int(ms.Out), "spam", int(spam), "virus", int(virus), "rej", int(rej))})
	}
	var sq, vq pmgQuar
	err := p.Get(ctx, "/quarantine/spamstatus", &sq)
	if err == nil {
		err = p.Get(ctx, "/quarantine/virusstatus", &vq)
	}
	if err != nil {
		add("quarantine", err, "quarantine")
	} else {
		size := float64(sq.MBytes+vq.MBytes) * 1024 * 1024
		out = append(out, model.Service{Key: "quarantine", Name: model.T("monitor64.svc.quarantine"), Kind: "quarantine", Default: true,
			Metrics: []model.Metric{{Name: "spam", Value: float64(sq.Count)}, {Name: "virus", Value: float64(vq.Count)}, {Name: "size", Value: size, Unit: "B"}},
			Text:    model.T("monitor64.txt.quarantine", "s", int(sq.Count), "v", int(vq.Count), "size", bytesText(size))})
	}
	var nodes []pmgClusterNode
	if err := p.Get(ctx, "/config/cluster/status", &nodes); err != nil {
		add("config/cluster/status", err, "cluster")
	} else if len(nodes) > 0 {
		out = append(out, pmgClusterService(nodes))
	}
	return out
}

// pmgClusterService: Nodes, die der Cluster nicht erreicht, zaehlen als offline; fehlender Abgleich der Datenbank
// ist eine Warnung.
func pmgClusterService(nodes []pmgClusterNode) model.Service {
	var down, unsync []string
	for _, n := range nodes {
		name := shortText(n.Name)
		switch {
		case strings.TrimSpace(n.ConnErr) != "":
			down = append(down, name)
		case n.InSync != nil && *n.InSync == 0:
			unsync = append(unsync, name)
		}
	}
	sort.Strings(down)
	sort.Strings(unsync)
	s := model.Service{Key: "cluster", Name: "Cluster", Kind: "cluster", Default: true,
		Metrics: []model.Metric{{Name: "nodes", Value: float64(len(nodes))}, {Name: "online", Value: float64(len(nodes) - len(down))}},
		Text:    model.T("monitor64.txt.nodes_online", "n", len(nodes)-len(down), "total", len(nodes))}
	if len(down) > 0 {
		s.Facts = append(s.Facts, model.Fact{Code: "cluster_node_down", Text: model.Raw(strings.Join(limitList(down, 5), ", ")) + " offline"})
	}
	if len(unsync) > 0 {
		l := model.Raw(strings.Join(limitList(unsync, 5), ", "))
		s.Facts = append(s.Facts, model.Fact{Code: "device_warn", Text: model.T("monitor64.txt.pmg_not_synced", "list", l)})
		s.Text += " · " + model.T("monitor64.txt.pmg_not_synced", "list", l)
	}
	return s
}

// pmgClamDB ist ein Eintrag aus /nodes/{node}/clamav/database.
type pmgClamDB struct {
	Name    string `json:"name"` // main, daily, bytecode
	Build   string `json:"build_time"`
	Version string `json:"version"`
}

// pmgClamTime liest die Bauzeit aus dem Kopf der Datenbank ("16 Mar 2016 23-17 +0000").
func pmgClamTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, l := range []string{"02 Jan 2006 15-04 -0700", "2 Jan 2006 15-04 -0700", "02 Jan 2006 15:04 -0700"} {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// pmgClamService: Alter der taeglichen Signaturen (nil = keine Datenbank, ClamAV nicht in Gebrauch).
func pmgClamService(db []pmgClamDB, now time.Time) *model.Service {
	var daily *pmgClamDB
	for i := range db {
		if db[i].Name == "daily" {
			daily = &db[i]
		}
	}
	if daily == nil {
		return nil
	}
	s := model.Service{Key: "clamav", Name: model.T("monitor64.svc.clamav"), Kind: "system", Default: true}
	built, ok := pmgClamTime(daily.Build)
	if !ok {
		s.Text = model.T("monitor64.txt.clamav_version", "v", shortText(daily.Version))
		return &s
	}
	age := now.Sub(built)
	if age < 0 {
		age = 0
	}
	days := int(age / (24 * time.Hour))
	s.Metrics = []model.Metric{{Name: "age", Value: round2(age.Hours() / 24)}}
	s.Text = model.T("monitor64.txt.clamav_age", "v", shortText(daily.Version), "n", days)
	if age > pmgClamMaxAge {
		s.Facts = append(s.Facts, model.Fact{Code: "device_warn", Text: model.T("monitor64.txt.clamav_old", "n", days)})
	}
	return &s
}
