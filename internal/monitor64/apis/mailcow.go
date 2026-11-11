package apis

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// mailcow (API unter /api/v1 mit Nur-Lese-Schluessel im Kopf X-API-Key; die Adresse der Node muss in mailcow unter
// "API-Zugriff erlauben von" stehen). Je Runde:
//
//	/api/v1/get/status/containers   Container (postfix, dovecot, rspamd, sogo ...): alle muessen laufen
//	/api/v1/get/status/vmail        Mail-Speicher (fs:vmail)
//	/api/v1/get/mailq/all           Warteschlange (mailq): zurueckgestellt, aktiv, angehalten
//
// Alle 5 min /api/v1/get/quarantine/all (Anzahl). Die Version kommt beim Test aus /api/v1/get/status/version;
// ob ein Update bereitsteht, sagt die API nicht.

const mcQuarEvery = 5 * time.Minute

// MailcowConfig sind die Verbindungsdaten eines mailcow-Servers.
type MailcowConfig struct {
	Address string        // https://mail.example.org
	APIKey  string        // Nur-Lese-Schluessel (Geheimnis, nie ausgeben)
	Pin     string        // SHA-256 des Zertifikats (hex); leer = System-CA
	Timeout time.Duration // ganze Runde (0 = DefaultTimeout)
}

// Mailcow ist der Sammler eines mailcow-Servers.
type Mailcow struct {
	cfg MailcowConfig
	wc  *webClient
	now func() time.Time
	mu  sync.Mutex

	quarAt time.Time
	quar   *model.Service
}

// NewMailcow baut den Sammler (prueft Adresse, Schluessel und Pin; fragt noch nichts ab).
func NewMailcow(cfg MailcowConfig) (*Mailcow, error) { return newMailcow(cfg, nil) }

func newMailcow(cfg MailcowConfig, roots *x509.CertPool) (*Mailcow, error) {
	t, err := parseWebAddr(cfg.Address, "https", "", false)
	if err != nil {
		return nil, err
	}
	key := strings.TrimSpace(cfg.APIKey)
	if key == "" {
		return nil, errors.New(model.T("monitor64.txt.apikey_missing"))
	}
	if strings.ContainsAny(key, "\r\n") {
		return nil, errors.New(model.T("monitor64.txt.apikey_invalid"))
	}
	wc, err := newWebClient(t, cfg.Pin, roots)
	if err != nil {
		return nil, err
	}
	wc.header = func(h http.Header) { h.Set("X-API-Key", key) }
	return &Mailcow{cfg: cfg, wc: wc, now: time.Now}, nil
}

func (m *Mailcow) timeout() time.Duration {
	if m.cfg.Timeout > 0 {
		return m.cfg.Timeout
	}
	return DefaultTimeout
}

func (m *Mailcow) secrets() []string { return []string{strings.TrimSpace(m.cfg.APIKey), m.cfg.APIKey} }

// Close gibt Verbindungen frei.
func (m *Mailcow) Close() { m.wc.close() }

// Queries nennt die Abfragen ("Was wird abgefragt?").
func (m *Mailcow) Queries() []string {
	return []string{"GET /api/v1/get/status/containers (X-API-Key)", "GET /api/v1/get/status/vmail", "GET /api/v1/get/mailq/all",
		"GET /api/v1/get/quarantine/all", "GET /api/v1/get/status/version"}
}

func (m *Mailcow) hint(err error) error {
	if webAuthErr(err) {
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.mc_hint_auth"))
	}
	return err
}

// get fragt einen Pfad ab. mailcow meldet manche Fehler mit Status 200 als {"type":"error","msg":...} und leere
// Listen als {} oder []; beides wird hier abgefangen (out bleibt bei einer leeren Liste leer).
func (m *Mailcow) get(ctx context.Context, path string, out any) error {
	var raw json.RawMessage
	if err := m.wc.get(ctx, path, &raw); err != nil {
		return err
	}
	b := bytes.TrimSpace(raw)
	if len(b) > 0 && b[0] == '{' {
		var e struct {
			Type string `json:"type"`
			Msg  any    `json:"msg"`
		}
		if json.Unmarshal(b, &e) == nil && (e.Type == "error" || e.Type == "danger") {
			kind := errWebResp
			if msg := strings.ToLower(jsonMsg(e.Msg)); strings.Contains(msg, "access denied") || strings.Contains(msg, "authentication") {
				kind = errWebAuth
			}
			return &webError{Kind: kind, Detail: devText(jsonMsg(e.Msg)), Where: "GET " + path}
		}
		if string(b) == "{}" {
			return nil // leere Liste
		}
	}
	if err := json.Unmarshal(b, out); err != nil {
		return &webError{Kind: errWebResp, Detail: model.T("monitor64.txt.resp_json") + ": " + devText(err.Error()), Where: "GET " + path}
	}
	return nil
}

// mcContainer ist ein Eintrag aus /status/containers (Schluessel = Name des Containers).
type mcContainer struct {
	Container string `json:"container"`
	State     string `json:"state"`
}

// mcVersion ist /status/version.
type mcVersion struct {
	Version string `json:"version"`
}

// Test prueft die Verbindung im Assistenten (Zertifikat, Schluessel, Container).
func (m *Mailcow) Test(ctx context.Context) TestResult {
	ctx, cancel := context.WithTimeout(ctx, m.timeout())
	defer cancel()
	res, proceed := probeCert(ctx, m.wc.t, m.wc.pin, m.wc.roots)
	if !proceed {
		return res
	}
	var ctrs map[string]mcContainer
	if err := m.get(ctx, "/api/v1/get/status/containers", &ctrs); err != nil {
		res.Error = scrub(m.hint(err).Error(), m.secrets()...)
		return res
	}
	res.OK = true
	svc := mcContainers(ctrs)
	res.Summary = svc.Text
	var v mcVersion
	if err := m.get(ctx, "/api/v1/get/status/version", &v); err == nil {
		res.Version = shortText(v.Version)
	}
	return res
}

// Collect ist eine Abfragerunde (nicht gleichzeitig mit sich selbst aufrufen).
func (m *Mailcow) Collect(ctx context.Context) ([]model.Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, m.timeout())
	defer cancel()
	now := m.now()
	var ctrs map[string]mcContainer
	if err := m.get(ctx, "/api/v1/get/status/containers", &ctrs); err != nil {
		return nil, scrubErr(m.hint(err), m.secrets()...)
	}
	part := &partial{secrets: m.secrets()}
	out := []model.Service{mcContainers(ctrs)}
	var vm mcVmail
	if err := m.get(ctx, "/api/v1/get/status/vmail", &vm); err != nil {
		part.add("status/vmail", err, "fs:vmail")
	} else if s, ok := vm.service(); ok {
		out = append(out, s)
	}
	var q []mcQueued
	if err := m.get(ctx, "/api/v1/get/mailq/all", &q); err != nil {
		part.add("mailq", err, "mailq")
	} else {
		out = append(out, mcQueue(q))
	}
	if m.quarAt.IsZero() || now.Sub(m.quarAt) >= mcQuarEvery {
		var ql mcQuarList
		if err := m.get(ctx, "/api/v1/get/quarantine/all", &ql); err != nil {
			part.add("quarantine", err, "quarantine")
			m.quar = nil
		} else {
			s := mcQuarantine(ql)
			m.quar = &s
		}
		m.quarAt = now
	}
	if m.quar != nil {
		out = append(out, *m.quar)
	}
	sortServices(out)
	return out, part.result()
}

// mcContainers: ein Dienst fuer alle Container; jeder, der nicht laeuft, zaehlt (Regel "Gast bzw. Container laeuft
// nicht").
func mcContainers(ctrs map[string]mcContainer) model.Service {
	var down []string
	run := 0
	for name, c := range ctrs {
		if strings.EqualFold(strings.TrimSpace(c.State), "running") {
			run++
			continue
		}
		down = append(down, shortText(firstNonEmpty(c.Container, name))+" ("+shortText(firstNonEmpty(c.State, "?"))+")")
	}
	sort.Strings(down)
	s := model.Service{Key: "containers", Name: model.T("monitor64.svc.mc_containers"), Kind: "ctr", Default: true,
		Metrics: []model.Metric{{Name: "running", Value: float64(run)}, {Name: "down", Value: float64(len(down))}},
		Text:    model.T("monitor64.txt.containers_running", "n", len(ctrs), "run", run)}
	if len(down) > 0 {
		l := model.Raw(strings.Join(limitList(down, 5), ", "))
		s.Facts = append(s.Facts, model.Fact{Code: "guest_down", Text: model.T("monitor64.txt.mc_ctr_down", "list", l)})
		s.Text += " · " + model.T("monitor64.txt.mc_ctr_down", "list", l)
	}
	return s
}

// mcVmail ist /status/vmail (Groessen wie df -h: "41G", Belegung "28%").
type mcVmail struct {
	Disk    string `json:"disk"`
	Total   string `json:"total"`
	Used    string `json:"used"`
	Percent string `json:"used_percent"`
}

// mcSize liest eine Groesse wie "41G", "1.5T" oder "512M" (Zweierpotenzen wie df -h).
func mcSize(s string) (float64, bool) {
	s = strings.TrimSpace(strings.ReplaceAll(s, ",", "."))
	if s == "" {
		return 0, false
	}
	mult := 1.0
	switch s[len(s)-1] {
	case 'K', 'k':
		mult = 1 << 10
	case 'M':
		mult = 1 << 20
	case 'G':
		mult = 1 << 30
	case 'T':
		mult = 1 << 40
	case 'P':
		mult = 1 << 50
	}
	if mult > 1 {
		s = s[:len(s)-1]
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || !finite(v) || v < 0 {
		return 0, false
	}
	return v * mult, true
}

func (v mcVmail) service() (model.Service, bool) {
	tot, okT := mcSize(v.Total)
	used, okU := mcSize(v.Used)
	p, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(v.Percent), "%"), 64)
	if err != nil || !finite(p) || p < 0 || p > 100 {
		if !okT || !okU || tot <= 0 {
			return model.Service{}, false
		}
		p = pct(used, tot)
	}
	s := model.Service{Key: "fs:vmail", Name: model.T("monitor64.svc.fs", "name", "vmail"), Kind: "fs", Default: true,
		Metrics: []model.Metric{{Name: "used", Value: round2(p), Unit: "%", Rule: model.RuleFS, Max: tot}}}
	if okT && okU && tot > 0 {
		free := max(tot-used, 0)
		s.Metrics = append(s.Metrics, model.Metric{Name: "free", Value: free, Unit: "B", Max: tot})
		s.Text = model.T("monitor64.txt.free_of", "free", bytesText(free), "total", bytesText(tot))
	}
	return s, true
}

// mcQueued ist eine Mail aus /mailq/all.
type mcQueued struct {
	Queue      string   `json:"queue_name"` // incoming, active, deferred, hold
	Recipients []string `json:"recipients"`
}

// mcQueue: wie beim Mail Gateway tragen die zurueckgestellten Mails die Schwelle; die groessten Ziel-Domains stehen
// im Text.
func mcQueue(list []mcQueued) model.Service {
	count := map[string]int{}
	dom := map[string]int{}
	for _, q := range list {
		count[q.Queue]++
		if q.Queue != "deferred" || len(q.Recipients) == 0 {
			continue
		}
		if i := strings.LastIndex(q.Recipients[0], "@"); i >= 0 {
			dom[strings.ToLower(q.Recipients[0][i+1:])]++
		}
	}
	active := count["active"] + count["incoming"]
	s := model.Service{Key: "mailq", Name: model.T("monitor64.svc.mailq"), Kind: "mailq", Default: true,
		Metrics: []model.Metric{{Name: "deferred", Value: float64(count["deferred"]), Rule: model.RuleMailQueue},
			{Name: "active", Value: float64(active)}, {Name: "hold", Value: float64(count["hold"])}},
		Text: model.T("monitor64.txt.mailq", "d", count["deferred"], "a", active, "h", count["hold"])}
	if len(dom) > 0 {
		names := make([]string, 0, len(dom))
		for d := range dom {
			names = append(names, d)
		}
		sort.Slice(names, func(i, j int) bool {
			if dom[names[i]] != dom[names[j]] {
				return dom[names[i]] > dom[names[j]]
			}
			return names[i] < names[j]
		})
		for i, d := range names {
			names[i] = shortText(d) + " " + strconv.Itoa(dom[d])
		}
		s.Text += " (" + model.Raw(strings.Join(limitList(names, 3), ", ")) + ")"
	}
	return s
}

// mcQuarItem ist eine Mail aus /quarantine/all.
type mcQuarItem struct {
	Virus num `json:"virus_flag"`
}

// mcQuarList nimmt die Liste auch als einzelnes Objekt an (so zeigt es die API-Beschreibung von mailcow).
type mcQuarList []mcQuarItem

func (l *mcQuarList) UnmarshalJSON(b []byte) error {
	if b = bytes.TrimSpace(b); len(b) > 0 && b[0] == '{' {
		var one mcQuarItem
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*l = mcQuarList{one}
		return nil
	}
	return json.Unmarshal(b, (*[]mcQuarItem)(l))
}

func mcQuarantine(list []mcQuarItem) model.Service {
	virus := 0
	for _, q := range list {
		if q.Virus != 0 {
			virus++
		}
	}
	spam := len(list) - virus
	return model.Service{Key: "quarantine", Name: model.T("monitor64.svc.quarantine"), Kind: "quarantine", Default: true,
		Metrics: []model.Metric{{Name: "spam", Value: float64(spam)}, {Name: "virus", Value: float64(virus)}},
		Text:    model.T("monitor64.txt.mc_quarantine", "s", spam, "v", virus)}
}
