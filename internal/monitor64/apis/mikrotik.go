package apis

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// MikroTik RouterOS ab Version 7 ueber die REST-API (https://router/rest/<menue>, Anmeldung per HTTP Basic bei jeder
// Anfrage). Es wird nur gelesen: ausschliesslich GET, also "print" eines Menues – kein Befehl, der etwas anstoesst
// (auch kein check-for-updates). Der Benutzer braucht eine Gruppe mit read, api und rest-api.
//
// Je Runde, nacheinander (der Router bearbeitet die Anfragen eines Benutzers ohnehin einzeln):
//
//	/rest/system/resource     CPU, RAM, Flash, Laufzeit, Version
//	/rest/system/health       Temperaturen, Spannungen, Luefter, Netzteile (fehlt auf Geraeten ohne Sensoren)
//	/rest/interface           Schnittstellen: Zustand, Durchsatz und Fehler aus den Zaehlern
//	/rest/interface/{wifi,wifiwave2,wireless}/registration-table, /rest/caps-man/registration-table   WLAN-Clients
//	/rest/routing/bgp/connection, /rest/routing/bgp/session, /rest/routing/ospf/neighbor   Nachbarn, falls eingerichtet
//
// Alle 30 min /rest/system/package/update und /rest/system/routerboard (Update-Stand, wie ihn der Router zuletzt
// selbst ermittelt hat, und RouterBOOT). Menues, die es auf dem Geraet nicht gibt ("no such command"), werden sechs
// Stunden lang nicht erneut gefragt.
//
// Alle Werte kommen als Text ("true", "687116288", "1d7h44m20s"); Felder, die nicht zutreffen, fehlen.
// RouterOS 6 hat keine REST-API – dort bleibt SNMP (Profil mikrotik).

const (
	mtSlowEvery   = 30 * time.Minute
	mtAbsentEvery = 6 * time.Hour
	mtMaxIfaces   = 256
	mtIfaceProps  = "name,type,running,disabled,dynamic,comment,rx-byte,tx-byte,rx-packet,tx-packet,rx-error,tx-error,rx-drop,tx-drop"
)

// MikrotikConfig sind die Verbindungsdaten eines RouterOS-Geraets.
type MikrotikConfig struct {
	Address  string        // https://192.168.88.1
	User     string        // Benutzer mit read, api, rest-api
	Password string        // Geheimnis, nie ausgeben
	Pin      string        // SHA-256 des Zertifikats (hex); leer = System-CA
	Timeout  time.Duration // ganze Runde (0 = DefaultTimeout)
}

// Mikrotik ist der Sammler eines RouterOS-Geraets.
type Mikrotik struct {
	cfg MikrotikConfig
	wc  *webClient
	now func() time.Time
	mu  sync.Mutex

	prev    *counter
	hasWlan bool                 // WLAN-Schnittstellen vorhanden (aus /interface; bleibt bei einem Teilfehler stehen)
	absent  map[string]time.Time // Menue -> zuletzt als nicht vorhanden gesehen
	slowAt  time.Time
	upd     *model.Service
}

// NewMikrotik baut den Sammler (prueft Adresse, Zugangsdaten und Pin; fragt noch nichts ab).
func NewMikrotik(cfg MikrotikConfig) (*Mikrotik, error) { return newMikrotik(cfg, nil) }

func newMikrotik(cfg MikrotikConfig, roots *x509.CertPool) (*Mikrotik, error) {
	t, err := parseWebAddr(cfg.Address, "https", "", false)
	if err != nil {
		return nil, err
	}
	user := strings.TrimSpace(cfg.User)
	if user == "" || cfg.Password == "" {
		return nil, errors.New(model.T("monitor64.txt.cred_required"))
	}
	if strings.ContainsAny(user, "\r\n:") || strings.ContainsAny(cfg.Password, "\r\n") {
		return nil, errors.New(model.T("monitor64.txt.cred_invalid"))
	}
	wc, err := newWebClient(t, cfg.Pin, roots)
	if err != nil {
		return nil, err
	}
	pw := cfg.Password
	wc.header = func(h http.Header) {
		req := http.Request{Header: h}
		req.SetBasicAuth(user, pw)
	}
	return &Mikrotik{cfg: cfg, wc: wc, now: time.Now, absent: map[string]time.Time{}}, nil
}

func (m *Mikrotik) timeout() time.Duration {
	if m.cfg.Timeout > 0 {
		return m.cfg.Timeout
	}
	return DefaultTimeout
}

func (m *Mikrotik) secrets() []string { return []string{m.cfg.Password} }

// Close gibt Verbindungen frei.
func (m *Mikrotik) Close() { m.wc.close() }

// Queries nennt die Abfragen ("Was wird abgefragt?").
func (m *Mikrotik) Queries() []string {
	return []string{"GET /rest/system/resource (HTTP Basic)", "GET /rest/system/health", "GET /rest/interface",
		"GET /rest/interface/wifi/registration-table (wifiwave2, wireless, caps-man)", "GET /rest/routing/bgp/connection", "GET /rest/routing/bgp/session",
		"GET /rest/routing/ospf/neighbor", "GET /rest/system/package/update", "GET /rest/system/routerboard", "GET /rest/system/identity"}
}

// mtRow ist ein Datensatz eines Menues (alle Werte als Text).
type mtRow map[string]string

func (r mtRow) num(name string) (float64, bool) {
	v, err := strconv.ParseFloat(strings.TrimSpace(r[name]), 64)
	if err != nil || !finite(v) {
		return 0, false
	}
	return v, true
}

func (r mtRow) on(name string) bool { return strings.EqualFold(strings.TrimSpace(r[name]), "true") }

// mtRows liest die Antwort eines Menues: eine Liste von Datensaetzen oder – bei Menues ohne Liste – ein einzelner.
// Werte kommen als Text; Zahlen und Wahrheitswerte (aeltere Versionen, andere Felder) werden zu Text.
func mtRows(raw json.RawMessage) ([]mtRow, error) {
	b := bytes.TrimSpace(raw)
	var list []map[string]any
	switch {
	case len(b) == 0:
		return nil, nil
	case b[0] == '[':
		if err := json.Unmarshal(b, &list); err != nil {
			return nil, err
		}
	default:
		var one map[string]any
		if err := json.Unmarshal(b, &one); err != nil {
			return nil, err
		}
		list = []map[string]any{one}
	}
	out := make([]mtRow, 0, len(list))
	for _, in := range list {
		row := make(mtRow, len(in))
		for k, v := range in {
			switch x := v.(type) {
			case string:
				row[k] = x
			case float64:
				row[k] = strconv.FormatFloat(x, 'f', -1, 64)
			case bool:
				row[k] = strconv.FormatBool(x)
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// mtNoMenu: das Menue gibt es auf diesem Geraet nicht (Paket nicht installiert, andere Version). RouterOS meldet das
// je nach Version mit 400 oder 406 und "no such command or directory (x)".
func mtNoMenu(err error) bool {
	var we *webError
	if !errors.As(err, &we) {
		return false
	}
	if we.Status == 404 {
		return true
	}
	d := strings.ToLower(we.Detail)
	return (we.Status == 400 || we.Status == 406) && (strings.Contains(d, "no such command") || strings.Contains(d, "bad command name"))
}

// get fragt ein Menue ab (nur GET = print). RouterOS meldet fehlende Rechte mit HTTP 500 ("not enough permissions",
// "not allowed") – das zaehlt hier wie 403.
func (m *Mikrotik) get(ctx context.Context, path string) ([]mtRow, error) {
	var raw json.RawMessage
	if err := m.wc.get(ctx, path, &raw); err != nil {
		var we *webError
		if errors.As(err, &we) && we.Status == 500 {
			if d := strings.ToLower(we.Detail); strings.Contains(d, "not enough permissions") || strings.Contains(d, "not allowed") {
				we.Kind = errWebPerm
			}
		}
		return nil, err
	}
	rows, err := mtRows(raw)
	if err != nil {
		return nil, &webError{Kind: errWebResp, Detail: model.T("monitor64.txt.resp_json") + ": " + devText(err.Error()), Where: "GET " + path}
	}
	return rows, nil
}

// optional fragt ein Menue ab, das es nicht auf jedem Geraet gibt: ok false = nicht vorhanden (ohne Fehler; wird
// eine Weile nicht erneut gefragt).
func (m *Mikrotik) optional(ctx context.Context, now time.Time, path string) (rows []mtRow, ok bool, err error) {
	menu, _, _ := strings.Cut(path, "?")
	if at, gone := m.absent[menu]; gone && now.Sub(at) < mtAbsentEvery {
		return nil, false, nil
	}
	rows, err = m.get(ctx, path)
	if mtNoMenu(err) {
		m.absent[menu] = now
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	delete(m.absent, menu)
	return rows, true, nil
}

func (m *Mikrotik) hint(err error) error {
	switch {
	case errors.Is(err, errWebAuth):
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.mt_hint_auth"))
	case errors.Is(err, errWebPerm):
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.mt_hint_perm"))
	}
	return err
}

// Test prueft die Verbindung im Assistenten (Zertifikat, Anmeldung, Version).
func (m *Mikrotik) Test(ctx context.Context) TestResult {
	ctx, cancel := context.WithTimeout(ctx, m.timeout())
	defer cancel()
	res, proceed := probeCert(ctx, m.wc.t, m.wc.pin, m.wc.roots)
	if !proceed {
		return res
	}
	rows, err := m.get(ctx, "/rest/system/resource")
	if err != nil {
		res.Error = scrub(m.hint(err).Error(), m.secrets()...)
		return res
	}
	if len(rows) == 0 {
		res.Error = (&webError{Kind: errWebResp, Detail: model.T("monitor64.txt.resp_empty"), Where: "GET /rest/system/resource"}).Error()
		return res
	}
	res.OK = true
	res.Version = shortText(rows[0]["version"])
	name := ""
	if id, err := m.get(ctx, "/rest/system/identity"); err == nil && len(id) > 0 {
		name = shortText(id[0]["name"])
	}
	res.Summary = model.Raw(strings.Join(nonEmpty(shortText(rows[0]["board-name"]), name), " · "))
	return res
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, x := range s {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

// Collect ist eine Abfragerunde (nicht gleichzeitig mit sich selbst aufrufen).
func (m *Mikrotik) Collect(ctx context.Context) ([]model.Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, m.timeout())
	defer cancel()
	now := m.now()
	res, err := m.get(ctx, "/rest/system/resource")
	if err != nil {
		return nil, scrubErr(m.hint(err), m.secrets()...)
	}
	if len(res) == 0 {
		return nil, &webError{Kind: errWebResp, Detail: model.T("monitor64.txt.resp_empty"), Where: "GET /rest/system/resource"}
	}
	part := hintPartial{partial: &partial{secrets: m.secrets()}, hint: m.hint}
	out := mtSystem(res[0])

	if rows, ok, err := m.optional(ctx, now, "/rest/system/health"); err != nil {
		part.add("system/health", err, "temp:", "fan:", "psu:", "power")
	} else if ok {
		out = append(out, mtHealth(rows)...)
	}

	if rows, err := m.get(ctx, "/rest/interface?.proplist="+mtIfaceProps); err != nil {
		part.add("interface", err, "if:")
	} else {
		cur := &counter{t: now, v: map[string]float64{}}
		out = append(out, mtInterfaces(rows, m.prev, cur)...)
		m.prev, m.hasWlan = cur, mtHasWlan(rows)
	}

	if s, ok := m.wlan(ctx, now, part); ok {
		out = append(out, s)
	}

	if conns, ok, err := m.optional(ctx, now, "/rest/routing/bgp/connection?.proplist=name,remote.address,disabled"); err != nil {
		part.add("routing/bgp", err, "bgp")
	} else if ok {
		if sess, _, err := m.optional(ctx, now, "/rest/routing/bgp/session?.proplist=name,remote.address,established"); err != nil {
			part.add("routing/bgp", err, "bgp")
		} else if s, has := mtBGP(conns, sess); has {
			out = append(out, s)
		}
	}
	if rows, ok, err := m.optional(ctx, now, "/rest/routing/ospf/neighbor?.proplist=instance,address,router-id,state"); err != nil {
		part.add("routing/ospf", err, "ospf")
	} else if ok && len(rows) > 0 {
		out = append(out, mtOSPF(rows))
	}

	if m.slowAt.IsZero() || now.Sub(m.slowAt) >= mtSlowEvery {
		upd, err := m.get(ctx, "/rest/system/package/update")
		if err != nil {
			part.add("package/update", err, "updates")
			m.upd = nil
		} else if len(upd) > 0 {
			var rb mtRow
			if rows, ok, err := m.optional(ctx, now, "/rest/system/routerboard"); err == nil && ok && len(rows) > 0 {
				rb = rows[0]
			}
			s := mtUpdates(upd[0], rb)
			m.upd = &s
		}
		m.slowAt = now
	}
	if m.upd != nil {
		out = append(out, *m.upd)
	}
	sortServices(out)
	return out, part.result()
}

var mtDurRE = regexp.MustCompile(`(\d+)(ms|us|w|d|h|m|s)`)

// mtDuration liest eine Dauer wie "1w2d3h4m5s", "16m44s" oder "4s70ms".
func mtDuration(s string) (time.Duration, bool) {
	s = strings.TrimSpace(s)
	ms := mtDurRE.FindAllStringSubmatch(s, -1)
	if len(ms) == 0 || mtDurRE.ReplaceAllString(s, "") != "" {
		return 0, false
	}
	var d time.Duration
	for _, x := range ms {
		n, err := strconv.ParseInt(x[1], 10, 64)
		if err != nil || n > 1e9 {
			return 0, false
		}
		unit := map[string]time.Duration{"w": 7 * 24 * time.Hour, "d": 24 * time.Hour, "h": time.Hour, "m": time.Minute, "s": time.Second,
			"ms": time.Millisecond, "us": time.Microsecond}[x[2]]
		d += time.Duration(n) * unit
	}
	return d, true
}

// mtSystem: CPU, RAM, Flash und der Dienst "system" (Version, Laufzeit) aus /system/resource.
func mtSystem(r mtRow) []model.Service {
	var out []model.Service
	if v, ok := r.num("cpu-load"); ok && v >= 0 {
		s := model.Service{Key: "cpu", Name: "CPU", Kind: "cpu", Default: true,
			Metrics: []model.Metric{{Name: "util", Value: round2(math.Min(v, 100)), Unit: "%", Rule: model.RuleCPU}}}
		var parts []string
		if n, ok := r.num("cpu-count"); ok && n > 0 {
			parts = append(parts, model.T("monitor64.txt.cores", "n", fmt.Sprintf("%.0f", n)))
		}
		if c := shortText(r["cpu"]); c != "" {
			parts = append(parts, model.Raw(c))
		}
		s.Text = strings.Join(parts, " · ")
		out = append(out, s)
	}
	if tot, ok := r.num("total-memory"); ok && tot > 0 {
		free, _ := r.num("free-memory")
		free = math.Min(math.Max(free, 0), tot)
		out = append(out, model.Service{Key: "mem", Name: "RAM", Kind: "mem", Default: true,
			Metrics: []model.Metric{{Name: "used", Value: pct(tot-free, tot), Unit: "%", Rule: model.RuleMem, Max: tot}, {Name: "avail", Value: free, Unit: "B"}},
			Text:    model.T("monitor64.txt.free_of", "free", bytesText(free), "total", bytesText(tot))})
	}
	if tot, ok := r.num("total-hdd-space"); ok && tot > 0 {
		free, _ := r.num("free-hdd-space")
		free = math.Min(math.Max(free, 0), tot)
		out = append(out, model.Service{Key: "fs:flash", Name: model.T("monitor64.svc.fs", "name", "Flash"), Kind: "fs", Default: true,
			Metrics: []model.Metric{{Name: "used", Value: pct(tot-free, tot), Unit: "%", Rule: model.RuleFS, Max: tot}, {Name: "free", Value: free, Unit: "B", Max: tot}},
			Text:    model.T("monitor64.txt.free_of", "free", bytesText(free), "total", bytesText(tot))})
	}
	sys := model.Service{Key: "system", Name: model.Raw(firstNonEmpty(shortText(r["board-name"]), "MikroTik")), Kind: "system", Default: true}
	ver := firstNonEmpty(shortText(r["version"]), "?")
	if up, ok := mtDuration(r["uptime"]); ok {
		sys.Metrics = []model.Metric{{Name: "uptime", Value: math.Floor(up.Seconds()), Unit: "s"}}
		t := hoursText(up)
		if up < time.Hour {
			t = model.T("monitor64.txt.dur_min", "n", int(up/time.Minute))
		}
		sys.Text = model.T("monitor64.txt.mt_system", "v", ver, "t", model.Sub(t))
	} else {
		sys.Text = model.T("monitor64.txt.mt_system_plain", "v", ver)
	}
	return append(out, sys)
}

// mtStateRE: Zustandswerte in /system/health (psu1-state, psu2-state, fan-state).
var mtStateRE = regexp.MustCompile(`^(psu|fan)[0-9]*-state$`)

// mtSensor ist ein Wert aus /system/health.
type mtSensor struct{ name, value, typ string }

// mtSensors liest /system/health: RouterOS 7 liefert je Sensor eine Zeile (name, value, type); die aeltere Form ist
// eine Zeile mit den Sensornamen als Feldern (dann sagt der Name die Einheit).
func mtSensors(rows []mtRow) []mtSensor {
	var out []mtSensor
	for _, r := range rows {
		if n, ok := r["name"]; ok {
			if _, has := r["value"]; has {
				out = append(out, mtSensor{name: strings.TrimSpace(n), value: strings.TrimSpace(r["value"]), typ: strings.TrimSpace(r["type"])})
				continue
			}
		}
		names := make([]string, 0, len(r))
		for k := range r {
			if !strings.HasPrefix(k, ".") {
				names = append(names, k)
			}
		}
		sort.Strings(names)
		for _, k := range names {
			typ := ""
			switch {
			case strings.Contains(k, "temperature"):
				typ = "C"
			case strings.HasSuffix(k, "voltage"):
				typ = "V"
			case strings.HasSuffix(k, "current"):
				typ = "A"
			case strings.HasSuffix(k, "consumption"):
				typ = "W"
			case strings.HasSuffix(k, "speed"):
				typ = "RPM"
			}
			out = append(out, mtSensor{name: k, value: strings.TrimSpace(r[k]), typ: typ})
		}
	}
	return out
}

// mtHealth: Temperaturen (temp:<name>), Luefter (fan:<name>), Netzteile (psu:<name>) und ein Dienst "power" mit
// Spannungen, Stroemen und Leistung.
func mtHealth(rows []mtRow) []model.Service {
	var out []model.Service
	power := model.Service{Key: "power", Name: model.T("monitor64.svc.power"), Kind: "power", Default: true}
	var powerParts []string
	for _, s := range mtSensors(rows) {
		name := shortText(s.name)
		if name == "" || s.value == "" {
			continue
		}
		v, err := strconv.ParseFloat(s.value, 64)
		isNum := err == nil && finite(v)
		switch strings.ToUpper(s.typ) {
		case "C":
			if !isNum || v <= -60 || v >= 300 {
				continue
			}
			out = append(out, model.Service{Key: "temp:" + name, Name: model.T("monitor64.svc.temp", "name", name), Kind: "temp", Default: true,
				Metrics: []model.Metric{{Name: "temp", Value: round2(v), Unit: "°C", Rule: model.RuleTemp}}, Text: fmt.Sprintf("%.0f °C", v)})
		case "RPM":
			if !isNum || v < 0 {
				continue
			}
			out = append(out, model.Service{Key: "fan:" + name, Name: model.T("monitor64.svc.fan", "name", name), Kind: "fan", Default: true,
				Metrics: []model.Metric{{Name: "rpm", Value: round2(v), Unit: "rpm"}}, Text: model.T("monitor64.txt.rpm", "v", fmt.Sprintf("%.0f", v))})
		case "V", "A", "W":
			if !isNum || v < 0 {
				continue
			}
			unit := strings.ToUpper(s.typ)
			power.Metrics = append(power.Metrics, model.Metric{Name: name, Value: round2(v), Unit: unit})
			powerParts = append(powerParts, model.Raw(name)+" "+strings.Replace(strconv.FormatFloat(round2(v), 'f', -1, 64), ".", ",", 1)+" "+unit)
		default:
			// Zustand eines Netzteils bzw. der Luefter: ok, fail, not-present, idle, no-input. Auf x86/CHR ist
			// /system/health ein Schalter ({"state":"disabled","state-after-reboot":"enabled"}) – kein Sensor.
			st := strings.ToLower(s.value)
			if isNum || st == "not-present" || !mtStateRE.MatchString(name) {
				continue
			}
			base := strings.TrimSuffix(name, "-state")
			svc := model.Service{Key: "psu:" + base, Name: model.T("monitor64.svc.psu", "name", base), Kind: "psu", Default: true, Text: model.Raw(shortText(s.value))}
			if strings.HasPrefix(base, "fan") {
				svc.Key, svc.Name, svc.Kind = "fan:"+base, model.T("monitor64.svc.fan", "name", base), "fan"
			}
			if st == "fail" || st == "no-input" {
				svc.Facts = append(svc.Facts, model.Fact{Code: "hw_failed", Text: model.T("monitor64.txt.mt_state", "name", name, "s", shortText(s.value))})
			}
			out = append(out, svc)
		}
	}
	if len(power.Metrics) > 0 {
		power.Text = strings.Join(limitList(powerParts, 4), " · ")
		out = append(out, power)
	}
	return out
}

// mtDefaultIface: Arten, die beim Erkennen vorgewaehlt werden, wenn die Schnittstelle laeuft (echte Ports und
// Verbindungen nach aussen; VLANs, Bruecken-Ports u. a. lassen sich dazunehmen).
var mtDefaultIface = map[string]bool{"ether": true, "wlan": true, "wifi": true, "wifiwave2": true, "lte": true, "pppoe-out": true,
	"l2tp-out": true, "sstp-out": true, "ovpn-out": true, "wg": true, "bond": true, "bridge": true}

// mtInterfaces: je Schnittstelle Zustand, Durchsatz und Fehler (Raten aus den Zaehlern gegenueber der vorigen Runde).
// Dynamische Schnittstellen (eingewaehlte Nutzer u. ae.) kommen und gehen – sie bleiben aussen vor.
func mtInterfaces(rows []mtRow, prev, cur *counter) []model.Service {
	var out []model.Service
	for _, r := range rows {
		name := strings.TrimSpace(r["name"])
		typ := strings.ToLower(strings.TrimSpace(r["type"]))
		if name == "" || typ == "loopback" || r.on("dynamic") || len(out) >= mtMaxIfaces {
			continue
		}
		running, disabled := r.on("running"), r.on("disabled")
		label := model.Raw(shortText(name))
		if c := shortText(r["comment"]); c != "" {
			label += " · " + model.Raw(c)
		}
		s := model.Service{Key: "if:" + name, Name: label, Kind: "if", Default: running && mtDefaultIface[typ]}
		var parts []string
		ctr := func(field string) (float64, bool) {
			v, ok := r.num(field)
			if !ok {
				return 0, false
			}
			cur.v[name+"|"+field] = v
			return rate(prev, cur.t, name+"|"+field, v)
		}
		rx, ok1 := ctr("rx-byte")
		tx, ok2 := ctr("tx-byte")
		if ok1 && ok2 {
			inM, outM := rx*8/1e6, tx*8/1e6
			s.Metrics = append(s.Metrics, model.Metric{Name: "in", Value: round2(inM), Unit: "Mbit/s"}, model.Metric{Name: "out", Value: round2(outM), Unit: "Mbit/s"})
			parts = append(parts, fmt.Sprintf("↓ %s · ↑ %s", mbitText(inM), mbitText(outM)))
		}
		rp, okp1 := ctr("rx-packet")
		tp, okp2 := ctr("tx-packet")
		re, oke1 := ctr("rx-error")
		te, oke2 := ctr("tx-error")
		if okp1 && okp2 && oke1 && oke2 {
			dt := cur.t.Sub(prev.t).Seconds()
			errs, pk := math.Round((re+te)*dt), (rp+tp)*dt
			ratePct := 0.0
			if pk > 0 {
				ratePct = errs / pk * 100
			}
			s.Metrics = append(s.Metrics, model.Metric{Name: "errrate", Value: math.Round(math.Min(100, ratePct)*1e4) / 1e4, Unit: "%", Rule: model.RuleIfErrRate},
				model.Metric{Name: "errors", Value: errs})
			if errs > 0 {
				parts = append(parts, model.T("monitor64.txt.errors_n", "n", fmt.Sprintf("%.0f", errs)))
			}
		}
		rd, okd1 := ctr("rx-drop")
		td, okd2 := ctr("tx-drop")
		if okd1 && okd2 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "drops", Value: math.Round((rd + td) * cur.t.Sub(prev.t).Seconds())})
		}
		switch {
		case disabled:
			parts = []string{model.T("monitor64.txt.disabled")}
		case !running:
			parts = append([]string{"down"}, parts...)
			s.Facts = append(s.Facts, model.Fact{Code: "if_down", Text: model.T("monitor64.txt.no_link", "name", name)})
		}
		s.Text = strings.Join(parts, " · ")
		out = append(out, s)
	}
	return out
}

// mtWlanMenus: Tabellen der angemeldeten WLAN-Clients je Treiber (neuer wifi-Treiber ab 7.13, wifiwave2 bis 7.12,
// alter wireless-Treiber, CAPsMAN des alten Treibers). Es zaehlen alle, die es auf dem Geraet gibt.
var mtWlanMenus = []string{"/rest/interface/wifi/registration-table", "/rest/interface/wifiwave2/registration-table",
	"/rest/interface/wireless/registration-table", "/rest/caps-man/registration-table"}

// mtHasWlan: das Geraet hat WLAN-Schnittstellen (eigene Funkmodule bzw. die der verwalteten CAPs). Das Menue der
// Clients gibt es ab 7.13 auch auf Geraeten ohne WLAN – dort waere "0 angemeldet" nur Laerm.
func mtHasWlan(rows []mtRow) bool {
	for _, r := range rows {
		switch t := strings.ToLower(strings.TrimSpace(r["type"])); {
		case t == "wlan", t == "cap", strings.HasPrefix(t, "wifi"):
			return true
		}
	}
	return false
}

// wlan: Anzahl der angemeldeten WLAN-Clients (ok false = kein WLAN auf dem Geraet).
func (m *Mikrotik) wlan(ctx context.Context, now time.Time, part hintPartial) (model.Service, bool) {
	if !m.hasWlan {
		return model.Service{}, false
	}
	total, found := 0, false
	for _, menu := range mtWlanMenus {
		rows, ok, err := m.optional(ctx, now, menu+"?.proplist="+url.QueryEscape("interface"))
		if err != nil {
			part.add("registration-table", err, "wlan")
			return model.Service{}, false
		}
		if ok {
			found = true
			total += len(rows)
		}
	}
	if !found {
		return model.Service{}, false
	}
	return model.Service{Key: "wlan", Name: model.T("monitor64.svc.wlan_clients"), Kind: "wlan", Default: true,
		Metrics: []model.Metric{{Name: "clients", Value: float64(total)}}, Text: model.T("monitor64.txt.mt_clients", "n", total)}, true
}

// mtBGP: ein Dienst fuer alle BGP-Verbindungen (has false = BGP ist nicht eingerichtet). Eine eingerichtete, nicht
// abgeschaltete Verbindung ohne aufgebaute Sitzung meldet der Dienst als Warnung des Geraets. Ein Peer, der nicht
// erreichbar ist, hat keine Zeile in /routing/bgp/session – deshalb zaehlen die Verbindungen; die Sitzung einer
// Verbindung heisst wie sie mit Zusatz ("upstream" -> "upstream-1"). Sitzungen ohne eigene Verbindung (Peers aus
// einem Netz) zaehlen dazu.
func mtBGP(conns, sess []mtRow) (model.Service, bool) {
	est := map[string]bool{}
	extra := 0
	for _, s := range sess {
		if !s.on("established") {
			continue
		}
		name, matched := strings.TrimSpace(s["name"]), false
		for _, c := range conns {
			if cn := strings.TrimSpace(c["name"]); cn != "" && (name == cn || strings.HasPrefix(name, cn+"-")) {
				est[cn], matched = true, true
				break
			}
		}
		if !matched {
			extra++
		}
	}
	up, total := extra, extra
	var down []string
	for _, c := range conns {
		if c.on("disabled") {
			continue
		}
		total++
		if cn := strings.TrimSpace(c["name"]); est[cn] {
			up++
		} else {
			down = append(down, shortText(firstNonEmpty(cn, c["remote.address"], "?")))
		}
	}
	if total == 0 {
		return model.Service{}, false
	}
	sort.Strings(down)
	s := model.Service{Key: "bgp", Name: "BGP", Kind: "routing", Default: true,
		Metrics: []model.Metric{{Name: "established", Value: float64(up)}, {Name: "down", Value: float64(len(down))}},
		Text:    model.T("monitor64.txt.mt_bgp", "up", up, "n", total)}
	if len(down) > 0 {
		t := model.T("monitor64.txt.mt_bgp_down", "list", model.Raw(strings.Join(limitList(down, 5), ", ")))
		s.Facts = append(s.Facts, model.Fact{Code: "device_warn", Text: t})
		s.Text += " · " + t
	}
	return s, true
}

// mtOSPF: ein Dienst fuer alle OSPF-Nachbarn (nur Anzeige: "2-Way" ist zwischen Nicht-DR-Routern der Normalfall).
func mtOSPF(rows []mtRow) model.Service {
	full := 0
	for _, r := range rows {
		if strings.EqualFold(strings.TrimSpace(r["state"]), "full") {
			full++
		}
	}
	return model.Service{Key: "ospf", Name: "OSPF", Kind: "routing", Default: true,
		Metrics: []model.Metric{{Name: "neighbors", Value: float64(len(rows))}, {Name: "full", Value: float64(full)}},
		Text:    model.T("monitor64.txt.mt_ospf", "n", len(rows), "full", full)}
}

// mtUpdates: Update-Stand, wie ihn der Router zuletzt selbst ermittelt hat (latest-version fehlt, solange er seit dem
// Start nicht gesucht hat – angestossen wird die Suche hier nie). rb = /system/routerboard (nil auf CHR/x86).
func mtUpdates(u, rb mtRow) model.Service {
	s := model.Service{Key: "updates", Name: "Updates", Kind: "updates", Default: true}
	inst, latest := shortText(u["installed-version"]), shortText(u["latest-version"])
	var parts []string
	switch {
	case latest == "":
		parts = append(parts, model.T("monitor64.txt.mt_update_unknown", "v", firstNonEmpty(inst, "?")))
	case inst != "" && latest != inst:
		t := model.T("monitor64.txt.mt_update", "v", latest, "cur", inst)
		s.Metrics = []model.Metric{{Name: "pending", Value: 1}}
		s.Facts = append(s.Facts, model.Fact{Code: "updates_security", Text: t})
		parts = append(parts, t)
	default:
		s.Metrics = []model.Metric{{Name: "pending", Value: 0}}
		parts = append(parts, model.T("monitor64.txt.none_pending"))
	}
	if cur, up := shortText(rb["current-firmware"]), shortText(rb["upgrade-firmware"]); rb.on("routerboard") && cur != "" && up != "" && cur != up {
		parts = append(parts, model.T("monitor64.txt.mt_routerboot", "cur", cur, "v", up))
	}
	s.Text = strings.Join(parts, " · ")
	return s
}
