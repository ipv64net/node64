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

	"github.com/coder/websocket"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// TrueNAS (SCALE und CORE). Zwei Wege, gleiche Methoden:
//
//	JSON-RPC 2.0 ueber WebSocket   wss://host/api/current (SCALE ab 25.04), Anmeldung mit Benutzer per
//	                               auth.login_ex (API_KEY_PLAIN), ohne per auth.login_with_api_key (ab 26 veraltet,
//	                               entfaellt mit 27); die REST-API ist ab 25.04 veraltet und mit 26 entfernt
//	REST v2.0                      https://host/api/v2.0/…, API-Key als Bearer (CORE 13, SCALE bis 24.10)
//
// Automatisch: erst JSON-RPC, antwortet /api/current nicht als WebSocket (404), REST. Nur https:// – TrueNAS
// widerruft API-Keys, die ueber http:// benutzt werden. Je Runde:
//
//	system.info                   Load je Kern, Laufzeit, Version (CPU/RAM-Auslastung gibt es nur ueber die
//	                              Reporting-Graphen, deren Format je Version wechselt: nicht abgefragt)
//	pool.query, boot.get_state    Pools (zfs:<pool>): Zustand, Belegung, Scrub, Geraetefehler
//	disk.query                    Platten (disk:<seriennummer>), Fehler aus der Pool-Topologie
//	alert.list                    nicht quittierte Alarme (alerts): WARNING/ERROR -> device_warn, ab CRITICAL -> device_crit
//	replication.query, pool.snapshottask.query, cloudsync.query, rsynctask.query
//	                              Aufgaben (job:<art>:<id>) mit letztem Zustand (job_failed)
//	app.query (bzw. chart.release.query), vm.query
//	                              Apps (app:<name>) und VMs (vm:<id>, Soll aus autostart), soweit vorhanden
//
// Seltener (SmartEvery, Standard 30 min): disk.temperatures und smart.test.results.

// TrueNASConfig sind die Verbindungsdaten eines TrueNAS.
type TrueNASConfig struct {
	Address    string        // https://truenas[:443]
	APIKey     string        // API-Key (Geheimnis, nie ausgeben)
	User       string        // Benutzer, dem der Key gehoert (JSON-RPC auth.login_ex; ab TrueNAS 27 noetig)
	Pin        string        // SHA-256 des Zertifikats (hex); leer = System-CA
	API        string        // TrueNASAuto, TrueNASRPC, TrueNASREST
	Timeout    time.Duration // ganze Runde (0 = DefaultTimeout)
	SmartEvery time.Duration // Temperaturen und SMART-Tests (0 = DefaultSmartEvery)
}

// Wege fuer TrueNASConfig.API.
const (
	TrueNASAuto = ""
	TrueNASRPC  = "jsonrpc"
	TrueNASREST = "rest"
)

const (
	tnMaxForeign = 200 // fremde Nachrichten (Ereignisse) je Aufruf hoechstens ueberlesen
	tnMaxDepth   = 8   // Tiefe der Pool-Topologie
)

// errTNNoRPC: /api/current ist keine WebSocket-Schnittstelle (aeltere Version) – REST nehmen.
var errTNNoRPC = errors.New("keine JSON-RPC-Schnittstelle")

// TrueNAS ist der Sammler eines TrueNAS.
type TrueNAS struct {
	cfg TrueNASConfig
	wc  *webClient
	now func() time.Time

	mu       sync.Mutex
	api      string // erkannter Weg (TrueNASRPC, TrueNASREST; "" = noch nicht erkannt)
	slowAt   time.Time
	temps    map[string]float64 // Geraetename -> °C
	smart    map[string]tnSmartTest
	bootName string // Name des Boot-Pools (Praefix bei Teilfehlern)
}

// NewTrueNAS baut den Sammler (prueft Adresse, Key und Pin; fragt noch nichts ab).
func NewTrueNAS(cfg TrueNASConfig) (*TrueNAS, error) {
	return newTrueNAS(cfg, nil)
}

func newTrueNAS(cfg TrueNASConfig, roots *x509.CertPool) (*TrueNAS, error) {
	t, err := parseWebAddr(cfg.Address, "https", "443", false)
	if err != nil {
		return nil, fmt.Errorf("%w – TrueNAS nur über https:// (API-Keys über http:// widerruft TrueNAS)", err)
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("API-Key fehlt")
	}
	if strings.ContainsAny(cfg.APIKey, "\r\n") || strings.ContainsAny(cfg.User, "\r\n") {
		return nil, errors.New("API-Key ungültig")
	}
	switch cfg.API {
	case TrueNASAuto, TrueNASRPC, TrueNASREST:
	default:
		return nil, fmt.Errorf("unbekannte TrueNAS-API %q", cfg.API)
	}
	wc, err := newWebClient(t, cfg.Pin, roots)
	if err != nil {
		return nil, err
	}
	key := strings.TrimSpace(cfg.APIKey)
	wc.header = func(h http.Header) { h.Set("Authorization", "Bearer "+key) }
	return &TrueNAS{cfg: cfg, wc: wc, now: time.Now, api: cfg.API, temps: map[string]float64{}, smart: map[string]tnSmartTest{}}, nil
}

func (t *TrueNAS) timeout() time.Duration {
	if t.cfg.Timeout > 0 {
		return t.cfg.Timeout
	}
	return DefaultTimeout
}

func (t *TrueNAS) secrets() []string { return []string{strings.TrimSpace(t.cfg.APIKey), t.cfg.APIKey} }

// Close gibt Verbindungen frei.
func (t *TrueNAS) Close() { t.wc.close() }

// Queries nennt die Methoden ("Was wird abgefragt?").
func (t *TrueNAS) Queries() []string {
	return []string{"JSON-RPC wss://…/api/current (sonst REST /api/v2.0)", "system.info", "pool.query, boot.get_state",
		"disk.query", "alert.list", "replication.query, pool.snapshottask.query, cloudsync.query, rsynctask.query",
		"app.query (bzw. chart.release.query), vm.query", "disk.temperatures, smart.test.results (alle 30 min)"}
}

// tnCaller ruft eine Methode der TrueNAS-API auf (JSON-RPC bzw. REST).
type tnCaller interface {
	call(ctx context.Context, method string, params []any, out any) error
	close()
}

// tnRPCError ist ein Fehler aus JSON-RPC.
type tnRPCError struct {
	Code    int
	Message string
	Errname string
	Method  string
}

func (e *tnRPCError) Error() string {
	m := firstNonEmpty(e.Errname, strconv.Itoa(e.Code))
	if e.Message != "" {
		m += " " + e.Message
	}
	return shortText(m)
}

// Unwrap ordnet Rechte- und Anmeldefehler ein (webAuthErr).
func (e *tnRPCError) Unwrap() error {
	switch e.Errname {
	case "EACCES", "EPERM":
		return errWebPerm
	case "ENOTAUTHENTICATED":
		return errWebAuth
	}
	return nil
}

// tnAbsent: Methode bzw. Pfad gibt es in dieser Version nicht.
func tnAbsent(err error) bool {
	var re *tnRPCError
	if errors.As(err, &re) {
		return re.Code == -32601 || re.Errname == "ENOMETHOD"
	}
	return webAbsent(err)
}

// tnRPC ist eine JSON-RPC-Sitzung (eine Runde).
type tnRPC struct {
	conn *websocket.Conn
	id   int
}

func (t *TrueNAS) dialRPC(ctx context.Context) (*tnRPC, error) {
	u := "wss://" + t.wc.t.hostPt + "/api/current"
	conn, resp, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: t.wc.hc})
	if err != nil {
		if resp != nil {
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			switch resp.StatusCode {
			case 400, 404, 405, 426, 501:
				return nil, errTNNoRPC
			case 401:
				return nil, &webError{Kind: errWebAuth, Status: 401, Where: "GET /api/current"}
			}
			return nil, &webError{Kind: errWebResp, Status: resp.StatusCode, Where: "GET /api/current"}
		}
		return nil, webClassify(err, "GET /api/current")
	}
	conn.SetReadLimit(webMaxBody)
	r := &tnRPC{conn: conn}
	if err := t.loginRPC(ctx, r); err != nil {
		r.close()
		return nil, err
	}
	return r, nil
}

// loginRPC meldet die Sitzung an: mit Benutzer auth.login_ex (API_KEY_PLAIN, ab 25.04; die einzige Form ab TrueNAS
// 27), sonst bzw. auf aelteren Versionen auth.login_with_api_key (ab 26 veraltet).
func (t *TrueNAS) loginRPC(ctx context.Context, r *tnRPC) error {
	key := strings.TrimSpace(t.cfg.APIKey)
	rejected := &webError{Kind: errWebAuth, Detail: "API-Key abgelehnt (widerrufen, abgelaufen oder falsch?)", Where: "Anmeldung"}
	if u := strings.TrimSpace(t.cfg.User); u != "" {
		var res struct {
			Type string `json:"response_type"`
		}
		err := r.call(ctx, "auth.login_ex", []any{map[string]any{"mechanism": "API_KEY_PLAIN", "username": u, "api_key": key}}, &res)
		switch {
		case err == nil && res.Type == "SUCCESS":
			return nil
		case err == nil:
			rejected.Detail += " – " + shortText(res.Type)
			return rejected
		case !tnAbsent(err):
			return err
		}
		// vor 25.04: auth.login_ex ohne API_KEY_PLAIN bzw. ohne die Methode
	}
	var ok bool
	if err := r.call(ctx, "auth.login_with_api_key", []any{key}, &ok); err != nil {
		if tnAbsent(err) {
			if t.cfg.User == "" {
				return errors.New("auth.login_with_api_key gibt es nicht mehr (TrueNAS 27) – Benutzer des API-Keys eintragen")
			}
			return errTNNoRPC
		}
		return err
	}
	if !ok {
		return rejected
	}
	return nil
}

func (r *tnRPC) close() { _ = r.conn.Close(websocket.StatusNormalClosure, "") }

func (r *tnRPC) call(ctx context.Context, method string, params []any, out any) error {
	ctx, cancel := context.WithTimeout(ctx, webReqTimeout)
	defer cancel()
	r.id++
	id := r.id
	if params == nil {
		params = []any{}
	}
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return err
	}
	if err := r.conn.Write(ctx, websocket.MessageText, b); err != nil {
		return webClassify(err, method)
	}
	for range tnMaxForeign {
		_, data, err := r.conn.Read(ctx)
		if err != nil {
			return webClassify(err, method)
		}
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int             `json:"code"`
				Message string          `json:"message"`
				Data    json.RawMessage `json:"data"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &msg) != nil || string(msg.ID) != strconv.Itoa(id) {
			continue // Ereignis bzw. Antwort auf etwas anderes
		}
		if msg.Error != nil {
			e := &tnRPCError{Code: msg.Error.Code, Message: msg.Error.Message, Method: method}
			var d struct {
				Errname string `json:"errname"`
				Reason  string `json:"reason"`
			}
			if json.Unmarshal(msg.Error.Data, &d) == nil {
				e.Errname = d.Errname
				if d.Reason != "" {
					e.Message = d.Reason
				}
			}
			return e
		}
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(msg.Result, out); err != nil {
			return &webError{Kind: errWebResp, Detail: "kein passendes JSON: " + shortText(err.Error()), Where: method}
		}
		return nil
	}
	return &webError{Kind: errWebResp, Detail: "keine Antwort (nur Ereignisse)", Where: method}
}

// tnREST ruft die Methoden ueber REST v2.0 auf.
type tnREST struct{ wc *webClient }

func (r *tnREST) close() {}

func (r *tnREST) call(ctx context.Context, method string, params []any, out any) error {
	verb, path := http.MethodGet, ""
	var body any
	switch method {
	case "system.info":
		path = "/system/info"
	case "pool.query":
		path = "/pool"
	case "boot.get_state":
		path = "/boot/get_state"
	case "disk.query":
		path = "/disk"
	case "disk.temperatures":
		verb, path, body = http.MethodPost, "/disk/temperatures", map[string]any{}
	case "smart.test.results":
		path = "/smart/test/results"
	case "alert.list":
		path = "/alert/list"
	case "replication.query":
		path = "/replication"
	case "pool.snapshottask.query":
		path = "/pool/snapshottask"
	case "cloudsync.query":
		path = "/cloudsync"
	case "rsynctask.query":
		path = "/rsynctask"
	case "app.query":
		path = "/app"
	case "chart.release.query":
		path = "/chart/release"
	case "vm.query":
		path = "/vm"
	case "pool.dataset.query": // nur mit Filter [["id","=",name]]
		name := ""
		if len(params) == 1 {
			if f, ok := params[0].([][]any); ok && len(f) == 1 && len(f[0]) == 3 {
				name, _ = f[0][2].(string)
			}
		}
		path = "/pool/dataset?id=" + url.QueryEscape(name)
	default:
		return &webError{Kind: errWebResp, Status: 404, Detail: "Methode ohne REST-Pfad", Where: method}
	}
	_, err := r.wc.do(ctx, verb, "/api/v2.0"+path, nil, body, out)
	return err
}

// connect oeffnet den Weg zur API (erkennt ihn beim ersten Mal).
func (t *TrueNAS) connect(ctx context.Context) (tnCaller, error) {
	switch t.api {
	case TrueNASREST:
		return &tnREST{wc: t.wc}, nil
	case TrueNASRPC:
		r, err := t.dialRPC(ctx)
		if err != nil {
			if errors.Is(err, errTNNoRPC) {
				return nil, errors.New("JSON-RPC (wss://…/api/current) nicht vorhanden – TrueNAS vor 25.04: REST wählen")
			}
			return nil, err
		}
		return r, nil
	}
	r, err := t.dialRPC(ctx)
	if err == nil {
		t.api = TrueNASRPC
		return r, nil
	}
	if !errors.Is(err, errTNNoRPC) {
		return nil, err
	}
	t.api = TrueNASREST
	return &tnREST{wc: t.wc}, nil
}

// tnTime ist ein Zeitpunkt der TrueNAS-API ({"$date": ms}, Zahl oder Text).
type tnTime struct{ T time.Time }

func (x *tnTime) UnmarshalJSON(b []byte) error {
	*x = tnTime{}
	var d struct {
		Date optF `json:"$date"`
	}
	if json.Unmarshal(b, &d) == nil && d.Date.Set {
		x.T = msTime(d.Date.V)
		return nil
	}
	var f optF
	if f.UnmarshalJSON(b) == nil && f.Set {
		x.T = msTime(f.V)
		return nil
	}
	var s string
	if json.Unmarshal(b, &s) == nil {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(s)); err == nil {
			x.T = t
		}
	}
	return nil
}

// msTime: Millisekunden (bzw. Sekunden bei kleinen Werten) seit 1970; unsinnige Werte = kein Zeitpunkt.
func msTime(v float64) time.Time {
	if v <= 0 || v > 1e15 {
		return time.Time{}
	}
	if v < 1e11 {
		return time.Unix(int64(v), 0)
	}
	return time.UnixMilli(int64(v))
}

// tnInfo ist der benutzte Teil von system.info.
type tnInfo struct {
	Version  string `json:"version"`
	Hostname string `json:"hostname"`
	Cores    optF   `json:"cores"`
	LoadAvg  []optF `json:"loadavg"`
	Uptime   optF   `json:"uptime_seconds"`
}

// tnVdev ist ein Knoten der Pool-Topologie.
type tnVdev struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Disk   string `json:"disk"`
	Stats  struct {
		Read  optF `json:"read_errors"`
		Write optF `json:"write_errors"`
		Cksum optF `json:"checksum_errors"`
	} `json:"stats"`
	Children []tnVdev `json:"children"`
}

// tnPool ist ein Eintrag aus pool.query bzw. boot.get_state.
type tnPool struct {
	Name         string              `json:"name"`
	Status       string              `json:"status"`
	StatusDetail string              `json:"status_detail"`
	Healthy      *bool               `json:"healthy"`
	Size         optF                `json:"size"`
	Allocated    optF                `json:"allocated"`
	Free         optF                `json:"free"`
	Frag         optF                `json:"fragmentation"`
	Topology     map[string][]tnVdev `json:"topology"`
	Scan         *struct {
		Function string  `json:"function"`
		State    string  `json:"state"`
		End      *tnTime `json:"end_time"`
		Pct      optF    `json:"percentage"`
		Errors   optF    `json:"errors"`
	} `json:"scan"`
}

// tnDisk ist ein Eintrag aus disk.query.
type tnDisk struct {
	Name   string `json:"name"`
	Serial string `json:"serial"`
	LunID  string `json:"lunid"`
	Model  string `json:"model"`
	Type   string `json:"type"`
	Size   optF   `json:"size"`
	Pool   string `json:"pool"`
}

type tnSmartTest struct {
	Status, Verbose, Desc string
}

// tnAlert ist ein Eintrag aus alert.list.
type tnAlert struct {
	Level     string `json:"level"`
	Formatted string `json:"formatted"`
	Text      string `json:"text"`
	Klass     string `json:"klass"`
	Dismissed bool   `json:"dismissed"`
}

// tnState ist der Zustand einer Aufgabe (replication, snapshottask: state; cloudsync, rsynctask: job).
type tnState struct {
	State    string  `json:"state"`
	Error    string  `json:"error"`
	DateTime *tnTime `json:"datetime"`
	Finished *tnTime `json:"time_finished"`
}

type tnTask struct {
	ID          json.RawMessage `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Dataset     string          `json:"dataset"`
	Path        string          `json:"path"`
	Enabled     *bool           `json:"enabled"`
	State       *tnState        `json:"state"`
	Job         *tnState        `json:"job"`
}

// Test prueft die Verbindung im Assistenten (Zertifikat, Key, Weg, Version).
func (t *TrueNAS) Test(ctx context.Context) TestResult {
	ctx, cancel := context.WithTimeout(ctx, t.timeout())
	defer cancel()
	res, proceed := probeCert(ctx, t.wc.t, t.wc.pin, t.wc.roots)
	if !proceed {
		return res
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	cl, err := t.connect(ctx)
	if err != nil {
		res.Error = scrub(err.Error(), t.secrets()...)
		return res
	}
	defer cl.close()
	var info tnInfo
	if err := cl.call(ctx, "system.info", nil, &info); err != nil {
		res.Error = scrub(t.hint(err).Error(), t.secrets()...)
		return res
	}
	res.OK = true
	res.Version, res.Node = shortText(info.Version), shortText(info.Hostname)
	var pools []tnPool
	var disks []tnDisk
	var alerts []tnAlert
	var warn []string
	for _, q := range []struct {
		m   string
		out any
	}{{"pool.query", &pools}, {"disk.query", &disks}, {"alert.list", &alerts}} {
		if err := cl.call(ctx, q.m, nil, q.out); err != nil {
			warn = append(warn, scrub(t.hint(err).Error(), t.secrets()...))
		}
	}
	open := 0
	for _, a := range alerts {
		if !a.Dismissed && tnLevel(a.Level) >= 2 {
			open++
		}
	}
	res.Summary = fmt.Sprintf("%d Pools, %d Platten, %d offene Alarme", len(pools), len(disks), open)
	if t.api == TrueNASREST {
		res.Summary += " (REST v2.0)"
		if v := tnMajor(info.Version); v >= 25 {
			warn = append(warn, "REST-API ist ab TrueNAS 25.04 veraltet – JSON-RPC wählen")
		}
	} else {
		res.Summary += " (JSON-RPC)"
		if strings.TrimSpace(t.cfg.User) == "" && tnMajor(info.Version) >= 26 {
			warn = append(warn, "Benutzer des API-Keys eintragen – die Anmeldung ohne Benutzer entfällt mit TrueNAS 27")
		}
	}
	res.Warning = strings.TrimSpace(strings.Join(append([]string{res.Warning}, warn...), "; "))
	res.Warning = strings.Trim(res.Warning, "; ")
	return res
}

// tnMajor: Hauptversion aus "TrueNAS-SCALE-24.10.2" bzw. "25.04.1" (0 = unbekannt).
func tnMajor(v string) int {
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == '-' || r == ' ' }) {
		if n, ok := leadingUint(f); ok && n >= 10 && n < 100 && strings.Contains(f, ".") {
			return int(n)
		}
	}
	return 0
}

// hint ergaenzt Rechtefehler um den Hinweis auf die Rolle.
func (t *TrueNAS) hint(err error) error {
	if errors.Is(err, errWebPerm) {
		return fmt.Errorf("%w – der API-Key braucht Leserechte (Benutzer mit Rolle Read-Only Administrator)", err)
	}
	if errors.Is(err, errWebAuth) {
		return fmt.Errorf("%w – API-Key prüfen (widerrufen? TrueNAS widerruft Keys, die über http:// benutzt wurden)", err)
	}
	return err
}

// Collect ist eine Abfragerunde (nicht gleichzeitig mit sich selbst aufrufen).
func (t *TrueNAS) Collect(ctx context.Context) ([]model.Service, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, t.timeout())
	defer cancel()
	now := t.now()
	cl, err := t.connect(ctx)
	if err != nil {
		return nil, scrubErr(t.hint(err), t.secrets()...)
	}
	defer cl.close()
	var info tnInfo
	if err := cl.call(ctx, "system.info", nil, &info); err != nil {
		if t.cfg.API == TrueNASAuto && t.api == TrueNASREST && webAbsent(err) {
			t.api = "" // REST entfernt (Update): beim naechsten Mal neu erkennen
		}
		return nil, scrubErr(t.hint(err), t.secrets()...)
	}
	part := hintPartial{partial: &partial{secrets: t.secrets()}, hint: t.hint}
	out := tnSystemServices(info)
	pools, topo := t.pools(ctx, cl, now, part)
	out = append(out, pools...)
	out = append(out, t.disks(ctx, cl, now, topo, part)...)
	out = append(out, t.alerts(ctx, cl, part)...)
	out = append(out, t.tasks(ctx, cl, now, part)...)
	out = append(out, t.guests(ctx, cl, part)...)
	sortServices(out)
	return out, part.result()
}

// tnSystemServices: Load je Kern mit Laufzeit.
func tnSystemServices(info tnInfo) []model.Service {
	var out []model.Service
	if len(info.LoadAvg) >= 3 && info.LoadAvg[0].Set && info.LoadAvg[1].Set && info.LoadAvg[2].Set {
		l1, l5, l15 := info.LoadAvg[0].V, info.LoadAvg[1].V, info.LoadAvg[2].V
		s := model.Service{Key: "load", Name: "Load", Kind: "load", Default: true,
			Metrics: []model.Metric{{Name: "l1", Value: round2(l1)}, {Name: "l5", Value: round2(l5)}, {Name: "l15", Value: round2(l15)}},
			Text:    fmt.Sprintf("%.2f %.2f %.2f", l1, l5, l15)}
		if info.Cores.Set && info.Cores.V > 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "per_core", Value: round2(l5 / info.Cores.V), Rule: model.RuleLoad})
			s.Text += fmt.Sprintf(" · %.0f Kerne", info.Cores.V)
		}
		if info.Uptime.Set && info.Uptime.V > 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "uptime", Value: float64(int64(info.Uptime.V)), Unit: "s"})
			s.Text += " · läuft seit " + hoursText(time.Duration(info.Uptime.V)*time.Second)
		}
		out = append(out, s)
	}
	return out
}

// pools liefert die Pool-Dienste und die Geraetefehler je Platte (Geraetename -> Fehler) aus der Topologie.
func (t *TrueNAS) pools(ctx context.Context, cl tnCaller, now time.Time, part hintPartial) ([]model.Service, map[string]tnDevErr) {
	topo := map[string]tnDevErr{}
	var pools []tnPool
	if err := cl.call(ctx, "pool.query", nil, &pools); err != nil {
		part.add("pool.query", err, "zfs:")
		return nil, nil
	}
	var boot tnPool
	if err := cl.call(ctx, "boot.get_state", nil, &boot); err != nil {
		if !tnAbsent(err) {
			pre := "zfs:"
			if t.bootName != "" {
				pre += t.bootName
			}
			part.add("boot.get_state", err, pre)
		}
	} else if boot.Name != "" {
		t.bootName = boot.Name
		pools = append(pools, boot)
	}
	var out []model.Service
	for i := range pools {
		p := &pools[i]
		if p.Name == "" {
			continue
		}
		if !p.Size.Set && p.Status != "" {
			t.datasetUsage(ctx, cl, p) // CORE: Belegung aus dem Wurzel-Dataset
		}
		for _, vd := range p.Topology {
			tnWalk(vd, topo, 0)
		}
		out = append(out, tnPoolService(*p, now))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, topo
}

// datasetUsage: Belegung eines Pools ohne size/allocated (aeltere Versionen) aus dem Wurzel-Dataset; Fehler egal.
func (t *TrueNAS) datasetUsage(ctx context.Context, cl tnCaller, p *tnPool) {
	var ds []struct {
		Used struct {
			Parsed optF `json:"parsed"`
		} `json:"used"`
		Avail struct {
			Parsed optF `json:"parsed"`
		} `json:"available"`
	}
	if err := cl.call(ctx, "pool.dataset.query", []any{[][]any{{"id", "=", p.Name}}}, &ds); err != nil || len(ds) != 1 {
		return
	}
	u, a := ds[0].Used.Parsed, ds[0].Avail.Parsed
	if u.Set && a.Set && u.V >= 0 && a.V >= 0 && u.V+a.V > 0 {
		p.Size, p.Allocated, p.Free = optF{V: u.V + a.V, Set: true}, u, a
	}
}

// tnDevErr sind die Fehlerzaehler einer Platte im Pool.
type tnDevErr struct {
	read, write, cksum float64
	status             string
}

func (e tnDevErr) sum() float64 { return e.read + e.write + e.cksum }

// tnWalk sammelt die Fehler je Platte (Blaetter mit disk) rekursiv.
func tnWalk(list []tnVdev, topo map[string]tnDevErr, depth int) {
	if depth > tnMaxDepth {
		return
	}
	for _, v := range list {
		if v.Disk != "" && len(v.Children) == 0 {
			e := topo[v.Disk]
			e.read += max(v.Stats.Read.V, 0)
			e.write += max(v.Stats.Write.V, 0)
			e.cksum += max(v.Stats.Cksum.V, 0)
			if v.Status != "" && !strings.EqualFold(v.Status, "ONLINE") {
				e.status = v.Status
			}
			topo[v.Disk] = e
		}
		tnWalk(v.Children, topo, depth+1)
	}
}

// tnPoolErrors: Summe der Geraetefehler eines Pools.
func tnPoolErrors(p tnPool) tnDevErr {
	topo := map[string]tnDevErr{}
	for _, vd := range p.Topology {
		tnWalk(vd, topo, 0)
	}
	var s tnDevErr
	for _, e := range topo {
		s.read += e.read
		s.write += e.write
		s.cksum += e.cksum
	}
	return s
}

// tnPoolService: Pool mit Zustand, Belegung, Scrub und Geraetefehlern (zfs_degraded wie beim Agent: nicht ONLINE,
// Fehler beim Scrub oder Geraetefehler auch bei ONLINE).
func tnPoolService(p tnPool, now time.Time) model.Service {
	s := model.Service{Key: "zfs:" + p.Name, Name: "ZFS " + p.Name, Kind: "zfs", Default: true}
	status := strings.ToUpper(firstNonEmpty(strings.TrimSpace(p.Status), "UNKNOWN"))
	parts := []string{status}
	if p.Size.Set && p.Size.V > 0 && p.Allocated.Set {
		tot := p.Size.V
		free := p.Free.V
		if !p.Free.Set {
			free = max(tot-p.Allocated.V, 0)
		}
		s.Metrics = append(s.Metrics, model.Metric{Name: "used", Value: pct(p.Allocated.V, tot), Unit: "%", Rule: model.RuleStore, Max: tot},
			model.Metric{Name: "free", Value: free, Unit: "B", Max: tot})
		if p.Frag.Set {
			s.Metrics = append(s.Metrics, model.Metric{Name: "frag", Value: round2(p.Frag.V), Unit: "%"})
		}
		parts = append(parts, fmt.Sprintf("%s von %s frei", bytesText(free), bytesText(tot)))
	}
	var bad []string
	if status != "ONLINE" || (p.Healthy != nil && !*p.Healthy && status == "UNKNOWN") {
		bad = append(bad, strings.TrimSpace(status+" "+shortText(p.StatusDetail)))
	}
	if sc := p.Scan; sc != nil && strings.EqualFold(sc.Function, "SCRUB") {
		switch strings.ToUpper(sc.State) {
		case "SCANNING":
			parts = append(parts, fmt.Sprintf("Scrub läuft (%.0f %%)", sc.Pct.V))
		case "FINISHED":
			if sc.End != nil && !sc.End.T.IsZero() {
				age := max(now.Sub(sc.End.T), 0)
				s.Metrics = append(s.Metrics, model.Metric{Name: "scrub_age", Value: round2(age.Hours() / 24), Unit: "d"})
				parts = append(parts, "letzter Scrub "+agoText(age))
			}
		case "CANCELED":
			parts = append(parts, "Scrub abgebrochen")
		}
		if sc.Errors.Set && sc.Errors.V > 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "scrub_errors", Value: sc.Errors.V})
			bad = append(bad, fmt.Sprintf("Scrub: %.0f Fehler", sc.Errors.V))
		}
	}
	if e := tnPoolErrors(p); e.sum() > 0 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "dev_errors", Value: e.sum()})
		bad = append(bad, fmt.Sprintf("Gerätefehler READ %.0f WRITE %.0f CKSUM %.0f", e.read, e.write, e.cksum))
	}
	if len(bad) > 0 {
		s.Facts = append(s.Facts, model.Fact{Code: "zfs_degraded", Text: strings.Join(bad, "; ")})
		if status == "ONLINE" {
			parts = append(parts, strings.Join(bad, "; "))
		} else if p.StatusDetail != "" {
			parts = append(parts, shortText(p.StatusDetail))
		}
	}
	s.Text = strings.Join(parts, " · ")
	return s
}

// disks: Platten aus disk.query; Temperaturen und SMART-Tests alle SmartEvery.
func (t *TrueNAS) disks(ctx context.Context, cl tnCaller, now time.Time, topo map[string]tnDevErr, part hintPartial) []model.Service {
	var list []tnDisk
	if err := cl.call(ctx, "disk.query", nil, &list); err != nil {
		part.add("disk.query", err, "disk:")
		return nil
	}
	every := t.cfg.SmartEvery
	if every <= 0 {
		every = DefaultSmartEvery
	}
	if t.slowAt.IsZero() || now.Sub(t.slowAt) >= every {
		t.slowAt = now
		temps, err := tnTemps(ctx, cl)
		switch {
		case err == nil:
			t.temps = temps
		case !tnAbsent(err):
			part.add("disk.temperatures", err) // Platten bleiben, Temperaturen vom vorigen Stand
		}
		var res []struct {
			Disk  string `json:"disk"`
			Tests []struct {
				Description string `json:"description"`
				Status      string `json:"status"`
				Verbose     string `json:"status_verbose"`
			} `json:"tests"`
		}
		err = cl.call(ctx, "smart.test.results", nil, &res)
		switch {
		case err == nil:
			sm := map[string]tnSmartTest{}
			for _, r := range res {
				if r.Disk != "" && len(r.Tests) > 0 {
					sm[r.Disk] = tnSmartTest{Status: r.Tests[0].Status, Verbose: r.Tests[0].Verbose, Desc: r.Tests[0].Description}
				}
			}
			t.smart = sm
		case !tnAbsent(err):
			part.add("smart.test.results", err)
		}
	}
	entries := make([]diskEntry, len(list))
	for i, d := range list {
		entries[i] = diskEntry{Name: d.Name, Serial: d.Serial, WWN: d.LunID}
	}
	keys := diskKeys(entries)
	seen := map[string]bool{}
	var out []model.Service
	for i, d := range list {
		if d.Name == "" || seen[keys[i]] {
			continue
		}
		seen[keys[i]] = true
		out = append(out, tnDiskService(keys[i], d, t.temps, t.smart, topo))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// tnTemps liest disk.temperatures ({"sda": 34, "sdb": null} bzw. Objekte mit temperature).
func tnTemps(ctx context.Context, cl tnCaller) (map[string]float64, error) {
	var raw map[string]json.RawMessage
	if err := cl.call(ctx, "disk.temperatures", nil, &raw); err != nil {
		return nil, err
	}
	out := map[string]float64{}
	for k, v := range raw {
		var f optF
		_ = f.UnmarshalJSON(v)
		if !f.Set {
			var o struct {
				Temperature optF `json:"temperature"`
				Temp        optF `json:"temp"`
			}
			if json.Unmarshal(v, &o) == nil {
				f = o.Temperature
				if !f.Set {
					f = o.Temp
				}
			}
		}
		if f.Set && f.V > 0 && f.V < 150 {
			out[k] = f.V
		}
	}
	return out, nil
}

func tnDiskService(key string, d tnDisk, temps map[string]float64, smart map[string]tnSmartTest, topo map[string]tnDevErr) model.Service {
	name := d.Name
	if m := strings.TrimSpace(d.Model); m != "" {
		name += " (" + shortText(m) + ")"
	}
	s := model.Service{Key: key, Name: name, Kind: "disk", Default: true}
	var parts []string
	if d.Size.Set && d.Size.V > 0 {
		parts = append(parts, bytesText(d.Size.V))
	}
	if d.Pool != "" {
		parts = append(parts, "Pool "+shortText(d.Pool))
	}
	if st, ok := smart[d.Name]; ok {
		switch strings.ToUpper(st.Status) {
		case "SUCCESS":
			parts = append(parts, "SMART-Test ok")
		case "FAILED":
			t := firstNonEmpty(shortText(st.Verbose), "fehlgeschlagen")
			parts = append(parts, "SMART-Test: "+t)
			s.Facts = append(s.Facts, model.Fact{Code: "smart_failed", Text: "letzter SMART-Test (" + shortText(st.Desc) + "): " + t})
		case "RUNNING":
			parts = append(parts, "SMART-Test läuft")
		}
	}
	if t, ok := temps[d.Name]; ok {
		rule := model.RuleDiskTemp
		if strings.HasPrefix(d.Name, "nvme") {
			rule = model.RuleNVMeTemp
		}
		s.Metrics = append(s.Metrics, model.Metric{Name: "temp", Value: round2(t), Unit: "°C", Rule: rule})
		parts = append(parts, fmt.Sprintf("%.0f °C", t))
	}
	if e, ok := topo[d.Name]; ok {
		s.Metrics = append(s.Metrics, model.Metric{Name: "read_err", Value: e.read}, model.Metric{Name: "write_err", Value: e.write},
			model.Metric{Name: "cksum_err", Value: e.cksum})
		if e.sum() > 0 {
			t := fmt.Sprintf("ZFS-Fehler READ %.0f WRITE %.0f CKSUM %.0f", e.read, e.write, e.cksum)
			parts = append(parts, t)
			s.Facts = append(s.Facts, model.Fact{Code: "disk_errors", Text: t})
		}
		if e.status != "" {
			parts = append(parts, "im Pool "+shortText(e.status))
		}
	}
	s.Text = strings.Join(parts, " · ")
	return s
}

// tnLevel: Rang einer Alarmstufe (2 = WARNING).
func tnLevel(l string) int {
	switch strings.ToUpper(l) {
	case "NOTICE":
		return 1
	case "WARNING":
		return 2
	case "ERROR":
		return 3
	case "CRITICAL":
		return 4
	case "ALERT":
		return 5
	case "EMERGENCY":
		return 6
	}
	return 0
}

// alerts: ein Dienst mit den nicht quittierten Alarmen (WARNING/ERROR -> device_warn, ab CRITICAL -> device_crit).
func (t *TrueNAS) alerts(ctx context.Context, cl tnCaller, part hintPartial) []model.Service {
	var list []tnAlert
	if err := cl.call(ctx, "alert.list", nil, &list); err != nil {
		part.add("alert.list", err, "alerts")
		return nil
	}
	return []model.Service{alertService(tnAlertItems(list))}
}

// alertItem ist eine offene Meldung eines Geraets (crit: ab kritisch).
type alertItem struct {
	text string
	crit bool
}

func tnAlertItems(list []tnAlert) []alertItem {
	var out []alertItem
	for _, a := range list {
		lv := tnLevel(a.Level)
		if a.Dismissed || lv < 2 {
			continue
		}
		out = append(out, alertItem{text: firstNonEmpty(stripTags(a.Formatted), stripTags(a.Text), a.Klass), crit: lv >= 4})
	}
	return out
}

// alertService: Dienst "alerts" mit Anzahl und Zustaenden device_warn/device_crit (TrueNAS, Unraid).
func alertService(items []alertItem) model.Service {
	s := model.Service{Key: "alerts", Name: "Alarme", Kind: "alerts", Default: true}
	var warn, crit []string
	for _, it := range items {
		if it.crit {
			crit = append(crit, it.text)
		} else {
			warn = append(warn, it.text)
		}
	}
	s.Metrics = []model.Metric{{Name: "warn", Value: float64(len(warn))}, {Name: "crit", Value: float64(len(crit))}}
	switch {
	case len(warn)+len(crit) == 0:
		s.Text = "keine offenen Alarme"
	default:
		s.Text = fmt.Sprintf("%d offen: %s", len(warn)+len(crit), strings.Join(limitList(append(append([]string{}, crit...), warn...), 3), "; "))
	}
	if len(crit) > 0 {
		s.Facts = append(s.Facts, model.Fact{Code: "device_crit", Text: strings.Join(limitList(crit, 3), "; ")})
	}
	if len(warn) > 0 {
		s.Facts = append(s.Facts, model.Fact{Code: "device_warn", Text: strings.Join(limitList(warn, 3), "; ")})
	}
	return s
}

// tasks: Replikations-, Snapshot-, Cloud-Sync- und Rsync-Aufgaben mit letztem Zustand.
func (t *TrueNAS) tasks(ctx context.Context, cl tnCaller, now time.Time, part hintPartial) []model.Service {
	var out []model.Service
	for _, k := range []struct{ method, kind, label string }{
		{"replication.query", "replication", "Replikation"},
		{"pool.snapshottask.query", "snapshot", "Snapshot-Aufgabe"},
		{"cloudsync.query", "cloudsync", "Cloud-Sync"},
		{"rsynctask.query", "rsync", "Rsync"},
	} {
		var list []tnTask
		if err := cl.call(ctx, k.method, nil, &list); err != nil {
			if !tnAbsent(err) {
				part.add(k.method, err, "job:"+k.kind+":")
			}
			continue
		}
		for _, x := range list {
			id := rawText(x.ID)
			if id == "" || id == "null" {
				continue
			}
			out = append(out, tnTaskService(k.kind, k.label, id, x, now))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// tnTaskService: letzter Lauf ok bzw. Fehler (job_failed wie bei PBS).
func tnTaskService(kind, label, id string, x tnTask, now time.Time) model.Service {
	what := shortText(firstNonEmpty(x.Name, x.Description, x.Dataset, x.Path, id))
	enabled := x.Enabled == nil || *x.Enabled
	s := model.Service{Key: "job:" + kind + ":" + id, Name: label + " " + what, Kind: "job", Default: enabled}
	st := x.State
	if st == nil {
		st = x.Job
	}
	var parts []string
	if !enabled {
		parts = append(parts, "abgeschaltet")
	}
	state := ""
	if st != nil {
		state = strings.ToUpper(strings.TrimSpace(st.State))
	}
	when := ""
	if st != nil {
		var at time.Time
		if st.Finished != nil {
			at = st.Finished.T
		}
		if at.IsZero() && st.DateTime != nil {
			at = st.DateTime.T
		}
		if !at.IsZero() && state != "RUNNING" && state != "PENDING" {
			age := max(now.Sub(at), 0)
			when = " " + agoText(age)
			s.Metrics = append(s.Metrics, model.Metric{Name: "age", Value: round2(age.Hours()), Unit: "h"})
		}
	}
	switch state {
	case "":
		parts = append(parts, "noch nicht gelaufen")
	case "RUNNING":
		parts = append(parts, "läuft gerade")
	case "PENDING", "WAITING", "HOLD":
		parts = append(parts, "wartet ("+state+")")
	case "FINISHED", "SUCCESS":
		s.Metrics = append(s.Metrics, model.Metric{Name: "failed", Value: 0})
		parts = append(parts, "letzter Lauf"+when+": OK")
	case "ERROR", "FAILED", "ABORTED":
		msg := firstNonEmpty(shortText(st.Error), state)
		s.Metrics = append(s.Metrics, model.Metric{Name: "failed", Value: 1})
		parts = append(parts, "letzter Lauf"+when+" fehlgeschlagen: "+msg)
		if enabled {
			s.Facts = append(s.Facts, model.Fact{Code: "job_failed", Text: msg})
		}
	default:
		parts = append(parts, "Zustand "+shortText(state))
	}
	s.Text = strings.Join(parts, " · ")
	return s
}

// guests: Apps (24.10+: app.query, davor chart.release.query) und VMs, soweit vorhanden.
func (t *TrueNAS) guests(ctx context.Context, cl tnCaller, part hintPartial) []model.Service {
	var out []model.Service
	var apps []struct {
		Name    string `json:"name"`
		State   string `json:"state"`
		Status  string `json:"status"` // chart.release
		Upgrade bool   `json:"upgrade_available"`
		Version string `json:"human_version"`
	}
	err := cl.call(ctx, "app.query", nil, &apps)
	if tnAbsent(err) {
		err = cl.call(ctx, "chart.release.query", nil, &apps)
	}
	switch {
	case err == nil:
		for _, a := range apps {
			if a.Name == "" {
				continue
			}
			out = append(out, tnAppService(a.Name, strings.ToUpper(firstNonEmpty(a.State, a.Status)), a.Upgrade, a.Version))
		}
	case !tnAbsent(err):
		part.add("app.query", err, "app:")
	}
	var vms []struct {
		ID        json.RawMessage `json:"id"`
		Name      string          `json:"name"`
		Autostart bool            `json:"autostart"`
		Status    struct {
			State string `json:"state"`
		} `json:"status"`
	}
	if err := cl.call(ctx, "vm.query", nil, &vms); err != nil {
		if !tnAbsent(err) {
			part.add("vm.query", err, "vm:")
		}
		return out
	}
	for _, v := range vms {
		id := rawText(v.ID)
		if id == "" || id == "null" {
			continue
		}
		out = append(out, tnVMService(id, v.Name, strings.ToUpper(v.Status.State), v.Autostart))
	}
	return out
}

// tnAppService: App als Dienst app:<name> (Art ctr); CRASHED ist eine Stoerung unabhaengig vom Soll.
func tnAppService(name, state string, upgrade bool, version string) model.Service {
	s := model.Service{Key: "app:" + name, Name: "App " + shortText(name), Kind: "ctr", Default: true}
	run := 0.0
	if state == "RUNNING" || state == "ACTIVE" {
		run = 1
	}
	s.Metrics = []model.Metric{{Name: "running", Value: run}}
	parts := []string{map[string]string{"RUNNING": "läuft", "ACTIVE": "läuft", "STOPPED": "gestoppt", "DEPLOYING": "wird bereitgestellt",
		"CRASHED": "abgestürzt", "STOPPING": "wird gestoppt"}[state]}
	if parts[0] == "" {
		parts[0] = firstNonEmpty(shortText(state), "unbekannt")
	}
	if version != "" {
		parts = append(parts, shortText(version))
	}
	if upgrade {
		parts = append(parts, "Update verfügbar")
	}
	if state == "CRASHED" {
		s.Facts = append(s.Facts, model.Fact{Code: "guest_fault", Text: "App abgestürzt (CRASHED)"})
	}
	s.Text = strings.Join(parts, " · ")
	return s
}

// tnVMService: VM als Dienst vm:<id>; autostart = soll laufen (wie onboot bei Proxmox).
func tnVMService(id, name, state string, autostart bool) model.Service {
	label := "VM " + id
	if name != "" {
		label = shortText(name) + " (VM " + id + ")"
	}
	s := model.Service{Key: "vm:" + id, Name: label, Kind: "vm", Default: true}
	run := 0.0
	if state == "RUNNING" {
		run = 1
	}
	s.Metrics = []model.Metric{{Name: "running", Value: run}, {Name: "locked", Value: 0}}
	st := map[string]string{"RUNNING": "läuft", "STOPPED": "gestoppt", "SUSPENDED": "angehalten", "ERROR": "Fehler"}[state]
	parts := []string{firstNonEmpty(st, shortText(state), "unbekannt")}
	if autostart {
		parts = append(parts, "soll laufen (Autostart)")
	} else {
		parts = append(parts, "darf aus sein")
	}
	switch {
	case state == "ERROR":
		s.Facts = append(s.Facts, model.Fact{Code: "guest_fault", Text: "VM im Fehlerzustand"})
	case autostart && state != "RUNNING" && state != "":
		s.Facts = append(s.Facts, model.Fact{Code: "guest_down", Text: parts[0] + ", soll laufen (Autostart)"})
	}
	s.Text = strings.Join(parts, " · ")
	return s
}
