package apis

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Unraid (Unraid-API, GraphQL unter /graphql mit API-Key im Kopf x-api-key; ab Unraid 7.2 eingebaut, davor mit
// dem Plugin "Unraid Connect"). Je Runde mehrere kleine Abfragen, damit ein fehlendes Feld einer aelteren API nur
// seinen Teil kostet:
//
//	info { os, cpu, versions }               Name, Laufzeit, Version (Pflicht: ohne Antwort kein Ergebnis)
//	metrics { cpu, memory }                  CPU und RAM/Swap (neuere API)
//	array { state, capacity, parities, disks, caches, parityCheckStatus }
//	                                         Array (raid:array), Pools (raid:<pool> bzw. zfs:<pool>), Platten
//	                                         (disk:<seriennummer>); Temperaturen aus dem Array-Stand (weckt keine
//	                                         Platten)
//	vars { mdNumInvalid, mdNumDisabled, mdResync, sbSynced, sbSyncErrs }
//	                                         Paritaet (aeltere API ohne parityCheckStatus)
//	docker { containers }, vms { domains }   Container (ctr:<name>, Soll aus Autostart) und VMs (vm:<name>)
//	notifications { overview, list }         ungelesene Warnungen/Alarme (alerts, device_warn)

// UnraidConfig sind die Verbindungsdaten eines Unraid-Servers.
type UnraidConfig struct {
	Address string        // http(s)://tower (https empfohlen)
	APIKey  string        // API-Key (Geheimnis, nie ausgeben)
	Pin     string        // SHA-256 des Zertifikats (hex) bei https mit eigenem Zertifikat
	Timeout time.Duration // ganze Runde (0 = DefaultTimeout)
}

// Unraid ist der Sammler eines Unraid-Servers.
type Unraid struct {
	cfg UnraidConfig
	wc  *webClient
	now func() time.Time
	mu  sync.Mutex
}

// NewUnraid baut den Sammler (prueft Adresse, Key und Pin; fragt noch nichts ab).
func NewUnraid(cfg UnraidConfig) (*Unraid, error) { return newUnraid(cfg, nil) }

func newUnraid(cfg UnraidConfig, roots *x509.CertPool) (*Unraid, error) {
	t, err := parseWebAddr(cfg.Address, "http", "", true)
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
	wc.header = func(h http.Header) { h.Set("x-api-key", key) }
	return &Unraid{cfg: cfg, wc: wc, now: time.Now}, nil
}

func (u *Unraid) timeout() time.Duration {
	if u.cfg.Timeout > 0 {
		return u.cfg.Timeout
	}
	return DefaultTimeout
}

func (u *Unraid) secrets() []string { return []string{strings.TrimSpace(u.cfg.APIKey), u.cfg.APIKey} }

// Close gibt Verbindungen frei.
func (u *Unraid) Close() { u.wc.close() }

// Queries nennt die Abfragen ("Was wird abgefragt?").
func (u *Unraid) Queries() []string {
	return []string{"POST /graphql (x-api-key)", "info { os cpu versions }", "metrics { cpu memory }",
		"array { state capacity parities disks caches parityCheckStatus }", "vars { mdNumInvalid mdNumDisabled mdResync sbSynced sbSyncErrs }",
		"docker { containers }", "vms { domains }", "notifications { overview list }"}
}

// gqlError ist ein Fehler aus der GraphQL-Antwort.
type gqlError struct {
	Msg    string
	Code   string
	schema bool // Feld bzw. Typ gibt es in dieser API-Version nicht
}

func (e *gqlError) Error() string {
	if e.Code != "" {
		return "GraphQL " + devText(e.Code) + ": " + devText(e.Msg)
	}
	return "GraphQL: " + devText(e.Msg)
}

func (e *gqlError) Unwrap() error {
	switch e.Code {
	case "UNAUTHENTICATED":
		return errWebAuth
	case "FORBIDDEN":
		return errWebPerm
	}
	return nil
}

// gqlSchema: die Abfrage passt nicht zu dieser API-Version (Feld fehlt) – Teil weglassen bzw. andere Form versuchen.
func gqlSchema(err error) bool {
	var ge *gqlError
	if errors.As(err, &ge) {
		return ge.schema
	}
	var we *webError
	if errors.As(err, &we) && we.Status == 400 {
		return isSchemaMsg(we.Detail)
	}
	return webAbsent(err)
}

func isSchemaMsg(m string) bool {
	for _, s := range []string{"Cannot query field", "Unknown argument", "Unknown type", "Unknown field"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

// gql sendet eine Abfrage und legt data in out ab. Fehler in der Antwort sind Fehler (auch mit Teil-Daten).
func (u *Unraid) gql(ctx context.Context, query string, out any) error {
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message    string `json:"message"`
			Extensions struct {
				Code string `json:"code"`
			} `json:"extensions"`
		} `json:"errors"`
	}
	if _, err := u.wc.do(ctx, http.MethodPost, "/graphql", nil, map[string]any{"query": query}, &env); err != nil {
		return err
	}
	if len(env.Errors) > 0 {
		e := env.Errors[0]
		return &gqlError{Msg: e.Message, Code: e.Extensions.Code, schema: e.Extensions.Code == "GRAPHQL_VALIDATION_FAILED" || isSchemaMsg(e.Message)}
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return &webError{Kind: errWebResp, Detail: model.T("monitor64.txt.resp_no_data"), Where: "POST /graphql"}
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return &webError{Kind: errWebResp, Detail: model.T("monitor64.txt.resp_json") + ": " + devText(err.Error()), Where: "POST /graphql"}
	}
	return nil
}

const (
	urInfoQ    = `query { info { os { hostname uptime } cpu { cores threads } versions { core { unraid api } } } }`
	urInfoOldQ = `query { info { os { hostname uptime } cpu { cores threads } versions { unraid } } }`
	urMetricsQ = `query { metrics { cpu { percentTotal } memory { total used available percentTotal swapTotal swapUsed } } }`
	urDiskF    = `id idx name device size status temp numErrors rotational isSpinning fsSize fsFree fsUsed fsType type`
	urArrayQ   = `query { array { state capacity { kilobytes { free used total } } parities { ` + urDiskF + ` } disks { ` + urDiskF +
		` } caches { ` + urDiskF + ` } parityCheckStatus { status progress errors running paused correcting date } } }`
	urArrayOldQ = `query { array { state capacity { kilobytes { free used total } } parities { ` + urDiskF + ` } disks { ` + urDiskF +
		` } caches { ` + urDiskF + ` } } }`
	urDiskMinF  = `id name device size status temp numErrors fsSize fsFree fsUsed`
	urArrayMinQ = `query { array { state capacity { kilobytes { free used total } } parities { ` + urDiskMinF + ` } disks { ` +
		urDiskMinF + ` } caches { ` + urDiskMinF + ` } } }`
	urVarsQ    = `query { vars { mdNumInvalid mdNumDisabled mdResync sbSynced sbSyncErrs } }`
	urDockerQ  = `query { docker { containers { names image state status autoStart } } }`
	urVMsQ     = `query { vms { domains { name state } } }`
	urVMsOldQ  = `query { vms { domain { name state } } }`
	urNotifyQ  = `query { notifications { overview { unread { warning alert } } alerts: list(filter: {type: UNREAD, importance: ALERT, offset: 0, limit: 3}) { subject description } warnings: list(filter: {type: UNREAD, importance: WARNING, offset: 0, limit: 3}) { subject description } } }`
	urNotifyOQ = `query { notifications { overview { unread { warning alert } } } }`
)

// urInfo ist die Antwort auf urInfoQ bzw. urInfoOldQ.
type urInfo struct {
	Info struct {
		OS struct {
			Hostname string          `json:"hostname"`
			Uptime   json.RawMessage `json:"uptime"`
		} `json:"os"`
		CPU struct {
			Cores   optF `json:"cores"`
			Threads optF `json:"threads"`
		} `json:"cpu"`
		Versions struct {
			Core struct {
				Unraid string `json:"unraid"`
				API    string `json:"api"`
			} `json:"core"`
			Unraid string `json:"unraid"`
		} `json:"versions"`
	} `json:"info"`
}

func (i urInfo) version() string {
	v := firstNonEmpty(i.Info.Versions.Core.Unraid, i.Info.Versions.Unraid)
	if a := i.Info.Versions.Core.API; a != "" {
		v = strings.TrimSpace(v + " (API " + a + ")")
	}
	return shortText(v)
}

// info fragt die Pflicht-Abfrage (neue, sonst alte Form der Versionen).
func (u *Unraid) info(ctx context.Context) (urInfo, error) {
	var in urInfo
	err := u.gql(ctx, urInfoQ, &in)
	if gqlSchema(err) {
		in = urInfo{}
		err = u.gql(ctx, urInfoOldQ, &in)
	}
	return in, err
}

// hint ergaenzt Anmelde- und Rechtefehler.
func (u *Unraid) hint(err error) error {
	switch {
	case errors.Is(err, errWebAuth):
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.ur_hint_auth"))
	case errors.Is(err, errWebPerm):
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.ur_hint_perm"))
	case webAbsent(err):
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.ur_hint_absent"))
	}
	return err
}

// Test prueft die Verbindung im Assistenten (Zertifikat, Key, Version).
func (u *Unraid) Test(ctx context.Context) TestResult {
	ctx, cancel := context.WithTimeout(ctx, u.timeout())
	defer cancel()
	res, proceed := probeCert(ctx, u.wc.t, u.wc.pin, u.wc.roots)
	if !proceed {
		return res
	}
	in, err := u.info(ctx)
	if err != nil {
		res.Error = scrub(u.hint(err).Error(), u.secrets()...)
		return res
	}
	res.OK = true
	res.Version, res.Node = in.version(), shortText(in.Info.OS.Hostname)
	var arr urArray
	err = u.gql(ctx, urArrayMinQ, &arr)
	if err != nil {
		res.Warning = strings.Trim(res.Warning+"; array: "+scrub(u.hint(err).Error(), u.secrets()...), "; ")
		return res
	}
	n := 0
	for _, d := range append(append(append([]urDisk{}, arr.Array.Parities...), arr.Array.Disks...), arr.Array.Caches...) {
		if d.present() {
			n++
		}
	}
	res.Summary = model.T("monitor64.txt.ur_summary", "state", firstNonEmpty(arr.Array.State, "?"), "n", n)
	return res
}

// urDisk ist eine Platte des Arrays bzw. eines Pools (Groessen in KB).
type urDisk struct {
	ID       string `json:"id"`
	Idx      optF   `json:"idx"`
	Name     string `json:"name"`
	Device   string `json:"device"`
	Size     optF   `json:"size"`
	Status   string `json:"status"`
	Temp     optF   `json:"temp"`
	Errors   optF   `json:"numErrors"`
	Rot      *bool  `json:"rotational"`
	Spinning *bool  `json:"isSpinning"`
	FSSize   optF   `json:"fsSize"`
	FSFree   optF   `json:"fsFree"`
	FSUsed   optF   `json:"fsUsed"`
	FSType   string `json:"fsType"`
	Type     string `json:"type"`
}

// present: Platz mit Platte (DISK_NP = leerer Platz).
func (d urDisk) present() bool {
	return d.Device != "" || (d.Status != "" && d.Status != "DISK_NP")
}

// urBad sind Zustaende einer Platte, die das Array bzw. den Pool schwaechen.
var urBad = map[string]string{"DISK_DSBL": "monitor64.txt.disk_disabled", "DISK_NP_DSBL": "monitor64.txt.disk_disabled_missing",
	"DISK_INVALID": "monitor64.txt.disk_invalid", "DISK_WRONG": "monitor64.txt.disk_wrong", "DISK_NP_MISSING": "monitor64.txt.disk_missing",
	"DISK_DSBL_NEW": "monitor64.txt.disk_disabled_new"}

var urStatusText = map[string]string{"DISK_NP": "monitor64.txt.empty", "DISK_NEW": "monitor64.txt.new"}

// urStatus: Zustand einer Platte als Text ("" = keiner).
func urStatus(status string) string {
	switch k := firstNonEmpty(urStatusText[status], urBad[status]); {
	case status == "DISK_OK":
		return "ok"
	case k != "":
		return model.T(k)
	}
	return devText(status)
}

// serial: Seriennummer aus der ID ("<server>:<Modell>_<Seriennummer>"); "" = nicht erkennbar.
func (d urDisk) serial() string {
	id := d.ID
	if i := strings.LastIndex(id, ":"); i >= 0 {
		id = id[i+1:]
	}
	i := strings.LastIndex(id, "_")
	if i < 0 || i == len(id)-1 {
		return ""
	}
	return id[i+1:]
}

type urArray struct {
	Array struct {
		State    string `json:"state"`
		Capacity struct {
			KB struct {
				Free  optF `json:"free"`
				Used  optF `json:"used"`
				Total optF `json:"total"`
			} `json:"kilobytes"`
		} `json:"capacity"`
		Parities []urDisk `json:"parities"`
		Disks    []urDisk `json:"disks"`
		Caches   []urDisk `json:"caches"`
		Parity   *struct {
			Status     string  `json:"status"`
			Progress   optF    `json:"progress"`
			Errors     optF    `json:"errors"`
			Running    bool    `json:"running"`
			Paused     bool    `json:"paused"`
			Correcting bool    `json:"correcting"`
			Date       *tnTime `json:"date"`
		} `json:"parityCheckStatus"`
	} `json:"array"`
}

type urVars struct {
	Vars struct {
		Invalid  optF `json:"mdNumInvalid"`
		Disabled optF `json:"mdNumDisabled"`
		Resync   optF `json:"mdResync"`
		Synced   optF `json:"sbSynced"`
		SyncErrs optF `json:"sbSyncErrs"`
	} `json:"vars"`
}

// Collect ist eine Abfragerunde (nicht gleichzeitig mit sich selbst aufrufen).
func (u *Unraid) Collect(ctx context.Context) ([]model.Service, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, u.timeout())
	defer cancel()
	now := u.now()
	in, err := u.info(ctx)
	if err != nil {
		return nil, scrubErr(u.hint(err), u.secrets()...)
	}
	part := &partial{secrets: u.secrets()}
	add := func(what string, err error, prefixes ...string) { part.add(what, u.hint(err), prefixes...) }
	out := u.system(ctx, in, now, add)
	// Array, Pools, Platten
	var arr urArray
	err = u.gql(ctx, urArrayQ, &arr)
	for _, q := range []string{urArrayOldQ, urArrayMinQ} { // aeltere API: ohne Paritaetspruefung bzw. weniger Felder
		if !gqlSchema(err) {
			break
		}
		arr = urArray{}
		err = u.gql(ctx, q, &arr)
	}
	if err != nil {
		add("array", err, "raid:", "zfs:", "disk:")
	} else {
		var vars *urVars
		if arr.Array.Parity == nil {
			var v urVars
			if err := u.gql(ctx, urVarsQ, &v); err == nil {
				vars = &v
			} else if !gqlSchema(err) {
				add("vars", err)
			}
		}
		out = append(out, urArrayServices(arr, vars, now)...)
	}
	out = append(out, u.containers(ctx, add)...)
	out = append(out, u.vms(ctx, add)...)
	if s, ok := u.notifications(ctx, add); ok {
		out = append(out, s)
	}
	sortServices(out)
	return out, part.result()
}

// system: CPU, RAM, Swap (metrics, neuere API) und Laufzeit.
func (u *Unraid) system(ctx context.Context, in urInfo, now time.Time, add func(string, error, ...string)) []model.Service {
	var out []model.Service
	var m struct {
		Metrics struct {
			CPU *struct {
				Pct optF `json:"percentTotal"`
			} `json:"cpu"`
			Mem *struct {
				Total     optF `json:"total"`
				Used      optF `json:"used"`
				Available optF `json:"available"`
				Pct       optF `json:"percentTotal"`
				SwapTotal optF `json:"swapTotal"`
				SwapUsed  optF `json:"swapUsed"`
			} `json:"memory"`
		} `json:"metrics"`
	}
	err := u.gql(ctx, urMetricsQ, &m)
	if err != nil && !gqlSchema(err) {
		add("metrics", err, "cpu", "mem", "swap")
	}
	cpu := model.Service{Key: "cpu", Name: "CPU", Kind: "cpu", Default: true}
	var parts []string
	if c := m.Metrics.CPU; err == nil && c != nil && c.Pct.Set {
		cpu.Metrics = []model.Metric{{Name: "util", Value: round2(min(max(c.Pct.V, 0), 100)), Unit: "%", Rule: model.RuleCPU}}
	}
	if th := in.Info.CPU.Threads; th.Set && th.V > 0 {
		parts = append(parts, fmt.Sprintf("%.0f Threads", th.V))
	}
	if up := urUptime(in.Info.OS.Uptime, now); up > 0 {
		cpu.Metrics = append(cpu.Metrics, model.Metric{Name: "uptime", Value: float64(int64(up.Seconds())), Unit: "s"})
		parts = append(parts, model.T("monitor64.txt.up_since", "d", model.Sub(hoursText(up))))
	}
	cpu.Text = strings.Join(parts, " · ")
	if len(cpu.Metrics) > 0 || cpu.Text != "" {
		out = append(out, cpu)
	}
	if mm := m.Metrics.Mem; err == nil && mm != nil && mm.Total.Set && mm.Total.V > 0 {
		tot := mm.Total.V
		used := tot - mm.Available.V // wie free: verfuegbar statt frei (Cache zaehlt nicht als belegt)
		if !mm.Available.Set {
			used = mm.Used.V
		}
		used = min(max(used, 0), tot)
		out = append(out, model.Service{Key: "mem", Name: "RAM", Kind: "mem", Default: true,
			Metrics: []model.Metric{{Name: "used", Value: pct(used, tot), Unit: "%", Rule: model.RuleMem, Max: tot},
				{Name: "avail", Value: tot - used, Unit: "B"}},
			Text: model.T("monitor64.txt.free_of", "free", bytesText(tot-used), "total", bytesText(tot))})
		if st := mm.SwapTotal.V; mm.SwapTotal.Set && st > 0 {
			out = append(out, model.Service{Key: "swap", Name: "Swap", Kind: "swap", Default: true,
				Metrics: []model.Metric{{Name: "used", Value: pct(min(max(mm.SwapUsed.V, 0), st), st), Unit: "%", Rule: model.RuleSwap, Max: st}}})
		}
	}
	return out
}

// urUptime: Laufzeit aus os.uptime (Startzeit als Text bzw. Sekunden).
func urUptime(raw json.RawMessage, now time.Time) time.Duration {
	var f optF
	if f.UnmarshalJSON(raw) == nil && f.Set && f.V > 0 && f.V < 1e9 {
		return time.Duration(f.V) * time.Second
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(s)); err == nil && t.Before(now) {
			return now.Sub(t)
		}
	}
	return 0
}

// poolName: Pool einer Pool-Platte ("cache2" -> "cache"; Poolnamen enden in Unraid nicht auf eine Ziffer).
func poolName(n string) string {
	p := strings.TrimRight(n, "0123456789")
	if p == "" {
		return n
	}
	return p
}

// urArrayServices: Array, Pools und Platten.
func urArrayServices(arr urArray, vars *urVars, now time.Time) []model.Service {
	a := arr.Array
	var out []model.Service
	// Array
	s := model.Service{Key: "raid:array", Name: "Array", Kind: "raid", Default: true}
	state := firstNonEmpty(a.State, "UNKNOWN")
	parts := []string{stateText(map[string]string{"STARTED": "monitor64.txt.started", "STOPPED": "monitor64.txt.stopped"}, state)}
	var bad []string
	if state != "STARTED" {
		bad = append(bad, model.T("monitor64.txt.array_not_started", "v", shortText(state)))
	}
	kb := a.Capacity.KB
	if kb.Total.Set && kb.Total.V > 0 && kb.Used.Set {
		tot := kb.Total.V * 1024
		free := max(kb.Free.V*1024, 0)
		s.Metrics = append(s.Metrics, model.Metric{Name: "used", Value: pct(kb.Used.V*1024, tot), Unit: "%", Rule: model.RuleStore, Max: tot},
			model.Metric{Name: "free", Value: free, Unit: "B", Max: tot})
		parts = append(parts, model.T("monitor64.txt.free_of", "free", bytesText(free), "total", bytesText(tot)))
	}
	members, active, parities := 0, 0, 0
	for _, d := range append(append([]urDisk{}, a.Parities...), a.Disks...) {
		if !d.present() {
			continue
		}
		members++
		if d.Status == "DISK_OK" {
			active++
		}
		if d.Type == "PARITY" || strings.HasPrefix(d.Name, "parity") {
			parities++
		}
		if t, ok := urBad[d.Status]; ok {
			bad = append(bad, model.Raw(d.Name)+" "+model.T(t))
		}
	}
	s.Metrics = append(s.Metrics, model.Metric{Name: "active", Value: float64(active)}, model.Metric{Name: "devices", Value: float64(members)})
	parts = append(parts, model.T("monitor64.txt.disks_ok", "n", active, "total", members))
	if parities == 0 {
		parts = append(parts, model.T("monitor64.txt.no_parity"))
	}
	if vars != nil {
		v := vars.Vars
		if v.Invalid.Set && v.Invalid.V > 0 && len(bad) == 0 {
			bad = append(bad, model.T("monitor64.txt.disks_invalid", "n", fmt.Sprintf("%.0f", v.Invalid.V)))
		}
		if v.Disabled.Set && v.Disabled.V > 0 && len(bad) == 0 {
			bad = append(bad, model.T("monitor64.txt.disks_disabled", "n", fmt.Sprintf("%.0f", v.Disabled.V)))
		}
	}
	if len(bad) > 0 {
		s.Facts = append(s.Facts, model.Fact{Code: "raid_degraded", Text: strings.Join(limitList(bad, 5), ", ")})
		parts = append(parts, strings.Join(limitList(bad, 5), ", "))
	}
	// Paritaetspruefung
	if p := a.Parity; p != nil && parities > 0 {
		st := strings.ToUpper(p.Status)
		switch {
		case p.Running && p.Paused:
			parts = append(parts, model.T("monitor64.txt.parity_paused", "v", fmt.Sprintf("%.0f", p.Progress.V)))
		case p.Running:
			parts = append(parts, model.T("monitor64.txt.parity_running_pct", "v", fmt.Sprintf("%.0f", p.Progress.V)))
		case st == "NEVER_RUN":
			parts = append(parts, model.T("monitor64.txt.parity_never"))
		default:
			txt := model.T("monitor64.txt.last_parity")
			if p.Date != nil && !p.Date.T.IsZero() {
				age := max(now.Sub(p.Date.T), 0)
				s.Metrics = append(s.Metrics, model.Metric{Name: "parity_age", Value: round2(age.Hours() / 24), Unit: "d"})
				txt += " " + agoText(age)
			}
			s.Metrics = append(s.Metrics, model.Metric{Name: "parity_errors", Value: max(p.Errors.V, 0)})
			switch {
			case st == "FAILED":
				parts = append(parts, txt+" "+model.T("monitor64.txt.failed"))
				s.Facts = append(s.Facts, model.Fact{Code: "parity_errors", Text: model.T("monitor64.txt.parity_failed")})
			case st == "CANCELLED":
				parts = append(parts, txt+" "+model.T("monitor64.txt.aborted"))
			case p.Errors.V > 0:
				parts = append(parts, txt+": "+parityErrors(p.Errors.V))
				s.Facts = append(s.Facts, model.Fact{Code: "parity_errors", Text: model.T("monitor64.txt.last_parity") + ": " + parityErrors(p.Errors.V)})
			default:
				parts = append(parts, txt+": "+parityErrors(0))
			}
		}
	} else if vars != nil && parities > 0 {
		v := vars.Vars
		switch {
		case v.Resync.V > 0:
			parts = append(parts, model.T("monitor64.txt.parity_running"))
		case v.Synced.Set && v.Synced.V > 0:
			age := max(now.Sub(msTime(v.Synced.V)), 0)
			s.Metrics = append(s.Metrics, model.Metric{Name: "parity_age", Value: round2(age.Hours() / 24), Unit: "d"},
				model.Metric{Name: "parity_errors", Value: max(v.SyncErrs.V, 0)})
			parts = append(parts, model.T("monitor64.txt.last_parity")+" "+agoText(age)+": "+parityErrors(max(v.SyncErrs.V, 0)))
			if v.SyncErrs.V > 0 {
				s.Facts = append(s.Facts, model.Fact{Code: "parity_errors", Text: model.T("monitor64.txt.last_parity") + ": " + parityErrors(v.SyncErrs.V)})
			}
		}
	}
	s.Text = strings.Join(parts, " · ")
	out = append(out, s)

	// Pools aus den Pool-Platten
	type pool struct {
		head    *urDisk
		members []urDisk
		bad     []string
	}
	pools := map[string]*pool{}
	var names []string
	for _, d := range a.Caches {
		if !d.present() || d.Name == "" {
			continue
		}
		n := poolName(d.Name)
		p := pools[n]
		if p == nil {
			p = &pool{}
			pools[n] = p
			names = append(names, n)
		}
		p.members = append(p.members, d)
		if t, ok := urBad[d.Status]; ok {
			p.bad = append(p.bad, model.Raw(d.Name)+" "+model.T(t))
		}
	}
	sort.Strings(names)
	for _, n := range names {
		p := pools[n]
		// Belegung steht an der ersten Platte des Pools (Name = Pool), sonst an einer mit Dateisystem
		p.head = &p.members[0]
		for i := range p.members {
			if m := &p.members[i]; m.Name == n || (!p.head.FSSize.Set && m.FSSize.Set && p.head.Name != n) {
				p.head = m
			}
		}
		kind, code := "raid", "raid_degraded"
		if strings.EqualFold(p.head.FSType, "zfs") {
			kind, code = "zfs", "zfs_degraded"
		}
		ps := model.Service{Key: kind + ":" + n, Name: "Pool " + model.Raw(n), Kind: kind, Default: true}
		var pp []string
		if t := p.head.FSType; t != "" {
			pp = append(pp, model.Raw(t))
		}
		if h := p.head; h.FSSize.Set && h.FSSize.V > 0 && h.FSUsed.Set {
			tot := h.FSSize.V * 1024
			free := max(h.FSFree.V*1024, 0)
			ps.Metrics = append(ps.Metrics, model.Metric{Name: "used", Value: pct(h.FSUsed.V*1024, tot), Unit: "%", Rule: model.RuleStore, Max: tot},
				model.Metric{Name: "free", Value: free, Unit: "B", Max: tot})
			pp = append(pp, model.T("monitor64.txt.free_of", "free", bytesText(free), "total", bytesText(tot)))
		}
		pp = append(pp, model.T("monitor64.txt.disks_n", "n", len(p.members)))
		if len(p.bad) > 0 {
			ps.Facts = append(ps.Facts, model.Fact{Code: code, Text: strings.Join(p.bad, ", ")})
			pp = append(pp, strings.Join(p.bad, ", "))
		}
		ps.Text = strings.Join(pp, " · ")
		out = append(out, ps)
	}

	// Platten (Paritaet, Daten, Pools)
	var disks []urDisk
	for _, l := range [][]urDisk{a.Parities, a.Disks, a.Caches} {
		for _, d := range l {
			if d.present() && d.Device != "" {
				disks = append(disks, d)
			}
		}
	}
	entries := make([]diskEntry, len(disks))
	for i, d := range disks {
		entries[i] = diskEntry{Name: firstNonEmpty(d.Device, d.Name), Serial: d.serial()}
	}
	keys := diskKeys(entries)
	seen := map[string]bool{}
	var ds []model.Service
	for i, d := range disks {
		if seen[keys[i]] {
			continue
		}
		seen[keys[i]] = true
		ds = append(ds, urDiskService(keys[i], d))
	}
	sort.SliceStable(ds, func(i, j int) bool { return ds[i].Name < ds[j].Name })
	return append(out, ds...)
}

// parityErrors: "3 Fehler" der Paritaetspruefung.
func parityErrors(n float64) string {
	return model.T("monitor64.txt.errors_n", "n", fmt.Sprintf("%.0f", n))
}

// urDiskService: Platte mit Zustand, Temperatur (fehlt, wenn sie schlaeft), Fehlern und Belegung.
func urDiskService(key string, d urDisk) model.Service {
	name := firstNonEmpty(d.Name, d.Device)
	if d.Device != "" && d.Name != "" {
		name += " (" + d.Device + ")"
	}
	s := model.Service{Key: key, Name: model.Raw(name), Kind: "disk", Default: true}
	var parts []string
	if d.Size.Set && d.Size.V > 0 {
		parts = append(parts, bytesText(d.Size.V*1024))
	}
	if st := urStatus(d.Status); st != "" {
		parts = append(parts, st)
	}
	if t, ok := urBad[d.Status]; ok {
		s.Facts = append(s.Facts, model.Fact{Code: "disk_errors", Text: model.T("monitor64.txt.disk_word") + " " + model.T(t)})
	}
	switch {
	case d.Temp.Set && d.Temp.V > 0 && d.Temp.V < 150:
		rule := model.RuleDiskTemp
		if strings.HasPrefix(d.Device, "nvme") {
			rule = model.RuleNVMeTemp
		}
		s.Metrics = append(s.Metrics, model.Metric{Name: "temp", Value: round2(d.Temp.V), Unit: "°C", Rule: rule})
		parts = append(parts, fmt.Sprintf("%.0f °C", d.Temp.V))
	case d.Spinning != nil && !*d.Spinning:
		parts = append(parts, model.T("monitor64.txt.sleeping"))
	}
	if d.Errors.Set && d.Errors.V >= 0 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "errors", Value: d.Errors.V})
		if d.Errors.V > 0 {
			parts = append(parts, model.T("monitor64.txt.errors_n", "n", fmt.Sprintf("%.0f", d.Errors.V)))
			s.Facts = append(s.Facts, model.Fact{Code: "disk_errors", Text: model.T("monitor64.txt.rw_errors", "n", fmt.Sprintf("%.0f", d.Errors.V))})
		}
	}
	if d.FSSize.Set && d.FSSize.V > 0 && d.FSUsed.Set && d.Type != "CACHE" && !strings.HasPrefix(d.Name, "parity") {
		tot := d.FSSize.V * 1024
		free := max(d.FSFree.V*1024, 0)
		s.Metrics = append(s.Metrics, model.Metric{Name: "used", Value: pct(d.FSUsed.V*1024, tot), Unit: "%", Rule: model.RuleFS, Max: tot},
			model.Metric{Name: "free", Value: free, Unit: "B", Max: tot})
		parts = append(parts, model.T("monitor64.txt.free", "v", bytesText(free)))
	}
	s.Text = strings.Join(parts, " · ")
	return s
}

// containers: Docker-Container (ctr:<name>); Autostart = soll laufen.
func (u *Unraid) containers(ctx context.Context, add func(string, error, ...string)) []model.Service {
	var r struct {
		Docker *struct {
			Containers []struct {
				Names     []string `json:"names"`
				Image     string   `json:"image"`
				State     string   `json:"state"`
				Status    string   `json:"status"`
				AutoStart bool     `json:"autoStart"`
			} `json:"containers"`
		} `json:"docker"`
	}
	if err := u.gql(ctx, urDockerQ, &r); err != nil {
		if !gqlSchema(err) {
			add("docker", err, "ctr:")
		}
		return nil
	}
	if r.Docker == nil {
		return nil // Docker aus
	}
	var out []model.Service
	seen := map[string]bool{}
	for _, c := range r.Docker.Containers {
		if len(c.Names) == 0 {
			continue
		}
		name := strings.TrimPrefix(c.Names[0], "/")
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		state := strings.ToUpper(c.State)
		s := model.Service{Key: "ctr:" + name, Name: devText(name), Kind: "ctr", Default: true}
		run := 0.0
		if state == "RUNNING" {
			run = 1
		}
		s.Metrics = []model.Metric{{Name: "running", Value: run}}
		parts := []string{stateText(map[string]string{"RUNNING": "monitor64.txt.running", "EXITED": "monitor64.txt.exited", "PAUSED": "monitor64.txt.paused"}, state)}
		if c.Status != "" {
			parts = append(parts, devText(c.Status))
		}
		if c.AutoStart {
			parts = append(parts, model.T("monitor64.txt.should_run_autostart"))
			if state != "RUNNING" && state != "PAUSED" {
				s.Facts = append(s.Facts, model.Fact{Code: "guest_down", Text: parts[0] + ", " + model.T("monitor64.txt.should_run_autostart")})
			}
		} else {
			parts = append(parts, model.T("monitor64.txt.may_be_off"))
		}
		if c.Image != "" {
			parts = append(parts, devText(c.Image))
		}
		s.Text = strings.Join(parts, " · ")
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// vms: VMs (vm:<name>); CRASHED ist eine Stoerung, ein Soll kennt die API nicht (am Dienst einstellen).
func (u *Unraid) vms(ctx context.Context, add func(string, error, ...string)) []model.Service {
	type dom struct {
		Name  string `json:"name"`
		State string `json:"state"`
	}
	var r struct {
		VMs *struct {
			Domains []dom `json:"domains"`
			Domain  []dom `json:"domain"`
		} `json:"vms"`
	}
	err := u.gql(ctx, urVMsQ, &r)
	if gqlSchema(err) {
		err = u.gql(ctx, urVMsOldQ, &r)
	}
	if err != nil {
		var ge *gqlError
		// VM-Dienst aus: die API meldet einen Fehler statt einer leeren Liste
		if !gqlSchema(err) && !(errors.As(err, &ge) && strings.Contains(strings.ToLower(ge.Msg), "libvirt")) {
			add("vms", err, "vm:")
		}
		return nil
	}
	if r.VMs == nil {
		return nil
	}
	var out []model.Service
	seen := map[string]bool{}
	for _, d := range append(r.VMs.Domains, r.VMs.Domain...) {
		if d.Name == "" || seen[d.Name] {
			continue
		}
		seen[d.Name] = true
		state := strings.ToUpper(d.State)
		s := model.Service{Key: "vm:" + d.Name, Name: "VM " + devText(d.Name), Kind: "vm", Default: true}
		run := 0.0
		if state == "RUNNING" || state == "IDLE" {
			run = 1
		}
		s.Metrics = []model.Metric{{Name: "running", Value: run}, {Name: "locked", Value: 0}}
		s.Text = stateText(map[string]string{"RUNNING": "monitor64.txt.running", "IDLE": "monitor64.txt.running_idle", "PAUSED": "monitor64.txt.paused",
			"SHUTOFF": "monitor64.txt.off", "SHUTDOWN": "monitor64.txt.shutting_down", "CRASHED": "monitor64.txt.crashed",
			"PMSUSPENDED": "monitor64.txt.sleep_state"}, state)
		if state == "CRASHED" {
			s.Facts = append(s.Facts, model.Fact{Code: "guest_fault", Text: model.T("monitor64.txt.vm_crashed")})
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// notifications: ungelesene Warnungen und Alarme (device_warn); Infos zaehlen nicht.
func (u *Unraid) notifications(ctx context.Context, add func(string, error, ...string)) (model.Service, bool) {
	type note struct {
		Subject     string `json:"subject"`
		Description string `json:"description"`
	}
	var r struct {
		N struct {
			Overview struct {
				Unread struct {
					Warning optF `json:"warning"`
					Alert   optF `json:"alert"`
				} `json:"unread"`
			} `json:"overview"`
			Alerts   []note `json:"alerts"`
			Warnings []note `json:"warnings"`
		} `json:"notifications"`
	}
	err := u.gql(ctx, urNotifyQ, &r)
	if gqlSchema(err) {
		err = u.gql(ctx, urNotifyOQ, &r)
	}
	if err != nil {
		if !gqlSchema(err) {
			add("notifications", err, "alerts")
		}
		return model.Service{}, false
	}
	n := r.N
	w, a := max(n.Overview.Unread.Warning.V, 0), max(n.Overview.Unread.Alert.V, 0)
	s := model.Service{Key: "alerts", Name: model.T("monitor64.svc.notifications"), Kind: "alerts", Default: true,
		Metrics: []model.Metric{{Name: "unread_warning", Value: w}, {Name: "unread_alert", Value: a}}}
	var texts []string
	for _, x := range append(append([]note{}, n.Alerts...), n.Warnings...) {
		if t := firstNonEmpty(stripTags(x.Subject), stripTags(x.Description)); t != "" {
			texts = append(texts, t)
		}
	}
	if total := int(w + a); total > 0 {
		sum := model.T("monitor64.txt.unread", "n", total, "a", fmt.Sprintf("%.0f", a), "w", fmt.Sprintf("%.0f", w))
		if len(texts) > 0 {
			sum += ": " + model.Raw(strings.Join(limitList(texts, 3), "; "))
		}
		s.Text = sum
		s.Facts = append(s.Facts, model.Fact{Code: "device_warn", Text: sum})
	} else {
		s.Text = model.T("monitor64.txt.no_unread")
	}
	return s, true
}
