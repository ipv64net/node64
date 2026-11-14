package apis

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// fakeRouterOS stellt die REST-API von RouterOS 7 nach (Formate aus dem MikroTik-Handbuch, REST API: alle Werte als
// Text, Menues ohne Liste als einzelnes Objekt, Fehler als {"error":400,"message":"Bad Request","detail":"..."}).
type fakeRouterOS struct {
	mu      sync.Mutex
	user    string
	pass    string
	routes  map[string]string
	hits    map[string]int
	queries map[string]string
	methods map[string]bool
	noPerm  bool // Gruppe ohne read: RouterOS antwortet mit HTTP 500
}

const (
	mtTestUser = "monitor64"
	mtTestPass = "geheim-mit:doppelpunkt"
)

func newFakeRouterOS() *fakeRouterOS {
	return &fakeRouterOS{user: mtTestUser, pass: mtTestPass, hits: map[string]int{}, queries: map[string]string{}, methods: map[string]bool{},
		routes: map[string]string{
			"/rest/system/resource": `{"architecture-name":"arm64","board-name":"hAP ax^2","build-time":"2024-07-24 10:39:01","cpu":"ARM64","cpu-count":"4",
				"cpu-frequency":"864","cpu-load":"7","free-hdd-space":"98041856","free-memory":"687116288","platform":"MikroTik",
				"total-hdd-space":"134217728","total-memory":"1073741824","uptime":"1d7h44m20s","version":"7.15.3 (stable)"}`,
			"/rest/system/identity": `{"name":"keller-router"}`,
			"/rest/system/health": `[{".id":"*d","name":"voltage","type":"V","value":"24.1"},{".id":"*e","name":"temperature","type":"C","value":"36"},
				{".id":"*f","name":"cpu-temperature","type":"C","value":"43"},{".id":"*10","name":"fan1-speed","type":"RPM","value":"5654"},
				{".id":"*11","name":"power-consumption","type":"W","value":"50.8"},{".id":"*12","name":"psu1-state","type":"","value":"fail"},
				{".id":"*13","name":"psu2-state","type":"","value":"ok"},{".id":"*14","name":"psu3-state","type":"","value":"not-present"}]`,
			"/rest/interface": `[
				{".id":"*1","name":"ether1","type":"ether","running":"true","disabled":"false","comment":"Uplink","rx-byte":"1000000000","tx-byte":"500000000","rx-packet":"1000000","tx-packet":"800000","rx-error":"0","tx-error":"0","rx-drop":"5","tx-drop":"0"},
				{".id":"*2","name":"ether2","type":"ether","running":"false","disabled":"false","rx-byte":"0","tx-byte":"0","rx-packet":"0","tx-packet":"0","rx-error":"0","tx-error":"0","rx-drop":"0","tx-drop":"0"},
				{".id":"*3","name":"ether3","type":"ether","running":"false","disabled":"true","rx-byte":"0","tx-byte":"0","rx-packet":"0","tx-packet":"0","rx-error":"0","tx-error":"0","rx-drop":"0","tx-drop":"0"},
				{".id":"*4","name":"vlan10","type":"vlan","running":"true","disabled":"false","rx-byte":"100","tx-byte":"100","rx-packet":"1","tx-packet":"1","rx-error":"0","tx-error":"0","rx-drop":"0","tx-drop":"0"},
				{".id":"*5","name":"pppoe-out1","type":"pppoe-out","running":"true","disabled":"false","rx-byte":"2000000000","tx-byte":"100000000","rx-packet":"2000000","tx-packet":"500000","rx-error":"0","tx-error":"0","rx-drop":"0","tx-drop":"0"},
				{".id":"*6","name":"<pppoe-kunde>","type":"pppoe-in","running":"true","disabled":"false","dynamic":"true","rx-byte":"1","tx-byte":"1"},
				{".id":"*7","name":"lo","type":"loopback","running":"true","disabled":"false","rx-byte":"1","tx-byte":"1"},
				{".id":"*8","name":"wifi1","type":"wifi","running":"true","disabled":"false","rx-byte":"1","tx-byte":"1"}]`,
			"/rest/interface/wifi/registration-table": `[{".id":"*1","interface":"wifi1"},{".id":"*2","interface":"wifi1"},{".id":"*3","interface":"wifi2"}]`,
			"/rest/caps-man/registration-table":       `[{".id":"*1","interface":"cap1"}]`,
			// wie auf einem echten RouterOS 7.25.1: der nicht erreichbare Peer hat keine Zeile unter session
			"/rest/routing/bgp/connection": `[{".id":"*1","name":"upstream","instance":"bgp1","remote.address":"192.0.2.1","remote.as":"64512","inactive":"false"},
				{".id":"*2","name":"peer-2","instance":"bgp1","remote.address":"192.0.2.2","remote.as":"64513","inactive":"false"},
				{".id":"*3","name":"alt","instance":"bgp1","remote.address":"192.0.2.3","remote.as":"64514","disabled":"true"}]`,
			"/rest/routing/bgp/session": `[{".id":"*1","name":"upstream-1","remote.address":"192.0.2.1","remote.as":"64512","established":"true","uptime":"5m30s","prefix-count":"12"},
				{".id":"*2","name":"dyn-kunde-1","remote.address":"198.51.100.7","remote.as":"64600","established":"true"}]`,
			"/rest/routing/ospf/neighbor": `[{".id":"*1","instance":"default","address":"10.0.0.2","router-id":"10.255.0.2","state":"Full"},{".id":"*2","instance":"default","address":"10.0.0.3","router-id":"10.255.0.3","state":"2-Way"}]`,
			"/rest/system/package/update": `{"channel":"stable","installed-version":"7.15.3","latest-version":"7.16.1","status":"New version is available"}`,
			"/rest/system/routerboard":    `{"routerboard":"true","board-name":"hAP ax^2","model":"C52iG-5HaxD2HaxD","serial-number":"HXX0000000","firmware-type":"ipq6000","factory-firmware":"7.6","current-firmware":"7.14","upgrade-firmware":"7.15.3"}`,
		}}
}

func (f *fakeRouterOS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	f.methods[r.Method] = true
	u, p, ok := r.BasicAuth()
	if !ok || u != f.user || p != f.pass {
		w.Header().Set("WWW-Authenticate", `Basic realm="rest"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":401,"message":"Unauthorized"}`))
		return
	}
	if f.noPerm {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"not enough permissions (9)","error":500,"message":"Internal Server Error"}`))
		return
	}
	f.hits[r.URL.Path]++
	f.queries[r.URL.Path] = r.URL.RawQuery
	body, ok := f.routes[r.URL.Path]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		last := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		_, _ = w.Write([]byte(`{"detail":"no such command or directory (` + last + `)","error":400,"message":"Bad Request"}`))
		return
	}
	_, _ = w.Write([]byte(body))
}

func (f *fakeRouterOS) set(path, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if body == "" {
		delete(f.routes, path)
		return
	}
	f.routes[path] = body
}

func mikrotikFor(t *testing.T, f *fakeRouterOS, pass string) (*Mikrotik, *time.Time) {
	t.Helper()
	addr, pin := tlsServer(t, f)
	m, err := NewMikrotik(MikrotikConfig{Address: addr, User: " " + mtTestUser + " ", Password: pass, Pin: pin})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	return m, &now
}

func TestMikrotikCollect(t *testing.T) {
	f := newFakeRouterOS()
	m, now := mikrotikFor(t, f, mtTestPass)
	svcs, err := m.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", deErr(err))
	}
	cpu := svcByKey(t, svcs, "cpu")
	if u := mustMetric(t, cpu, "util"); u.Value != 7 || u.Rule != model.RuleCPU || cpu.Text != "4 Kerne · ARM64" {
		t.Errorf("cpu: %+v %q", cpu.Metrics, cpu.Text)
	}
	mem := svcByKey(t, svcs, "mem")
	if u := mustMetric(t, mem, "used"); u.Value != 36.01 || u.Rule != model.RuleMem || u.Max != 1073741824 || mustMetric(t, mem, "avail").Value != 687116288 {
		t.Errorf("mem: %+v", mem.Metrics)
	}
	fs := svcByKey(t, svcs, "fs:flash")
	if u := mustMetric(t, fs, "used"); u.Value != 26.95 || u.Rule != model.RuleFS || mustMetric(t, fs, "free").Value != 98041856 || fs.Name != "Dateisystem Flash" {
		t.Errorf("flash: %+v %q", fs.Metrics, fs.Name)
	}
	sys := svcByKey(t, svcs, "system")
	if sys.Name != "hAP ax^2" || mustMetric(t, sys, "uptime").Value != 114260 || sys.Text != "RouterOS 7.15.3 (stable) · läuft seit 31 Std." {
		t.Errorf("system: %q %+v %q", sys.Name, sys.Metrics, sys.Text)
	}
	// Sensoren
	if tm := svcByKey(t, svcs, "temp:cpu-temperature"); mustMetric(t, tm, "temp").Value != 43 || mustMetric(t, tm, "temp").Rule != model.RuleTemp || tm.Name != "Temperatur cpu-temperature" {
		t.Errorf("temp: %+v %q", tm.Metrics, tm.Name)
	}
	if fan := svcByKey(t, svcs, "fan:fan1-speed"); mustMetric(t, fan, "rpm").Value != 5654 || fan.Kind != "fan" {
		t.Errorf("fan: %+v", fan)
	}
	pw := svcByKey(t, svcs, "power")
	if mustMetric(t, pw, "voltage").Value != 24.1 || mustMetric(t, pw, "voltage").Unit != "V" || mustMetric(t, pw, "power-consumption").Value != 50.8 ||
		pw.Text != "voltage 24,1 V · power-consumption 50,8 W" {
		t.Errorf("power: %+v %q", pw.Metrics, pw.Text)
	}
	if p1 := svcByKey(t, svcs, "psu:psu1"); !hasFact(p1, "hw_failed") || p1.Kind != "psu" || p1.Facts[0].Text != "psu1-state: fail" {
		t.Errorf("psu1: %+v", p1)
	}
	if p2 := svcByKey(t, svcs, "psu:psu2"); hasFact(p2, "hw_failed") || p2.Text != "ok" {
		t.Errorf("psu2: %+v", p2)
	}
	for _, s := range svcs {
		if s.Key == "psu:psu3" || s.Key == "if:lo" || s.Key == "if:<pppoe-kunde>" {
			t.Errorf("Dienst %s sollte fehlen", s.Key)
		}
	}
	// Schnittstellen: erste Runde ohne Raten
	e1 := svcByKey(t, svcs, "if:ether1")
	if !e1.Default || e1.Name != "ether1 · Uplink" || len(e1.Metrics) != 0 || len(e1.Facts) != 0 {
		t.Errorf("ether1 (Runde 1): %+v", e1)
	}
	if e2 := svcByKey(t, svcs, "if:ether2"); e2.Default || !hasFact(e2, "if_down") || e2.Text != "down" {
		t.Errorf("ether2: %+v", e2)
	}
	if e3 := svcByKey(t, svcs, "if:ether3"); e3.Default || hasFact(e3, "if_down") || e3.Text != "abgeschaltet" {
		t.Errorf("ether3: %+v", e3)
	}
	if v := svcByKey(t, svcs, "if:vlan10"); v.Default {
		t.Errorf("vlan10 vorgewaehlt")
	}
	if p := svcByKey(t, svcs, "if:pppoe-out1"); !p.Default {
		t.Errorf("pppoe-out1 nicht vorgewaehlt")
	}
	// WLAN: alle vorhandenen Tabellen zaehlen (wifi 3 + caps-man 1)
	if w := svcByKey(t, svcs, "wlan"); mustMetric(t, w, "clients").Value != 4 || w.Kind != "wlan" || w.Name != "WLAN-Clients" || w.Text != "4 angemeldet" {
		t.Errorf("wlan: %+v", w)
	}
	bgp := svcByKey(t, svcs, "bgp")
	if bgp.Kind != "routing" || mustMetric(t, bgp, "established").Value != 2 || mustMetric(t, bgp, "down").Value != 1 || !hasFact(bgp, "device_warn") ||
		bgp.Text != "2 von 3 Sitzungen aufgebaut · nicht aufgebaut: peer-2" {
		t.Errorf("bgp: %+v", bgp)
	}
	if o := svcByKey(t, svcs, "ospf"); len(o.Facts) != 0 || o.Text != "2 Nachbarn, 1 Full" {
		t.Errorf("ospf: %+v", o)
	}
	upd := svcByKey(t, svcs, "updates")
	if !hasFact(upd, "firmware_update") || mustMetric(t, upd, "pending").Value != 1 ||
		upd.Text != "RouterOS-Update verfügbar: 7.16.1 (installiert 7.15.3) · RouterBOOT 7.14, 7.15.3 steht bereit" {
		t.Errorf("updates: %+v", upd)
	}

	// zweite Runde nach 60 s: Raten aus den Zaehlern, seltene Abfragen und fehlende Menues nicht erneut
	*now = now.Add(time.Minute)
	f.set("/rest/interface", `[
		{".id":"*1","name":"ether1","type":"ether","running":"true","disabled":"false","comment":"Uplink","rx-byte":"1075000000","tx-byte":"507500000","rx-packet":"1060000","tx-packet":"839997","rx-error":"2","tx-error":"1","rx-drop":"8","tx-drop":"1"},
		{".id":"*5","name":"pppoe-out1","type":"pppoe-out","running":"true","disabled":"false","rx-byte":"100","tx-byte":"100000000","rx-packet":"2000000","tx-packet":"500000","rx-error":"0","tx-error":"0","rx-drop":"0","tx-drop":"0"},
		{".id":"*8","name":"wifi1","type":"wifi","running":"true","disabled":"false","rx-byte":"1","tx-byte":"1"}]`)
	svcs, err = m.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect 2: %v", deErr(err))
	}
	e1 = svcByKey(t, svcs, "if:ether1")
	if mustMetric(t, e1, "in").Value != 10 || mustMetric(t, e1, "out").Value != 1 || mustMetric(t, e1, "errors").Value != 3 ||
		mustMetric(t, e1, "errrate").Value != 0.003 || mustMetric(t, e1, "errrate").Rule != model.RuleIfErrRate || mustMetric(t, e1, "drops").Value != 4 ||
		e1.Text != "↓ 10 Mbit/s · ↑ 1,0 Mbit/s · 3 Fehler" {
		t.Errorf("ether1 (Runde 2): %+v %q", e1.Metrics, e1.Text)
	}
	// Zaehler zurueckgesprungen (Neustart der Verbindung): diese Runde kein Durchsatz statt einer Spitze
	p := svcByKey(t, svcs, "if:pppoe-out1")
	if _, has := metric(p, "in"); has || mustMetric(t, p, "errors").Value != 0 {
		t.Errorf("pppoe-out1 nach Ruecksprung: %+v", p.Metrics)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hits["/rest/system/resource"] != 2 || f.hits["/rest/interface"] != 2 || f.hits["/rest/system/package/update"] != 1 || f.hits["/rest/system/routerboard"] != 1 {
		t.Errorf("Abfragen: %v", f.hits)
	}
	if f.hits["/rest/interface/wifiwave2/registration-table"] != 1 || f.hits["/rest/interface/wireless/registration-table"] != 1 || f.hits["/rest/interface/wifi/registration-table"] != 2 {
		t.Errorf("fehlende WLAN-Menues erneut gefragt: %v", f.hits)
	}
	if len(f.methods) != 1 || !f.methods[http.MethodGet] {
		t.Errorf("nicht nur GET: %v", f.methods)
	}
	if q := f.queries["/rest/interface"]; !strings.HasPrefix(q, ".proplist=name,type,running,") {
		t.Errorf("interface ohne .proplist: %q", q)
	}
}

// Geraete ohne Sensoren, WLAN und Routing (CHR): die Menues fehlen bzw. sind leer – keine Teilfehler, keine Dienste.
// Aeltere Formen: /system/resource als Liste, /system/health als eine Zeile mit den Sensornamen als Feldern.
func TestMikrotikVariants(t *testing.T) {
	f := newFakeRouterOS()
	for _, p := range []string{"/rest/caps-man/registration-table", "/rest/system/routerboard"} {
		f.set(p, "")
	}
	// so antwortet ein echtes CHR 7.25.1: health ist dort ein Schalter, das WLAN-Menue gibt es auch ohne WLAN
	f.set("/rest/system/health", `{"state":"disabled","state-after-reboot":"enabled"}`)
	f.set("/rest/interface/wifi/registration-table", `[]`)
	f.set("/rest/interface", `[{".id":"*2","disabled":"false","name":"ether1","running":"true","type":"ether"},{".id":"*1","disabled":"false","name":"lo","running":"true","type":"loopback"}]`)
	f.set("/rest/routing/bgp/session", `[]`)
	f.set("/rest/routing/bgp/connection", `[]`)
	f.set("/rest/routing/ospf/neighbor", `[]`)
	f.set("/rest/system/resource", `[{"board-name":"CHR","cpu-count":"2","cpu-load":"0","free-memory":"200000000","total-memory":"256000000","uptime":"29s","version":"7.16rc1 (testing)"}]`)
	f.set("/rest/system/package/update", `{"channel":"stable","installed-version":"7.16rc1"}`)
	m, now := mikrotikFor(t, f, mtTestPass)
	svcs, err := m.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", deErr(err))
	}
	for _, s := range svcs {
		if s.Kind == "temp" || s.Kind == "fan" || s.Kind == "psu" || s.Kind == "power" || s.Kind == "wlan" || s.Kind == "routing" {
			t.Errorf("Dienst %s ohne Menue", s.Key)
		}
	}
	if sys := svcByKey(t, svcs, "system"); sys.Name != "CHR" || mustMetric(t, sys, "uptime").Value != 29 || sys.Text != "RouterOS 7.16rc1 (testing) · läuft seit 0 Min." {
		t.Errorf("system: %+v", sys)
	}
	if upd := svcByKey(t, svcs, "updates"); len(upd.Facts) != 0 || len(upd.Metrics) != 0 ||
		upd.Text != "RouterOS 7.16rc1 – Update-Stand unbekannt (der Router hat seit dem Start nicht nach Updates gesucht)" {
		t.Errorf("updates (unbekannt): %+v", upd)
	}
	// nach dem naechsten langsamen Lauf: aktuell; Sensoren in der alten Form
	*now = now.Add(31 * time.Minute)
	f.set("/rest/system/package/update", `{"channel":"stable","installed-version":"7.16.1","latest-version":"7.16.1","status":"System is already up to date"}`)
	f.set("/rest/system/routerboard", `{"routerboard":"false"}`)
	svcs, err = m.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect 2: %v", deErr(err))
	}
	if upd := svcByKey(t, svcs, "updates"); len(upd.Facts) != 0 || mustMetric(t, upd, "pending").Value != 0 || upd.Text != "keine ausstehend" {
		t.Errorf("updates (aktuell): %+v", upd)
	}
	f.mu.Lock()
	if f.hits["/rest/system/routerboard"] != 1 || f.hits["/rest/interface/wifi/registration-table"] != 0 {
		t.Errorf("fehlendes Menue erneut bzw. WLAN ohne WLAN gefragt: %v", f.hits)
	}
	f.mu.Unlock()
	// sechs Stunden spaeter wird wieder gefragt (Paket nachinstalliert, Update)
	*now = now.Add(6 * time.Hour)
	f.set("/rest/system/health", `{"voltage":"24.5","temperature":"38","cpu-temperature":"45","fan1-speed":"4000","psu1-state":"ok"}`)
	svcs, err = m.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect 3: %v", deErr(err))
	}
	if mustMetric(t, svcByKey(t, svcs, "temp:temperature"), "temp").Value != 38 || mustMetric(t, svcByKey(t, svcs, "fan:fan1-speed"), "rpm").Value != 4000 ||
		mustMetric(t, svcByKey(t, svcs, "power"), "voltage").Value != 24.5 || svcByKey(t, svcs, "psu:psu1").Text != "ok" {
		t.Errorf("Sensoren (alte Form) fehlen")
	}
}

func TestMikrotikErrors(t *testing.T) {
	f := newFakeRouterOS()
	// falsches Passwort: Hinweis auf Gruppe und Adresse, das Passwort steht nirgends
	bad, _ := mikrotikFor(t, f, "falsch-"+mtTestPass)
	_, err := bad.Collect(context.Background())
	if err == nil || !strings.Contains(deErr(err), "HTTP 401 Anmeldung abgelehnt") || !strings.Contains(deErr(err), "read, api und rest-api") || strings.Contains(err.Error(), mtTestPass) {
		t.Fatalf("falsches Passwort: %v", deErr(err))
	}
	res := bad.Test(context.Background())
	if res.OK || !strings.Contains(de(res.Error), "Anmeldung abgelehnt") || res.Fingerprint == "" {
		t.Fatalf("Test mit falschem Passwort: %+v", res)
	}
	// fehlende Rechte meldet RouterOS mit HTTP 500
	f.noPerm = true
	m, _ := mikrotikFor(t, f, mtTestPass)
	_, err = m.Collect(context.Background())
	if err == nil || !strings.Contains(deErr(err), "HTTP 500 keine Berechtigung") || !strings.Contains(deErr(err), "fehlen Rechte") {
		t.Fatalf("fehlende Rechte: %v", deErr(err))
	}
	f.mu.Lock()
	f.noPerm = false
	f.mu.Unlock()
	// eine Teilabfrage scheitert: die uebrigen Dienste kommen, der Fehler nennt die Abfrage
	f.set("/rest/interface", `{kaputt`)
	svcs, err := m.Collect(context.Background())
	if !IsPartial(err) || !strings.Contains(deErr(err), "interface") || len(svcs) < 5 {
		t.Fatalf("Teilfehler: %d Dienste, %v", len(svcs), deErr(err))
	}
	for _, s := range svcs {
		if s.Kind == "if" {
			t.Errorf("Schnittstelle trotz Fehler: %s", s.Key)
		}
	}
	// Zugangsdaten und Adresse
	for _, c := range []MikrotikConfig{
		{Address: "https://192.0.2.1", User: "", Password: "x"},
		{Address: "https://192.0.2.1", User: "a:b", Password: "x"},
		{Address: "https://192.0.2.1", User: "a", Password: ""},
		{Address: "http://192.0.2.1", User: "a", Password: "x"},
		{Address: "https://192.0.2.1/rest", User: "a", Password: "x"},
	} {
		if _, err := NewMikrotik(c); err == nil {
			t.Errorf("angenommen: %+v", c)
		}
	}
}

func TestMikrotikTest(t *testing.T) {
	f := newFakeRouterOS()
	addr, pin := tlsServer(t, f)
	// ohne Pin und ohne Vertrauen: nichts senden, Fingerabdruck bestaetigen lassen
	m, err := NewMikrotik(MikrotikConfig{Address: addr, User: mtTestUser, Password: mtTestPass})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	res := m.Test(context.Background())
	if res.OK || !res.NeedConfirm || res.Fingerprint != pin {
		t.Fatalf("ohne Pin: %+v", res)
	}
	f.mu.Lock()
	if len(f.hits) != 0 || len(f.methods) != 0 {
		t.Errorf("Anfrage vor der Bestaetigung: %v", f.hits)
	}
	f.mu.Unlock()
	ok, _ := mikrotikFor(t, f, mtTestPass)
	res = ok.Test(context.Background())
	if !res.OK || res.Version != "7.15.3 (stable)" || res.Summary != "hAP ax^2 · keller-router" {
		t.Fatalf("mit Pin: %+v", res)
	}
}

func TestMtDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"29s":        29 * time.Second,
		"16m44s":     16*time.Minute + 44*time.Second,
		"1d7h44m20s": 31*time.Hour + 44*time.Minute + 20*time.Second,
		"1w2d3h4m5s": 9*24*time.Hour + 3*time.Hour + 4*time.Minute + 5*time.Second,
		"4s70ms":     4*time.Second + 70*time.Millisecond,
		"10ms230us":  10*time.Millisecond + 230*time.Microsecond,
	} {
		if got, ok := mtDuration(in); !ok || got != want {
			t.Errorf("mtDuration(%q) = %v, %v; erwartet %v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "never", "12", "1x", "5m bla", "99999999999999999999s"} {
		if _, ok := mtDuration(bad); ok {
			t.Errorf("mtDuration(%q) angenommen", bad)
		}
	}
}
