package apis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// fakeUnifi stellt die Controller-API der UniFi Network Application nach: als UniFi-OS-Konsole (Pfade unter
// /proxy/network, API-Schluessel oder Anmeldung ueber /api/auth/login mit Cookie TOKEN und CSRF-Token) oder als
// selbst gehosteter Network Server (GET / leitet weiter, /api/login, Cookie unifises). Formate und Muster aus den
// Bibliotheken unpoller/unifi und aiounifi (Gateway, Switch US-16-150W, stat/health).
type fakeUnifi struct {
	mu       sync.Mutex
	os       bool
	key      string
	user     string
	pass     string
	routes   map[string]string
	status   map[string]int
	hits     map[string]int
	methods  map[string]int
	logins   int
	logouts  int
	session  int  // laufende Nummer der gueltigen Sitzung (0 = keine)
	loginRC  int  // erzwungener Status der Anmeldung (0 = normal)
	noCSRF   int  // Anfragen ohne passenden CSRF-Token
	keyCalls int  // Anfragen mit API-Schluessel
	expire   bool // die naechste Datenabfrage antwortet "Sitzung abgelaufen"
	starting bool // selbst gehostet: die Anwendung startet noch
}

const (
	ufTestKey  = "uf-KEY-0123456789abcdef"
	ufTestUser = "monitor64"
	ufTestPass = `pass"wort mit {json}`
)

const ufDevicesJSON = `[
 {"type":"udm","model":"UDMPRO","name":"Gateway","mac":"28:70:4E:85:A9:E9","state":1,"adopted":true,"version":"4.1.13","upgradable":false,
  "uptime":492633,"num_sta":8,"system-stats":{"cpu":"5.6","mem":"67.2","uptime":"492633"},
  "temperatures":[{"name":"Local","type":"board","value":48.75},{"name":"CPU","type":"cpu","value":66.0}],
  "port_table":[{"port_idx":9,"name":"WAN","up":true,"enable":true,"speed":1000,"full_duplex":true,"is_uplink":true,
    "rx_bytes-r":60325,"tx_bytes-r":175689,"rx_packets":1000000,"tx_packets":800000,"rx_errors":0,"tx_errors":0}]},
 {"type":"usw","model":"US16P150","name":"Switch 16","mac":"fc:ec:da:11:22:33","state":1,"adopted":true,"version":"4.0.66.10832",
  "upgradable":true,"upgrade_to_firmware":"4.0.80.10875","uptime":"3971865","num_sta":4,"general_temperature":56,"overheating":false,
  "total_max_power":135,"system-stats":{"cpu":"100.0","mem":"49.3","uptime":"3971865"},
  "port_table":[
   {"port_idx":3,"name":"Port 3","up":true,"enable":true,"speed":1000,"full_duplex":true,"port_poe":true,"poe_enable":true,"poe_good":true,
    "poe_power":"3.24","rx_bytes-r":0,"tx_bytes-r":670,"rx_packets":5000,"tx_packets":5000,"rx_errors":0,"tx_errors":0},
   {"port_idx":4,"name":"Drucker","up":false,"enable":true,"speed":0,"port_poe":true,"poe_enable":false,"poe_power":"0.00",
    "rx_bytes-r":0,"tx_bytes-r":0,"rx_packets":10,"tx_packets":10,"rx_errors":0,"tx_errors":0},
   {"port_idx":5,"name":"Port 5","up":false,"enable":false,"speed":0},
   {"port_idx":6,"name":"Port 6","up":true,"enable":true,"speed":100,"full_duplex":false,"port_poe":true,"poe_enable":true,"poe_power":"12.5",
    "rx_bytes-r":125000,"tx_bytes-r":1250000,"rx_packets":100,"tx_packets":100,"rx_errors":0,"tx_errors":0}]},
 {"type":"uap","model":"U6LR","name":"AP Flur","mac":"74:ac:b9:00:00:01","state":1,"adopted":true,"version":"6.6.77","upgradable":"true",
  "upgrade_to_firmware":"6.7.10","uptime":86400,"num_sta":"12","system-stats":{"cpu":"3.1","mem":"27.4"},
  "port_table":[{"port_idx":1,"name":"eth0","up":true}]},
 {"type":"uap","model":"U6LR","name":"","mac":"74:ac:b9:00:00:02","state":0,"adopted":true,"version":"6.6.77","system-stats":{}},
 {"type":"uap","model":"U7PRO","name":"Neu","mac":"74:ac:b9:00:00:03","state":2,"adopted":false}]`

const ufHealthJSON = `[
 {"subsystem":"wlan","num_user":7,"num_guest":2,"num_iot":0,"tx_bytes-r":0,"rx_bytes-r":0,"status":"ok","num_ap":2,"num_adopted":2,"num_disconnected":1},
 {"subsystem":"wan","num_gw":1,"num_adopted":1,"status":"ok","wan_ip":"203.0.113.154","gateways":[],"num_sta":8,"tx_bytes-r":34263,"rx_bytes-r":1250000,
  "gw_mac":"28:70:4e:85:a9:e9","gw_system-stats":{"cpu":"5.6","mem":"67.2","uptime":"492633"},"isp_name":"Beispiel Netz"},
 {"subsystem":"www","status":"ok","tx_bytes-r":34263,"rx_bytes-r":19465,"latency":9,"uptime":492506,"drops":1,"xput_up":41.5,"xput_down":250.0,"speedtest_status":"Success"},
 {"subsystem":"lan","lan_ip":null,"status":"ok","num_user":"14","num_guest":0,"num_sw":1},
 {"subsystem":"vpn","status":"error","site_to_site_enabled":true}]`

func newFakeUnifi(os bool) *fakeUnifi {
	return &fakeUnifi{os: os, key: ufTestKey, user: ufTestUser, pass: ufTestPass, hits: map[string]int{}, methods: map[string]int{}, status: map[string]int{},
		routes: map[string]string{
			"/api/self/sites":                 `[{"_id":"1","name":"default","desc":"Zuhause","role":"readonly"},{"_id":"2","name":"a1b2c3d4","desc":"Büro","role":"readonly"}]`,
			"/api/s/default/stat/device":      ufDevicesJSON,
			"/api/s/default/stat/health":      ufHealthJSON,
			"/api/s/default/stat/sysinfo":     `[{"version":"10.4.57","update_available":true,"console_display_version":"4.1.13","name":"Console","hostname":"unifi"}]`,
			"/api/s/default/list/alarm":       `[{"key":"EVT_AP_Lost_Contact","msg":"AP[74:ac:b9:00:00:02] was disconnected","datetime":"2026-11-13T08:00:00Z","archived":false},{"key":"EVT_GW_WANTransition","msg":"alt","datetime":"2026-11-01T08:00:00Z","archived":true},{"key":"EVT_SW_Lost_Contact","msg":"Switch <b>16</b> lost contact","datetime":"2026-11-13T09:00:00Z"}]`,
			"/api/s/a1b2c3d4/stat/device":     `[]`,
			"/api/s/a1b2c3d4/stat/health":     `[{"subsystem":"wan","status":"unknown"},{"subsystem":"wlan","status":"unknown"}]`,
			"/api/s/a1b2c3d4/list/alarm":      `[]`,
			"/api/s/a1b2c3d4/stat/sysinfo":    `[{"version":"10.4.57"}]`,
			"/api/s/gibtsnicht/stat/device":   "",
			"/api/s/gibtsnicht/stat/sysinfo":  "",
			"/api/s/gibtsnicht/stat/health":   "",
			"/api/s/gibtsnicht/list/alarm":    "",
			"/api/s/gibtsnicht/rest/whatever": "",
		}}
}

func (f *fakeUnifi) fail(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	if f.os && (status == 401 || status == 403) && !strings.HasPrefix(msg, "api.err.") {
		_, _ = fmt.Fprintf(w, `{"error":{"code":%d,"message":%q}}`, status, msg)
		return
	}
	_, _ = fmt.Fprintf(w, `{"meta":{"rc":"error","msg":%q},"data":[]}`, msg)
}

func (f *fakeUnifi) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.methods[r.Method]++
	path := r.URL.Path
	loginPath, logoutPath := "/api/login", "/api/logout"
	if f.os {
		loginPath, logoutPath = "/api/auth/login", "/api/auth/logout"
	}
	switch {
	case path == "/status" && f.os: // UniFi OS: die Oberflaeche der Konsole, keine Huelle der Network Application
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>UniFi OS</html>"))
		return
	case path == "/status":
		w.Header().Set("Content-Type", "application/json")
		if f.starting {
			_, _ = w.Write([]byte(`{"meta":{"rc":"ok","server_version":"10.0.162","server_running":false,"db_migrating":false,"up":false,"app_context_status":"UniFi Network Application is starting up..."},"data":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok","up":true,"server_version":"10.0.162","uuid":"b3dac373-99c9-4629-94b7-b568f0d44110"},"data":[]}`))
		return
	case path == loginPath && r.Method == http.MethodPost:
		f.logins++
		w.Header().Set("Content-Type", "application/json")
		var in struct{ Username, Password string }
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &in)
		switch {
		case f.loginRC == 429:
			w.WriteHeader(429)
			_, _ = w.Write([]byte(`{"code":"AUTHENTICATION_FAILED_LIMIT_REACHED","message":"You've reached the login attempt limit"}`))
		case f.loginRC != 0:
			f.fail(w, f.loginRC, "MFA required")
		case in.Username != f.user || in.Password != f.pass:
			if f.os {
				f.fail(w, 403, "Invalid username or password")
			} else {
				f.fail(w, 400, "api.err.Invalid")
			}
		default:
			f.session++
			if f.os {
				http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: fmt.Sprintf("jwt-%d", f.session), Path: "/"})
				w.Header().Set("X-Csrf-Token", fmt.Sprintf("csrf-%d", f.session))
			} else {
				http.SetCookie(w, &http.Cookie{Name: "unifises", Value: fmt.Sprintf("ses-%d", f.session), Path: "/"})
				http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: fmt.Sprintf("csrf-%d", f.session), Path: "/"})
			}
			_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
		}
		return
	case path == logoutPath && r.Method == http.MethodPost:
		f.logouts++
		f.session = 0
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if f.os {
		p, ok := strings.CutPrefix(path, ufOSPrefix)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		path = p
	} else if strings.HasPrefix(path, ufOSPrefix) {
		w.WriteHeader(http.StatusNotFound) // der selbst gehostete Server kennt das Praefix nicht
		_, _ = w.Write([]byte(`<html>404</html>`))
		return
	}
	// Anmeldung pruefen: API-Schluessel (nur UniFi OS) oder Sitzung mit CSRF-Token
	authed := false
	if k := r.Header.Get("X-API-KEY"); k != "" {
		f.keyCalls++
		authed = f.os && k == f.key
	} else if f.session > 0 {
		name, val := "unifises", fmt.Sprintf("ses-%d", f.session)
		if f.os {
			name, val = "TOKEN", fmt.Sprintf("jwt-%d", f.session)
		}
		if c, err := r.Cookie(name); err == nil && c.Value == val {
			authed = true
			if r.Header.Get("X-Csrf-Token") != fmt.Sprintf("csrf-%d", f.session) {
				f.noCSRF++
			}
		}
	}
	if authed && f.expire {
		f.expire, f.session, authed = false, 0, false
	}
	if !authed {
		if f.os {
			f.fail(w, 401, "Unauthorized")
		} else {
			f.fail(w, 401, "api.err.LoginRequired")
		}
		return
	}
	f.hits[path]++
	if st := f.status[path]; st != 0 {
		f.fail(w, st, f.routes[path])
		return
	}
	body, ok := f.routes[path]
	switch {
	case !ok:
		f.fail(w, 404, "api.err.NotFound")
	case body == "":
		f.fail(w, 401, "api.err.NoSiteContext")
	default:
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":` + body + `}`))
	}
}

func (f *fakeUnifi) set(path, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[path] = body
}

func unifiFor(t *testing.T, f *fakeUnifi, cfg UnifiConfig) (*Unifi, *time.Time) {
	t.Helper()
	addr, pin := tlsServer(t, f)
	cfg.Address, cfg.Pin = addr, pin
	u, err := NewUnifi(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(u.Close)
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	u.now = func() time.Time { return now }
	return u, &now
}

// API-Schluessel auf UniFi OS: keine Anmeldung, alle Pfade unter /proxy/network, nur GET.
func TestUnifiCollectAPIKey(t *testing.T) {
	f := newFakeUnifi(true)
	u, now := unifiFor(t, f, UnifiConfig{Secret: " " + ufTestKey + " "})
	svcs, err := u.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", deErr(err))
	}
	// Geraete: Zahlen als Text bzw. Zahl, Temperatur der CPU vor der Platine
	gw := svcByKey(t, svcs, "dev:28:70:4e:85:a9:e9")
	if gw.Kind != "netdev" || gw.Name != "Gateway" || mustMetric(t, gw, "cpu").Value != 5.6 || mustMetric(t, gw, "cpu").Rule != model.RuleCPU ||
		mustMetric(t, gw, "mem").Value != 67.2 || mustMetric(t, gw, "temp").Value != 66 || mustMetric(t, gw, "temp").Rule != model.RuleTemp ||
		mustMetric(t, gw, "clients").Value != 8 || mustMetric(t, gw, "uptime").Value != 492633 || len(gw.Facts) != 0 ||
		gw.Text != "online · UDMPRO · 66 °C · 8 Clients · Firmware 4.1.13" {
		t.Errorf("Gateway: %+v %q", gw.Metrics, gw.Text)
	}
	sw := svcByKey(t, svcs, "dev:fc:ec:da:11:22:33")
	if mustMetric(t, sw, "temp").Value != 56 || mustMetric(t, sw, "uptime").Value != 3971865 || !strings.HasSuffix(sw.Text, "Firmware 4.0.66.10832 · Update verfügbar") {
		t.Errorf("Switch: %+v %q", sw.Metrics, sw.Text)
	}
	if ap := svcByKey(t, svcs, "dev:74:ac:b9:00:00:01"); mustMetric(t, ap, "clients").Value != 12 || mustMetric(t, ap, "cpu").Value != 3.1 {
		t.Errorf("AP: %+v", ap.Metrics)
	}
	off := svcByKey(t, svcs, "dev:74:ac:b9:00:00:02")
	if !hasFact(off, "device_crit") || len(off.Metrics) != 0 || off.Name != "U6LR 74:ac:b9:00:00:02" || off.Facts[0].Text != "U6LR 74:ac:b9:00:00:02: offline" ||
		!strings.HasPrefix(off.Text, "offline · U6LR") {
		t.Errorf("AP offline: %+v", off)
	}
	for _, s := range svcs {
		if strings.Contains(s.Key, "00:00:03") || strings.HasPrefix(s.Key, "port:74:ac") {
			t.Errorf("Dienst %s sollte fehlen (nicht uebernommen bzw. Port eines Access Points)", s.Key)
		}
	}
	// Ports: Raten vom Controller (Bytes/s), Auslastung, PoE; ohne Link, abgeschaltet, Halbduplex
	p3 := svcByKey(t, svcs, "port:fc:ec:da:11:22:33:3")
	if !p3.Default || p3.Kind != "if" || p3.Name != "Switch 16 · Port 3" || mustMetric(t, p3, "out").Value != 0.01 || mustMetric(t, p3, "poe").Value != 3.24 ||
		p3.Text != "1,0 Gbit/s · ↓ 0,0 Mbit/s · ↑ 0,0 Mbit/s · PoE 3,2 W" {
		t.Errorf("Port 3: %+v %q", p3.Metrics, p3.Text)
	}
	if p4 := svcByKey(t, svcs, "port:fc:ec:da:11:22:33:4"); p4.Default || !hasFact(p4, "if_down") || p4.Text != "down" || p4.Name != "Switch 16 · Drucker" {
		t.Errorf("Port 4: %+v", p4)
	}
	if p5 := svcByKey(t, svcs, "port:fc:ec:da:11:22:33:5"); p5.Default || len(p5.Facts) != 0 || p5.Text != "abgeschaltet" {
		t.Errorf("Port 5: %+v", p5)
	}
	p6 := svcByKey(t, svcs, "port:fc:ec:da:11:22:33:6")
	if !hasFact(p6, "if_half_duplex") || mustMetric(t, p6, "in").Value != 1 || mustMetric(t, p6, "out").Value != 10 || mustMetric(t, p6, "util").Value != 10 ||
		mustMetric(t, p6, "util").Rule != model.RuleIfUtil {
		t.Errorf("Port 6: %+v %q", p6.Metrics, p6.Text)
	}
	poe := svcByKey(t, svcs, "poe:fc:ec:da:11:22:33")
	if poe.Kind != "poe" || mustMetric(t, poe, "used").Value != 11.66 || mustMetric(t, poe, "used").Rule != model.RulePoEUsed || mustMetric(t, poe, "watts").Value != 15.74 ||
		poe.Text != "15,7 W von 135 W an 2 Ports" {
		t.Errorf("PoE: %+v %q", poe.Metrics, poe.Text)
	}
	if wp := svcByKey(t, svcs, "port:28:70:4e:85:a9:e9:9"); wp.Name != "Gateway · WAN" || mustMetric(t, wp, "in").Value != 0.48 {
		t.Errorf("WAN-Port: %+v", wp)
	}
	// Internet und Clients aus stat/health (ein inaktiver VPN-Tunnel zaehlt nicht)
	wan := svcByKey(t, svcs, "wan")
	if wan.Kind != "wan" || len(wan.Facts) != 0 || mustMetric(t, wan, "latency").Value != 9 || mustMetric(t, wan, "in").Value != 10 ||
		mustMetric(t, wan, "speedtest_down").Value != 250 || wan.Text != "online · 203.0.113.154 · Beispiel Netz · 9 ms · ↓ 10 Mbit/s · ↑ 0,3 Mbit/s" {
		t.Errorf("wan: %+v %q", wan.Metrics, wan.Text)
	}
	if c := svcByKey(t, svcs, "clients"); mustMetric(t, c, "wlan").Value != 7 || mustMetric(t, c, "lan").Value != 14 || c.Text != "7 WLAN, 14 LAN, 2 Gäste" || c.Name != "Clients" {
		t.Errorf("clients: %+v %q", c.Metrics, c.Text)
	}
	al := svcByKey(t, svcs, "alerts")
	if mustMetric(t, al, "count").Value != 2 || !hasFact(al, "device_warn") ||
		al.Text != "2 offene Alarme: Switch 16 lost contact; AP[74:ac:b9:00:00:02] was disconnected" {
		t.Errorf("alerts: %+v %q", al.Metrics, al.Text)
	}
	sys := svcByKey(t, svcs, "system")
	if sys.Name != "UniFi Network" || mustMetric(t, sys, "devices").Value != 4 || mustMetric(t, sys, "offline").Value != 1 ||
		sys.Text != "Version 10.4.57 · UniFi OS 4.1.13 · 4 Geräte, 1 offline" {
		t.Errorf("system: %+v %q", sys.Metrics, sys.Text)
	}
	upd := svcByKey(t, svcs, "updates")
	if !hasFact(upd, "updates_security") || mustMetric(t, upd, "pending").Value != 3 ||
		upd.Text != "Update der Network Application verfügbar · Firmware-Update für 2 Geräte: AP Flur 6.7.10, Switch 16 4.0.80.10875" {
		t.Errorf("updates: %+v %q", upd.Metrics, upd.Text)
	}

	// zweite Runde: Fehlerrate aus den Zaehlern; sysinfo nicht erneut
	*now = now.Add(time.Minute)
	f.set("/api/s/default/stat/device", strings.Replace(ufDevicesJSON,
		`"rx_bytes-r":125000,"tx_bytes-r":1250000,"rx_packets":100,"tx_packets":100,"rx_errors":0,"tx_errors":0`,
		`"rx_bytes-r":125000,"tx_bytes-r":1250000,"rx_packets":600,"tx_packets":600,"rx_errors":3,"tx_errors":2`, 1))
	svcs, err = u.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect 2: %v", deErr(err))
	}
	p6 = svcByKey(t, svcs, "port:fc:ec:da:11:22:33:6")
	if mustMetric(t, p6, "errors").Value != 5 || mustMetric(t, p6, "errrate").Value != 0.5 || mustMetric(t, p6, "errrate").Rule != model.RuleIfErrRate || !strings.Contains(p6.Text, "5 Fehler") {
		t.Errorf("Port 6 (Runde 2): %+v %q", p6.Metrics, p6.Text)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.logins != 0 || f.keyCalls == 0 || len(f.methods) != 1 || f.methods[http.MethodGet] == 0 {
		t.Errorf("Anmeldung bzw. andere Methoden mit API-Schluessel: logins=%d %v", f.logins, f.methods)
	}
	if f.hits["/api/s/default/stat/device"] != 2 || f.hits["/api/s/default/stat/health"] != 2 || f.hits["/api/s/default/stat/sysinfo"] != 1 {
		t.Errorf("Abfragen: %v", f.hits)
	}
}

// Benutzer und Passwort auf UniFi OS: eine Anmeldung, Cookie und CSRF-Token bei jeder Abfrage; laeuft die Sitzung ab,
// wird einmal neu angemeldet; Close meldet ab.
func TestUnifiLoginOS(t *testing.T) {
	f := newFakeUnifi(true)
	u, now := unifiFor(t, f, UnifiConfig{User: ufTestUser, Secret: ufTestPass})
	for round := 0; round < 2; round++ {
		if _, err := u.Collect(context.Background()); err != nil {
			t.Fatalf("Collect %d: %v", round, deErr(err))
		}
		*now = now.Add(time.Minute)
	}
	f.mu.Lock()
	if f.logins != 1 || f.noCSRF != 0 || f.keyCalls != 0 || f.hits["/api/s/default/stat/device"] != 2 {
		t.Fatalf("Sitzung: logins=%d ohne CSRF=%d hits=%v", f.logins, f.noCSRF, f.hits)
	}
	f.expire = true
	f.mu.Unlock()
	svcs, err := u.Collect(context.Background())
	if err != nil || len(svcs) < 10 {
		t.Fatalf("nach Ablauf der Sitzung: %d Dienste, %v", len(svcs), deErr(err))
	}
	f.mu.Lock()
	if f.logins != 2 {
		t.Errorf("neue Anmeldung nach Ablauf: %d", f.logins)
	}
	f.mu.Unlock()
	u.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.logouts != 1 || f.session != 0 {
		t.Errorf("Abmeldung: %d", f.logouts)
	}
}

// Selbst gehosteter Network Server: GET / leitet weiter -> /api/login, Pfade ohne /proxy/network.
func TestUnifiLoginClassic(t *testing.T) {
	f := newFakeUnifi(false)
	u, _ := unifiFor(t, f, UnifiConfig{User: ufTestUser, Secret: ufTestPass})
	svcs, err := u.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", deErr(err))
	}
	if svcByKey(t, svcs, "system").Text != "Version 10.4.57 · UniFi OS 4.1.13 · 4 Geräte, 1 offline" {
		t.Errorf("system: %q", svcByKey(t, svcs, "system").Text)
	}
	f.mu.Lock()
	if f.logins != 1 || f.noCSRF != 0 || f.hits["/api/s/default/stat/device"] != 1 {
		t.Errorf("klassisch: logins=%d ohne CSRF=%d hits=%v", f.logins, f.noCSRF, f.hits)
	}
	f.mu.Unlock()
	// startet der Server noch, wird nicht geraten, sondern gewartet (und danach richtig erkannt)
	f.starting = true
	st, _ := unifiFor(t, f, UnifiConfig{User: ufTestUser, Secret: ufTestPass})
	if _, err := st.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "startet noch") {
		t.Errorf("startender Server: %v", deErr(err))
	}
	f.mu.Lock()
	f.starting = false
	n := f.logins
	f.mu.Unlock()
	if _, err := st.Collect(context.Background()); err != nil {
		t.Errorf("nach dem Start: %v", deErr(err))
	}
	f.mu.Lock()
	if f.logins != n+1 {
		t.Errorf("Anmeldung nach dem Start: %d statt %d", f.logins, n+1)
	}
	f.mu.Unlock()
	// ein API-Schluessel geht dort nicht: klarer Hinweis statt "nicht gefunden"
	k, _ := unifiFor(t, f, UnifiConfig{Secret: ufTestKey})
	if _, err := k.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "kein UniFi OS") {
		t.Errorf("API-Schluessel am selbst gehosteten Server: %v", deErr(err))
	}
}

// Abgelehnte Anmeldung: Hinweis, und danach Pause statt bei jeder Runde neu zu versuchen (die Konsole sperrt sonst
// immer laenger). Das Passwort steht in keiner Meldung.
func TestUnifiLoginRejected(t *testing.T) {
	f := newFakeUnifi(true)
	u, now := unifiFor(t, f, UnifiConfig{User: ufTestUser, Secret: ufTestPass + "-falsch"})
	_, err := u.Collect(context.Background())
	if err == nil || !strings.Contains(deErr(err), "HTTP 403 Anmeldung abgelehnt") || !strings.Contains(deErr(err), "nächster Versuch in 5 Min.") ||
		!strings.Contains(deErr(err), "lokaler Admin") || strings.Contains(err.Error(), ufTestPass) {
		t.Fatalf("falsches Passwort: %v", deErr(err))
	}
	for i := 0; i < 3; i++ { // weitere Runden innerhalb der Pause: kein neuer Versuch
		*now = now.Add(time.Minute)
		if _, err := u.Collect(context.Background()); err == nil {
			t.Fatal("ohne Anmeldung geliefert")
		}
	}
	f.mu.Lock()
	if f.logins != 1 {
		t.Errorf("Anmeldeversuche in der Pause: %d", f.logins)
	}
	f.mu.Unlock()
	*now = now.Add(5 * time.Minute)
	if _, err := u.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "nächster Versuch in 15 Min.") {
		t.Errorf("zweiter Versuch: %v", deErr(err))
	}
	f.mu.Lock()
	if f.logins != 2 {
		t.Errorf("Anmeldeversuche nach der Pause: %d", f.logins)
	}
	f.mu.Unlock()

	// Sperre der Konsole und zweiter Faktor
	f.loginRC = 429
	lock, _ := unifiFor(t, f, UnifiConfig{User: ufTestUser, Secret: ufTestPass})
	if _, err := lock.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "sperrt vorübergehend") {
		t.Errorf("Sperre: %v", deErr(err))
	}
	f.loginRC = 499
	mfa, _ := unifiFor(t, f, UnifiConfig{User: ufTestUser, Secret: ufTestPass})
	if _, err := mfa.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "zweiten Faktor") {
		t.Errorf("MFA: %v", deErr(err))
	}
	// selbst gehostet: api.err.Invalid
	c := newFakeUnifi(false)
	bad, _ := unifiFor(t, c, UnifiConfig{User: ufTestUser, Secret: "falsch"})
	if _, err := bad.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "Anmeldung abgelehnt") {
		t.Errorf("klassisch, falsches Passwort: %v", deErr(err))
	}
}

// Neuere Versionen haben list/alarm entfernt (404 bzw. 400 api.err.InvalidObject): kein Dienst, kein Teilfehler,
// nicht bei jeder Runde neu gefragt. Falscher Schluessel und unbekannte Site geben klare Hinweise.
func TestUnifiVariants(t *testing.T) {
	f := newFakeUnifi(true)
	f.status["/api/s/default/list/alarm"] = 400
	f.routes["/api/s/default/list/alarm"] = "api.err.InvalidObject"
	u, now := unifiFor(t, f, UnifiConfig{Secret: ufTestKey})
	for round := 0; round < 2; round++ {
		svcs, err := u.Collect(context.Background())
		if err != nil {
			t.Fatalf("Collect %d: %v", round, deErr(err))
		}
		for _, s := range svcs {
			if s.Key == "alerts" {
				t.Error("Dienst alerts ohne Endpunkt")
			}
		}
		*now = now.Add(time.Minute)
	}
	f.mu.Lock()
	if f.hits["/api/s/default/list/alarm"] != 1 {
		t.Errorf("entfernter Endpunkt erneut gefragt: %d", f.hits["/api/s/default/list/alarm"])
	}
	f.mu.Unlock()

	// Site ohne Gateway und ohne Geraete: kein Dienst wan, keine Clients-Zahlen, aber system und updates
	empty, _ := unifiFor(t, f, UnifiConfig{Secret: ufTestKey, Site: "a1b2c3d4"})
	svcs, err := empty.Collect(context.Background())
	if err != nil {
		t.Fatalf("leere Site: %v", deErr(err))
	}
	if len(svcs) != 3 || svcByKey(t, svcs, "updates").Text != "keine ausstehend" || svcByKey(t, svcs, "system").Text != "Version 10.4.57 · 0 Geräte, 0 offline" ||
		svcByKey(t, svcs, "alerts").Text != "keine offenen Alarme" {
		t.Errorf("leere Site: %d Dienste", len(svcs))
	}

	bad, _ := unifiFor(t, f, UnifiConfig{Secret: ufTestKey + "x"})
	if _, err := bad.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "HTTP 401 Anmeldung abgelehnt") ||
		!strings.Contains(deErr(err), "Integrations") || strings.Contains(err.Error(), ufTestKey) {
		t.Errorf("falscher Schluessel: %v", deErr(err))
	}
	site, _ := unifiFor(t, f, UnifiConfig{Secret: ufTestKey, Site: "gibtsnicht"})
	if _, err := site.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "die Site „gibtsnicht“ gibt es nicht") {
		t.Errorf("unbekannte Site: %v", deErr(err))
	}
	// mit Anmeldung: die unbekannte Site (401 api.err.NoSiteContext, so auch am echten Server) loest keine neue Anmeldung aus
	ls, _ := unifiFor(t, f, UnifiConfig{User: ufTestUser, Secret: ufTestPass, Site: "gibtsnicht"})
	for i := 0; i < 2; i++ {
		if _, err := ls.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "die Site „gibtsnicht“ gibt es nicht") {
			t.Errorf("unbekannte Site mit Anmeldung: %v", deErr(err))
		}
	}
	f.mu.Lock()
	if f.logins != 1 {
		t.Errorf("Anmeldungen bei unbekannter Site: %d", f.logins)
	}
	f.mu.Unlock()
	for _, c := range []UnifiConfig{
		{Address: "https://192.0.2.1"},
		{Address: "https://192.0.2.1", User: "a"},
		{Address: "http://192.0.2.1", Secret: "k"},
		{Address: "https://192.0.2.1", Secret: "k", Site: "a/b"},
		{Address: "https://192.0.2.1", Secret: "k\nx"},
	} {
		if _, err := NewUnifi(c); err == nil {
			t.Errorf("angenommen: %+v", c)
		}
	}
}

func TestUnifiTest(t *testing.T) {
	f := newFakeUnifi(true)
	addr, pin := tlsServer(t, f)
	u, err := NewUnifi(UnifiConfig{Address: addr, Secret: ufTestKey})
	if err != nil {
		t.Fatal(err)
	}
	res := u.Test(context.Background())
	u.Close()
	if res.OK || !res.NeedConfirm || res.Fingerprint != pin {
		t.Fatalf("ohne Pin: %+v", res)
	}
	f.mu.Lock()
	if len(f.methods) != 0 {
		t.Errorf("Anfrage vor der Bestaetigung: %v", f.methods)
	}
	f.mu.Unlock()
	ok, _ := unifiFor(t, f, UnifiConfig{Secret: ufTestKey})
	res = ok.Test(context.Background())
	if !res.OK || res.Version != "10.4.57" || de(res.Summary) != "4 Geräte" {
		t.Fatalf("mit Pin: %+v", res)
	}
	site, _ := unifiFor(t, f, UnifiConfig{Secret: ufTestKey, Site: "buero"})
	res = site.Test(context.Background())
	if res.OK || de(res.Error) != "Site „buero“ nicht gefunden – vorhanden: a1b2c3d4 (Büro), default (Zuhause)" {
		t.Fatalf("unbekannte Site: %+v", de(res.Error))
	}
	login, _ := unifiFor(t, f, UnifiConfig{User: ufTestUser, Secret: ufTestPass})
	if res = login.Test(context.Background()); !res.OK {
		t.Fatalf("Test mit Anmeldung: %s", de(res.Error))
	}
}
