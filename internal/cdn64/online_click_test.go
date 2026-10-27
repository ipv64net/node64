package cdn64

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/cdnedge"
	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/notify"
)

// fakeOnline spielt ipv64 /cdn64o fuer die Node.
type fakeOnline struct {
	mu       sync.Mutex
	ready    bool
	edges    []ipv64api.CDN64Edge
	tunnels  map[string]bool
	hosts    map[int64]string
	modes    map[int64]int
	next     int64
	paused   map[int64]bool
	extra    []ipv64api.CDN64Host // Namen, die die Node nicht verwaltet (Modus 3 von der Webseite)
	calls    int                  // Abrufe von Overview
	maps     map[int64][]ipv64api.CDN64Mapping
	mapNext  int64
	mapErr   error                     // naechstes AddMapping scheitert
	sessions int                       // parallele Verbindungen, die ipv64 der Klasse erlaubt
	prot     *ipv64api.CDN64Protection // Antwort von /cdn64o/protection
	protErr  error                     // /cdn64o/protection scheitert
	protDays []int                     // abgefragte Zeitraeume
	waf      map[int64]bool            // WAF je Name (gesetzt ueber SetProtection)
	ja4      map[int64]string          // JA4-Stufe je Name
}

func (f *fakeOnline) Ready(context.Context) bool { f.mu.Lock(); defer f.mu.Unlock(); return f.ready }

func (f *fakeOnline) Overview(context.Context) (*ipv64api.CDN64Overview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ov := &ipv64api.CDN64Overview{Edges: f.edges}
	ov.Quota.Domains.Limit = 5
	f.calls++
	for id := range f.tunnels {
		ov.Tunnels = append(ov.Tunnels, ipv64api.CDN64Tunnel{ID: id, Status: "active", Sessions: f.sessions})
	}
	for id, n := range f.hosts {
		ov.Hosts = append(ov.Hosts, ipv64api.CDN64Host{ID: id, FQDN: n, Status: "active", Mode: max(f.modes[id], 1), Paused: f.paused[id], Mappings: f.maps[id],
			WAF: f.waf[id], JA4: f.ja4[id]})
	}
	for _, h := range f.extra {
		h.Paused = f.paused[h.ID]
		if v, ok := f.ja4[h.ID]; ok {
			h.WAF, h.JA4 = f.waf[h.ID], v
		}
		ov.Hosts = append(ov.Hosts, h)
	}
	return ov, nil
}

func (f *fakeOnline) CreateTunnel(context.Context, string) (*ipv64api.CDN64Tunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tunnels["tn_t4"] = true
	return &ipv64api.CDN64Tunnel{ID: "tn_t4", Status: "active", Token: "tok-t4", Edges: f.edges}, nil
}

func (f *fakeOnline) DeleteTunnel(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.tunnels, id)
	return nil
}

func (f *fakeOnline) AddHost(_ context.Context, fqdn, tunnelID string, mode int, tgt *ipv64api.CDN64Target) (*ipv64api.CDN64Host, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if fqdn == "nope.test" {
		return nil, &ipv64api.APIError{Status: 422, Code: "domain_not_in_account", Detail: "not in account"}
	}
	if mode == 3 && (tgt == nil || tunnelID != "") || mode != 3 && !f.tunnels[tunnelID] || mode < 1 || mode > 3 {
		return nil, &ipv64api.APIError{Status: 404, Code: "cdn64o_tunnel_not_found"}
	}
	f.next++
	f.hosts[f.next] = fqdn
	f.modes[f.next] = mode
	return &ipv64api.CDN64Host{ID: f.next, FQDN: fqdn, Mode: mode, Status: "active"}, nil
}

func (f *fakeOnline) SetMode(_ context.Context, id int64, mode int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.hosts[id]; !ok {
		return &ipv64api.APIError{Status: 404, Code: "cdn64o_host_not_found"}
	}
	f.modes[id] = mode
	return nil
}

func (f *fakeOnline) SetPaused(_ context.Context, id int64, paused bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	known := f.hosts[id] != ""
	for _, h := range f.extra {
		known = known || h.ID == id
	}
	if !known {
		return &ipv64api.APIError{Status: 404, Code: "cdn64o_host_not_found"}
	}
	if f.paused == nil {
		f.paused = map[int64]bool{}
	}
	f.paused[id] = paused
	return nil
}

func (f *fakeOnline) Protection(_ context.Context, days int) (*ipv64api.CDN64Protection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.protDays = append(f.protDays, days)
	if f.protErr != nil {
		return nil, f.protErr
	}
	if f.prot == nil {
		return &ipv64api.CDN64Protection{Days: days, JA4Global: "count"}, nil
	}
	p := *f.prot
	p.Days = days
	return &p, nil
}

func (f *fakeOnline) SetProtection(_ context.Context, id int64, waf *bool, ja4 string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	known := f.hosts[id] != ""
	for _, h := range f.extra {
		known = known || h.ID == id
	}
	if !known {
		return &ipv64api.APIError{Status: 404, Code: "cdn64o_host_not_found"}
	}
	if f.waf == nil {
		f.waf, f.ja4 = map[int64]bool{}, map[int64]string{}
	}
	if waf != nil {
		f.waf[id] = *waf
	}
	if ja4 != "" {
		f.ja4[id] = ja4
	}
	return nil
}

func (f *fakeOnline) AddMapping(_ context.Context, id int64, name, transport string, targetPort int) ([]ipv64api.CDN64Mapping, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.mapErr; err != nil {
		f.mapErr = nil
		return nil, err
	}
	if f.hosts[id] == "" {
		return nil, &ipv64api.APIError{Status: 404, Code: "cdn64o_host_not_found"}
	}
	if f.maps == nil {
		f.maps = map[int64][]ipv64api.CDN64Mapping{}
	}
	for _, x := range f.maps[id] {
		if x.Transport == transport && x.TargetPort == targetPort {
			return nil, &ipv64api.APIError{Status: 409, Code: "mapping_exists"}
		}
	}
	f.mapNext++
	f.maps[id] = append(f.maps[id], ipv64api.CDN64Mapping{ID: f.mapNext, Name: name, Transport: transport, TargetPort: targetPort, ListenPort: 50000 + int(f.mapNext)})
	return f.maps[id], nil
}

func (f *fakeOnline) DeleteMapping(_ context.Context, id, mapping int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, x := range f.maps[id] {
		if x.ID == mapping {
			f.maps[id] = append(f.maps[id][:i], f.maps[id][i+1:]...)
			return nil
		}
	}
	return &ipv64api.APIError{Status: 404, Code: "not_found"}
}

func (f *fakeOnline) DeleteHost(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.hosts[id]; !ok {
		return &ipv64api.APIError{Status: 404, Code: "cdn64o_host_not_found"}
	}
	delete(f.hosts, id)
	delete(f.maps, id)
	return nil
}

func (f *fakeOnline) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.tunnels), len(f.hosts)
}

// Ein Klick ueber einen echten cdn64-edge: ohne Account Hinweis, Tunnel anmelden, Namen einschalten (einer
// scheitert mit Code und Text), Selbsttest ueber den Server, geteilter DNS, Ausschalten raeumt alles ab; ein
// geloeschter Host wird beim Abgleich bei ipv64 ausgetragen.
func TestOnlineOneClick(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "hello") }))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)
	bport, _ := strconv.Atoi(bu.Port())
	certPEM, keyPEM := selfSigned(t, "app.test")
	if _, err := e.crt.Upload(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	// Server wie srv07 mit fester Zuordnung (ipv64 liefert sie im Betrieb)
	conf, pool := edgeCert(t)
	dir := t.TempDir()
	cf, kf := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	kb, _ := x509.MarshalECPrivateKey(conf.Certificates[0].PrivateKey.(*ecdsa.PrivateKey))
	_ = os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: conf.Certificates[0].Certificate[0]}), 0o600)
	_ = os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	sum := sha256.Sum256([]byte("tok-t4"))
	p80, p443, pt := freePort(t), freePort(t), freePort(t)
	ecfg := &cdnedge.Config{Name: "srv07", ListenHTTP: "127.0.0.1:" + strconv.Itoa(p80), ListenHTTPS: "127.0.0.1:" + strconv.Itoa(p443),
		TunnelListen: "127.0.0.1:" + strconv.Itoa(pt), TLSCert: cf, TLSKey: kf, DataDir: filepath.Join(dir, "data"),
		Tunnels: []cdnedge.TunnelEntry{{ID: "tn_t4", TokenSHA256: hex.EncodeToString(sum[:])}},
		Hosts:   []cdnedge.HostEntry{{Name: "app.test", Tunnel: "tn_t4"}}}
	srv := cdnedge.New(ecfg, slog.New(slog.DiscardHandler), "test")
	ectx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = srv.Run(ectx); close(done) }()
	defer func() { cancel(); <-done }()

	f := &fakeOnline{tunnels: map[string]bool{}, hosts: map[int64]string{}, modes: map[int64]int{},
		edges: []ipv64api.CDN64Edge{{Name: "srv07", Host: "127.0.0.1", Port: pt, IPs: []string{"127.0.0.1"}}}}
	e.m.SetOnlineAPI(f)
	e.m.online.roots = pool
	e.m.online.ports = [2]int{p443, p80}
	old := publicLookup
	publicLookup = func(context.Context, string) []string { return []string{"127.0.0.1"} }
	defer func() { publicLookup = old }()
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"app.test", "nope.test", "*.wild.test"}, "127.0.0.1", bport
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}
	hp := "/api/cdn64/hosts/" + strconv.FormatInt(h.ID, 10) + "/online"

	// ohne Account: Code fuer "Account verbinden"
	if rec, out := call("POST", "/api/cdn64/online/tunnel", ""); rec.Code != http.StatusConflict || out["code"] != "no_api_key" {
		t.Fatalf("no key: %d %v", rec.Code, out)
	}
	f.mu.Lock()
	f.ready = true
	f.mu.Unlock()
	rec, out := call("POST", "/api/cdn64/online/tunnel", "")
	if rec.Code != 200 || out["tunnel"] != "tn_t4" {
		t.Fatalf("tunnel: %d %s", rec.Code, rec.Body)
	}
	if eds, _ := out["edges"].([]any); len(eds) != 1 || !eds[0].(map[string]any)["connected"].(bool) {
		t.Fatalf("edges: %v", out["edges"])
	}
	// Namen einschalten
	rec, out = call("POST", hp, `{"mode":1}`)
	if rec.Code != 200 {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body)
	}
	res := map[string]map[string]any{}
	for _, x := range out["results"].([]any) {
		r := x.(map[string]any)
		res[r["name"].(string)] = r
	}
	if res["app.test"]["result"] != "on" || res["nope.test"]["code"] != "domain_not_in_account" || res["*.wild.test"]["code"] != "wildcard_name" {
		t.Fatalf("results: %v", res)
	}
	if !e.m.OnlineName("APP.test.") || e.m.OnlineName("nope.test") {
		t.Fatal("split names")
	}
	rows, _ := e.m.rows(ctx)
	if len(rows) != 1 || rows[0].Online == nil || len(rows[0].Online.Names) != 1 || rows[0].Online.Missing != 1 || rows[0].Online.Edges[0].State != "direct" ||
		rows[0].Online.Via == "" || rows[0].Online.Edges[0].Via != rows[0].Online.Via {
		t.Fatalf("row: %+v", rows[0].Online)
	}
	// Selbsttest ueber den Server: kommt durch den Tunnel dieser Node an
	rec = httptest.NewRecorder()
	e.mux.ServeHTTP(rec, httptest.NewRequest("POST", hp+"/test", nil))
	var tests []onlineTest
	_ = json.Unmarshal(rec.Body.Bytes(), &tests)
	if rec.Code != 200 || len(tests) != 1 || len(tests[0].Probes) != 1 || !tests[0].Probes[0].OK || !tests[0].TLS || !tests[0].DNSOK ||
		tests[0].Probes[0].Trusted == nil || *tests[0].Probes[0].Trusted {
		t.Fatalf("selftest: %d %s", rec.Code, rec.Body)
	}
	// Wechsel auf Modus 2: derselbe Name, nur der Modus bei ipv64 und hier
	if rec, out := call("POST", hp, `{"mode":2}`); rec.Code != 200 || out["results"].([]any)[0].(map[string]any)["result"] != "on" {
		t.Fatalf("mode 2: %d %v", rec.Code, out)
	}
	if f.modes[1] != 2 {
		t.Fatalf("mode not switched at ipv64: %v", f.modes)
	}
	if rows, _ := e.m.rows(ctx); rows[0].Online.Mode != 2 {
		t.Fatal("row mode")
	}
	_, _ = call("POST", hp, `{"mode":1}`)
	// auf der Webseite gewechselt: der Abgleich uebernimmt den Modus
	f.mu.Lock()
	f.modes[1] = 2
	f.mu.Unlock()
	e.m.onlineSync(ctx)
	if list, _ := e.m.onlineNames(ctx); len(list) != 1 || list[0].Mode != 2 {
		t.Fatalf("remote mode not adopted: %+v", list)
	}
	// "TLS durchreichen" kann Modus 2 nicht: zurueck auf 1
	if _, err := e.m.core.Writer().ExecContext(ctx, `UPDATE cdn_hosts SET kind = ? WHERE id = ?`, KindPass, h.ID); err != nil {
		t.Fatal(err)
	}
	e.m.onlineSync(ctx)
	if f.modes[1] != 1 {
		t.Fatalf("passthrough host left in mode 2: %v", f.modes)
	}
	if _, err := e.m.core.Writer().ExecContext(ctx, `UPDATE cdn_hosts SET kind = ? WHERE id = ?`, KindProxy, h.ID); err != nil {
		t.Fatal(err)
	}
	e.m.onlineSync(ctx)
	// Name in der Node von einem anderen Modul belegt: der Selbsttest sagt es
	e.m.mu.Lock()
	e.m.routeErr[h.ID] = "name app.test is used by dns64"
	e.m.mu.Unlock()
	rec = httptest.NewRecorder()
	e.mux.ServeHTTP(rec, httptest.NewRequest("POST", hp+"/test", nil))
	tests = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &tests)
	if len(tests) != 1 || tests[0].Route == "" {
		t.Fatalf("route error not reported: %s", rec.Body)
	}
	e.m.mu.Lock()
	delete(e.m.routeErr, h.ID)
	e.m.mu.Unlock()
	// auf der Webseite ausgeschaltet (Notfall ohne Zugriff auf die Node): der Abgleich nimmt den Namen hier heraus
	f.mu.Lock()
	delete(f.hosts, 1)
	f.mu.Unlock()
	e.m.onlineSync(ctx)
	if list, _ := e.m.onlineNames(ctx); len(list) != 0 || e.m.OnlineName("app.test") {
		t.Fatalf("name still on after switch-off on the website: %+v", list)
	}
	if nt, nh := f.counts(); nt != 0 || nh != 0 {
		t.Fatalf("after switch-off on the website: tunnels %d hosts %d", nt, nh)
	}
	if rec, _ := call("POST", hp, `{"mode":1}`); rec.Code != 200 {
		t.Fatalf("enable after website switch-off: %d %s", rec.Code, rec.Body)
	}
	// Ausschalten: Name und Tunnel bei ipv64 weg, Einstellung leer
	if rec, _ := call("DELETE", hp, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body)
	}
	if nt, nh := f.counts(); nt != 0 || nh != 0 || e.m.OnlineName("app.test") || e.m.core.SettingOr(ctx, setOnline, "") != "" || e.m.onlineRunning() {
		t.Fatalf("after disable: tunnels %d hosts %d", nt, nh)
	}
	// wieder ein, dann Host loeschen: der Abgleich schaltet bei ipv64 aus
	if rec, _ := call("POST", hp, ``); rec.Code != 200 {
		t.Fatalf("enable 2: %d %s", rec.Code, rec.Body)
	}
	if _, nh := f.counts(); nh != 1 {
		t.Fatal("enable 2: not at ipv64")
	}
	if err := e.m.deleteHost(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if nt, nh := f.counts(); nt == 0 && nh == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if nt, nh := f.counts(); nt != 0 || nh != 0 || e.m.OnlineName("app.test") {
		t.Fatalf("after host delete: tunnels %d hosts %d", nt, nh)
	}
}

// Meldungen: Tunnel zu keinem Server -> erst nach der Schonfrist, einmal; Sperre bei ipv64 einmal je Name.
func TestOnlineAlarm(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	var got []notify.Alert
	e.m.SetNotifier(func(a notify.Alert) { got = append(got, a) })
	if _, err := e.m.core.Writer().ExecContext(ctx, `INSERT INTO cdn_online (name, host_id, remote_id, mode, created_at) VALUES ('a.test', 1, 9, 1, '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	reason := "traffic"
	e.m.online.remote.Store(&onlineRemote{At: time.Now(), Data: &ipv64api.CDN64Overview{Hosts: []ipv64api.CDN64Host{{ID: 9, FQDN: "a.test", Status: "blocked", BlockedReason: &reason}}}})
	a := &onlineAlarm{blocked: map[string]bool{}}
	t0 := time.Now()
	e.m.onlineCheckAlarm(ctx, a, t0)
	e.m.onlineCheckAlarm(ctx, a, t0.Add(time.Minute))
	if len(got) != 1 || got[0].Kind != notify.KindCDNOnlineBlocked || got[0].Reason != "traffic" {
		t.Fatalf("blocked: %+v", got)
	}
	e.m.onlineCheckAlarm(ctx, a, t0.Add(onlineGrace+time.Second))
	e.m.onlineCheckAlarm(ctx, a, t0.Add(onlineGrace+time.Minute))
	if len(got) != 2 || got[1].Kind != notify.KindCDNOnlineDown || got[1].Check.Name != "a.test" || !got[1].Check.Local {
		t.Fatalf("down: %+v", got)
	}
}

// Modus 3 gibt es nur auf ipv64.net/cdn64: die Node lehnt ihn ab (ohne Aufruf bei ipv64); ein alter Modus-3-Name
// laesst sich auf Modus 1 umstellen (bei ipv64 aus und neu ein, jetzt mit Tunnel).
func TestOnlineMode3(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	f := &fakeOnline{ready: true, tunnels: map[string]bool{}, hosts: map[int64]string{}, modes: map[int64]int{},
		edges: []ipv64api.CDN64Edge{{Name: "srv07", Host: "127.0.0.1", Port: 1, IPs: []string{"127.0.0.1"}}}}
	e.m.SetOnlineAPI(f)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"m3.test"}, "93.184.216.34", 8080
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.onlineEnable(ctx, h, 3); onlineCode(err) != "mode3_web" {
		t.Fatalf("mode 3 from the node: %v", err)
	}
	if nt, nh := f.counts(); nt != 0 || nh != 0 {
		t.Fatalf("mode 3 called ipv64: tunnels %d hosts %d", nt, nh)
	}
	// alter Modus-3-Name (frueher in der Node eingeschaltet)
	f.mu.Lock()
	f.hosts[7], f.modes[7] = "m3.test", 3
	f.mu.Unlock()
	if _, err := e.m.core.Writer().ExecContext(ctx, `INSERT INTO cdn_online (name, host_id, remote_id, mode, created_at) VALUES ('m3.test', ?, 7, 3, '2026-01-01T00:00:00Z')`, h.ID); err != nil {
		t.Fatal(err)
	}
	res, err := e.m.onlineEnable(ctx, h, 1)
	if err != nil || len(res) != 1 || res[0].Result != "on" || f.hosts[7] != "" || len(f.hosts) != 1 || len(f.tunnels) != 1 {
		t.Fatalf("3 -> 1: %v %+v hosts=%v modes=%v", err, res, f.hosts, f.modes)
	}
	if list, _ := e.m.onlineNames(ctx); len(list) != 1 || list[0].Mode != 1 {
		t.Fatalf("names after switch: %+v", list)
	}
}
