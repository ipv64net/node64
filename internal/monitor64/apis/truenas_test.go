package apis

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// tnFiles: Methode -> Datei in testdata/truenas (fehlt = Methode unbekannt).
var tnFiles = map[string]string{"system.info": "system_info", "pool.query": "pool", "boot.get_state": "boot_get_state",
	"disk.query": "disk", "disk.temperatures": "disk_temperatures", "smart.test.results": "smart_test_results",
	"alert.list": "alert_list", "replication.query": "replication", "pool.snapshottask.query": "pool_snapshottask",
	"cloudsync.query": "cloudsync", "app.query": "app", "vm.query": "vm"}

// tnREST-Pfade -> Methode.
var tnPaths = map[string]string{"GET /system/info": "system.info", "GET /pool": "pool.query", "GET /boot/get_state": "boot.get_state",
	"GET /disk": "disk.query", "POST /disk/temperatures": "disk.temperatures", "GET /smart/test/results": "smart.test.results",
	"GET /alert/list": "alert.list", "GET /replication": "replication.query", "GET /pool/snapshottask": "pool.snapshottask.query",
	"GET /cloudsync": "cloudsync.query", "GET /rsynctask": "rsynctask.query", "GET /app": "app.query", "GET /vm": "vm.query"}

// fakeTrueNAS beantwortet REST v2.0 und (mit rpc) JSON-RPC ueber WebSocket aus denselben Dateien.
type fakeTrueNAS struct {
	t      *testing.T
	rpc    bool
	key    string
	mu     sync.Mutex
	calls  map[string]int
	fail   map[string]int // Methode -> HTTP-Status bzw. (RPC) Fehler
	auths  []string       // Authorization-Kopfzeilen (REST) bzw. Login-Keys (RPC)
	logins int
	noOld  bool // ohne auth.login_with_api_key (TrueNAS 27)
}

func newFakeTrueNAS(t *testing.T, rpc bool) *fakeTrueNAS {
	return &fakeTrueNAS{t: t, rpc: rpc, key: testSecret, calls: map[string]int{}, fail: map[string]int{}}
}

func (f *fakeTrueNAS) answer(method string) (json.RawMessage, int) {
	f.mu.Lock()
	f.calls[method]++
	st := f.fail[method]
	f.mu.Unlock()
	if st != 0 {
		return nil, st
	}
	name, ok := tnFiles[method]
	if !ok {
		return nil, 404
	}
	b, err := os.ReadFile(filepath.Join("testdata", "truenas", name+".json"))
	if err != nil {
		f.t.Fatal(err)
	}
	return b, 200
}

func (f *fakeTrueNAS) count(m string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[m]
}

func (f *fakeTrueNAS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/current" {
		if !f.rpc {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f.serveRPC(w, r)
		return
	}
	f.mu.Lock()
	f.auths = append(f.auths, r.Header.Get("Authorization"))
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.key {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Invalid API key"}`))
		return
	}
	m, ok := tnPaths[r.Method+" "+strings.TrimPrefix(r.URL.Path, "/api/v2.0")]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	b, st := f.answer(m)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(st)
	if st == 200 {
		_, _ = w.Write(b)
	} else {
		_, _ = w.Write([]byte(`{"message":"[EFAULT] kaputt"}`))
	}
}

func (f *fakeTrueNAS) serveRPC(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	ctx := r.Context()
	authed := false
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		var req struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if json.Unmarshal(data, &req) != nil {
			return
		}
		send := func(v map[string]any) {
			v["jsonrpc"], v["id"] = "2.0", req.ID
			b, _ := json.Marshal(v)
			_ = c.Write(ctx, websocket.MessageText, b)
		}
		// Ereignis vor jeder Antwort (muss ueberlesen werden)
		_ = c.Write(ctx, websocket.MessageText, []byte(`{"jsonrpc":"2.0","method":"collection_update","params":{"msg":"changed","collection":"alert.list"}}`))
		if req.Method == "auth.login_ex" {
			f.mu.Lock()
			f.logins++
			f.mu.Unlock()
			p, _ := req.Params[0].(map[string]any)
			authed = p["mechanism"] == "API_KEY_PLAIN" && p["username"] == "monitor" && p["api_key"] == f.key
			rt := "AUTH_ERR"
			if authed {
				rt = "SUCCESS"
			}
			send(map[string]any{"result": map[string]any{"response_type": rt}})
			continue
		}
		if req.Method == "auth.login_with_api_key" && f.noOld {
			send(map[string]any{"error": map[string]any{"code": -32601, "message": "Method not found"}})
			continue
		}
		if req.Method == "auth.login_with_api_key" {
			f.mu.Lock()
			f.logins++
			if len(req.Params) == 1 {
				s, _ := req.Params[0].(string)
				f.auths = append(f.auths, s)
			}
			f.mu.Unlock()
			authed = len(req.Params) == 1 && req.Params[0] == f.key
			send(map[string]any{"result": authed})
			continue
		}
		if !authed {
			send(map[string]any{"error": map[string]any{"code": -32001, "message": "Method call error", "data": map[string]any{"errname": "ENOTAUTHENTICATED", "reason": "Not authenticated"}}})
			continue
		}
		b, st := f.answer(req.Method)
		switch st {
		case 200:
			send(map[string]any{"result": json.RawMessage(b)})
		case 404:
			send(map[string]any{"error": map[string]any{"code": -32601, "message": "Method not found"}})
		case 403:
			send(map[string]any{"error": map[string]any{"code": -32001, "message": "Method call error", "data": map[string]any{"errname": "EACCES", "reason": "Not authorized"}}})
		default:
			send(map[string]any{"error": map[string]any{"code": -32001, "message": "Method call error", "data": map[string]any{"errname": "EFAULT", "reason": "kaputt"}}})
		}
	}
}

func tnNow() time.Time { return time.Unix(1731150000, 0) }

func checkTrueNAS(t *testing.T, svcs []model.Service) {
	t.Helper()
	load := svcByKey(t, svcs, "load")
	if m := mustMetric(t, load, "per_core"); m.Value != 0.08 || m.Rule != model.RuleLoad {
		t.Errorf("load = %+v", m)
	}
	if !strings.Contains(load.Text, "16 Kerne · läuft seit 12 Tage") {
		t.Errorf("load Text = %q", load.Text)
	}
	tank := svcByKey(t, svcs, "zfs:tank")
	if m := mustMetric(t, tank, "used"); m.Value != 70 || m.Rule != model.RuleStore {
		t.Errorf("tank used = %+v", m)
	}
	if m := mustMetric(t, tank, "scrub_age"); m.Value != 6 || m.Unit != "d" {
		t.Errorf("tank scrub_age = %+v", m)
	}
	if !hasFact(tank, "zfs_degraded") || !strings.Contains(tank.Facts[0].Text, "DEGRADED One or more devices") ||
		!strings.Contains(tank.Facts[0].Text, "Gerätefehler READ 2 WRITE 0 CKSUM 14") {
		t.Errorf("tank = %+v", tank)
	}
	fast := svcByKey(t, svcs, "zfs:fast")
	if len(fast.Facts) != 0 || !strings.Contains(fast.Text, "Scrub läuft (42 %)") {
		t.Errorf("fast = %+v", fast)
	}
	if b := svcByKey(t, svcs, "zfs:boot-pool"); len(b.Facts) != 0 || !strings.HasPrefix(b.Text, "ONLINE · ") {
		t.Errorf("boot-pool = %+v", b)
	}
	sda := svcByKey(t, svcs, "disk:WD-WX12D80ABCDE")
	if m := mustMetric(t, sda, "temp"); m.Value != 36 || m.Rule != model.RuleDiskTemp {
		t.Errorf("sda temp = %+v", m)
	}
	if len(sda.Facts) != 0 || !strings.Contains(sda.Text, "SMART-Test ok") || sda.Name != "sda (WDC WD120EFBX-68B0EN0)" {
		t.Errorf("sda = %+v", sda)
	}
	sdb := svcByKey(t, svcs, "disk:WD-WX12D80FGHIJ")
	if !hasFact(sdb, "smart_failed") || !hasFact(sdb, "disk_errors") || mustMetric(t, sdb, "cksum_err").Value != 14 {
		t.Errorf("sdb = %+v", sdb)
	}
	if sdc := svcByKey(t, svcs, "disk:2246E8C1A2B3"); hasSvc(svcs, "disk:sdc") || len(sdc.Metrics) != 3 {
		t.Errorf("sdc (ohne Temperatur) = %+v", sdc)
	}
	if m := mustMetric(t, svcByKey(t, svcs, "disk:S5GXNF0R123456"), "temp"); m.Rule != model.RuleNVMeTemp || m.Value != 48 {
		t.Errorf("nvme0n1 temp = %+v", m)
	}
	if m := mustMetric(t, svcByKey(t, svcs, "disk:eui.2222"), "temp"); m.Value != 43 {
		t.Errorf("nvme2n1 (ohne Seriennummer, Temperatur als Objekt) = %+v", m)
	}
	al := svcByKey(t, svcs, "alerts")
	if mustMetric(t, al, "crit").Value != 2 || mustMetric(t, al, "warn").Value != 1 || !hasFact(al, "device_crit") || !hasFact(al, "device_warn") {
		t.Errorf("alerts = %+v", al)
	}
	if strings.Contains(al.Text, "<") || strings.Contains(al.Text, "paused") || strings.Contains(al.Text, "update available") {
		t.Errorf("alerts Text = %q", al.Text)
	}
	rep := svcByKey(t, svcs, "job:replication:1")
	if !hasFact(rep, "job_failed") || !strings.Contains(rep.Text, "No incremental base") || rep.Name != "Replikation tank/data - backup/tank" {
		t.Errorf("replication 1 = %+v", rep)
	}
	if r2 := svcByKey(t, svcs, "job:replication:2"); r2.Default || len(r2.Facts) != 0 || !strings.HasPrefix(r2.Text, "abgeschaltet") {
		t.Errorf("replication 2 = %+v", r2)
	}
	if sn := svcByKey(t, svcs, "job:snapshot:1"); len(sn.Facts) != 0 || mustMetric(t, sn, "age").Value != 1 {
		t.Errorf("snapshot = %+v", sn)
	}
	if cs := svcByKey(t, svcs, "job:cloudsync:3"); !hasFact(cs, "job_failed") || !strings.Contains(cs.Facts[0].Text, "403 Forbidden") {
		t.Errorf("cloudsync = %+v", cs)
	}
	if p := svcByKey(t, svcs, "app:plex"); mustMetric(t, p, "running").Value != 1 || !strings.Contains(p.Text, "Update verfügbar") || p.Kind != "ctr" {
		t.Errorf("plex = %+v", p)
	}
	if n := svcByKey(t, svcs, "app:nextcloud"); !hasFact(n, "guest_fault") {
		t.Errorf("nextcloud = %+v", n)
	}
	if v := svcByKey(t, svcs, "vm:1"); !hasFact(v, "guest_down") || v.Name != "homeassistant (VM 1)" {
		t.Errorf("vm 1 = %+v", v)
	}
	if v := svcByKey(t, svcs, "vm:2"); len(v.Facts) != 0 || mustMetric(t, v, "running").Value != 1 {
		t.Errorf("vm 2 = %+v", v)
	}
}

func TestTrueNASREST(t *testing.T) {
	f := newFakeTrueNAS(t, false)
	addr, pin := tlsServer(t, f)
	tn, err := NewTrueNAS(TrueNASConfig{Address: addr, APIKey: testSecret, Pin: pin})
	if err != nil {
		t.Fatal(err)
	}
	tn.now = tnNow
	svcs, err := tn.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if tn.api != TrueNASREST {
		t.Errorf("Weg = %q", tn.api)
	}
	checkTrueNAS(t, svcs)
	// zweite Runde: Temperaturen/SMART nicht erneut, Weg nicht neu erkannt
	if _, err := tn.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.count("disk.temperatures") != 1 || f.count("smart.test.results") != 1 || f.count("pool.query") != 2 {
		t.Errorf("Abrufe: temps %d smart %d pool %d", f.count("disk.temperatures"), f.count("smart.test.results"), f.count("pool.query"))
	}
	r := deRes(tn.Test(context.Background()))
	if !r.OK || r.Version != "TrueNAS-SCALE-24.10.2" || r.Node != "nas01" || r.Summary != "2 Pools, 6 Platten, 3 offene Alarme (REST v2.0)" {
		t.Errorf("Test = %+v", r)
	}
}

func TestTrueNASRPC(t *testing.T) {
	f := newFakeTrueNAS(t, true)
	addr, pin := tlsServer(t, f)
	tn, err := NewTrueNAS(TrueNASConfig{Address: addr, APIKey: testSecret, Pin: pin})
	if err != nil {
		t.Fatal(err)
	}
	tn.now = tnNow
	svcs, err := tn.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if tn.api != TrueNASRPC {
		t.Errorf("Weg = %q", tn.api)
	}
	checkTrueNAS(t, svcs)
	f.mu.Lock()
	auths := strings.Join(f.auths, ",")
	f.mu.Unlock()
	if auths != testSecret {
		t.Errorf("Anmeldungen = %q", auths)
	}
	r := deRes(tn.Test(context.Background()))
	if !r.OK || !strings.HasSuffix(r.Summary, "(JSON-RPC)") || r.Warning != "" {
		t.Errorf("Test = %+v", r)
	}
	// Teilfehler: alert.list kaputt, vm.query ohne Rechte
	f.mu.Lock()
	f.fail["alert.list"], f.fail["vm.query"] = 500, 403
	f.mu.Unlock()
	svcs, err = tn.Collect(context.Background())
	pe := partialOf(t, err)
	if !hasPrefix(pe, "alerts") || !hasPrefix(pe, "vm:") || hasSvc(svcs, "alerts") || !hasSvc(svcs, "zfs:tank") {
		t.Errorf("Teilfehler = %+v", pe)
	}
	if !strings.Contains(deErr(pe), "Read-Only Administrator") {
		t.Errorf("Rechte-Hinweis fehlt: %v", pe)
	}
	// falscher Key: Fehler ohne Geheimnis
	f.mu.Lock()
	f.key = "anderer-key-123456"
	f.mu.Unlock()
	_, err = tn.Collect(context.Background())
	if err == nil || strings.Contains(deErr(err), testSecret) || !strings.Contains(deErr(err), "abgelehnt") {
		t.Errorf("falscher Key: %v", err)
	}
}

func TestTrueNASTestConfirm(t *testing.T) {
	f := newFakeTrueNAS(t, true)
	addr, pin := tlsServer(t, f)
	tn, _ := NewTrueNAS(TrueNASConfig{Address: addr, APIKey: testSecret})
	r := deRes(tn.Test(context.Background()))
	if r.OK || !r.NeedConfirm || r.Fingerprint != pin {
		t.Errorf("Test ohne Pin = %+v", r)
	}
	if f.logins != 0 || len(f.auths) != 0 {
		t.Errorf("Key vor der Bestaetigung gesendet")
	}
	if _, err := tn.Collect(context.Background()); err == nil {
		t.Error("Collect ohne Pin ging durch")
	}
	// nur REST verlangt, aber auch REST fehlt
	tn, _ = NewTrueNAS(TrueNASConfig{Address: addr, APIKey: testSecret, Pin: pin, API: TrueNASRPC})
	if _, err := tn.Collect(context.Background()); err != nil {
		t.Errorf("JSON-RPC fest: %v", err)
	}
	f2 := newFakeTrueNAS(t, false)
	addr2, pin2 := tlsServer(t, f2)
	tn, _ = NewTrueNAS(TrueNASConfig{Address: addr2, APIKey: testSecret, Pin: pin2, API: TrueNASRPC})
	if _, err := tn.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "REST wählen") {
		t.Errorf("JSON-RPC fest ohne RPC: %v", err)
	}
}

func TestTrueNASConfig(t *testing.T) {
	for _, c := range []TrueNASConfig{
		{Address: "http://nas", APIKey: "x"},
		{Address: "https://nas"},
		{Address: "https://nas", APIKey: "a\nb"},
		{Address: "https://nas", APIKey: "x", API: "soap"},
		{Address: "https://nas", APIKey: "x", Pin: "123"},
	} {
		if _, err := NewTrueNAS(c); err == nil {
			t.Errorf("%+v angenommen", c)
		}
	}
	if v := tnMajor("TrueNAS-SCALE-24.10.2"); v != 24 {
		t.Errorf("tnMajor = %d", v)
	}
	if v := tnMajor("25.04.1"); v != 25 {
		t.Errorf("tnMajor = %d", v)
	}
	if v := tnMajor("TrueNAS-13.0-U6.2"); v != 13 {
		t.Errorf("tnMajor CORE = %d", v)
	}
}

func TestTrueNASPoolCore(t *testing.T) {
	// CORE ohne size/allocated: Belegung aus dem Wurzel-Dataset (REST /pool/dataset?id=)
	f := newTreeAPI(t, "truenas")
	f.set("GET /api/v2.0/system/info", 200, `{"version":"TrueNAS-13.0-U6.2","hostname":"core","cores":4,"loadavg":[0.1,0.2,0.3],"uptime_seconds":100}`)
	f.set("GET /api/v2.0/pool", 200, `[{"name":"tank","status":"ONLINE","healthy":true,"topology":{"data":[]},"scan":{"function":"SCRUB","state":"FINISHED","end_time":{"$date":1730631600000},"errors":3}}]`)
	f.set("GET /api/v2.0/pool/dataset?id=tank", 200, `[{"id":"tank","used":{"parsed":3000,"rawvalue":"3000"},"available":{"parsed":1000,"rawvalue":"1000"}}]`)
	f.set("GET /api/v2.0/boot/get_state", 200, `{"name":"freenas-boot","status":"ONLINE","topology":{"data":[]}}`)
	f.set("GET /api/v2.0/disk", 200, `[]`)
	f.set("POST /api/v2.0/disk/temperatures", 200, `{}`)
	f.set("GET /api/v2.0/alert/list", 200, `[]`)
	f.set("GET /api/v2.0/pool/dataset", 200, `[]`)
	addr, pin := tlsServer(t, f)
	tn, _ := NewTrueNAS(TrueNASConfig{Address: addr, APIKey: testSecret, Pin: pin, API: TrueNASREST})
	tn.now = tnNow
	svcs, err := tn.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	tank := svcByKey(t, svcs, "zfs:tank")
	if m := mustMetric(t, tank, "used"); m.Value != 75 || m.Max != 4000 {
		t.Errorf("tank used = %+v", m)
	}
	if !hasFact(tank, "zfs_degraded") || !strings.Contains(tank.Facts[0].Text, "Scrub: 3 Fehler") {
		t.Errorf("tank (Scrub-Fehler) = %+v", tank)
	}
	if !hasSvc(svcs, "zfs:freenas-boot") || !hasSvc(svcs, "alerts") {
		t.Errorf("Dienste = %+v", svcs)
	}
	if svcByKey(t, svcs, "alerts").Text != "keine offenen Alarme" {
		t.Errorf("alerts = %+v", svcByKey(t, svcs, "alerts"))
	}
}

func TestTrueNASLoginEx(t *testing.T) {
	f := newFakeTrueNAS(t, true)
	f.noOld = true
	addr, pin := tlsServer(t, f)
	tn, _ := NewTrueNAS(TrueNASConfig{Address: addr, APIKey: testSecret, Pin: pin})
	if _, err := tn.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "Benutzer des API-Keys eintragen") {
		t.Errorf("ohne Benutzer (TrueNAS 27): %v", err)
	}
	tn, _ = NewTrueNAS(TrueNASConfig{Address: addr, APIKey: testSecret, User: "monitor", Pin: pin})
	if _, err := tn.Collect(context.Background()); err != nil {
		t.Errorf("auth.login_ex: %v", err)
	}
	tn, _ = NewTrueNAS(TrueNASConfig{Address: addr, APIKey: testSecret, User: "anderer", Pin: pin})
	if _, err := tn.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "AUTH_ERR") || strings.Contains(deErr(err), testSecret) {
		t.Errorf("auth.login_ex falscher Benutzer: %v", err)
	}
}
