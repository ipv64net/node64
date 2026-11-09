package apis

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// fakeUnraid beantwortet GraphQL-Abfragen nach ihrem Inhalt aus testdata/unraid.
type fakeUnraid struct {
	t        *testing.T
	mu       sync.Mutex
	keys     []string
	queries  []string
	oldAPI   bool              // ohne parityCheckStatus und ohne versions.core (aeltere API)
	failArea map[string]string // Bereich -> GraphQL-Fehlercode
}

func (f *fakeUnraid) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path != "/graphql" || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	b, _ := io.ReadAll(r.Body)
	var req struct {
		Query string `json:"query"`
	}
	_ = json.Unmarshal(b, &req)
	f.mu.Lock()
	f.keys = append(f.keys, r.Header.Get("x-api-key"))
	f.queries = append(f.queries, req.Query)
	old, fail := f.oldAPI, f.failArea
	f.mu.Unlock()
	if r.Header.Get("x-api-key") != testSecret {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"message":"Unauthorized","extensions":{"code":"UNAUTHENTICATED"}}],"data":null}`))
		return
	}
	invalid := func(field, typ string) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":[{"message":"Cannot query field \"` + field + `\" on type \"` + typ + `\".","extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}`))
	}
	q := req.Query
	area := ""
	for _, a := range []string{"info {", "metrics {", "array {", "vars {", "docker {", "vms {", "notifications {"} {
		if strings.Contains(q, a) {
			area = strings.TrimSuffix(a, " {")
			break
		}
	}
	if code, ok := fail[area]; ok {
		_, _ = w.Write([]byte(`{"errors":[{"message":"kaputt","extensions":{"code":"` + code + `"}}],"data":null}`))
		return
	}
	switch area {
	case "info":
		if old && strings.Contains(q, "core {") {
			invalid("core", "InfoVersions")
			return
		}
		if old {
			_, _ = w.Write([]byte(`{"data":{"info":{"os":{"hostname":"Tower","uptime":"2024-10-28T08:15:54.000Z"},"cpu":{"cores":4,"threads":8},"versions":{"unraid":"6.12.13"}}}}`))
			return
		}
		_, _ = w.Write([]byte(fixture(f.t, "unraid/info.json")))
	case "metrics":
		if old {
			invalid("metrics", "Query")
			return
		}
		_, _ = w.Write([]byte(fixture(f.t, "unraid/metrics.json")))
	case "array":
		if old && strings.Contains(q, "parityCheckStatus") {
			invalid("parityCheckStatus", "UnraidArray")
			return
		}
		body := fixture(f.t, "unraid/array.json")
		if old {
			var m map[string]map[string]map[string]any
			_ = json.Unmarshal([]byte(body), &m)
			delete(m["data"]["array"], "parityCheckStatus")
			nb, _ := json.Marshal(m)
			body = string(nb)
		}
		_, _ = w.Write([]byte(body))
	case "vars":
		_, _ = w.Write([]byte(`{"data":{"vars":{"mdNumInvalid":0,"mdNumDisabled":1,"mdResync":0,"sbSynced":1730612472,"sbSyncErrs":0}}}`))
	case "docker":
		_, _ = w.Write([]byte(fixture(f.t, "unraid/docker.json")))
	case "vms":
		if old && strings.Contains(q, "domains") {
			invalid("domains", "Vms")
			return
		}
		body := fixture(f.t, "unraid/vms.json")
		if old {
			body = strings.Replace(body, `"domains"`, `"domain"`, 1)
		}
		_, _ = w.Write([]byte(body))
	case "notifications":
		if old && strings.Contains(q, "list(") {
			invalid("list", "Notifications")
			return
		}
		_, _ = w.Write([]byte(fixture(f.t, "unraid/notifications.json")))
	default:
		invalid("x", "Query")
	}
}

func urNow() time.Time { return time.Date(2024, 11, 9, 8, 15, 54, 0, time.UTC) }

func TestUnraidCollect(t *testing.T) {
	f := &fakeUnraid{t: t}
	srv := httptest.NewServer(f)
	defer srv.Close()
	u, err := NewUnraid(UnraidConfig{Address: srv.URL, APIKey: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	u.now = urNow
	svcs, err := u.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	cpu := svcByKey(t, svcs, "cpu")
	if m := mustMetric(t, cpu, "util"); m.Value != 12.5 || m.Rule != model.RuleCPU {
		t.Errorf("cpu = %+v", m)
	}
	if cpu.Text != "12 Threads · läuft seit 12 Tage" {
		t.Errorf("cpu Text = %q", cpu.Text)
	}
	if m := mustMetric(t, svcByKey(t, svcs, "mem"), "used"); m.Value != 25 {
		t.Errorf("mem = %+v", m)
	}
	if hasSvc(svcs, "swap") {
		t.Error("swap ohne Swap")
	}
	arr := svcByKey(t, svcs, "raid:array")
	if m := mustMetric(t, arr, "used"); !near(m.Value, 58.33) || m.Rule != model.RuleStore {
		t.Errorf("array used = %+v", m)
	}
	if mustMetric(t, arr, "active").Value != 3 || mustMetric(t, arr, "devices").Value != 4 {
		t.Errorf("array Platten = %+v", arr.Metrics)
	}
	if !hasFact(arr, "raid_degraded") || !strings.Contains(arr.Text, "disk2 deaktiviert") {
		t.Errorf("array = %+v", arr)
	}
	if !hasFact(arr, "parity_errors") || mustMetric(t, arr, "parity_errors").Value != 3 || !near(mustMetric(t, arr, "parity_age").Value, 6.11) {
		t.Errorf("array Paritaet = %+v", arr)
	}
	cache := svcByKey(t, svcs, "raid:cache")
	if !hasFact(cache, "raid_degraded") || mustMetric(t, cache, "used").Value != 50 || !strings.Contains(cache.Text, "cache2 fehlt") {
		t.Errorf("cache = %+v", cache)
	}
	if fp := svcByKey(t, svcs, "zfs:fastpool"); len(fp.Facts) != 0 || !near(mustMetric(t, fp, "used").Value, 9.77) {
		t.Errorf("fastpool = %+v", fp)
	}
	d1 := svcByKey(t, svcs, "disk:VAKABCD1")
	if m := mustMetric(t, d1, "temp"); m.Value != 36 || m.Rule != model.RuleDiskTemp {
		t.Errorf("disk1 temp = %+v", m)
	}
	if m := mustMetric(t, d1, "used"); m.Value != 80 || m.Rule != model.RuleFS {
		t.Errorf("disk1 used = %+v", m)
	}
	if d1.Name != "disk1 (sdc)" || len(d1.Facts) != 0 {
		t.Errorf("disk1 = %+v", d1)
	}
	d2 := svcByKey(t, svcs, "disk:WSD0XYZ2")
	if !hasFact(d2, "disk_errors") || mustMetric(t, d2, "errors").Value != 128 {
		t.Errorf("disk2 = %+v", d2)
	}
	if d3 := svcByKey(t, svcs, "disk:WSD0XYZ3"); !strings.Contains(d3.Text, "schläft") {
		t.Errorf("disk3 = %+v", d3)
	} else if _, ok := metric(d3, "temp"); ok {
		t.Errorf("disk3 schlafend mit Temperatur")
	}
	if p := svcByKey(t, svcs, "disk:D7HABCDE"); hasMetricName(p, "used") {
		t.Errorf("parity mit Belegung: %+v", p)
	}
	if c := svcByKey(t, svcs, "disk:S4EWNX0R111111"); mustMetric(t, c, "temp").Rule != model.RuleNVMeTemp || hasMetricName(c, "used") {
		t.Errorf("cache-Platte = %+v", c)
	}
	if c2 := svcByKey(t, svcs, "disk:S4EWNX0R222222"); !hasFact(c2, "disk_errors") {
		t.Errorf("cache2 = %+v", c2)
	}
	if hasSvc(svcs, "disk:parity2") {
		t.Error("leerer Paritaetsplatz als Platte")
	}
	if p := svcByKey(t, svcs, "ctr:plex"); mustMetric(t, p, "running").Value != 1 || len(p.Facts) != 0 {
		t.Errorf("plex = %+v", p)
	}
	if n := svcByKey(t, svcs, "ctr:nextcloud"); !hasFact(n, "guest_down") {
		t.Errorf("nextcloud = %+v", n)
	}
	if x := svcByKey(t, svcs, "ctr:test"); len(x.Facts) != 0 || !strings.Contains(x.Text, "darf aus sein") {
		t.Errorf("test = %+v", x)
	}
	if v := svcByKey(t, svcs, "vm:HomeAssistant"); !hasFact(v, "guest_fault") {
		t.Errorf("vm HomeAssistant = %+v", v)
	}
	if v := svcByKey(t, svcs, "vm:Windows 11"); mustMetric(t, v, "running").Value != 1 {
		t.Errorf("vm Windows = %+v", v)
	}
	al := svcByKey(t, svcs, "alerts")
	if !hasFact(al, "device_warn") || mustMetric(t, al, "unread_alert").Value != 1 || !strings.Contains(al.Text, "cache pool full") ||
		strings.Contains(al.Text, "<b>") {
		t.Errorf("alerts = %+v", al)
	}
	f.mu.Lock()
	for _, k := range f.keys {
		if k != testSecret {
			t.Errorf("Key fehlt: %q", k)
		}
	}
	f.mu.Unlock()
}

func hasMetricName(s model.Service, name string) bool {
	_, ok := metric(s, name)
	return ok
}

func TestUnraidOldAPI(t *testing.T) {
	f := &fakeUnraid{t: t, oldAPI: true}
	srv := httptest.NewServer(f)
	defer srv.Close()
	u, _ := NewUnraid(UnraidConfig{Address: srv.URL, APIKey: testSecret})
	u.now = urNow
	svcs, err := u.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if hasSvc(svcs, "mem") {
		t.Error("mem ohne metrics")
	}
	arr := svcByKey(t, svcs, "raid:array")
	if !near(mustMetric(t, arr, "parity_age").Value, 6.11) || hasFact(arr, "parity_errors") {
		t.Errorf("array (vars) = %+v", arr)
	}
	if !hasSvc(svcs, "vm:Debian") || !hasSvc(svcs, "alerts") {
		t.Errorf("Dienste = %+v", svcs)
	}
	r := u.Test(context.Background())
	if !r.OK || r.Version != "6.12.13" || r.Node != "Tower" || r.Summary != "Array STARTED, 7 Platten" || !strings.Contains(r.Warning, "unverschlüsselt") {
		t.Errorf("Test = %+v", r)
	}
}

func TestUnraidErrors(t *testing.T) {
	f := &fakeUnraid{t: t, failArea: map[string]string{"docker": "INTERNAL_SERVER_ERROR", "vms": "FORBIDDEN"}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	u, _ := NewUnraid(UnraidConfig{Address: srv.URL, APIKey: testSecret})
	u.now = urNow
	svcs, err := u.Collect(context.Background())
	pe := partialOf(t, err)
	if !hasPrefix(pe, "ctr:") || !hasPrefix(pe, "vm:") || !strings.Contains(pe.Error(), "Rolle Viewer") || !hasSvc(svcs, "raid:array") {
		t.Errorf("Teilfehler = %v", pe)
	}
	u2, _ := NewUnraid(UnraidConfig{Address: srv.URL, APIKey: "falsch-" + testSecret})
	if _, err := u2.Collect(context.Background()); err == nil || strings.Contains(err.Error(), testSecret) || !strings.Contains(err.Error(), "API-Key prüfen") {
		t.Errorf("falscher Key: %v", err)
	}
	// kein /graphql (alte Version ohne API)
	srv404 := httptest.NewServer(http.NotFoundHandler())
	defer srv404.Close()
	u3, _ := NewUnraid(UnraidConfig{Address: srv404.URL, APIKey: testSecret})
	if r := u3.Test(context.Background()); r.OK || !strings.Contains(r.Error, "Unraid Connect") {
		t.Errorf("ohne API = %+v", r)
	}
	for _, c := range []UnraidConfig{{Address: "tower"}, {Address: "ftp://tower", APIKey: "x"}, {Address: "http://tower", APIKey: "x", Pin: strings.Repeat("a", 64)}} {
		if _, err := NewUnraid(c); err == nil {
			t.Errorf("%+v angenommen", c)
		}
	}
}

func TestUnraidHTTPS(t *testing.T) {
	f := &fakeUnraid{t: t}
	addr, pin := tlsServer(t, f)
	u, _ := NewUnraid(UnraidConfig{Address: addr, APIKey: testSecret})
	if r := u.Test(context.Background()); r.OK || !r.NeedConfirm || r.Fingerprint != pin {
		t.Errorf("ohne Pin = %+v", r)
	}
	f.mu.Lock()
	n := len(f.keys)
	f.mu.Unlock()
	if n != 0 {
		t.Error("Key vor der Bestaetigung gesendet")
	}
	u, _ = NewUnraid(UnraidConfig{Address: addr, APIKey: testSecret, Pin: pin})
	if r := u.Test(context.Background()); !r.OK || r.Version != "7.2.0 (API 4.25.2)" || r.Warning != "" {
		t.Errorf("mit Pin = %+v", r)
	}
}

func TestPoolNameAndSerial(t *testing.T) {
	for in, want := range map[string]string{"cache": "cache", "cache2": "cache", "cache12": "cache", "fast": "fast", "123": "123"} {
		if got := poolName(in); got != want {
			t.Errorf("poolName(%q) = %q", in, got)
		}
	}
	for in, want := range map[string]string{"srv:WDC_WD80EFAX-68KNBN0_VAKABCD1": "VAKABCD1", "srv:": "", "noid": "", "x_": ""} {
		if got := (urDisk{ID: in}).serial(); got != want {
			t.Errorf("serial(%q) = %q", in, got)
		}
	}
}
