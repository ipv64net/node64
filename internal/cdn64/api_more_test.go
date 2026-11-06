package cdn64

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
)

func (e *env) call(t *testing.T, method, path, body string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// Docker-Abgleich, Freigeben und lokales DNS ueber die API wie auf den Seiten.
func TestAPIDockerReleaseLocalDNS(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)

	// Docker: fehlende Felder bleiben, gleiche Pruefungen wie die Seite
	if code, out := e.call(t, "PUT", "/api/cdn64/docker", `{"docker_host":"ssh://user@nas"}`); code != 422 || out["field"] != "docker_host" {
		t.Fatalf("ssh host: %d %v", code, out)
	}
	if code, out := e.call(t, "PUT", "/api/cdn64/docker", `{"enabled":true,"traefik":false}`); code != 200 || out["settings"].(map[string]any)["traefik"] != false || out["enabled"] != true {
		t.Fatalf("enable: %d %v", code, out)
	}
	if e.m.core.SettingOr(ctx, setDocker, "") != "on" || e.m.core.SettingOr(ctx, setDockerTraefik, "") != "off" {
		t.Fatal("settings not stored")
	}
	if code, out := e.call(t, "PUT", "/api/cdn64/docker", `{"certificate":"auto"}`); code != 422 || out["field"] != "docker_cert" {
		t.Fatalf("cert without tos: %d %v", code, out)
	}
	if code, out := e.call(t, "PUT", "/api/cdn64/docker", `{"certificate":"auto","accept_tos":true}`); code != 200 || out["settings"].(map[string]any)["certificate"] != "auto" {
		t.Fatalf("cert with tos: %d %v", code, out)
	}
	if !e.m.certs.Account(ctx).TOSAccepted || e.m.core.SettingOr(ctx, setDocker, "") != "on" {
		t.Fatal("tos not accepted or switch lost")
	}

	// Freigeben: Sperre weg und Adresse in der Freigabeliste
	a := netip.MustParseAddr("198.51.100.9")
	e.m.lim.mu.Lock()
	e.m.lim.bans[limKey(a)] = time.Now().Add(time.Hour)
	e.m.lim.nbans.Add(1)
	e.m.lim.mu.Unlock()
	if code, _ := e.call(t, "POST", "/api/cdn64/release", `{"ip":"198.51.100.9","from":"x"}`); code != 422 {
		t.Fatalf("bad from: %d", code)
	}
	if code, out := e.call(t, "POST", "/api/cdn64/release", `{"ip":"198.51.100.9"}`); code != 200 || !slices.Contains(toStrings(out["allow"]), "198.51.100.9") {
		t.Fatalf("release: %d %v", code, out)
	}
	if code, _ := e.call(t, "POST", "/api/cdn64/release", `{"ip":"198.51.100.9"}`); code != 404 {
		t.Fatalf("second release: %d", code)
	}

	// lokales DNS
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"nas.example.de"}, "192.168.1.20", 5000
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	p := "/api/cdn64/hosts/" + strconv.FormatInt(h.ID, 10) + "/localdns"
	if code, _ := e.call(t, "POST", p, `{"ipv4":"192.168.1.5"}`); code != 409 {
		t.Fatalf("DNS64 off: %d", code)
	}
	f := &fakeLocal{}
	e.m.SetLocalDNS(func() LocalDNS { return f })
	if code, out := e.call(t, "POST", p, `{"ipv4":"127.0.0.1"}`); code != 422 || out["field"] != "ip" {
		t.Fatalf("bad ip: %d %v", code, out)
	}
	if code, out := e.call(t, "POST", p, `{"ipv4":"192.168.1.5"}`); code != 200 || out["added"] != 1.0 || strings.Join(f.added, "|") != "nas.example.de A 192.168.1.5" {
		t.Fatalf("add: %d %v %v", code, out, f.added)
	}
	if code, _ := e.call(t, "POST", "/api/cdn64/hosts/999/localdns", `{}`); code != 404 {
		t.Fatalf("unknown host: %d", code)
	}
}

func toStrings(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// CDN64-Schutz und Server je Name ueber die API.
func TestAPIProtectionServers(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	f := &fakeOnline{ready: true, tunnels: map[string]bool{}, hosts: map[int64]string{}, modes: map[int64]int{}, hostSrv: map[int64]*ipv64api.CDN64Servers{},
		edges: []ipv64api.CDN64Edge{{Name: "srv07", Host: "127.0.0.1", Port: 1, IPs: []string{"127.0.0.1"}}}}
	e.m.SetOnlineAPI(f)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"app.test"}, "93.184.216.34", 8080
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.onlineEnable(ctx, h, 2); err != nil {
		t.Fatal(err)
	}
	list, _ := e.m.onlineNames(ctx)
	rid := list[0].RemoteID
	f.mu.Lock()
	f.waf, f.ja4 = map[int64]bool{rid: true}, map[int64]string{rid: "block"}
	f.prot = &ipv64api.CDN64Protection{JA4Global: "block", Hosts: []ipv64api.CDN64ProtectionHost{{ID: rid, FQDN: "app.test", Mode: 2,
		CDN64ProtectionCounts: ipv64api.CDN64ProtectionCounts{BlockedWAF: 3}}}}
	f.hostSrv[rid] = &ipv64api.CDN64Servers{Count: 1, Choice: 1, Max: 4, All: true, Total: 4, Selectable: true, Assigned: []string{"srv07"}, Sessions: 3, SessionsMax: 4}
	f.mu.Unlock()
	ov, err := f.Overview(ctx)
	e.m.onlineSetRemote(ov, err)
	id := strconv.FormatInt(h.ID, 10)

	code, out := e.call(t, "GET", "/api/cdn64/protection?days=1", "")
	hosts, _ := out["hosts"].([]any)
	if code != 200 || out["days"] != 1.0 || len(hosts) != 1 {
		t.Fatalf("protection: %d %v", code, out)
	}
	if x := hosts[0].(map[string]any); x["waf"] != true || x["ja4"] != "block" || x["host_id"] != float64(h.ID) || x["blocked"] != 3.0 {
		t.Fatalf("protection row: %v", x)
	}
	if code, _ := e.call(t, "PUT", "/api/cdn64/hosts/"+id+"/protection", `{"ja4":"nein"}`); code != 422 {
		t.Fatalf("bad ja4: %d", code)
	}
	if code, out := e.call(t, "PUT", "/api/cdn64/hosts/"+id+"/protection", `{"ja4":"count"}`); code != 200 || out["waf"] != true || out["ja4"] != "count" {
		t.Fatalf("set ja4 (waf stays): %d %v", code, out)
	}
	if f.ja4[rid] != "count" || !f.waf[rid] {
		t.Fatalf("not set at ipv64: %v %v", f.waf, f.ja4)
	}
	if code, _ := e.call(t, "PUT", "/api/cdn64/hosts/999/protection", `{"waf":false}`); code != 404 {
		t.Fatalf("unknown host: %d", code)
	}

	// Server je Name
	code, out = e.call(t, "GET", "/api/cdn64/hosts/"+id+"/servers", "")
	if code != 200 || out["sessions"] != 3.0 || len(toStrings(out["session_options"])) != 4 || len(out["options"].([]any)) != 5 {
		t.Fatalf("servers: %d %v", code, out)
	}
	if code, _ := e.call(t, "PUT", "/api/cdn64/hosts/"+id+"/servers", `{"sessions":2}`); code != 422 {
		t.Fatalf("without count: %d", code)
	}
	code, out = e.call(t, "PUT", "/api/cdn64/hosts/"+id+"/servers", `{"count":2}`)
	if code != 200 || out["count"] != 2.0 || out["sessions"] != 3.0 || !slices.Equal(f.setHost, []int64{rid}) {
		t.Fatalf("set servers (sessions stay): %d %v %v", code, out, f.setHost)
	}
	// eigener Tunnel: Portal mit Server je Name hat keine Auswahl je Tunnel
	if code, out := e.call(t, "GET", "/api/cdn64/online/servers", ""); code != 409 || out["code"] != "not_configured" {
		t.Fatalf("tunnel servers: %d %v", code, out)
	}
	f.mu.Lock()
	f.servers = &ipv64api.CDN64Servers{Count: 2, Max: 4, All: true, Total: 4, Selectable: true, Assigned: []string{"srv07", "srv08"}, Sessions: 1, SessionsMax: 4}
	f.mu.Unlock()
	ov, err = f.Overview(ctx)
	e.m.onlineSetRemote(ov, err)
	if code, out := e.call(t, "PUT", "/api/cdn64/online/servers", `{"count":3,"sessions":2}`); code != 200 || out["count"] != 3.0 || len(f.setCount) != 1 {
		t.Fatalf("tunnel set: %d %v %v", code, out, f.setCount)
	}
}

// Zertifikat beim Anlegen per API: eigene CA ueber ca_id, selbst signiert ohne Let's-Encrypt-Konto.
func TestAPICreateCertSelfCA(t *testing.T) {
	e := newEnv(t)
	e.enable(t)
	code, out := e.call(t, "POST", "/api/cdn64/hosts", `{"names":["self.test"],"scheme":"http","target_host":"192.0.2.1","target_port":80,"request_certificate":{"source":"self"}}`)
	if code != 201 || out["certificate_error"] != nil {
		t.Fatalf("self: %d %v", code, out)
	}
	code, out = e.call(t, "POST", "/api/cdn64/hosts", `{"names":["ca.test"],"scheme":"http","target_host":"192.0.2.1","target_port":80,"request_certificate":{"source":"ca","ca_id":999}}`)
	if code != 201 || out["certificate_error"] == nil {
		t.Fatalf("unknown ca: %d %v", code, out)
	}
}
