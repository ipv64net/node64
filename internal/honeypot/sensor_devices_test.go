package honeypot

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSensorDeviceLogins(t *testing.T) {
	// Geraete mit eigenem Profil antworten auf dessen Port, die anderen auf dem Webserver (nginx)
	p := sensorFreePort(t)
	ports := map[string]int{"": p}
	cfg := Config{Services: []Service{{SvcHTTP, p, ""}}, Personas: map[string]string{}}
	for _, pe := range []string{PersonaPVE, PersonaHA, PersonaNAS, PersonaGrafana} {
		ports[pe] = sensorFreePort(t)
		cfg.Services = append(cfg.Services, Service{Service: SvcHTTP, Port: ports[pe]})
		cfg.Personas[PersonaKey(SvcHTTP, ports[pe])] = pe
	}
	_, rec := sensorStart(t, cfg)
	cl := &http.Client{Timeout: 5 * time.Second}
	base := "http://" + sensorAddrOf(p)
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	jsn := map[string]string{"Content-Type": "application/json"}

	for _, c := range []struct {
		path, body string
		hdr        map[string]string
		code       int
		dev, user  string
		pass       string
		persona    string
	}{
		{"/api2/json/access/ticket", url.Values{"username": {"root@pam"}, "password": {"pve1"}}.Encode(), form, 401, "proxmox", "root@pam", "pve1", PersonaPVE},
		{"/auth/login_flow/abc", `{"username":"admin","password":"ha1","client_id":"x"}`, jsn, 200, "homeassistant", "admin", "ha1", PersonaHA},
		{"/api/login", `{"username":"ubnt","password":"ubnt"}`, jsn, 400, "unifi", "ubnt", "ubnt", ""},
		{"/webapi/auth.cgi", url.Values{"account": {"admin"}, "passwd": {"nas1"}}.Encode(), form, 200, "nas", "admin", "nas1", PersonaNAS},
		{"/webconsole/Controller", url.Values{"mode": {"151"}, "json": {`{"username":"admin","password":"fw1"}`}}.Encode(), form, 200, "firewall", "admin", "fw1", ""},
		{"/cgi-bin/luci", url.Values{"luci_username": {"root"}, "luci_password": {"owrt"}}.Encode(), form, 403, "openwrt", "root", "owrt", ""},
		{"/remote/logincheck", url.Values{"username": {"vpn"}, "credential": {"vpn1"}}.Encode(), form, 200, "sslvpn", "vpn", "vpn1", ""},
		{"/login", `{"user":"admin","password":"graf1"}`, jsn, 401, "grafana", "admin", "graf1", PersonaGrafana},
	} {
		code, _, _ := sensorGet(t, cl, "POST", "http://"+sensorAddrOf(ports[c.persona])+c.path, "curl/8", c.body, c.hdr)
		if code != c.code {
			t.Fatalf("%s: %d, want %d", c.path, code, c.code)
		}
		e := rec.wait(t, func(e Event) bool { return e.Path == c.path && e.Kind == KindHTTPBrute })
		if e.Username != c.user || e.Password != c.pass || !strings.Contains(e.Detail, "device="+c.dev) || e.Page != "" {
			t.Fatalf("%s: %+v", c.path, e)
		}
	}

	// FRITZ!Box: Abfrage ohne Login liefert SessionInfo mit Challenge, Benutzername wird erfasst (Antwort ist ein Hash)
	code, body, _ := sensorGet(t, cl, "GET", base+"/login_sid.lua?version=2", "curl/8", "", nil)
	if code != 200 || !strings.Contains(body, "<SID>0000000000000000</SID>") || strings.Contains(body, "%r") {
		t.Fatalf("login_sid: %d %q", code, body)
	}
	// /login ohne JSON bleibt der normale Koeder
	code, body, _ = sensorGet(t, cl, "GET", base+"/login", "curl/8", "", nil)
	if code != 200 || !strings.Contains(body, "<form") {
		t.Fatalf("/login HTML: %d %q", code, body)
	}
}
