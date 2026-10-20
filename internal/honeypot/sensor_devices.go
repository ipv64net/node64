package honeypot

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
)

// Login-Endpunkte verbreiteter Geraete und Oberflaechen (Router, Firewalls, NAS, Smart Home, Virtualisierung), die
// Bots im Internet abklappern. Der Koeder beantwortet nur den Login-Aufruf mit einer schlichten, plausiblen Ablehnung
// (Status und Format wie die API, ohne Logos, Namen oder Inhalte der Hersteller), damit Bots ihre Zugangsdaten
// schicken. Erfasst wird ueber sensorHTTPCreds; das Geraet steht im Detail ("device=<name>").

type sensorDevice struct {
	name   string
	prefix bool   // Pfad beginnt mit path (sonst exakt)
	path   string // klein geschrieben
	ctype  string // Antwort
	status int
	body   string // %r = Zufallswert
}

var sensorDevices = []sensorDevice{
	{"fritzbox", false, "/login_sid.lua", "text/xml", 200, `<?xml version="1.0" encoding="utf-8"?><SessionInfo><SID>0000000000000000</SID><Challenge>%r</Challenge><BlockTime>0</BlockTime><Rights></Rights></SessionInfo>`},
	{"speedport", false, "/data/login.json", "application/json", 200, `[{"vartype":"status","varid":"login","varvalue":"failed"}]`},
	{"proxmox", false, "/api2/json/access/ticket", "application/json", 401, `{"data":null}`},
	{"homeassistant", false, "/auth/login_flow", "application/json", 200, `{"type":"form","flow_id":"%r","step_id":"init","data_schema":[{"type":"string","name":"username"},{"type":"string","name":"password"}],"errors":{}}`},
	{"homeassistant", true, "/auth/login_flow/", "application/json", 200, `{"type":"form","flow_id":"%r","step_id":"init","errors":{"base":"invalid_auth"}}`},
	{"unifi", false, "/api/login", "application/json", 400, `{"meta":{"rc":"error","msg":"api.err.Invalid"},"data":[]}`},
	{"unifi", false, "/api/auth/login", "application/json", 401, `{"code":"AUTHENTICATION_FAILED_INVALID_CREDENTIALS","message":"Invalid username or password"}`},
	{"nas", false, "/webapi/auth.cgi", "application/json", 200, `{"error":{"code":400},"success":false}`},
	{"nas", false, "/webapi/entry.cgi", "application/json", 200, `{"error":{"code":400},"success":false}`},
	{"firewall", false, "/webconsole/controller", "application/json", 200, `{"status":401}`},
	{"sslvpn", false, "/remote/logincheck", "text/plain", 200, `ret=0,redir=/remote/login?&err=sslvpn_login_permission_denied`},
	{"openwrt", false, "/cgi-bin/luci", "text/html", 403, ``},
	{"router", false, "/boaform/admin/formlogin", "text/html", 200, ``},
	{"router", false, "/goform/login", "text/html", 200, ``},
	{"router", false, "/cgi-bin/login.cgi", "text/html", 200, ``},
	{"webmin", false, "/session_login.cgi", "text/html", 200, ``},
	{"jenkins", false, "/j_spring_security_check", "text/html", 401, ``},
	{"portainer", false, "/api/auth", "application/json", 422, `{"message":"Invalid credentials","details":"Unauthorized"}`},
	{"grafana", false, "/login", "application/json", 401, `{"message":"Invalid username or password"}`},
}

// sensorDeviceFor liefert den Endpunkt fuer einen Pfad (nil = keiner). /login gilt nur fuer JSON-Anfragen (sonst
// bleibt es beim normalen Koeder).
func sensorDeviceFor(r *http.Request) *sensorDevice {
	p := strings.ToLower(r.URL.Path)
	for i := range sensorDevices {
		d := &sensorDevices[i]
		if (d.prefix && strings.HasPrefix(p, d.path)) || (!d.prefix && p == d.path) {
			if d.path == "/login" && !strings.Contains(r.Header.Get("Content-Type"), "json") {
				return nil
			}
			return d
		}
	}
	return nil
}

// reply schreibt die Ablehnung. Leerer Body bei HTML: der schlichte Login-Koeder mit Fehlermeldung.
func (d *sensorDevice) reply(w http.ResponseWriter, failed bool) {
	h := w.Header()
	h.Set("Content-Type", d.ctype+"; charset=UTF-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(d.status)
	body := d.body
	if body == "" && strings.HasPrefix(d.ctype, "text/html") {
		body = sensorPageHTML("admin", failed)
	}
	if strings.Contains(body, "%r") {
		var b [8]byte
		_, _ = rand.Read(b[:])
		body = strings.ReplaceAll(body, "%r", hex.EncodeToString(b[:]))
	}
	_, _ = io.WriteString(w, body)
}
