package honeypot

import (
	"strings"
	"testing"
)

// FortiGate-Profil (#36): Kopfzeilen und Antworten wie FortiOS, Anmeldungen am SSL-VPN (username/credential) und an der
// Verwaltung (username/secretkey) werden erfasst; Standard auf 10443 bzw. beim Koeder sslvpn.
func TestSensorFortiPersona(t *testing.T) {
	if DefaultPersona(SvcHTTPS, 10443, "") != PersonaForti || DefaultPersona(SvcHTTPS, 4443, "sslvpn") != PersonaForti || PersonaLabels[PersonaForti] == "" {
		t.Fatal("forti default/label")
	}
	p := sensorFreePort(t)
	cfg := Config{Seed: personaTestSeed, Services: []Service{{Service: SvcHTTPS, Port: p}}, Personas: map[string]string{PersonaKey(SvcHTTPS, p): PersonaForti}}
	_, rec := sensorStart(t, cfg)
	cl := personaClient()
	u := func(path string) string { return "https://" + sensorAddrOf(p) + path }
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

	code, body, h := sensorGet(t, cl, "GET", u("/remote/login?lang=en"), "curl/8", "", nil)
	if code != 200 || h.Get("Server") != "xxxxxxxx-xxxxx" || h.Get("X-Frame-Options") != "SAMEORIGIN" || !strings.Contains(body, `action="/remote/logincheck"`) ||
		!strings.Contains(body, `name="credential"`) || strings.Contains(body, "<script") || strings.Contains(strings.ToLower(body), "<img") {
		t.Fatalf("remote/login: %d %v %q", code, h, body)
	}
	if e := rec.wait(t, func(e Event) bool { return e.Path == "/remote/login?lang=en" }); e.Page != "sslvpn" {
		t.Fatalf("page: %+v", e)
	}
	code, body, _ = sensorGet(t, cl, "POST", u("/remote/logincheck"), "curl/8", "ajax=1&username=vpnuser&realm=&credential=Forti123", form)
	if code != 200 || !strings.HasPrefix(body, "ret=0,redir=/remote/login") {
		t.Fatalf("logincheck: %d %q", code, body)
	}
	rec.wait(t, func(e Event) bool {
		return e.Kind == KindHTTPBrute && e.Username == "vpnuser" && e.Password == "Forti123" && strings.Contains(e.Detail, "device=sslvpn")
	})
	code, body, _ = sensorGet(t, cl, "GET", u("/login"), "curl/8", "", nil)
	if code != 200 || !strings.Contains(body, `action="/logincheck"`) || !strings.Contains(body, `name="secretkey"`) {
		t.Fatalf("admin login: %d %q", code, body)
	}
	if code, body, _ = sensorGet(t, cl, "POST", u("/logincheck"), "curl/8", "ajax=1&username=admin&secretkey=fortinet", form); code != 200 || body != "0" {
		t.Fatalf("admin logincheck: %d %q", code, body)
	}
	rec.wait(t, func(e Event) bool { return e.Username == "admin" && e.Password == "fortinet" })
	if code, body, _ = sensorGet(t, cl, "GET", u("/api/v2/monitor/system/status"), "curl/8", "", nil); code != 401 || !strings.Contains(body, `"http_status":401`) {
		t.Fatalf("api: %d %q", code, body)
	}
	if code, _, h = sensorGet(t, cl, "GET", u("/"), "curl/8", "", nil); code != 302 || !strings.HasPrefix(h.Get("Location"), "/remote/login") {
		t.Fatalf("root: %d %v", code, h)
	}
}
