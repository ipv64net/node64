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

// rfAuth prueft die Anmeldung am Fake-BMC: Basic-Auth bzw. gueltige Sitzung (Wurzel ohne Anmeldung).
type rfAuth struct {
	mu       sync.Mutex
	user     string
	pass     string
	valid    map[string]bool // gueltige Tokens
	n        int
	deleted  []string
	noAuth   int // Anfragen ohne Anmeldung (ausser Wurzel)
	sessions int
}

func (a *rfAuth) before(w http.ResponseWriter, r *http.Request) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case r.URL.Path == "/redfish/v1/" || r.URL.Path == "/redfish/v1":
		return false
	case r.Method == http.MethodPost && r.URL.Path == "/redfish/v1/SessionService/Sessions":
		b, _ := io.ReadAll(r.Body)
		var c struct{ UserName, Password string }
		_ = json.Unmarshal(b, &c)
		if c.UserName != a.user || c.Password != a.pass {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"Base.1.8.GeneralError","message":"Login failed","@Message.ExtendedInfo":[{"Message":"The authentication credentials included with this request are missing or invalid."}]}}`))
			return true
		}
		a.n++
		a.sessions++
		tok := fmt.Sprintf("tok-%d", a.n)
		a.valid[tok] = true
		w.Header().Set("X-Auth-Token", tok)
		w.Header().Set("Location", fmt.Sprintf("/redfish/v1/SessionService/Sessions/%d", a.n))
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"x"}`))
		return true
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/redfish/v1/SessionService/Sessions/"):
		a.deleted = append(a.deleted, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	if tok := r.Header.Get("X-Auth-Token"); tok != "" {
		if a.valid[tok] {
			return false
		}
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}
	if u, p, ok := r.BasicAuth(); ok && u == a.user && p == a.pass {
		return false
	}
	a.noAuth++
	w.WriteHeader(http.StatusUnauthorized)
	return true
}

func rfFake(t *testing.T) (*treeAPI, *rfAuth, RedfishConfig) {
	f := newTreeAPI(t, "redfish")
	a := &rfAuth{user: "monitor", pass: testSecret, valid: map[string]bool{}}
	f.before = a.before
	addr, pin := tlsServer(t, f)
	return f, a, RedfishConfig{Address: addr, User: "monitor", Password: testSecret, Pin: pin}
}

func checkRedfish(t *testing.T, svcs []model.Service) {
	t.Helper()
	sys := svcByKey(t, svcs, "system")
	if sys.Name != "System Contoso 3500" || mustMetric(t, sys, "power_on").Value != 1 || !hasFact(sys, "device_crit") ||
		!strings.Contains(sys.Facts[0].Text, "RAM Critical") || !strings.Contains(sys.Text, "2 CPU · 96 GiB RAM") {
		t.Errorf("system = %+v", sys)
	}
	c1 := svcByKey(t, svcs, "temp:1U/CPU1 Temp")
	if m := mustMetric(t, c1, "temp"); m.Value != 62 || m.Rule != "" || len(c1.Facts) != 0 {
		t.Errorf("CPU1 (Geraeteschwellen, keine Standard-Regel) = %+v", c1)
	}
	if c1.Text != "62 °C · Gerät: Warnung ab 75, kritisch ab 90" || c1.Name != "Temperatur CPU1 Temp (1U)" {
		t.Errorf("CPU1 Text = %q / %q", c1.Text, c1.Name)
	}
	if b := svcByKey(t, svcs, "temp:Blade2/CPU1 Temp"); mustMetric(t, b, "temp").Value != 55.5 {
		t.Errorf("Blade2 CPU1 = %+v", b)
	}
	if c2 := svcByKey(t, svcs, "temp:CPU2 Temp"); !hasFact(c2, "device_crit") || len(c2.Facts) != 1 {
		t.Errorf("CPU2 = %+v", c2)
	}
	if in := svcByKey(t, svcs, "temp:Chassis Intake Temp"); !hasFact(in, "device_warn") || hasFact(in, "device_crit") {
		t.Errorf("Intake = %+v", in)
	}
	if bt := svcByKey(t, svcs, "temp:Board Temp"); mustMetric(t, bt, "temp").Rule != model.RuleTemp {
		t.Errorf("Board (ohne Schwellen) = %+v", bt)
	}
	if hasSvc(svcs, "temp:CPU3 Temp") || hasSvc(svcs, "fan:Fan 3") || hasSvc(svcs, "psu:Power Supply Bay 3") || hasSvc(svcs, "temp:PS1 Voltage") {
		t.Error("fehlende Bauteile bzw. Spannung als Dienst")
	}
	if mustMetric(t, svcByKey(t, svcs, "temp:Inlet Temp"), "temp").Rule != model.RuleTemp {
		t.Error("Inlet (Sensors, absolute URL) fehlt Regel")
	}
	if f := svcByKey(t, svcs, "fan:BaseBoard System Fan"); mustMetric(t, f, "rpm").Value != 2100 || len(f.Facts) != 0 {
		t.Errorf("Fan = %+v", f)
	}
	if f := svcByKey(t, svcs, "fan:BaseBoard System Fan Backup"); !hasFact(f, "device_crit") || !strings.Contains(f.Facts[0].Text, "kritisch unter 1000") {
		t.Errorf("Fan Backup = %+v", f)
	}
	if f := svcByKey(t, svcs, "fan:Fan 1"); mustMetric(t, f, "rpm").Value != 7200 {
		t.Errorf("Fan 1 (Sensors) = %+v", f)
	}
	p1 := svcByKey(t, svcs, "psu:Power Supply Bay 1")
	if mustMetric(t, p1, "watts").Value != 210 || mustMetric(t, p1, "input_voltage").Value != 238 || len(p1.Facts) != 0 {
		t.Errorf("PSU 1 = %+v", p1)
	}
	if p2 := svcByKey(t, svcs, "psu:Power Supply Bay 2"); !hasFact(p2, "device_crit") || !strings.Contains(p2.Text, "UnavailableOffline") {
		t.Errorf("PSU 2 = %+v", p2)
	}
	if !hasSvc(svcs, "psu:Blade PSU") {
		t.Error("PowerSubsystem-Netzteil fehlt")
	}
	pw := svcByKey(t, svcs, "power")
	if mustMetric(t, pw, "watts").Value != 344 || !hasFact(pw, "device_warn") || !strings.Contains(pw.Facts[0].Text, "Redundancy Group 1 verloren") {
		t.Errorf("power = %+v", pw)
	}
	if c := svcByKey(t, svcs, "ctrl:1"); len(c.Facts) != 0 || !strings.Contains(c.Text, "12Gbs Integrated RAID (FW 1.0.0.7)") {
		t.Errorf("ctrl = %+v", c)
	}
	if d := svcByKey(t, svcs, "disk:1234570"); len(d.Facts) != 0 || d.Name != "Drive Sample (C123)" {
		t.Errorf("Disk 0 = %+v", d)
	}
	ssd := svcByKey(t, svcs, "disk:PHYG0123456789")
	if !hasFact(ssd, "disk_errors") || mustMetric(t, ssd, "wear").Value != 88 || mustMetric(t, ssd, "wear").Rule != model.RuleWear {
		t.Errorf("SSD = %+v", ssd)
	}
	if d := svcByKey(t, svcs, "disk:ZC2ABCDE"); !hasFact(d, "smart_failed") {
		t.Errorf("Disk 2 = %+v", d)
	}
	if v := svcByKey(t, svcs, "raid:1/1"); len(v.Facts) != 0 || v.Name != "Volume Virtual Disk 0" {
		t.Errorf("Volume 1 = %+v", v)
	}
	if v := svcByKey(t, svcs, "raid:1/2"); !hasFact(v, "raid_degraded") || !strings.Contains(v.Text, "Rebuild 45 %") {
		t.Errorf("Volume 2 = %+v", v)
	}
}

func TestRedfishBasic(t *testing.T) {
	f, a, cfg := rfFake(t)
	r, err := NewRedfish(cfg)
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := r.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	checkRedfish(t, svcs)
	if a.noAuth != 0 || a.sessions != 0 {
		t.Errorf("ohne Anmeldung %d, Sitzungen %d", a.noAuth, a.sessions)
	}
	if f.count("GET /etc/passwd") != 0 {
		t.Error("ungueltiger Verweis abgefragt")
	}
	// zweite Runde: Storage aus dem Speicher
	if _, err := r.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := f.count("GET /redfish/v1/Systems/437XR1138R2/Storage/1/Drives/Disk.Bay.0"); n != 1 {
		t.Errorf("Laufwerk %d mal abgefragt", n)
	}
	if n := f.count("GET /redfish/v1/Chassis/1U/Thermal"); n != 2 {
		t.Errorf("Thermal %d mal abgefragt", n)
	}
	res := r.Test(context.Background())
	if !res.OK || res.Version != "Contoso Contoso BMC 2000 Redfish 1.15.0" || res.Node != "web483" || res.Summary != "Contoso 3500 (an)" {
		t.Errorf("Test = %+v", res)
	}
	// falsches Passwort: Fehler ohne Geheimnis
	cfg.Password = "falsch-" + testSecret
	r2, _ := NewRedfish(cfg)
	_, err = r2.Collect(context.Background())
	if err == nil || strings.Contains(err.Error(), testSecret) || !strings.Contains(err.Error(), "Benutzer und Passwort prüfen") {
		t.Errorf("falsches Passwort: %v", err)
	}
}

func TestRedfishSession(t *testing.T) {
	_, a, cfg := rfFake(t)
	cfg.Session = true
	r, _ := NewRedfish(cfg)
	svcs, err := r.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	checkRedfish(t, svcs)
	if a.sessions != 1 || a.noAuth != 0 {
		t.Errorf("Sitzungen %d, ohne Anmeldung %d", a.sessions, a.noAuth)
	}
	// Sitzung laeuft ab: genau eine neue Anmeldung, auch bei parallelen Abfragen
	a.mu.Lock()
	a.valid = map[string]bool{}
	a.mu.Unlock()
	r.storAt = time.Time{} // Storage erneut (parallele Laufwerks-Abfragen)
	if _, err := r.Collect(context.Background()); err != nil {
		t.Fatalf("Collect nach Ablauf: %v", err)
	}
	if a.sessions != 2 {
		t.Errorf("Sitzungen nach Ablauf = %d", a.sessions)
	}
	r.Close()
	if len(a.deleted) != 1 || a.deleted[0] != "/redfish/v1/SessionService/Sessions/2" {
		t.Errorf("abgemeldet = %v", a.deleted)
	}
	// falsches Passwort bei der Anmeldung
	cfg.Password = "falsch-" + testSecret
	r2, _ := NewRedfish(cfg)
	res := r2.Test(context.Background())
	if res.OK || strings.Contains(res.Error, testSecret) || !strings.Contains(res.Error, "401") {
		t.Errorf("Test falsches Passwort = %+v", res)
	}
}

func TestRedfishConfirmAndPartial(t *testing.T) {
	f, a, cfg := rfFake(t)
	pin := cfg.Pin
	cfg.Pin = ""
	r, _ := NewRedfish(cfg)
	res := r.Test(context.Background())
	if res.OK || !res.NeedConfirm || res.Fingerprint != pin {
		t.Errorf("ohne Pin = %+v", res)
	}
	for _, h := range f.headers() {
		if h.Get("Authorization") != "" {
			t.Fatal("Zugangsdaten vor der Bestaetigung gesendet")
		}
	}
	_ = a
	// Teilfehler: Power kaputt, Volumes fehlen -> Praefixe
	cfg.Pin = pin
	f.set("GET /redfish/v1/Chassis/1U/Power", 500, `{"error":{"code":"Base.1.8.InternalError","message":"internal error"}}`)
	f.set("GET /redfish/v1/Systems/437XR1138R2/Storage/1/Volumes/2", 503, `{}`)
	r, _ = NewRedfish(cfg)
	svcs, err := r.Collect(context.Background())
	pe := partialOf(t, err)
	if !hasPrefix(pe, "psu:") || !hasPrefix(pe, "power") || !hasPrefix(pe, "raid:1/") || !strings.Contains(pe.Error(), "internal error") {
		t.Errorf("Teilfehler = %+v", pe)
	}
	if !hasSvc(svcs, "raid:1/1") || hasSvc(svcs, "raid:1/2") || hasSvc(svcs, "power") || !hasSvc(svcs, "temp:CPU2 Temp") {
		t.Errorf("Dienste bei Teilfehler falsch")
	}
	if !r.storAt.IsZero() {
		t.Error("unvollstaendiger Storage-Stand gemerkt")
	}
}

func TestRedfishPathAndConfig(t *testing.T) {
	for in, want := range map[string]string{
		"/redfish/v1/Systems/1":                   "/redfish/v1/Systems/1",
		"/redfish/v1/Systems/1/":                  "/redfish/v1/Systems/1",
		"https://other/redfish/v1/Chassis/1":      "/redfish/v1/Chassis/1",
		"/redfish/v1/../../etc/passwd":            "",
		"/redfish/v1/%2e%2e/x":                    "",
		"/etc/passwd":                             "",
		"/redfish/v1/Systems?$expand=*":           "",
		"":                                        "",
		"/redfish/v1/" + strings.Repeat("a", 600): "",
	} {
		got, ok := rfPath(in)
		if got != want || ok != (want != "") {
			t.Errorf("rfPath(%q) = %q %v", in, got, ok)
		}
	}
	for _, c := range []RedfishConfig{
		{Address: "https://bmc", User: "u"},
		{Address: "https://bmc", Password: "p"},
		{Address: "http://bmc", User: "u", Password: "p"},
		{Address: "https://bmc", User: "u:x", Password: "p"},
		{Address: "https://bmc", User: "u", Password: "p", Pin: "x"},
	} {
		if _, err := NewRedfish(c); err == nil {
			t.Errorf("%+v angenommen", c)
		}
	}
}

func TestRedfishTempThresholds(t *testing.T) {
	set := func(v float64) optF { return optF{V: v, Set: true} }
	// nur Fatal-Schwelle: gilt als kritisch
	it, ok := rfTempItem("1", "PCH", "", set(101), optF{}, optF{}, set(100), rfStatus{State: "Enabled", Health: "OK"})
	if !ok || !hasFact(it.svc, "device_crit") {
		t.Errorf("Fatal = %+v", it.svc)
	}
	// ohne Wert, aber Health Warning: Dienst mit Zustand
	it, ok = rfTempItem("1", "X", "", optF{}, optF{}, optF{}, optF{}, rfStatus{Health: "Warning"})
	if !ok || !hasFact(it.svc, "device_warn") || len(it.svc.Metrics) != 0 {
		t.Errorf("ohne Wert = %+v", it.svc)
	}
	// ohne Wert und ohne Zustand: kein Dienst
	if _, ok := rfTempItem("1", "Y", "", optF{}, optF{}, optF{}, optF{}, rfStatus{}); ok {
		t.Error("leerer Sensor als Dienst")
	}
	// unsinniger Wert
	it, _ = rfTempItem("1", "Z", "", set(9999), optF{}, optF{}, optF{}, rfStatus{Health: "OK"})
	if len(it.svc.Metrics) != 0 {
		t.Errorf("9999 °C angenommen: %+v", it.svc)
	}
}

func TestRedfishSimpleStorage(t *testing.T) {
	f := newTreeAPI(t, "redfish-none")
	f.set("GET /redfish/v1/", 200, `{"RedfishVersion":"1.0.2","Systems":{"@odata.id":"/redfish/v1/Systems"},"Chassis":{"@odata.id":"/redfish/v1/Chassis"}}`)
	f.set("GET /redfish/v1/Systems", 200, `{"Members":[{"@odata.id":"/redfish/v1/Systems/1"}]}`)
	f.set("GET /redfish/v1/Systems/1", 200, `{"Id":"1","PowerState":"Off","Status":{"Health":"Warning"},"SimpleStorage":{"@odata.id":"/redfish/v1/Systems/1/SimpleStorage"}}`)
	f.set("GET /redfish/v1/Chassis", 200, `{"Members":[]}`)
	f.set("GET /redfish/v1/Systems/1/SimpleStorage", 200, `{"Members":[{"@odata.id":"/redfish/v1/Systems/1/SimpleStorage/1"}]}`)
	f.set("GET /redfish/v1/Systems/1/SimpleStorage/1", 200, `{"Id":"1","Name":"Simple Storage Controller","Description":"System SATA","Status":{"State":"Enabled","Health":"OK"},
"Devices":[{"Name":"SATA Bay 1","Model":"3000GT8","CapacityBytes":8000000000000,"Status":{"State":"Enabled","Health":"OK"}},
{"Name":"SATA Bay 2","Model":"3000GT7","Status":{"State":"Enabled","Health":"Warning"}},{"Name":"SATA Bay 3","Status":{"State":"Absent"}}]}`)
	addr, pin := tlsServer(t, f)
	r, _ := NewRedfish(RedfishConfig{Address: addr, User: "u", Password: testSecret, Pin: pin})
	svcs, err := r.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	sys := svcByKey(t, svcs, "system")
	if mustMetric(t, sys, "power_on").Value != 0 || !hasFact(sys, "device_warn") || !strings.HasPrefix(sys.Text, "aus") {
		t.Errorf("system (aus, ohne Teilzustaende) = %+v", sys)
	}
	if c := svcByKey(t, svcs, "ctrl:1"); c.Name != "Controller Simple Storage Controller System SATA" || len(c.Facts) != 0 {
		t.Errorf("ctrl = %+v", c)
	}
	if d := svcByKey(t, svcs, "disk:1/SATA Bay 1"); d.Name != "SATA Bay 1 (3000GT8)" || len(d.Facts) != 0 {
		t.Errorf("Bay 1 = %+v", d)
	}
	if d := svcByKey(t, svcs, "disk:1/SATA Bay 2"); !hasFact(d, "disk_errors") {
		t.Errorf("Bay 2 = %+v", d)
	}
	if hasSvc(svcs, "disk:1/SATA Bay 3") {
		t.Error("leerer Platz als Laufwerk")
	}
}
