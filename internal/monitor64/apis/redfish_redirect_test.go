package apis

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// ilo4 verhaelt sich wie HPE iLO 4 (Firmware 2.82, #141): jede Ressource liegt unter dem Pfad mit Schraegstrich am
// Ende; ohne ihn antwortet der BMC mit 308 und der absoluten Adresse mit Schraegstrich (curl: "308
// https://10.1.15.17/redfish/v1/Systems/"). Das gilt auch fuer die Anmeldung einer Sitzung.
type ilo4 struct {
	next      http.Handler
	mu        sync.Mutex
	redirects int
	foreign   string // Weiterleitung auf einen anderen Host (fuer den Test, dass ihr nicht gefolgt wird)
}

func (b *ilo4) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if b.foreign != "" && strings.TrimSuffix(p, "/") == "/redfish/v1/Chassis" {
		w.Header().Set("Location", b.foreign)
		w.WriteHeader(http.StatusPermanentRedirect)
		return
	}
	if strings.HasPrefix(p, "/redfish/v1") && !strings.HasSuffix(p, "/") {
		b.mu.Lock()
		b.redirects++
		b.mu.Unlock()
		w.Header().Set("Location", "https://"+r.Host+p+"/")
		w.WriteHeader(http.StatusPermanentRedirect)
		return
	}
	if p != "/redfish/v1/" {
		r.URL.Path = strings.TrimSuffix(p, "/") // der Fake unter iLO kennt die Pfade ohne Schraegstrich
	}
	b.next.ServeHTTP(w, r)
}

func ilo4Fake(t *testing.T) (*ilo4, *rfAuth, RedfishConfig) {
	t.Helper()
	f := newTreeAPI(t, "redfish")
	a := &rfAuth{user: "monitor", pass: testSecret, valid: map[string]bool{}}
	f.before = a.before
	b := &ilo4{next: f}
	addr, pin := tlsServer(t, b)
	return b, a, RedfishConfig{Address: addr, User: "monitor", Password: testSecret, Pin: pin}
}

// #141: Weiterleitungen auf denselben BMC werden befolgt; danach haengt der Sammler den Schraegstrich selbst an,
// statt jede Anfrage zweimal zu stellen.
func TestRedfishILO4Redirect(t *testing.T) {
	b, a, cfg := ilo4Fake(t)
	r, err := NewRedfish(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	res := deRes(r.Test(context.Background()))
	if !res.OK || res.Node != "web483" {
		t.Fatalf("Test hinter iLO 4: %+v", res)
	}
	svcs, err := r.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect hinter iLO 4: %v", deErr(err))
	}
	checkRedfish(t, svcs)
	b.mu.Lock()
	first := b.redirects
	b.mu.Unlock()
	if first == 0 || first > 2 {
		t.Errorf("Weiterleitungen in der ersten Runde: %d (erwartet: eine, danach mit Schraegstrich)", first)
	}
	if _, err := r.Collect(context.Background()); err != nil {
		t.Fatal(deErr(err))
	}
	b.mu.Lock()
	if b.redirects != first {
		t.Errorf("zweite Runde mit %d weiteren Weiterleitungen", b.redirects-first)
	}
	b.mu.Unlock()
	if a.noAuth != 0 {
		t.Errorf("%d Anfragen ohne Anmeldung", a.noAuth)
	}

	// Sitzung: auch die Anmeldung (POST) folgt der Weiterleitung
	cfg.Session = true
	s, _ := NewRedfish(cfg)
	if _, err := s.Collect(context.Background()); err != nil {
		t.Fatalf("Sitzung hinter iLO 4: %v", deErr(err))
	}
	if a.sessions != 1 {
		t.Errorf("Sitzungen: %d", a.sessions)
	}
	s.Close()
}

// Einer Weiterleitung auf einen anderen Host folgt der Sammler nicht (die Zugangsdaten gehoeren nur dem BMC).
func TestRedfishForeignRedirect(t *testing.T) {
	b, _, cfg := ilo4Fake(t)
	b.foreign = "https://evil.example/redfish/v1/Chassis/"
	r, _ := NewRedfish(cfg)
	defer r.Close()
	_, err := r.Collect(context.Background())
	if err == nil || !strings.Contains(deErr(err), "HTTP 308") {
		t.Fatalf("fremde Weiterleitung: %v", deErr(err))
	}
}

// #141: Wer die vollstaendige Adresse eintraegt (https://bmc/redfish/v1/Systems/), bekommt keinen Fehler mehr – der
// Pfad unter /redfish wird ignoriert. Andere Pfade bleiben abgelehnt.
func TestRedfishAddressWithPath(t *testing.T) {
	_, _, cfg := ilo4Fake(t)
	base := cfg.Address
	for _, p := range []string{"/redfish/v1/Systems/", "/redfish/v1/", "/redfish/v1", "/redfish"} {
		cfg.Address = base + p
		r, err := NewRedfish(cfg)
		if err != nil {
			t.Errorf("%s abgelehnt: %v", p, deErr(err))
			continue
		}
		if res := r.Test(context.Background()); !res.OK {
			t.Errorf("%s: %s", p, de(res.Error))
		}
		r.Close()
	}
	cfg.Address = base + "/irgendwas"
	if _, err := NewRedfish(cfg); err == nil {
		t.Error("Pfad ausserhalb von /redfish angenommen")
	}
}
