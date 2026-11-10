package apis

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/monitor64/model/modeltest"
)

// Ein Geraet darf ueber keinen Text seiner Antworten (Namen von Gaesten, Pools, Platten, Sensoren, Zustaende,
// Fehlermeldungen) ein eigenes Token einschleusen. hostileAPI haengt an jeden Text der JSON-Antworten eines
// Test-Servers ein Token an; danach darf kein Dienst, kein Fehler und kein Testergebnis es enthalten.

const evilToken = "i18n:monitor64.state.crit"

// hostileKeep: Felder, die die Abfrage steuern (Verweise, Arten, IDs in Pfaden) – sie bleiben, sonst kaeme nichts an.
var hostileKeep = map[string]bool{"@odata.id": true, "@odata.type": true, "@odata.context": true, "id": true, "type": true, "node": true,
	"upid": true, "response_type": true}

func hostileValue(key string, v any) any {
	switch x := v.(type) {
	case string:
		if hostileKeep[strings.ToLower(key)] {
			return x
		}
		return x + " " + evilToken
	case []any:
		for i := range x {
			x[i] = hostileValue(key, x[i])
		}
	case map[string]any:
		for k, e := range x {
			x[k] = hostileValue(k, e)
		}
	}
	return v
}

// hostileAPI reicht Anfragen an h weiter und haengt in JSON-Antworten an jeden Text das Token an.
func hostileAPI(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		body := rec.Body.Bytes()
		var v any
		if json.Unmarshal(body, &v) == nil {
			if b, err := json.Marshal(hostileValue("", v)); err == nil {
				body = b
			}
		}
		for k, vals := range rec.Header() {
			if k != "Content-Length" {
				w.Header()[k] = vals
			}
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(body)
	})
}

// checkNoInjection prueft Dienste, Fehler und Testergebnis; min ist die Zahl der Dienste, die trotz der veraenderten
// Antworten mindestens entstehen muss (sonst prueft der Test nichts mehr).
func checkNoInjection(t *testing.T, what string, svcs []model.Service, err error, res TestResult, min int) {
	t.Helper()
	check := func(where, text string) {
		t.Helper()
		for _, k := range model.Keys(text) {
			if k == "monitor64.state.crit" {
				t.Errorf("%s: %s enthaelt ein Token des Geraets: %q", what, where, text)
			}
		}
		if strings.Contains(modeltest.DE(text), "Kritisch") {
			t.Errorf("%s: %s uebersetzt den Text des Geraets: %q", what, where, modeltest.DE(text))
		}
	}
	if len(svcs) < min {
		t.Errorf("%s: nur %d Dienste (%v)", what, len(svcs), err)
	}
	seen := false
	for _, s := range svcs {
		check(s.Key+" Name", s.Name)
		check(s.Key+" Text", s.Text)
		seen = seen || strings.Contains(s.Name+s.Text, "monitor64.state.crit") || strings.Contains(s.Name+s.Text, "monitor64.state")
		for _, f := range s.Facts {
			check(s.Key+" Fact "+f.Code, f.Text)
		}
	}
	if min > 0 && !seen {
		t.Errorf("%s: der Text des Geraets kommt in keinem Dienst an – der Test prueft nichts", what)
	}
	if err != nil {
		check("Fehler", err.Error())
	}
	check("Test Fehler", res.Error)
	check("Test Warnung", res.Warning)
	check("Test Zusammenfassung", res.Summary)
}

func TestNoInjection(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	t.Run("pve", func(t *testing.T) {
		addr, pin := tlsServer(t, hostileAPI(pveRoutes(t)))
		p := newTestPVE(t, PVEConfig{Addresses: []string{addr}, TokenID: "monitor64@pve!node64", Secret: testSecret, Pin: pin, Node: "pve1"}, &now)
		svcs, err := p.Collect(ctx)
		checkNoInjection(t, "pve", svcs, err, p.Test(ctx), 10)
	})
	t.Run("pbs", func(t *testing.T) {
		f, cfg := pbsFake(t, now)
		addr, pin := tlsServer(t, hostileAPI(f))
		cfg.Addresses, cfg.Pin = []string{addr}, pin
		p, err := NewPBS(cfg)
		if err != nil {
			t.Fatal(err)
		}
		p.now = func() time.Time { return now }
		svcs, err := p.Collect(ctx)
		checkNoInjection(t, "pbs", svcs, err, p.Test(ctx), 5)
	})
	t.Run("docker", func(t *testing.T) {
		f, _ := dockerFake(t, now)
		srv := httptest.NewServer(hostileAPI(f))
		defer srv.Close()
		d := newTestDocker(t, srv.URL, &now)
		svcs, err := d.Collect(ctx)
		checkNoInjection(t, "docker", svcs, err, d.Test(ctx), 3)
	})
	t.Run("truenas", func(t *testing.T) {
		addr, pin := tlsServer(t, hostileAPI(newFakeTrueNAS(t, false)))
		tn, err := NewTrueNAS(TrueNASConfig{Address: addr, APIKey: testSecret, Pin: pin})
		if err != nil {
			t.Fatal(err)
		}
		tn.now = tnNow
		svcs, err := tn.Collect(ctx)
		checkNoInjection(t, "truenas", svcs, err, tn.Test(ctx), 8)
	})
	t.Run("unraid", func(t *testing.T) {
		srv := httptest.NewServer(hostileAPI(&fakeUnraid{t: t}))
		defer srv.Close()
		u, err := NewUnraid(UnraidConfig{Address: srv.URL, APIKey: testSecret})
		if err != nil {
			t.Fatal(err)
		}
		u.now = urNow
		svcs, err := u.Collect(ctx)
		checkNoInjection(t, "unraid", svcs, err, u.Test(ctx), 8)
	})
	t.Run("redfish", func(t *testing.T) {
		f, a, cfg := rfFake(t)
		_ = a
		addr, pin := tlsServer(t, hostileAPI(f))
		cfg.Address, cfg.Pin = addr, pin
		r, err := NewRedfish(cfg)
		if err != nil {
			t.Fatal(err)
		}
		svcs, err := r.Collect(ctx)
		checkNoInjection(t, "redfish", svcs, err, r.Test(ctx), 8)
	})
	t.Run("nut", func(t *testing.T) {
		f := nutFake(t)
		for name, vars := range f.ups {
			f.ups[name] = strings.ReplaceAll(vars, "\"\n", " "+evilToken+"\"\n")
		}
		n, err := NewNUT(NUTConfig{Address: f.addr()})
		if err != nil {
			t.Fatal(err)
		}
		svcs, err := n.Collect(ctx)
		checkNoInjection(t, "nut", svcs, err, n.Test(ctx), 2)
	})
}

// Zusammengesetzte Texte der Sammler in beiden Sprachen (Stichproben): Eigennamen und Groessen bleiben.
func TestTextsBothLanguages(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	f, cfg := pveFake(t)
	_ = f
	p := newTestPVE(t, cfg, &now)
	svcs, err := p.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range svcs {
		de, en := modeltest.Service("de", s), modeltest.Service("en", s)
		for _, x := range []model.Service{de, en} {
			for _, text := range append([]string{x.Name, x.Text}, factTexts(x)...) {
				if len(model.Keys(text)) != 0 || strings.Contains(text, "monitor64.") {
					t.Errorf("%s: nicht uebersetzt: %q", s.Key, text)
				}
			}
		}
		// in der englischen Ausgabe steht kein deutscher Text der Sammler
		for _, bad := range []string{" frei", "läuft", "gestoppt", "soll laufen", "darf aus", "Speicher ", "Dateisystem", "Kerne", "verfügbar", "gestört", "Sperre"} {
			if strings.Contains(en.Name+" "+en.Text+" "+strings.Join(factTexts(en), " "), bad) {
				t.Errorf("%s (en) enthaelt %q: %q / %q", s.Key, bad, en.Name, en.Text)
			}
		}
	}
	for key, want := range map[string][2]string{
		"store:local": {"Speicher local", "Storage local"},
		"fs:/":        {"Dateisystem /", "Filesystem /"},
	} {
		for _, s := range svcs {
			if s.Key == key && (modeltest.DE(s.Name) != want[0] || modeltest.EN(s.Name) != want[1]) {
				t.Errorf("%s: %q / %q", key, modeltest.DE(s.Name), modeltest.EN(s.Name))
			}
		}
	}
}

func factTexts(s model.Service) []string {
	var out []string
	for _, f := range s.Facts {
		out = append(out, f.Text)
	}
	return out
}
