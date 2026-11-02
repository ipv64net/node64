package honeypot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// TestReportFromForm: ohne Key schaltet der Haken nur die anonyme Meldung; die Voreinstellung (mit Key an) bleibt,
// auch wenn ohne Key mit leerem Haken gespeichert wird. Mit Key gilt der Haken direkt.
func TestReportFromForm(t *testing.T) {
	m, _ := modTest(t, modFreePort(t))
	ctx := context.Background()
	form := func(on bool) *http.Request {
		v := url.Values{"profile": {"standard"}}
		if on {
			v.Set("report", "1")
		}
		r := httptest.NewRequest(http.MethodPost, "/honeypot/settings", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		return r
	}
	c := DefaultConfig()
	m.reportFromForm(ctx, form(false), &c) // ohne Key, Haken leer (z. B. nur das Profil geaendert)
	if !c.Report || c.ReportAnon {
		t.Fatalf("no key, unticked: default must stay: %+v", c)
	}
	m.reportFromForm(ctx, form(true), &c) // ohne Key angehakt: anonym
	if !c.Report || !c.ReportAnon {
		t.Fatalf("no key, ticked: %+v", c)
	}
	m.reportFromForm(ctx, form(false), &c) // anonym wieder aus, Voreinstellung bleibt
	if !c.Report || c.ReportAnon {
		t.Fatalf("no key, unticked again: %+v", c)
	}
	if _, err := m.SaveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	// Key eingetragen: die gespeicherte Voreinstellung meldet jetzt
	if err := m.core.SetSetting(ctx, ipv64api.SetKey, repKey); err != nil {
		t.Fatal(err)
	}
	m.SetKey(ipv64api.NewKey(m.core, nil, ipv64api.NewClient("http://127.0.0.1:1/api/v2", "test"), m.log))
	if !m.reportOn(ctx) {
		t.Fatal("with key: saved default must report")
	}
	m.reportFromForm(ctx, form(false), &c) // mit Key: Haken leer = aus
	if c.Report {
		t.Fatalf("with key, unticked: %+v", c)
	}
}
