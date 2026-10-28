package dyndns

import (
	"bytes"
	"context"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// pickView ist die Sicht der Templates im Test (Texte = Schluessel).
type pickView struct {
	Data          any
	CSRF, Version string
}

func (pickView) T(key string, _ ...any) string { return key }
func (pickView) Doc(string) template.HTML      { return "" }

// Auswahl aus dem Account: Formular mit Bestaetigungsfeld und Fenster fuer die Rueckfrage (dyndns.js).
func TestTargetNewConfirmRender(t *testing.T) {
	tp, err := template.New("target_new.html").ParseFS(templateFS, "templates/pages/target_new.html")
	if err != nil {
		t.Fatal(err)
	}
	d := newData{HasKey: true, Modes4P: pickModes4, Modes6P: pickModes6,
		Names: []*pickName{{Key: "home.ipv64.net|", Domain: "home.ipv64.net", FQDN: "home.ipv64.net", First: true, Def4: Mode4Auto, Def6: Mode6Host}}}
	var buf bytes.Buffer
	if err := tp.ExecuteTemplate(&buf, "content", pickView{Data: d}); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	for _, want := range []string{"data-pick-form", `name="confirm_many" value=""`, "data-pick-modal", "data-pick-confirm", "data-pick-count",
		"data-pick-list", "dyn.pick.confirm_text", "dyn.pick.confirm_ok", `aria-label="home.ipv64.net"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("target_new misses %s", want)
		}
	}
}

// Mehr als ein Name wird nur mit Bestaetigung angelegt; Namen mit IPv4 und IPv6 "aus" zaehlen nicht mit.
func TestTargetPickNeedsConfirm(t *testing.T) {
	srv := fakeIPv64(t)
	defer srv.Close()
	m, core := newTargetModule(t, true)
	m.SetKey(ipv64api.NewKey(core, nil, ipv64api.NewClient(srv.URL, "test"), slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err := core.SetSetting(context.Background(), ipv64api.SetKey, testKey); err != nil {
		t.Fatal(err)
	}
	var flash []string
	m.g.Flash = func(_ http.ResponseWriter, _ *http.Request, kind, text string) { flash = append(flash, kind+": "+text) }
	m.g.T = func(_ *http.Request, key string, _ ...any) string { return key }
	m.g.Audit = func(*http.Request, string, string, string) {}
	post := func(v url.Values) {
		flash = nil
		req := httptest.NewRequest("POST", "/dyndns/targets/new", strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		m.pageTargetPick(httptest.NewRecorder(), req)
	}
	count := func() int {
		list, err := m.Targets(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return len(list)
	}
	two := url.Values{"pick": {"home.ipv64.net|", "home.ipv64.net|nas"}}
	post(two)
	if count() != 0 || len(flash) != 1 || flash[0] != "warning: dyn.pick.confirm_needed" {
		t.Fatalf("without confirmation: %d %v", count(), flash)
	}
	// zweiter Name mit beiden Familien "aus": nur einer zaehlt, keine Rueckfrage noetig
	off := url.Values{"pick": {"home.ipv64.net|", "home.ipv64.net|nas"}, "m4:home.ipv64.net|nas": {Mode4Off}, "m6:home.ipv64.net|nas": {Mode6Off}}
	post(off)
	if count() != 1 {
		t.Fatalf("one effective name: %d %v", count(), flash)
	}
	two.Set("confirm_many", "1")
	two.Set("pick", "home.ipv64.net|nas")
	two.Add("pick", "dslite.any64.de|")
	post(two)
	if count() != 3 {
		t.Fatalf("with confirmation: %d %v", count(), flash)
	}
}
