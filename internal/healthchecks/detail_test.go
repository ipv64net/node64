package healthchecks

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/scheduler"
)

// detailView: renderView plus Duration (Detailseite: Wartungsfenster, Stoerungen).
type detailView struct{ renderView }

func (detailView) Duration(d time.Duration) string { return d.String() }

// Detailseite: Rolle „Nur lesen“ sieht weder Passwort noch Kopfzeilen, Request-Body oder TCP-Send; Pillen und
// Zertifikat nur fuer den einen Check.
func TestDetailPage(t *testing.T) {
	m, _ := newTestModule(t)
	ctx := context.Background()
	funcs := template.FuncMap{"add": func(a, b int) int { return a + b }, "sub": func(a, b int) int { return a - b }, "join": strings.Join,
		"split": strings.Fields, "contains": strings.Contains, "ms": func(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) },
		"pct": func(f float64) string { return strconv.FormatFloat(f, 'f', 2, 64) }}
	render := func(w http.ResponseWriter, r *http.Request, status int, page, titleKey string, data any) {
		tpl := template.Must(template.New("root").Funcs(funcs).Parse(`{{template "content" .}}{{block "scripts" .}}{{end}}`))
		if _, err := tpl.ParseFS(templateFS, "templates/pages/"+strings.TrimPrefix(page, Name+"/")+".html"); err != nil {
			t.Fatalf("%s: %v", page, err)
		}
		var buf bytes.Buffer
		if err := tpl.Execute(&buf, detailView{renderView{Data: data, CSRF: "csrf", Version: "v"}}); err != nil {
			t.Fatalf("%s: %v", page, err)
		}
		w.WriteHeader(status)
		_, _ = w.Write(buf.Bytes())
	}
	readOnly := true
	pass := func(h http.Handler) http.Handler { return h }
	mux := http.NewServeMux()
	m.Routes(mux, module.Guards{Enabled: pass, Auth: pass, Render: render, T: func(r *http.Request, key string, args ...any) string { return key },
		Actor: func(*http.Request) string { return "test" }, Lang: func(*http.Request) string { return "de" }, Timezone: func(*http.Request) *time.Location { return time.UTC },
		ReadOnly: func(*http.Request) bool { return readOnly }})
	get := func(path string) string {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	web := removedCheck(t, m.st, checks.TypeHTTP, "self", "web")
	web.Target, web.Params = "https://example.org/", json.RawMessage(`{"method":"POST","body":"{\"pw\":\"geheim-body\"}","basic_user":"u","basic_password":"geheim-pw","headers":{"X-Key":"geheim-h"}}`)
	if err := m.st.Update(ctx, web); err != nil {
		t.Fatal(err)
	}
	tcp := removedCheck(t, m.st, checks.TypeTCP, "self", "smtp")
	tcp.Target, tcp.Params = "mail.example.org:25", json.RawMessage(`{"send":"AUTH geheim-send","expect":"220"}`)
	if err := m.st.Update(ctx, tcp); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		_ = m.st.SaveMeasurement(ctx, scheduler.Measurement{Token: web.Token, Time: now.Add(-time.Duration(i) * time.Minute), Status: checks.Up,
			Details: map[string]any{"cert_not_after": "2027-02-01T00:00:00Z"}})
		_ = m.st.SaveMeasurement(ctx, scheduler.Measurement{Token: tcp.Token, Time: now.Add(-time.Duration(i) * time.Minute), Status: checks.Up})
	}
	for _, path := range []string{"/healthchecks/" + web.Token, "/healthchecks/" + tcp.Token} {
		if b := get(path); strings.Contains(b, "geheim") {
			t.Fatalf("read only %s: %s", path, b)
		}
	}
	readOnly = false
	if b := get("/healthchecks/" + web.Token); !strings.Contains(b, "geheim-body") || !strings.Contains(b, "geheim-h") || strings.Contains(b, "geheim-pw") {
		t.Fatal("admin: body and headers visible, password never")
	}
	if b := get("/healthchecks/" + tcp.Token); !strings.Contains(b, "geheim-send") {
		t.Fatal("admin: send visible")
	}
	// Pillen nur fuer den angefragten Check
	pills, err := m.pillsFor(ctx, "de", time.UTC, 300, web.Token)
	if err != nil || len(pills) != 1 || len(pills[web.Token]) != 3 {
		t.Fatalf("pills: %v %v", pills, err)
	}
	if all, _ := m.pillsFor(ctx, "de", time.UTC, 30, ""); len(all) != 2 {
		t.Fatalf("all pills: %v", all)
	}
}
