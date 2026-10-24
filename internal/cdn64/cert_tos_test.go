package cdn64

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/certs"
)

// "Zertifikat gleich mit anfordern" ohne Let's-Encrypt-Konto: der Host bleibt ungespeichert und das Formular zeigt den
// Hinweis; mit dem Haken im Formular werden die Nutzungsbedingungen angenommen und der Host gespeichert.
func TestHostFormNeedsTOS(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	var status int
	var data any
	e.m.g.Render = func(w http.ResponseWriter, _ *http.Request, st int, _, _ string, d any) {
		status, data = st, d
		w.WriteHeader(st)
	}
	var flash string
	e.m.g.Flash = func(_ http.ResponseWriter, _ *http.Request, kind, text string) { flash = kind + ": " + text }
	e.m.g.T = func(_ *http.Request, key string, args ...any) string { return key + fmt.Sprint(args...) }
	post := func(extra url.Values) *httptest.ResponseRecorder {
		form := url.Values{"names": {"tos.test"}, "scheme": {"http"}, "target_host": {"192.168.1.10"}, "target_port": {"8080"}, "enabled": {"on"},
			"cert_id": {"new"}, "cert_source": {"http"}}
		for k, v := range extra {
			form[k] = v
		}
		req := httptest.NewRequest("POST", "/cdn64/hosts", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h := newHostKind(KindProxy)
		_ = req.ParseForm()
		hostFromForm(req, h)
		e.m.saveForm(rec, req, h, true)
		return rec
	}
	post(nil)
	d, _ := data.(formData)
	if status != http.StatusUnprocessableEntity || d.Errors["cert_id"] == "" || !d.NewCert {
		t.Fatalf("without terms: status %d errors %v", status, d.Errors)
	}
	if list, _ := e.m.hosts(ctx); len(list) != 0 {
		t.Fatalf("host saved without terms: %d", len(list))
	}
	body := aiRender(t, "host_form.html", d)
	if !strings.Contains(body, `name="accept_tos"`) {
		t.Fatal("form misses the terms checkbox")
	}
	status, data = 0, nil
	rec := post(url.Values{"accept_tos": {"on"}})
	if rec.Code != http.StatusSeeOther || !e.m.certs.Account(ctx).TOSAccepted {
		t.Fatalf("with terms: %d, accepted %v", rec.Code, e.m.certs.Account(ctx).TOSAccepted)
	}
	if list, _ := e.m.hosts(ctx); len(list) != 1 {
		t.Fatalf("host not saved: %d", len(list))
	}
	if strings.Contains(flash, "certs.err.tos") { // HTTP-01 gibt es in der Testumgebung nicht, der Grund darf aber nicht das Konto sein
		t.Fatalf("certificate still blocked by the terms: %s", flash)
	}
	d2 := e.m.form(ctx, newHostKind(KindProxy), true)
	if body := aiRender(t, "host_form.html", d2); strings.Contains(body, `name="accept_tos"`) {
		t.Fatal("terms checkbox still shown after accepting")
	}
}

// Host-Formular: alle Wege zum Zertifikat wie unter Zertifikate (nicht verfuegbare ausgegraut mit Grund); selbst
// signiert braucht kein Let's-Encrypt-Konto und wird gleich ausgestellt.
func TestHostFormCertWays(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	body := aiRender(t, "host_form.html", e.m.form(ctx, newHostKind(KindProxy), true))
	for _, want := range []string{`value="auto"`, `value="ipv64"`, `value="alias" disabled`, `value="http"`, `value="dns" disabled`, `value="ca" disabled`, `value="self"`, `data-cert-tos`} {
		if !strings.Contains(body, want) {
			t.Fatalf("host form misses %s", want)
		}
	}
	var flash string
	e.m.g.Flash = func(_ http.ResponseWriter, _ *http.Request, kind, text string) { flash = kind + ": " + text }
	e.m.g.T = func(_ *http.Request, key string, args ...any) string { return key + fmt.Sprint(args...) }
	form := url.Values{"names": {"self.test"}, "scheme": {"http"}, "target_host": {"192.168.1.10"}, "target_port": {"8080"}, "enabled": {"on"},
		"cert_id": {"new"}, "cert_source": {"self"}}
	req := httptest.NewRequest("POST", "/cdn64/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h := newHostKind(KindProxy)
	_ = req.ParseForm()
	hostFromForm(req, h)
	e.m.saveForm(rec, req, h, true)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(flash, "success: certs.host_saved_cert") || e.m.certs.Account(ctx).TOSAccepted {
		t.Fatalf("self signed: %d %q tos=%v", rec.Code, flash, e.m.certs.Account(ctx).TOSAccepted)
	}
}

// Eigene CA im Host-Formular: das Zertifikat kommt gleich von der CA (ohne Let's-Encrypt-Konto); nach einem Fehler im
// Formular bleibt der gewaehlte Weg ausgewaehlt.
func TestHostFormCertCA(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	off := false
	ca, err := e.m.certs.CreateCA(ctx, certs.CAInput{Name: "Heimnetz", Constrained: &off})
	if err != nil {
		t.Fatal(err)
	}
	way := "ca:" + strconv.FormatInt(ca.ID, 10)
	if body := aiRender(t, "host_form.html", e.m.form(ctx, newHostKind(KindProxy), true)); !strings.Contains(body, `value="`+way+`"`) {
		t.Fatalf("host form misses %s", way)
	}
	var data any
	e.m.g.Render = func(w http.ResponseWriter, _ *http.Request, st int, _, _ string, d any) { data = d; w.WriteHeader(st) }
	var flash string
	e.m.g.Flash = func(_ http.ResponseWriter, _ *http.Request, kind, text string) { flash = kind + ": " + text }
	e.m.g.T = func(_ *http.Request, key string, args ...any) string { return key + fmt.Sprint(args...) }
	post := func(names, src string) int {
		form := url.Values{"names": {names}, "scheme": {"http"}, "target_host": {"192.168.1.10"}, "target_port": {"8080"}, "enabled": {"on"},
			"cert_id": {"new"}, "cert_source": {src}}
		req := httptest.NewRequest("POST", "/cdn64/hosts", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h := newHostKind(KindProxy)
		_ = req.ParseForm()
		hostFromForm(req, h)
		e.m.saveForm(rec, req, h, true)
		return rec.Code
	}
	// Fehler im Formular (kein Name) bzw. fehlender Haken: Weg bleibt ausgewaehlt
	for _, src := range []string{way, "http", "self"} {
		names := ""
		if src == "http" {
			names = "tos.test" // scheitert am Haken fuer die Nutzungsbedingungen
		}
		data = nil
		if c := post(names, src); c != http.StatusUnprocessableEntity {
			t.Fatalf("%s: status %d", src, c)
		}
		d, _ := data.(formData)
		if body := aiRender(t, "host_form.html", d); !strings.Contains(body, `value="`+src+`" selected`) || strings.Contains(body, `value="auto" selected`) {
			t.Fatalf("%s not preselected after error", src)
		}
	}
	if c := post("ca.test", way); c != http.StatusSeeOther || !strings.HasPrefix(flash, "success: certs.host_saved_cert") || e.m.certs.Account(ctx).TOSAccepted {
		t.Fatalf("own CA: %d %q", c, flash)
	}
	list, _ := e.m.certs.List(ctx)
	found := false
	for _, c := range list {
		if strings.Join(c.Names, ",") == "ca.test" && c.Source == "ca" && c.CAID == ca.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("no certificate from the CA: %+v", list)
	}
}
