package cdn64

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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
