package certs

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// #108: netcup CloudDNS (REST-API v1) - Domain suchen, ACME-Pruefung setzen und wieder loeschen, nur mit API-Key.
func TestNetcupV1(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true") // keine DNS-Abfrage im Test
	var mu sync.Mutex
	var calls []string
	unauth := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer schluessel64" {
			unauth++
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":"authenticationError","message":"Authentication token is not valid or has expired."}],"result":null}`)
			return
		}
		b, _ := io.ReadAll(r.Body)
		calls = append(calls, r.Method+" "+r.URL.RequestURI()+" "+strings.TrimSpace(string(b)))
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/domain":
			switch r.URL.Query().Get("fqdn") {
			case "example.de":
				_, _ = io.WriteString(w, `{"success":true,"meta":null,"result":[{"id":42,"fqdn":"example.de","isDnsManaged":true}]}`)
			case "extern.de":
				_, _ = io.WriteString(w, `{"success":true,"meta":null,"result":[{"id":7,"fqdn":"extern.de","isDnsManaged":false}]}`)
			case "home.example.de": // wie netcup: nicht in diesem Account
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":"resourceDoesNotExist","message":"not found"}],"result":null}`)
			default:
				_, _ = io.WriteString(w, `{"success":true,"meta":null,"result":[]}`)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/v1/domain/42/acme/challenge":
			var in map[string]string
			_ = json.Unmarshal(b, &in)
			_, _ = io.WriteString(w, `{"success":true,"result":[{"scope":"`+in["scope"]+`","value":"`+in["value"]+`","fqdn":"_acme-challenge.example.de","status":"ok"}]}`)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/domain/42/acme/challenge/"):
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	prov, err := buildProvider("netcupv1", map[string]string{"key": "schluessel64"})
	if err != nil {
		t.Fatal(err)
	}
	p := prov.(*netcupV1)
	p.baseURL = srv.URL + "/v1"
	if to, iv := p.Timeout(); to.Minutes() != 15 || iv.Seconds() != 30 {
		t.Fatalf("timeout %v %v", to, iv)
	}
	if err := p.Present("nas.home.example.de", "tok", "tok.fingerprint"); err != nil {
		t.Fatal(err)
	}
	if err := p.CleanUp("nas.home.example.de", "tok", "tok.fingerprint"); err != nil {
		t.Fatal(err)
	}
	if err := p.Present("example.de", "tok", "tok.fingerprint"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := strings.Join(calls, "\n")
	mu.Unlock()
	val := "" // Wert wie lego (SHA-256 der Key-Authorization, base64url)
	for _, c := range calls {
		if strings.HasPrefix(c, "POST ") {
			var in map[string]string
			_ = json.Unmarshal([]byte(c[strings.Index(c, "{"):]), &in)
			val = in["value"]
			break
		}
	}
	for _, want := range []string{
		"GET /v1/domain?fqdn=nas.home.example.de ", "GET /v1/domain?fqdn=home.example.de ", "GET /v1/domain?fqdn=example.de ",
		`POST /v1/domain/42/acme/challenge {"scope":"nas.home","value":"` + val + `"}`,
		"DELETE /v1/domain/42/acme/challenge/nas.home/" + val + " ",
		`POST /v1/domain/42/acme/challenge {"scope":"@","value":"` + val + `"}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if len(val) != 43 {
		t.Fatalf("value %q", val)
	}
	// unbekannte Domain bzw. falscher Schluessel: klare Meldung
	if err := p.Present("other.org", "tok", "ka"); err == nil || !strings.Contains(err.Error(), "no domain found for other.org") {
		t.Fatalf("unknown domain: %v", err)
	}
	if err := p.Present("www.extern.de", "tok", "ka"); err == nil || !strings.Contains(err.Error(), "not managed by netcup CloudDNS") {
		t.Fatalf("external dns: %v", err)
	}
	p.key = "falsch"
	if err := p.Present("a.b.example.de", "tok", "ka"); err == nil || !strings.Contains(err.Error(), "authenticationError") {
		t.Fatalf("bad key: %v", err)
	}
	mu.Lock()
	if unauth != 1 { // falscher Schluessel: nicht weiter nach oben suchen
		t.Fatalf("requests with bad key: %d", unauth)
	}
	mu.Unlock()
	// Feld Pflicht, in der Liste mit englischem Hinweis
	if _, err := checkValues("netcupv1", map[string]string{}); err == nil {
		t.Fatal("key required")
	}
	found := false
	for _, x := range ProvidersFor("en") {
		if x.ID == "netcupv1" {
			found = x.Name == "netcup CloudDNS (REST API)" && strings.HasPrefix(x.Docs, "Domains on the name servers") && x.Fields[0].Label == "API key"
		}
	}
	if !found {
		t.Fatal("provider list (en)")
	}
}
