package cdnedge

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func TestRegDomain(t *testing.T) {
	for in, want := range map[string]string{"x.y.any64.de": "any64.de", "any64.de": "any64.de", "a.b.ipv64.net": "b.ipv64.net", "c.home64.de": "c.home64.de", "x.ipv64.de": "x.ipv64.de",
		"*.foo.example.org": "example.org", "Shop.Example.CO.UK.": "example.co.uk"} {
		if got := regDomain(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

// Let's Encrypt bis zur Grenze, dann ZeroSSL; Erneuerungen bleiben bei Let's Encrypt; "rateLimited" -> ZeroSSL und
// 24 h Pause fuer die Domain; ohne Ausweg ein Fehler; /health zeigt es.
func TestCAChoice(t *testing.T) {
	cfg := &Config{Name: "A", DataDir: t.TempDir(), APIURL: "http://x", ACMEEmail: "ops@example.org", ACMELEWeekLimit: 2}
	s := New(cfg, slog.New(slog.DiscardHandler), "test")
	cf, kf, _, _ := testCA(t, "a.any64.de")
	cp, _ := os.ReadFile(cf)
	kp, _ := os.ReadFile(kf)
	var used []string
	limited := map[string]bool{}
	s.obtainHook = func(_ context.Context, caName string) ([]byte, []byte, error) {
		used = append(used, caName)
		if limited[caName] {
			return nil, nil, &acme.Error{StatusCode: 429, ProblemType: "urn:ietf:params:acme:error:rateLimited", Detail: "too many certificates"}
		}
		return cp, kp, nil
	}
	ctx := context.Background()
	for _, n := range []string{"a.any64.de", "b.any64.de", "c.any64.de", "d.other64.de"} {
		if _, _, err := s.obtain(ctx, n); err != nil {
			t.Fatal(n, err)
		}
	}
	want := []string{"letsencrypt:a.any64.de", "letsencrypt:b.any64.de", "zerossl:c.any64.de", "letsencrypt:d.other64.de"}
	if strings.Join(used, ",") != strings.Join(want, ",") {
		t.Fatalf("CA choice: %v", used)
	}
	// Erneuerung (Zertifikat vorhanden): Let's Encrypt, auch ueber der Grenze
	if err := s.certs.put("a.any64.de", cp, kp); err != nil {
		t.Fatal(err)
	}
	used = nil
	if _, _, err := s.obtain(ctx, "a.any64.de"); err != nil || used[0] != "letsencrypt:a.any64.de" {
		t.Fatalf("renewal: %v %v", used, err)
	}
	// rateLimited von Let's Encrypt: sofort ZeroSSL, danach direkt ZeroSSL fuer die Domain
	limited["letsencrypt:e.third64.de"] = true
	used = nil
	if _, _, err := s.obtain(ctx, "e.third64.de"); err != nil || strings.Join(used, ",") != "letsencrypt:e.third64.de,zerossl:e.third64.de" {
		t.Fatalf("rate limited: %v %v", used, err)
	}
	used = nil
	if _, _, err := s.obtain(ctx, "f.third64.de"); err != nil || strings.Join(used, ",") != "zerossl:f.third64.de" {
		t.Fatalf("cooldown: %v %v", used, err)
	}
	// /health: Warnung (any64.de an der Grenze, third64.de in Pause), Einzelheiten nur lokal
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	req.RemoteAddr = "127.0.0.1:1"
	s.health(rec, req)
	var h Health
	_ = json.Unmarshal(rec.Body.Bytes(), &h)
	if h.ACME != "warn" || h.CA == nil || h.CA.LEWeek["any64.de"] != 2 || h.CA.FallbackWk != 3 || h.CA.Fallback != "zerossl" ||
		strings.Join(h.CA.Cooldown, ",") != "third64.de" {
		t.Fatalf("health: %s", rec.Body)
	}
	// Zaehlung ueberlebt den Neustart
	s2 := New(cfg, slog.New(slog.DiscardHandler), "test")
	if n := s2.ca.leCount("any64.de", time.Now()); n != 2 {
		t.Fatalf("count after restart: %d", n)
	}
	// -1: Let's Encrypt aus, alles zum Ausweg (auch Erneuerungen)
	cfgOff := *cfg
	cfgOff.ACMELEWeekLimit = -1
	sOff := New(&cfgOff, slog.New(slog.DiscardHandler), "test")
	sOff.obtainHook = s.obtainHook
	used = nil
	if _, _, err := sOff.obtain(ctx, "h.fourth64.de"); err != nil || strings.Join(used, ",") != "zerossl:h.fourth64.de" {
		t.Fatalf("le off: %v %v", used, err)
	}
	// ohne Ausweg: Fehler statt Let's Encrypt ueber die Grenze
	cfg2 := *cfg
	cfg2.ACMEEmail, cfg2.DataDir = "", cfg.DataDir
	s3 := New(&cfg2, slog.New(slog.DiscardHandler), "test")
	s3.obtainHook = s.obtainHook
	if _, _, err := s3.obtain(ctx, "g.any64.de"); err == nil || !strings.Contains(err.Error(), "no fallback") {
		t.Fatalf("no fallback: %v", err)
	}
	rec = httptest.NewRecorder()
	s3.health(rec, req)
	if !strings.Contains(rec.Body.String(), `"acme":"error"`) {
		t.Fatalf("health without fallback: %s", rec.Body)
	}
}

// EAB fuer ZeroSSL: einmal per E-Mail abgerufen, gespeichert, danach ohne Abruf; aus der Konfiguration geht vor.
func TestZeroSSLEAB(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		b, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || string(b) != "email=ops%40example.org" {
			http.Error(w, "bad", 400)
			return
		}
		_, _ = io.WriteString(w, `{"success":true,"eab_kid":"kid123","eab_hmac_key":"c2VjcmV0LWhtYWMta2V5"}`)
	}))
	defer srv.Close()
	old := zeroSSLEABURL
	zeroSSLEABURL = srv.URL
	defer func() { zeroSSLEABURL = old }()
	dir := t.TempDir()
	s := New(&Config{Name: "A", DataDir: dir, ACMEEmail: "ops@example.org"}, slog.New(slog.DiscardHandler), "test")
	for i := 0; i < 2; i++ {
		eab, err := s.zeroSSLEAB(context.Background())
		if err != nil || eab.KID != "kid123" || string(eab.Key) != "secret-hmac-key" {
			t.Fatalf("eab: %+v %v", eab, err)
		}
	}
	if calls != 1 {
		t.Fatalf("fetched %d times", calls)
	}
	if st, err := os.Stat(filepath.Join(dir, "acme-zerossl-eab.json")); err != nil || (st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/') {
		t.Fatalf("saved eab: %v", err)
	}
	s2 := New(&Config{Name: "A", DataDir: t.TempDir(), ACMEFallbackEABKID: "cfgkid", ACMEFallbackEABHMAC: "YWJj"}, slog.New(slog.DiscardHandler), "test")
	if eab, err := s2.zeroSSLEAB(context.Background()); err != nil || eab.KID != "cfgkid" || string(eab.Key) != "abc" || calls != 1 {
		t.Fatalf("eab from config: %+v %v", eab, err)
	}
	if s2.fallbackName() != "zerossl" || New(&Config{DataDir: t.TempDir(), ACMEEmail: "x@y", ACMEFallback: "off"}, slog.New(slog.DiscardHandler), "t").fallbackName() != "off" {
		t.Fatal("fallbackName")
	}
}
