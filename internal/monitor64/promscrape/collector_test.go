package promscrape

import (
	"compress/gzip"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/proxmox"
)

const testSecret = "geheim-token-1234"

func fixtureText(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// fakeMap: ein Dienst je Abschnitt (der echte Mapper wird im Paket-externen Test geprueft).
func fakeMap(prev, cur *m64proto.Report) []model.Service {
	var out []model.Service
	add := func(k string) {
		out = append(out, model.Service{Key: k, Kind: strings.TrimSuffix(strings.SplitN(k, ":", 2)[0], ":"), Default: true})
	}
	if cur.CPU != nil {
		add("cpu")
	}
	if cur.Mem != nil {
		add("mem")
	}
	for _, f := range cur.FS {
		add("fs:" + f.Mount)
	}
	for _, d := range cur.Disks {
		add("disk:" + d.Name)
	}
	for _, w := range cur.WinSvc {
		add("winsvc:" + w.Name)
	}
	return out
}

// testServer liefert body (veraenderbar) und merkt sich den Authorization-Header.
type testServer struct {
	mu      sync.Mutex
	body    string
	gz      bool
	status  int
	auth    string
	hits    atomic.Int32
	handler http.HandlerFunc
}

func (s *testServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.hits.Add(1)
	s.mu.Lock()
	s.auth = r.Header.Get("Authorization")
	body, gz, status, h := s.body, s.gz, s.status, s.handler
	s.mu.Unlock()
	if h != nil {
		h(w, r)
		return
	}
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if gz && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		_, _ = zw.Write([]byte(body))
		_ = zw.Close()
		return
	}
	_, _ = w.Write([]byte(body))
}

func (s *testServer) set(f func(s *testServer)) {
	s.mu.Lock()
	f(s)
	s.mu.Unlock()
}

func (s *testServer) lastAuth() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.auth
}

func TestNormalizeURL(t *testing.T) {
	for _, tc := range []struct{ in, want, err string }{
		{"10.0.0.5", "http://10.0.0.5:9100/metrics", ""},
		{"nas.local:9182", "http://nas.local:9182/metrics", ""},
		{"[fd00::1]", "http://[fd00::1]:9100/metrics", ""},
		{"https://exp.example.org", "https://exp.example.org/metrics", ""},
		{"https://exp.example.org/node/metrics?collect[]=cpu", "https://exp.example.org/node/metrics?collect[]=cpu", ""},
		{"HTTP://host:80/", "http://host:80/metrics", ""},
		{"http://user:pw@host", "", "Zugangsdaten"},
		{"ftp://host", "", "nur http"},
		{"http://host:99999", "", "Port"},
		{"", "", "fehlt"},
		{"http://", "", "ungültig"},
	} {
		got, err := NormalizeURL(tc.in, DefaultPort)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%q: Fehler %v, erwartet %q", tc.in, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q -> %q, %v (erwartet %q)", tc.in, got, err, tc.want)
		}
	}
}

func TestCollectNodeGzipBasicAuth(t *testing.T) {
	ts := &testServer{body: fixtureText(t, "node_exporter-1.12.1.txt"), gz: true}
	srv := httptest.NewServer(ts)
	defer srv.Close()
	var prevSeen []*m64proto.Report
	mapper := func(prev, cur *m64proto.Report) []model.Service {
		prevSeen = append(prevSeen, prev)
		return fakeMap(prev, cur)
	}
	c, err := New(Config{URL: srv.URL, User: "prom", Secret: testSecret, Map: mapper})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	svcs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ts.lastAuth() != "Basic cHJvbTpnZWhlaW0tdG9rZW4tMTIzNA==" {
		t.Errorf("Auth %q", ts.lastAuth())
	}
	if len(svcs) != 4 || svcs[0].Key != "cpu" || svcs[2].Key != "fs:/" {
		t.Errorf("Dienste %+v", svcs)
	}
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(prevSeen) != 2 || prevSeen[0] != nil || prevSeen[1] == nil {
		t.Errorf("voriger Bericht nicht weitergegeben: %v", prevSeen)
	}
	if k, v := c.Exporter(); k != ExporterNode || v != "1.12.1" {
		t.Errorf("Exporter %q %q", k, v)
	}
}

func TestCollectBearerAndErrors(t *testing.T) {
	ts := &testServer{body: "nginx_up 1\n"}
	srv := httptest.NewServer(ts)
	defer srv.Close()
	c, err := New(Config{URL: srv.URL + "/m", Secret: testSecret, Map: fakeMap, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := c.Collect(context.Background())
	if err != nil || len(svcs) != 0 {
		t.Fatalf("unbekannter Exporter ohne eigene Metriken: %v %v", svcs, err)
	}
	if ts.lastAuth() != "Bearer "+testSecret {
		t.Errorf("Auth %q", ts.lastAuth())
	}
	cases := []struct {
		name string
		set  func(s *testServer)
		want string
	}{
		{"401", func(s *testServer) { s.status = 401 }, "Anmeldung abgelehnt"},
		{"404", func(s *testServer) { s.status = 404 }, "404"},
		{"500", func(s *testServer) { s.status = 500 }, "HTTP 500"},
		{"html", func(s *testServer) { s.status = 0; s.body = "<html><body>Login</body></html>" }, "keine Prometheus-Metriken"},
		{"redirect", func(s *testServer) {
			s.handler = func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "http://evil.example/steal", http.StatusFound)
			}
		}, "Weiterleitungen"},
		{"protobuf", func(s *testServer) {
			s.handler = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily")
				_, _ = w.Write([]byte{1, 2, 3})
			}
		}, "Protobuf"},
		{"zeitlimit", func(s *testServer) {
			s.handler = func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-r.Context().Done():
				case <-time.After(5 * time.Second):
				}
			}
		}, "Zeitlimit"},
		{"geheimnis im fehler", func(s *testServer) {
			s.handler = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				_, _ = w.Write([]byte("kein gzip " + testSecret))
			}
		}, "gzip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts.set(func(s *testServer) { s.status, s.handler, s.body = 0, nil, "nginx_up 1\n"; tc.set(s) })
			_, err := c.Collect(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Fehler %v, erwartet %q", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), testSecret) {
				t.Errorf("Geheimnis im Fehler: %v", err)
			}
		})
	}
}

func TestCollectSizeLimits(t *testing.T) {
	big := strings.Repeat("a_metric_with_a_long_name{label=\"value\"} 1\n", 5000) // ~220 KB
	ts := &testServer{body: big}
	srv := httptest.NewServer(ts)
	defer srv.Close()
	c, err := New(Config{URL: srv.URL, Map: fakeMap, Limits: Limits{MaxBytes: 100 << 10}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Collect(context.Background()); !errors.Is(err, ErrTooLarge) && (err == nil || !strings.Contains(err.Error(), "zu groß")) {
		t.Errorf("unkomprimiert: %v", err)
	}
	// gzip-Bombe: klein uebertragen, gross entpackt
	ts.set(func(s *testServer) { s.gz = true; s.body = strings.Repeat("a 1\n", 1<<20) })
	if _, err := c.Collect(context.Background()); err == nil || !strings.Contains(err.Error(), "zu groß") {
		t.Errorf("gzip: %v", err)
	}
	// zu viele Serien
	c2, _ := New(Config{URL: srv.URL, Map: fakeMap, Limits: Limits{MaxSeries: 10}})
	ts.set(func(s *testServer) { s.gz = false; s.body = strings.Repeat("a 1\n", 20) })
	if _, err := c2.Collect(context.Background()); !errors.Is(err, ErrTooManySeries) {
		t.Errorf("Serien: %v", err)
	}
}

func TestTLSPinning(t *testing.T) {
	ts := &testServer{body: fixtureText(t, "node_exporter-1.12.1.txt")}
	srv := httptest.NewUnstartedServer(ts)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // abgelehnte Handshakes sind hier gewollt
	srv.StartTLS()
	defer srv.Close()
	fp := proxmox.CertFingerprint(srv.Certificate().Raw)

	// ohne Pin, Zertifikat unbekannt: NeedConfirm, Zugangsdaten nicht gesendet
	c, err := New(Config{URL: srv.URL, Secret: testSecret, Map: fakeMap})
	if err != nil {
		t.Fatal(err)
	}
	res := c.Test(context.Background())
	if res.OK || !res.NeedConfirm || res.Fingerprint != fp || res.Trusted {
		t.Errorf("unbestaetigt: %+v", res)
	}
	if ts.hits.Load() != 0 {
		t.Errorf("Anfrage trotz unbestaetigtem Zertifikat (%d)", ts.hits.Load())
	}
	if _, err := c.Collect(context.Background()); !errors.Is(err, ErrUnconfirmed) {
		t.Errorf("Collect: %v", err)
	}

	// mit passendem Pin (Doppelpunkte, Grossbuchstaben)
	pin := strings.ToUpper(fp[:2] + ":" + fp[2:])
	c, err = New(Config{URL: srv.URL, Secret: testSecret, Pin: pin, Map: fakeMap})
	if err != nil {
		t.Fatal(err)
	}
	res = c.Test(context.Background())
	if !res.OK || res.Fingerprint != fp || res.Version != "node_exporter 1.12.1" || !strings.Contains(res.Summary, "4 Dienste") || res.Warning != "" {
		t.Errorf("Pin: %+v", res)
	}
	if ts.lastAuth() != "Bearer "+testSecret {
		t.Errorf("Auth %q", ts.lastAuth())
	}

	// falscher Pin
	c, _ = New(Config{URL: srv.URL, Pin: strings.Repeat("ab", 32), Map: fakeMap})
	if _, err := c.Collect(context.Background()); !errors.Is(err, ErrPinMismatch) {
		t.Errorf("falscher Pin: %v", err)
	}
	if _, err := New(Config{URL: srv.URL, Pin: "xyz"}); err == nil {
		t.Error("ungueltiger Pin angenommen")
	}

	// vertrauenswuerdige CA (Testwurzel) ohne Pin
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	c, _ = New(Config{URL: srv.URL, Map: fakeMap, roots: roots})
	res = c.Test(context.Background())
	if !res.OK || !res.Trusted || res.NeedConfirm {
		t.Errorf("CA: %+v", res)
	}
}

func TestTestWarnings(t *testing.T) {
	ts := &testServer{body: "nginx_up 1\n"}
	srv := httptest.NewServer(ts)
	defer srv.Close()
	c, _ := New(Config{URL: srv.URL, Secret: testSecret})
	res := c.Test(context.Background())
	if !res.OK || !strings.Contains(res.Warning, "unverschlüsselt") || !strings.Contains(res.Warning, "eigene Metriken eintragen") ||
		res.Version != "Unbekannter Exporter" {
		t.Errorf("%+v", res)
	}
	c, _ = New(Config{URL: srv.URL, Metrics: []CustomMetric{{Name: "nginx_up"}}})
	res = c.Test(context.Background())
	if !res.OK || res.Warning != "" || !strings.Contains(res.Summary, "1 Dienste") {
		t.Errorf("mit eigener Metrik: %+v", res)
	}
	ts.set(func(s *testServer) { s.status = 401 })
	res = c.Test(context.Background())
	if res.OK || !strings.Contains(res.Error, "Anmeldung") {
		t.Errorf("401: %+v", res)
	}
}

func TestPartialCollectorFailure(t *testing.T) {
	base := fixtureText(t, "windows_exporter-0.32.txt")
	ts := &testServer{body: base}
	srv := httptest.NewServer(ts)
	defer srv.Close()
	c, _ := New(Config{URL: srv.URL, Map: fakeMap})
	svcs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n := len(svcs)
	// Dienst-Sammler faellt aus: keine Dienste-Serien, success 0
	broken := strings.ReplaceAll(base, `windows_exporter_collector_success{collector="service"} 1`, `windows_exporter_collector_success{collector="service"} 0`)
	var b strings.Builder
	for _, ln := range strings.Split(broken, "\n") {
		if !strings.HasPrefix(ln, "windows_service_") {
			b.WriteString(ln + "\n")
		}
	}
	ts.set(func(s *testServer) { s.body = b.String() })
	for round := 0; round < 2; round++ { // auch in der zweiten Runde noch Teilfehler (Schluessel bleiben gemerkt)
		svcs, err = c.Collect(context.Background())
		var pe *apis.PartialError
		if !errors.As(err, &pe) || strings.Join(pe.Prefixes, ",") != "winsvc:" || !pe.Affects("winsvc:Themes") || pe.Affects("cpu") {
			t.Fatalf("Runde %d: %v", round, err)
		}
		if len(svcs) != n-3 {
			t.Errorf("Runde %d: %d Dienste", round, len(svcs))
		}
	}
	ts.set(func(s *testServer) { s.body = base })
	if _, err := c.Collect(context.Background()); err != nil {
		t.Errorf("wieder gut: %v", err)
	}
	// Sammler ohne vorherige Dienste (z. B. bonding ohne Bond) ist kein Teilfehler
	ts.set(func(s *testServer) { s.body = fixtureText(t, "node_exporter-1.12.1.txt") })
	c2, _ := New(Config{URL: srv.URL, Map: fakeMap})
	for i := 0; i < 2; i++ {
		if _, err := c2.Collect(context.Background()); err != nil {
			t.Errorf("node: %v", err)
		}
	}
}

func TestCustomMetrics(t *testing.T) {
	text := `# TYPE nginx_connections_active gauge
nginx_connections_active 12
# TYPE http_requests_total counter
http_requests_total{code="200",method="get"} 1000
http_requests_total{code="500",method="get"} 10
temp_millicelsius{sensor="a"} 45500
bad_value NaN
`
	ts := &testServer{body: text}
	srv := httptest.NewServer(ts)
	defer srv.Close()
	cm := []CustomMetric{
		{Name: "nginx_connections_active", Title: "Verbindungen"},
		{Name: "http_requests_total", Rate: true, Unit: "1/s"},
		{Name: "http_requests_total", Labels: map[string]string{"code": "500"}, Title: "Fehler", Rate: true},
		{Name: "temp_millicelsius", Factor: 0.001, Unit: "°C"},
		{Name: "bad_value"},
		{Name: "fehlt_ganz"},
	}
	c, err := New(Config{URL: srv.URL, Metrics: cm})
	if err != nil {
		t.Fatal(err)
	}
	now := testNow
	c.now = func() time.Time { return now }
	svcs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]model.Service{}
	for _, s := range svcs {
		by[s.Key] = s
		if s.Kind != "prom" || !s.Default {
			t.Errorf("Art/Default %+v", s)
		}
	}
	if len(svcs) != 5 {
		t.Errorf("%d Dienste: %v", len(svcs), keys(by))
	}
	if s := by["prom:nginx_connections_active"]; s.Name != "Verbindungen" || len(s.Metrics) != 1 || s.Metrics[0].Value != 12 {
		t.Errorf("gauge %+v", s)
	}
	if s := by[`prom:temp_millicelsius{sensor="a"}`]; len(s.Metrics) != 1 || s.Metrics[0].Value != 45.5 || s.Metrics[0].Unit != "°C" || s.Text != "45.5 °C" {
		t.Errorf("Faktor %+v", s)
	}
	k200 := `prom:http_requests_total{code="200",method="get"}`
	if s := by[k200]; len(s.Metrics) != 0 || s.Name != "http_requests_total (code=200, method=get)" {
		t.Errorf("Rate erste Runde %+v", s)
	}
	if s := by["prom:bad_value"]; len(s.Metrics) != 0 || s.Text == "" {
		t.Errorf("NaN %+v", s)
	}
	// zweite Runde: Rate
	now = now.Add(10 * time.Second)
	ts.set(func(s *testServer) {
		s.body = strings.ReplaceAll(strings.ReplaceAll(text, "} 1000", "} 1500"), `"500",method="get"} 10`, `"500",method="get"} 5`)
	})
	svcs, _ = c.Collect(context.Background())
	by = map[string]model.Service{}
	for _, s := range svcs {
		by[s.Key] = s
	}
	if s := by[k200]; len(s.Metrics) != 1 || s.Metrics[0].Value != 50 || s.Metrics[0].Unit != "1/s" {
		t.Errorf("Rate %+v", s)
	}
	if s := by[`prom:http_requests_total{code="500",method="get"}`]; len(s.Metrics) != 0 { // Zaehler zurueckgesetzt
		t.Errorf("Reset %+v", s)
	}
}

func TestValidateCustomAndKeys(t *testing.T) {
	bad := [][]CustomMetric{
		{{Name: ""}},
		{{Name: "1abc"}},
		{{Name: "a b"}},
		{{Name: "ok", Unit: strings.Repeat("x", 17)}},
		{{Name: "ok", Labels: map[string]string{"": "x"}}},
		make([]CustomMetric, MaxCustom+1),
	}
	for i, l := range bad {
		if err := ValidateCustom(l); err == nil {
			t.Errorf("%d: angenommen", i)
		}
	}
	if err := ValidateCustom([]CustomMetric{{Name: "node_x:y_total", Labels: map[string]string{"a": ""}}}); err != nil {
		t.Error(err)
	}
	s := Sample{Name: "m", Labels: []Label{{"z", strings.Repeat("v", 300)}, {"a", "1"}}}
	k := customKey(&s)
	if len(k) > maxCustomKeyLength || !strings.HasPrefix(k, `prom:m{a="1",z=`) || !strings.Contains(k, "#") {
		t.Errorf("Schluessel %q (%d)", k, len(k))
	}
	if customKey(&s) != k {
		t.Error("Schluessel nicht stabil")
	}
}

func TestQueries(t *testing.T) {
	c, _ := New(Config{URL: "host", Metrics: []CustomMetric{{Name: "x"}}})
	q := c.Queries()
	if !strings.Contains(q[0], "http://host:9100/metrics") || q[len(q)-1] != "eigene Metrik: x" {
		t.Errorf("%v", q)
	}
	if _, err := New(Config{URL: "host", User: "a:b"}); err == nil {
		t.Error("Benutzer mit Doppelpunkt angenommen")
	}
}

func TestCollectWithoutMapper(t *testing.T) {
	srv := httptest.NewServer(&testServer{body: fixtureText(t, "node_exporter-1.12.1.txt")})
	defer srv.Close()
	c, _ := New(Config{URL: srv.URL})
	if _, err := c.Collect(context.Background()); err == nil {
		t.Error("ohne Mapper kein Fehler")
	}
}
