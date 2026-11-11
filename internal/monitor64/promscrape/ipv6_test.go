package promscrape

import (
	"context"
	"net"
	"net/http/httptest"
	"testing"
)

// IPv6 in der Adresse des Exporters: ohne Klammern, mit Klammern, mit Port, mit Zone (Link-Local).
func TestNormalizeURLIPv6(t *testing.T) {
	for in, want := range map[string]string{
		"fd00::1":                       "http://[fd00::1]:9100/metrics",
		"::1":                           "http://[::1]:9100/metrics",
		"[fd00::1]:9182":                "http://[fd00::1]:9182/metrics",
		"http://fd00::1":                "http://[fd00::1]/metrics",
		"https://[fd00::1]:9100/m":      "https://[fd00::1]:9100/m",
		"fe80::1%eth0":                  "http://[fe80::1%25eth0]:9100/metrics",
		"[fe80::1%eth0]:9100":           "http://[fe80::1%25eth0]:9100/metrics",
		"http://[fe80::1%25eth0]:9100/": "http://[fe80::1%25eth0]:9100/metrics",
	} {
		got, err := NormalizeURL(in, DefaultPort)
		if err != nil || got != want {
			t.Errorf("NormalizeURL(%q) = %q, Fehler %v, erwartet %q", in, got, err, want)
		}
	}
}

// Abfrage ueber IPv6: Exporter nur auf [::1].
func TestCollectOverIPv6(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("kein IPv6-Loopback:", err)
	}
	srv := httptest.NewUnstartedServer(&testServer{body: fixtureText(t, "node_exporter-1.12.1.txt")})
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	c, err := New(Config{URL: "[::1]:" + port, Secret: testSecret, Map: fakeMap})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Abfrage ueber [::1]: %v", err)
	}
}
