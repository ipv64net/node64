package apis

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// IPv6 in den Adressen der HTTPS-Zugaenge: ohne Klammern, mit Klammern, mit Port und mit Zone (Link-Local).
func TestParseWebAddrIPv6(t *testing.T) {
	for _, c := range []struct{ in, base, host, hp string }{
		{"fd00::10", "https://[fd00::10]:8006", "fd00::10", "[fd00::10]:8006"},
		{"[fd00::10]", "https://[fd00::10]:8006", "fd00::10", "[fd00::10]:8006"},
		{"[fd00::10]:8443", "https://[fd00::10]:8443", "fd00::10", "[fd00::10]:8443"},
		{"https://fd00::10", "https://[fd00::10]:8006", "fd00::10", "[fd00::10]:8006"},
		{"https://[FD00::10]:8006/", "https://[fd00::10]:8006", "fd00::10", "[fd00::10]:8006"},
		{"fe80::1%eth0", "https://[fe80::1%25eth0]:8006", "fe80::1", "[fe80::1%eth0]:8006"},
		{"https://[fe80::1%eth0]:8006", "https://[fe80::1%25eth0]:8006", "fe80::1", "[fe80::1%eth0]:8006"},
		{"https://[fe80::1%25eth0]:8006", "https://[fe80::1%25eth0]:8006", "fe80::1", "[fe80::1%eth0]:8006"},
		{"::ffff:192.168.1.5", "https://[::ffff:192.168.1.5]:8006", "::ffff:192.168.1.5", "[::ffff:192.168.1.5]:8006"},
	} {
		got, err := parseWebAddr(c.in, "https", "8006", false)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got.base != c.base || got.host != c.host || got.hostPt != c.hp {
			t.Errorf("%q: base %q host %q hostPt %q, erwartet %q %q %q", c.in, got.base, got.host, got.hostPt, c.base, c.host, c.hp)
		}
	}
}

// Abfrage ueber IPv6: Server nur auf [::1], Adresse ohne Klammern bzw. als [::1]:port.
func TestWebClientOverIPv6(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("kein IPv6-Loopback:", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"host":"` + r.Host + `"}`))
	}))
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	for _, addr := range []string{"http://[::1]:" + port, "[::1]:" + port, "http://::1"} {
		tg, err := parseWebAddr(addr, "http", port, true)
		if err != nil {
			t.Fatalf("%q: %v", addr, err)
		}
		c, err := newWebClient(tg, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var out struct {
			Host string `json:"host"`
		}
		err = c.get(ctx, "/x", &out)
		cancel()
		if err != nil || !strings.HasPrefix(out.Host, "[::1]:") {
			t.Errorf("%q: Antwort %+v, Fehler %v", addr, out, err)
		}
	}
}

// Docker: IPv6 ohne Klammern wird nicht mehr still zu Host "fd00:" und Port 1.
func TestDockerHostIPv6(t *testing.T) {
	for in, want := range map[string]string{
		"tcp://fd00::1":                             "tcp://[fd00::1]",
		"tcp://[fd00::1]:2375":                      "tcp://[fd00::1]:2375",
		"ssh://root@fd00::1":                        "ssh://root@[fd00::1]",
		"ssh://root@[fd00::1]:2222/run/podman.sock": "ssh://root@[fd00::1]:2222/run/podman.sock",
		"https://fd00::1":                           "https://[fd00::1]",
	} {
		d, err := NewDocker(DockerConfig{Host: in})
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if d.cfg.Host != want {
			t.Errorf("%q: Host %q, erwartet %q", in, d.cfg.Host, want)
		}
		d.Close()
	}
}

func TestNUTAddrIPv6(t *testing.T) {
	for in, want := range map[string]string{"fd00::5": "[fd00::5]:3493", "[fd00::5]": "[fd00::5]:3493", "nut://[fd00::5]:3500": "[fd00::5]:3500",
		"fe80::1%eth0": "[fe80::1%eth0]:3493", "[fe80::1%eth0]:3500": "[fe80::1%eth0]:3500"} {
		h, p, err := nutAddr(in)
		if got := net.JoinHostPort(h, p); err != nil || got != want {
			t.Errorf("%q: %q, Fehler %v, erwartet %q", in, got, err, want)
		}
	}
}
