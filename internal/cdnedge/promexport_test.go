package cdnedge

import (
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Prometheus: nur erlaubte Adresse mit Token; Token-Datei wird mit 0600 angelegt; Inhalt mit Verkehr je Name/Account.
func TestMetricsExport(t *testing.T) {
	back, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer back.Close()
	go func() {
		for {
			c, err := back.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); b := make([]byte, 10); n, _ := c.Read(b); _, _ = c.Write(b[:n]) }()
		}
	}()
	cf, kf, pool, _ := testCA(t, "edge.test")
	dir := t.TempDir()
	maddr := freeAddr(t)
	cfg := &Config{Name: "srvT", Location: "nbg", ListenHTTP: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: dir, PortRange: "1024-65535",
		MetricsListen: maddr, MetricsAllow: []string{"127.0.0.1/32", "::1"}, MetricsTokenFile: filepath.Join(dir, "metrics-token")}
	s := startEdge(t, cfg, pool)
	s.targetOK = func(a netip.Addr) bool { return a.IsLoopback() }
	listen := freeListenPort(t, "tcp")
	s.applyConfig(&apiConfig{Hosts: []apiHost{{ID: 7, Name: "m.test", Mode: 3, UserID: 42,
		Target:   &apiTarget{Addrs: []string{"127.0.0.1"}, Port: 80, Scheme: "http"},
		Mappings: []apiMapping{{Listen: listen, Transport: "tcp", Port: port(back.Addr().String())}}}}})
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(listen), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("hello"))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Read(make([]byte, 10))
	c.Close()

	// Token-Datei
	var tok string
	for i := 0; i < 50; i++ {
		if b, err := os.ReadFile(cfg.MetricsTokenFile); err == nil {
			tok = strings.TrimSpace(string(b))
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(tok) != 64 {
		t.Fatalf("token: %q", tok)
	}
	if fi, _ := os.Stat(cfg.MetricsTokenFile); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode %v", fi.Mode().Perm())
	}
	get := func(token string) (int, string) {
		req, _ := http.NewRequest("GET", "http://"+maddr+"/metrics", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := get(""); code != http.StatusForbidden {
		t.Fatalf("without token: %d", code)
	}
	if code, _ := get(strings.Repeat("0", 64)); code != http.StatusForbidden {
		t.Fatalf("wrong token: %d", code)
	}
	var body string
	for i := 0; i < 50; i++ { // Verkehr wird beim Schliessen gezaehlt
		code, b := get(tok)
		if code != http.StatusOK {
			t.Fatalf("with token: %d %s", code, b)
		}
		body = b
		if strings.Contains(body, `cdn64_edge_host_bytes_total{server="srvT",host="m.test",mode="3",account_id="42",direction="in"} 5`) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, want := range []string{
		`cdn64_edge_info{server="srvT",version=`,
		`cdn64_edge_hosts{server="srvT",mode="3"} 1`,
		`cdn64_edge_accounts{server="srvT"} 1`,
		`cdn64_edge_account_bytes_total{server="srvT",account_id="42",direction="in"} 5`,
		`cdn64_edge_host_bytes_total{server="srvT",host="m.test",mode="3",account_id="42",direction="in"} 5`,
		`cdn64_edge_portmap_ports{server="srvT",transport="tcp"} 1`,
		`cdn64_edge_guard_rejected_total{server="srvT",reason="blocklist"} 0`,
		`cdn64_edge_tunnel_connections{server="srvT",transport="quic"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	if t.Failed() {
		t.Log(body)
	}
}

func TestMetricsConfig(t *testing.T) {
	if _, err := parseAllow([]string{"10.0.0.0/8", "2001:db8::1", " "}); err != nil {
		t.Fatal(err)
	}
	if _, err := parseAllow([]string{"kein-netz"}); err == nil {
		t.Fatal("invalid entry must fail")
	}
	// ohne metrics_allow bleibt der Port zu
	s := &Server{cfg: &Config{MetricsListen: "127.0.0.1:0"}}
	if err := s.startMetrics(); err != nil || len(s.lns) != 0 {
		t.Fatalf("port must stay closed without metrics_allow: %v %d", err, len(s.lns))
	}
}
