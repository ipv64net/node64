package cdnedge

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/tunnel"
)

// fakeAPI spielt ipv64: /cdn64o/edge/config mit ETag, /cdn64o/edge/report sammelt Meldungen.
type fakeAPI struct {
	mu      sync.Mutex
	cfg     apiConfig
	secret  string
	reports []map[string]any
	n304    int
	down    bool
}

func (f *fakeAPI) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		http.Error(w, "down", http.StatusBadGateway)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+f.secret {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/cdn64o/edge/config":
		b, _ := json.Marshal(f.cfg)
		etag := `"` + strconv.Itoa(len(b)) + f.cfg.Version + `"`
		if r.Header.Get("If-None-Match") == etag {
			f.n304++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write([]byte(`{"data":` + string(b) + `}`))
	case "/cdn64o/edge/report":
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		f.reports = append(f.reports, m)
		_, _ = w.Write([]byte(`{"data":{"changed":0}}`))
	default:
		http.NotFound(w, r)
	}
}

func TestAPIConfigAndReport(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	_, _, _, nodeCert := testCA(t, "api.test")
	tok := strings.Repeat("t", 64)
	api := &fakeAPI{secret: strings.Repeat("e", 40), cfg: apiConfig{Version: "v1",
		Tunnels: []apiTunnel{{ID: "tn_a", TokenSHA256: sha256hex(tok), UserID: 522}},
		Hosts: []apiHost{{ID: 7, Name: "api.test", Wildcard: true, Mode: 1, UserID: 522, Tunnels: []string{"tn_a"}},
			{ID: 8, Name: "gesperrt.test", Mode: 1, UserID: 522, Tunnels: []string{"tn_a"}, Blocked: "traffic"}},
		Bandwidth: map[string]int{"522": 0}}}
	hs := httptest.NewServer(http.HandlerFunc(api.handler))
	defer hs.Close()
	dir := t.TempDir()
	cfg := &Config{Name: "B", ListenHTTP: freeAddr(t), ListenHTTPS: freeAddr(t), TunnelListen: freeAddr(t), TLSCert: cf, TLSKey: kf,
		DataDir: dir, APIURL: hs.URL, APISecret: api.secret, Shield: ShieldConfig{BlocklistBase: hs.URL + "/blocklists/"}}
	s := startEdge(t, cfg, pool)
	for i := 0; i < 100 && s.apiCfg.Load() == nil; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if s.routes.Load().lookup("x.api.test") == nil || s.routes.Load().lookup("api.test").HostID != 7 {
		t.Fatal("routes from api (incl. wildcard)")
	}
	node := tunnel.NewClient(tunnel.ClientConfig{Tunnel: "tn_a", Token: tok, RootCAs: pool,
		Edges: []tunnel.Edge{{Name: "B", Host: "127.0.0.1", Port: port(cfg.TunnelListen)}},
		Handler: func(st tunnel.Stream, h tunnel.Header) {
			c := tls.Server(st, &tls.Config{Certificates: []tls.Certificate{nodeCert}})
			defer c.Close()
			if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
				return
			}
			body := strings.Repeat("x", 10000)
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
		}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go node.Run(ctx)
	for i := 0; i < 200 && s.peer("tn_a") == nil; i++ {
		time.Sleep(25 * time.Millisecond)
	}
	if s.peer("tn_a") == nil {
		t.Fatal("tunnel from api config not accepted")
	}
	c, err := tls.Dial("tcp", cfg.ListenHTTPS, &tls.Config{ServerName: "www.api.test", InsecureSkipVerify: true}) //nolint:gosec // Test
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: www.api.test\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	c.Close()
	if len(b) != 10000 {
		t.Fatalf("via wildcard: %d bytes", len(b))
	}
	// gesperrt: Port 80 bekommt 503
	req, _ := http.NewRequest("GET", "http://"+cfg.ListenHTTP+"/", nil)
	req.Host = "gesperrt.test"
	r80, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r80.Body.Close()
	if r80.StatusCode != 503 {
		t.Fatalf("blocked: %d", r80.StatusCode)
	}
	// Meldung: Differenz je Host-ID; zweite Meldung ohne neuen Traffic meldet nichts
	s.apiReport(ctx)
	s.apiReport(ctx)
	api.mu.Lock()
	reps := append([]map[string]any(nil), api.reports...)
	api.mu.Unlock()
	tr := reps[0]["traffic"].([]any)
	first := tr[0].(map[string]any)
	if len(tr) != 1 || first["host_id"].(float64) != 7 || first["bytes_out"].(float64) < 10000 || first["conns"].(float64) != 1 {
		t.Fatalf("report: %+v", reps[0])
	}
	if reps[1]["traffic"] != nil {
		t.Fatalf("second report without traffic: %+v", reps[1]["traffic"])
	}
	if tl := reps[0]["tunnels"].([]any); len(tl) != 1 || tl[0].(map[string]any)["id"] != "tn_a" {
		t.Fatalf("tunnels: %+v", reps[0]["tunnels"])
	}
	// unveraendert: 304
	s.apiFetch(ctx)
	api.mu.Lock()
	n := api.n304
	api.mu.Unlock()
	if n == 0 {
		t.Fatal("etag not used")
	}
	// Tunnel bei ipv64 entfernt: wird getrennt
	api.mu.Lock()
	api.cfg.Version, api.cfg.Tunnels = "v2", nil
	api.mu.Unlock()
	s.apiFetch(ctx)
	for i := 0; i < 100 && s.peer("tn_a") != nil; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if s.peer("tn_a") != nil {
		t.Fatal("removed tunnel still connected")
	}
	// ipv64 weg: ein neuer Server-Prozess startet mit dem Zwischenspeicher
	api.mu.Lock()
	api.down = true
	api.mu.Unlock()
	cfg2 := *cfg
	cfg2.ListenHTTP, cfg2.ListenHTTPS, cfg2.TunnelListen = freeAddr(t), freeAddr(t), freeAddr(t)
	s2 := startEdge(t, &cfg2, pool)
	for i := 0; i < 100 && s2.apiCfg.Load() == nil; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if c := s2.apiCfg.Load(); c == nil || c.Version != "v2" || s2.routes.Load().lookup("api.test") == nil {
		t.Fatal("config cache not used")
	}
}

func TestBandwidth(t *testing.T) {
	now := time.Unix(1000, 0)
	var slept time.Duration
	w := newBandwidth()
	w.now = func() time.Time { return now }
	w.sleep = func(d time.Duration) { slept += d; now = now.Add(d) }
	w.setLimits(map[int]int{1: 8}) // 8 Mbit/s = 1.000.000 B/s
	for i := 0; i < 30; i++ {      // 3 MB
		w.take(1, 100000)
	}
	if slept < 2400*time.Millisecond || slept > 3100*time.Millisecond {
		t.Fatalf("3 MB at 1 MB/s: slept %v", slept)
	}
	// Nachbar nutzt 0,75 MB/s: hier bleiben 0,25 MB/s
	slept = 0
	w.setPeer(map[int]float64{1: 750000})
	for i := 0; i < 5; i++ {
		w.take(1, 100000)
	}
	if slept < 1500*time.Millisecond {
		t.Fatalf("with peer rate: slept %v", slept)
	}
	// ohne Limit: nie warten
	slept = 0
	w.take(2, 50<<20)
	if slept != 0 {
		t.Fatal("unlimited account must not wait")
	}
	if r := w.rates(); r[1] <= 0 {
		t.Fatalf("rates: %v", r)
	}
}
