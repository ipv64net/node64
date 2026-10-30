package edge

import (
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Debug-Beobachter: unbekannte Namen (mit Status), gescheiterte TLS-Handshakes und kein TLS auf 443; Anfragen an
// bekannte Namen gehen nicht an ihn.
func TestEdgeWatch(t *testing.T) {
	e, cfg := newEdge(t, nil)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: app}}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	got := map[string]int{}
	var unk string
	e.SetWatch(func(ip netip.Addr, host, method, path string, status int, kind string) {
		mu.Lock()
		defer mu.Unlock()
		if ip.String() != "127.0.0.1" {
			t.Errorf("ip %s (%s)", ip, kind)
		}
		got[kind]++
		if kind == WatchUnknown {
			unk = host + path + " " + strconv.Itoa(status)
		}
	})
	c := client(cfg, false)
	if code, _, _, _ := get(t, c, "https://app.test/"); code != 200 {
		t.Fatalf("app: %d", code)
	}
	get(t, c, "http://fremd.test/x?y=1")
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(cfg.HTTPSPort))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	_, _ = io.Copy(io.Discard, conn)
	conn.Close()
	cfg.Default = DefaultClose // unbekannter Name: Handshake scheitert
	if err := e.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	if code, _, _, _ := get(t, c, "https://unknown.test/"); code != 0 {
		t.Fatalf("unknown name must fail the handshake: %d", code)
	}
	want := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return got[WatchUnknown] == 1 && got[WatchNoTLS] == 1 && got[WatchTLS] >= 1 && unk == "fremd.test/x?y=1 404"
	}
	for i := 0; i < 50 && !want(); i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if !want() {
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("watch: %v %q", got, unk)
	}
	e.SetWatch(nil)
	get(t, c, "http://fremd.test/")
	mu.Lock()
	defer mu.Unlock()
	if got[WatchUnknown] != 1 {
		t.Fatalf("after SetWatch(nil): %v", got)
	}
}
