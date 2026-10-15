//go:build loadtest

package cdn64

// Lasttest (nicht im normalen Lauf): go test -tags loadtest -run TestLoad -v -timeout 20m ./internal/cdn64/
// Misst Durchsatz und Latenz ueber den gemeinsamen Eingang, viele WebSockets, grosse Uploads und den Speicher
// im Leerlauf. Client, Proxy und Ziel laufen auf derselben Maschine.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func heapMB() float64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return float64(ms.HeapAlloc) / (1 << 20)
}

func TestLoad(t *testing.T) {
	ctx := context.Background()
	idle0 := heapMB()
	e := newEnv(t)
	idleOff := heapMB()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/ws":
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer c.CloseNow()
			for {
				typ, b, err := c.Read(r.Context())
				if err != nil {
					return
				}
				if c.Write(r.Context(), typ, b) != nil {
					return
				}
			}
		case r.Method == http.MethodPost:
			n, _ := io.Copy(io.Discard, r.Body)
			_, _ = io.WriteString(w, strconv.FormatInt(n, 10))
		default:
			_, _ = w.Write(make([]byte, 1024))
		}
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)
	bport, _ := strconv.Atoi(bu.Port())
	certPEM, keyPEM := selfSigned(t, "load.test")
	if _, err := e.crt.Upload(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	e.m.SetDataDir(t.TempDir())
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.BlockExploits = []string{"load.test"}, "127.0.0.1", bport, true
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 99; i++ { // 100 Hosts insgesamt, wie eine grosse Heim-Installation
		x := newHost()
		x.Names, x.TargetHost, x.TargetPort = []string{"h" + strconv.Itoa(i) + ".load.test"}, "127.0.0.1", bport
		if err := e.m.saveHost(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	idleOn := heapMB()
	t.Logf("Heap: ohne Modul %.1f MB (Basis %.1f MB), Modul an mit 100 Hosts %.1f MB", idleOff, idle0, idleOn)

	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+strconv.Itoa(e.cfg.HTTPSPort))
	}

	// A: 1000 gleichzeitige Clients (eigene TLS-Verbindung je Client), je 20 Anfragen
	const clients, perClient = 1000, 20
	var lat []time.Duration
	var mu sync.Mutex
	var fails atomic.Int64
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DialContext: dial, MaxIdleConnsPerHost: 1, ForceAttemptHTTP2: false,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "load.test"}}} //nolint:gosec // Test
			defer c.CloseIdleConnections()
			local := make([]time.Duration, 0, perClient)
			for j := 0; j < perClient; j++ {
				t0 := time.Now()
				resp, err := c.Get("https://load.test/x")
				if err != nil {
					fails.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 {
					fails.Add(1)
				}
				local = append(local, time.Since(t0))
			}
			mu.Lock()
			lat = append(lat, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	dur := time.Since(start)
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) time.Duration {
		if len(lat) == 0 {
			return 0
		}
		return lat[int(float64(len(lat)-1)*p)]
	}
	total := clients * perClient
	t.Logf("A) %d Clients x %d Anfragen: %d in %s = %.0f/s, Fehler %d, p50 %s, p95 %s, p99 %s", clients, perClient, total, dur.Round(time.Millisecond),
		float64(total)/dur.Seconds(), fails.Load(), pct(0.5).Round(time.Microsecond), pct(0.95).Round(time.Microsecond), pct(0.99).Round(time.Microsecond))
	t.Logf("   Heap nach A: %.1f MB", heapMB())
	if fails.Load() > int64(total/100) {
		t.Errorf("mehr als 1 %% Fehler: %d", fails.Load())
	}

	// B: 500 WebSockets gleichzeitig offen, je 10 Nachrichten
	const sockets = 500
	var wsFail atomic.Int64
	conns := make([]*websocket.Conn, sockets)
	hc := &http.Client{Transport: &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "load.test"}}} //nolint:gosec // Test
	start = time.Now()
	for i := range conns {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, _, err := websocket.Dial(ctx, "wss://load.test/ws", &websocket.DialOptions{HTTPClient: hc})
			if err != nil {
				wsFail.Add(1)
				return
			}
			conns[i] = c
		}(i)
	}
	wg.Wait()
	heapWS := heapMB()
	for _, c := range conns {
		if c == nil {
			continue
		}
		wg.Add(1)
		go func(c *websocket.Conn) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if c.Write(ctx, websocket.MessageText, []byte("ping")) != nil {
					wsFail.Add(1)
					return
				}
				if _, b, err := c.Read(ctx); err != nil || string(b) != "ping" {
					wsFail.Add(1)
					return
				}
			}
		}(c)
	}
	wg.Wait()
	for _, c := range conns {
		if c != nil {
			c.CloseNow()
		}
	}
	t.Logf("B) %d WebSockets offen + je 10 Echo: %s, Fehler %d, Heap mit allen offen %.1f MB", sockets, time.Since(start).Round(time.Millisecond),
		wsFail.Load(), heapWS)
	if wsFail.Load() > 0 {
		t.Errorf("websocket errors: %d", wsFail.Load())
	}

	// C: 10 gleichzeitige Uploads zu je 100 MB (gestreamt, darf den Speicher nicht fuellen)
	const uploads, size = 10, 100 << 20
	var upFail atomic.Int64
	var peak atomic.Uint64
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				if ms.HeapAlloc > peak.Load() {
					peak.Store(ms.HeapAlloc)
				}
			}
		}
	}()
	start = time.Now()
	for i := 0; i < uploads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &http.Client{Transport: &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "load.test"}}} //nolint:gosec // Test
			resp, err := c.Post("https://load.test/up", "application/octet-stream", io.LimitReader(zeroReader{}, size))
			if err != nil {
				upFail.Add(1)
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.TrimSpace(string(b)) != strconv.Itoa(size) {
				upFail.Add(1)
			}
		}()
	}
	wg.Wait()
	close(stop)
	up := time.Since(start)
	t.Logf("C) %d Uploads x %d MB: %s = %.0f MB/s, Fehler %d, Heap-Spitze %.1f MB", uploads, size>>20, up.Round(time.Millisecond),
		float64(uploads*size>>20)/up.Seconds(), upFail.Load(), float64(peak.Load())/(1<<20))

	st := e.m.statsOf(h.ID)
	t.Logf("Zaehler Host: %d Anfragen, %d Fehler", st.requests.Load(), st.errors.Load())

	// D: Modul aus, Speicher wieder frei?
	if err := e.reg.Disable(ctx, Name); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	t.Logf("D) Heap nach Abschalten: %.1f MB, Goroutinen %d", heapMB(), runtime.NumGoroutine())
	fmt.Println()
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
