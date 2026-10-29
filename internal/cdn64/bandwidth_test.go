package cdn64

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// Bandbreite: Grenze je Host, gemeinsam fuer alle Anfragen, Aendern wirkt auf den vorhandenen Eimer, 0 = unbegrenzt.
func TestBandwidthSet(t *testing.T) {
	var s bwSet
	if s.of(1, 0, 0) != nil {
		t.Fatal("unlimited host must not get limiters")
	}
	p := s.of(1, 8, 0) // 8 Mbit/s = 1 MB/s
	if p.down.Limit() != rate.Limit(1e6) || p.up.Limit() != rate.Inf || p.down.Burst() != 100000 {
		t.Fatalf("limits: %v %v burst %d", p.down.Limit(), p.up.Limit(), p.down.Burst())
	}
	if q := s.of(1, 80, 1); q != p || p.down.Limit() != rate.Limit(1e7) || p.up.Limit() != rate.Limit(125000) || p.up.Burst() != 16<<10 {
		t.Fatalf("update: same=%v %v %v burst %d", q == p, p.down.Limit(), p.up.Limit(), p.up.Burst())
	}
	if s.of(1, 0, 0) != nil || len(s.m) != 0 {
		t.Fatal("back to unlimited must drop the host")
	}
}

// Schreiben und Lesen warten auf ihren Anteil: 1 Mbit/s = 125 000 B/s, 250 000 B dauern gut 1,5 s (ein Eimer vorab).
func TestBandwidthShape(t *testing.T) {
	var s bwSet
	p := s.of(2, 1, 1)
	data := make([]byte, 250000)
	var out bytes.Buffer
	start := time.Now()
	if n, err := bwWrite(context.Background(), p.down, &out, data); err != nil || n != len(data) || out.Len() != len(data) {
		t.Fatalf("write: %d %v", n, err)
	}
	if d := time.Since(start); d < 1700*time.Millisecond || d > 4*time.Second {
		t.Fatalf("download not shaped: %v", d)
	}
	start = time.Now()
	b := &bwBody{ReadCloser: io.NopCloser(bytes.NewReader(data)), ctx: context.Background(), l: p.up, n: new(atomic.Int64)}
	got, err := io.ReadAll(b)
	if err != nil || len(got) != len(data) || b.n.Load() != int64(len(data)) {
		t.Fatalf("read: %d %v", len(got), err)
	}
	if d := time.Since(start); d < 1700*time.Millisecond {
		t.Fatalf("upload not shaped: %v", d)
	}
	// abgebrochene Anfrage wartet nicht weiter
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := bwWrite(ctx, p.down, io.Discard, data); err == nil {
		t.Fatal("cancelled write must stop")
	}
	// unbegrenzt: sofort
	start = time.Now()
	if _, err := bwWrite(context.Background(), nil, io.Discard, make([]byte, 50<<20)); err != nil || time.Since(start) > time.Second {
		t.Fatal("unlimited write slowed down")
	}
}

// Proxy-Host mit Grenze: Download und Upload laufen gebremst durch, ohne Grenze sofort; Aendern wirkt ohne Neustart.
func TestBandwidthProxyHost(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	big := make([]byte, 250000)
	_, _ = crand.Read(big)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			n, _ := io.Copy(io.Discard, r.Body)
			_, _ = io.WriteString(w, strconv.FormatInt(n, 10))
			return
		}
		_, _ = w.Write(big)
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)
	bport, _ := strconv.Atoi(bu.Port())
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"bw.test"}, "127.0.0.1", bport, CertNone
	h.Advanced.Gzip, h.Advanced.BWDownMbit, h.Advanced.BWUpMbit = false, 1, 1
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	timed := func(method string, body io.Reader) (int, string, time.Duration) {
		t.Helper()
		req, _ := http.NewRequest(method, "http://bw.test/", body)
		start := time.Now()
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b), time.Since(start)
	}
	c.Timeout = 20 * time.Second
	if code, body, d := timed("GET", nil); code != 200 || len(body) != len(big) || d < 1500*time.Millisecond {
		t.Fatalf("limited download: %d %d %v", code, len(body), d)
	}
	if code, body, d := timed("POST", bytes.NewReader(big)); code != 200 || body != strconv.Itoa(len(big)) || d < 1500*time.Millisecond {
		t.Fatalf("limited upload: %d %q %v", code, body, d)
	}
	rows, _ := e.m.rowsOf(ctx, KindProxy)
	if page := renderHosts(t, listData{Kind: KindProxy, Rows: rows}); !strings.Contains(page, "data-bw-badge") || !strings.Contains(page, "↓1 ↑1 Mbit/s") {
		t.Fatal("host list misses the bandwidth badge")
	}
	if form := aiRender(t, "host_form.html", e.m.form(ctx, h, false)); !strings.Contains(form, `name="adv_bw_down" value="1"`) || !strings.Contains(form, `name="adv_bw_up" value="1"`) {
		t.Fatal("host form misses the bandwidth fields")
	}
	h.Advanced.BWDownMbit, h.Advanced.BWUpMbit = 0, 0
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if code, body, d := timed("GET", nil); code != 200 || len(body) != len(big) || d > time.Second {
		t.Fatalf("unlimited download: %d %d %v", code, len(body), d)
	}
	h.Advanced.BWDownMbit = bwMaxMbit + 1
	var fe *FieldError
	if err := e.m.saveHost(ctx, h); !errors.As(err, &fe) || fe.Key != "cdn64.err.bandwidth" {
		t.Fatalf("too high: %v", err)
	}
}

// Stream mit Grenze: TCP zum Besucher und UDP vom Besucher gebremst, ohne Grenze sofort; kein Neustart beim Aendern.
func TestBandwidthStream(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	big := make([]byte, 250000)
	_, _ = crand.Read(big)
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = c.Write(big); c.Close() }()
		}
	}()
	ul, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	var got atomic.Int64
	go func() {
		b := make([]byte, 64<<10)
		for {
			n, _, err := ul.ReadFrom(b)
			if err != nil {
				return
			}
			got.Add(int64(n))
		}
	}()
	_, tport, _ := net.SplitHostPort(tl.Addr().String())
	_, uport, _ := net.SplitHostPort(ul.LocalAddr().String())
	sp := freePort(t)
	st := &Stream{Enabled: true, ListenPort: sp, TCP: true, TargetHost: "127.0.0.1", BWDownMbit: 1}
	st.TargetPort, _ = strconv.Atoi(tport)
	if err := e.m.saveStream(ctx, st); err != nil {
		t.Fatal(err)
	}
	su := &Stream{Enabled: true, ListenPort: sp, UDP: true, TargetHost: "127.0.0.1", BWUpMbit: 1}
	su.TargetPort, _ = strconv.Atoi(uport)
	if err := e.m.saveStream(ctx, su); err != nil {
		t.Fatal(err)
	}
	download := func() time.Duration {
		t.Helper()
		c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(sp))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		start := time.Now()
		b, _ := io.ReadAll(c)
		if len(b) != len(big) {
			t.Fatalf("tcp: %d bytes", len(b))
		}
		return time.Since(start)
	}
	if d := download(); d < 1500*time.Millisecond {
		t.Fatalf("limited tcp not shaped: %v", d)
	}
	uc, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	start := time.Now()
	for i := 0; i < 12; i++ { // 120 000 B in 0,55 s gesendet, bei 125 000 B/s erst nach gut 0,8 s durch (Puffer klein halten)
		_, _ = uc.Write(make([]byte, 10000))
		time.Sleep(50 * time.Millisecond)
	}
	for i := 0; i < 500 && got.Load() < 120000; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if d := time.Since(start); got.Load() != 120000 || d < 750*time.Millisecond {
		t.Fatalf("limited udp: %d bytes in %v", got.Load(), d)
	}
	e.m.smu.Lock()
	run := e.m.runs[st.ID]
	e.m.smu.Unlock()
	st.BWDownMbit = 0
	if err := e.m.saveStream(ctx, st); err != nil {
		t.Fatal(err)
	}
	e.m.smu.Lock()
	same := e.m.runs[st.ID] == run
	e.m.smu.Unlock()
	if d := download(); !same || d > time.Second {
		t.Fatalf("unlimited tcp: restart=%v %v", !same, d)
	}
	st.BWUpMbit = -1
	var fe *FieldError
	if err := e.m.saveStream(ctx, st); !errors.As(err, &fe) || fe.Key != "cdn64.err.bandwidth" {
		t.Fatalf("negative: %v", err)
	}
	// Oberflaeche: Felder im Formular, Abzeichen in der Liste
	fd := e.m.streamFormData(ctx, su, false)
	if form := renderPage(t, "stream_form.html", fd); !strings.Contains(form, `name="bw_up" value="1"`) {
		t.Fatal("stream form misses the bandwidth")
	}
	srows, _ := e.m.streamRows(ctx)
	if page := renderPage(t, "streams.html", streamsData{Streams: srows, Local: srows}); !strings.Contains(page, "↓∞ ↑1 Mbit/s") {
		t.Fatal("streams page misses the bandwidth badge")
	}
}

// TLS durchreichen mit Grenze: die verschluesselte Verbindung laeuft gebremst durch, ohne Grenze sofort.
func TestBandwidthPassthrough(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	big := make([]byte, 250000)
	_, _ = crand.Read(big)
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(big) }))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)
	bport, _ := strconv.Atoi(bu.Port())
	h := newHostKind(KindPass)
	h.Names, h.TargetHost, h.TargetPort = []string{"pass.test"}, "127.0.0.1", bport
	h.Advanced.BWDownMbit = 1
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	get := func() time.Duration {
		t.Helper()
		c := e.client(false)
		c.Timeout = 20 * time.Second
		start := time.Now()
		resp, err := c.Get("https://pass.test/")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if len(b) != len(big) {
			t.Fatalf("passthrough: %d bytes", len(b))
		}
		return time.Since(start)
	}
	if d := get(); d < 1500*time.Millisecond {
		t.Fatalf("limited passthrough not shaped: %v", d)
	}
	h.Advanced.BWDownMbit = 0
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if d := get(); d > time.Second {
		t.Fatalf("unlimited passthrough: %v", d)
	}
	h.Advanced.BWUpMbit = 2
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if form := aiRender(t, "host_form.html", e.m.form(ctx, h, false)); !strings.Contains(form, `name="has_bw"`) || !strings.Contains(form, `name="adv_bw_up" value="2"`) {
		t.Fatal("passthrough form misses the bandwidth")
	}
	rows, _ := e.m.rowsOf(ctx, KindPass)
	if page := renderPage(t, "streams.html", streamsData{Pass: rows}); !strings.Contains(page, "↓∞ ↑2 Mbit/s") {
		t.Fatal("passthrough list misses the bandwidth badge")
	}
}
