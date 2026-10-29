package cdn64

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"errors"
	"io"
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
