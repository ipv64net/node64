package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/geoip"
	"github.com/ipv64net/node64/internal/honeypot"
)

// TestMain: Laenderdaten in Tests nie von ipv64.net laden (Honeypot64 fordert sie beim Start an).
func TestMain(m *testing.M) {
	os.Setenv(geoip.EnvBase, "http://127.0.0.1:1/")
	os.Exit(m.Run())
}

// writeGeoCache legt Laenderdaten als Zwischenspeicher unter <dataDir>/geoip ab (wie nach einem Abruf).
func writeGeoCache(t *testing.T, dataDir, data string) {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = io.WriteString(w, data)
	_ = w.Close()
	if err := os.MkdirAll(filepath.Join(dataDir, "geoip"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "geoip", "country_ranges.txt.gz"), b.Bytes(), 0o640); err != nil {
		t.Fatal(err)
	}
}

func waitGeo(t *testing.T, loaded bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for geoip.Current().Loaded != loaded {
		if time.Now().After(deadline) {
			t.Fatalf("geoip loaded = %v expected", loaded)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestHPInfoCountries: Info-Seite ohne und mit Laenderdaten (Flaggen an Top-IPs, Herkunft nach Land), Prometheus je Land.
func TestHPInfoCountries(t *testing.T) {
	h, _ := newTestHPInfo(t, "")
	body := hpDo(h, "GET", "/", "127.0.0.1:1", map[string]string{"Accept-Language": "de"}).Body.String()
	if !strings.Contains(body, "Herkunft nach Land (7 Tage)") || !strings.Contains(body, "Noch keine Länderdaten") || strings.Contains(body, "\U0001F1E9\U0001F1EA") {
		t.Fatalf("page without country data:\n%s", body)
	}
	if strings.Contains(body, `<svg class="map"`) {
		t.Fatal("no map without country data")
	}
	dir := t.TempDir()
	writeGeoCache(t, dir, "DE 192.0.2.0 192.0.2.255\nUS 198.51.100.0 198.51.100.255\n")
	release := geoip.Start(dir, "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer release()
	waitGeo(t, true)
	h.mu.Lock()
	h.at = time.Time{} // Zwischenspeicher der Statistik verwerfen
	h.mu.Unlock()
	body = hpDo(h, "GET", "/", "127.0.0.1:1", map[string]string{"Accept-Language": "de"}).Body.String()
	for _, s := range []string{"\U0001F1E9\U0001F1EA <small>DE</small>", `title="Deutschland"`, "Vereinigte Staaten", "<progress max="} {
		if !strings.Contains(body, s) {
			t.Errorf("page lacks %q", s)
		}
	}
	if !strings.Contains(hpDo(h, "GET", "/", "127.0.0.1:1", nil).Body.String(), `title="Germany"`) {
		t.Error("english country name expected")
	}
	// Laenderkarte: DE und US je 1 Ereignis (Stufe 5), Rest neutral, Legende; ohne Inline-Styles (CSP)
	for _, s := range []string{`<svg class="map" viewBox="0 0 `, `<path class="m5"`, `<path class="m0"`, "<title>\U0001F1E9\U0001F1EA Deutschland: 1 Ereignisse, 1 IPs</title>",
		`<span class="sw m5"></span> 1</p>`, "Herkunft auf der Karte (7 Tage)"} {
		if !strings.Contains(body, s) {
			t.Errorf("map lacks %q", s)
		}
	}
	if strings.Contains(body, "style=") || strings.Contains(body, " fill=") {
		t.Error("info page must not use inline styles")
	}
	honeypot.CountEvents(func(honeypot.Event) {})(honeypot.Event{Src: netip.MustParseAddr("192.0.2.99"), Kind: honeypot.KindProbe})
	m := hpDo(h, "GET", "/metrics", "127.0.0.1:1", nil).Body.String()
	if !strings.Contains(m, `node64_honeypot_events_by_country_total{country="DE"}`) {
		t.Errorf("metrics lack country:\n%s", m)
	}
}

// TestHoneypotRunGeo: der Modus ohne Oberflaeche fordert die Laenderdaten an (aus dem Zwischenspeicher sofort nutzbar)
// und gibt sie beim Beenden zurueck.
func TestHoneypotRunGeo(t *testing.T) {
	dir := t.TempDir()
	writeGeoCache(t, dir, "NL 203.0.113.0 203.0.113.255\n")
	hc, err := honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_SERVICES": "tcp:" + strconv.Itoa(hpFreePort(t)),
		"NODE64_HONEYPOT_INFO_PORT": strconv.Itoa(hpFreePort(t)), "NODE64_HONEYPOT_SCAN": "0"}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready, done := make(chan string, 1), make(chan error, 1)
	go func() {
		done <- honeypotRun(ctx, &config.Config{DataDir: dir, BindAddr: "127.0.0.1"}, hc, slog.New(slog.NewTextHandler(io.Discard, nil)), func(info string) { ready <- info })
	}()
	var info string
	select {
	case info = <-ready:
	case err := <-done:
		t.Fatalf("run ended early: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("run did not become ready")
	}
	waitGeo(t, true)
	if cc, ok := geoip.Lookup(netip.MustParseAddr("203.0.113.7")); !ok || cc != "NL" {
		t.Fatalf("lookup %q %v", cc, ok)
	}
	resp, err := http.Get("http://" + info + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("run did not stop")
	}
	waitGeo(t, false)
}
