package web

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/config"
)

// Ein Port, beide Protokolle: HTTP wie bisher, HTTPS mit dem Zertifikat der Oberflaeche; ein stummer Client
// haelt andere nicht auf.
func TestDualPort(t *testing.T) {
	cfg := &config.Config{DataDir: t.TempDir()}
	cert, err := loadOrCreateCertificate(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dl := newDualListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			_, _ = io.WriteString(w, "tls")
			return
		}
		_, _ = io.WriteString(w, "plain")
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(dl) }()
	t.Cleanup(func() { _ = srv.Close() })
	addr := ln.Addr().String()
	// stummer Client zuerst: darf die anderen nicht blockieren
	silent, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	get := func(c *http.Client, url string) string {
		t.Helper()
		resp, err := c.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if got := get(c, "http://"+addr+"/"); got != "plain" {
		t.Fatalf("http: %q", got)
	}
	if got := get(c, "https://"+addr+"/"); got != "tls" {
		t.Fatalf("https: %q", got)
	}
}
