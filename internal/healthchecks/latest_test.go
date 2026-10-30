package healthchecks

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/proxmox"
)

// Tests holen nichts aus dem Internet: ohne eigenen Abruf bleibt die neueste Version unbekannt (kein Badge).
func init() {
	latestFetch = func(context.Context, string) (io.ReadCloser, error) { return nil, errors.New("offline in tests") }
}

// latestSet setzt den Zwischenstand einer Quelle (frisch, kein Abruf).
func latestSet(t *testing.T, key, v string) {
	t.Helper()
	latest.mu.Lock()
	latest.m[key] = &latestEntry{version: v, at: time.Now(), ok: true}
	latest.mu.Unlock()
	t.Cleanup(func() {
		latest.mu.Lock()
		delete(latest.m, key)
		latest.mu.Unlock()
	})
}

func TestVerCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"28.5.1", "28.5.1+dfsg1", 0}, {"28.10.0", "28.9.9", 1}, {"8.2.4", "8.4", -1}, {"v29.0.0", "28.99.0", 1}, {"9.0.11~1", "9.0.10", 1}} {
		if got := verCompare(c.a, c.b); got != c.want {
			t.Errorf("verCompare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if verCore("unknown") != "" || verCore("26.1.5+dfsg1") != "26.1.5" {
		t.Fatal("verCore")
	}
}

func TestLatestSources(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("Package: pve-manager\nVersion: 9.0.10\n\nPackage: pve-docs\nVersion: 9.9.9\n\nPackage: pve-manager\nVersion: 9.0.11\nArchitecture: amd64\n\n"))
	_ = zw.Close()
	fetch := func(_ context.Context, url string) (io.ReadCloser, error) {
		switch {
		case strings.Contains(url, "download.docker.com"):
			return io.NopCloser(strings.NewReader(`<a href="docker-27.5.1.tgz">x</a> <a href="docker-28.10.0.tgz">x</a> <a href="docker-28.9.1.tgz">x</a> <a href="docker-rootless-extras-29.0.0.tgz">x</a>`)), nil
		case strings.Contains(url, "/trixie/pve-no-subscription/"):
			return io.NopCloser(bytes.NewReader(gz.Bytes())), nil
		}
		return nil, errors.New("404")
	}
	if v, err := latestDocker(context.Background(), fetch); err != nil || v != "28.10.0" {
		t.Fatalf("docker: %q %v", v, err)
	}
	if v, err := latestPVE(context.Background(), fetch, 9); err != nil || v != "9.0.11" {
		t.Fatalf("pve: %q %v", v, err)
	}
	if _, err := latestPVE(context.Background(), fetch, 7); err == nil {
		t.Fatal("unknown major must fail")
	}
}

func TestLatestUpdate(t *testing.T) {
	latestSet(t, "docker", "28.5.1")
	latestSet(t, "pve/8", "8.4.14")
	latestSet(t, "pve/9", "9.0.11")
	if u := latestUpdate(proxmox.KindDocker, "28.5.1"); u != nil {
		t.Fatalf("docker current: %+v", u)
	}
	if u := latestUpdate(proxmox.KindDocker, "26.1.5+dfsg1"); u == nil || u.Latest != "28.5.1" || u.Installed != "26.1.5" || !u.Major {
		t.Fatalf("docker old: %+v", u)
	}
	if u := latestUpdate(proxmox.KindPVE, "8.2.4"); u == nil || u.Latest != "8.4.14" || u.Major { // erst die eigene Linie
		t.Fatalf("pve patch: %+v", u)
	}
	if u := latestUpdate(proxmox.KindPVE, "8.4.14"); u == nil || u.Latest != "9.0.11" || !u.Major {
		t.Fatalf("pve major: %+v", u)
	}
	if u := latestUpdate(proxmox.KindPVE, "9.0.11"); u != nil {
		t.Fatalf("pve current: %+v", u)
	}
	if u := latestUpdate(proxmox.KindPVE, ""); u != nil {
		t.Fatal("no version, no badge")
	}
}
