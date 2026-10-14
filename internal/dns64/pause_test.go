package dns64

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/filter"
)

func TestPauseBlocking(t *testing.T) {
	m, port := testModule(t)
	ctx := context.Background()
	// eine Blockliste mit ads.example.com vorab ablegen (Dateiname wie filter: list-<sha256(url)[:6]>.txt)
	h := sha256.Sum256([]byte(filter.DefaultLists[0].URL))
	dir := filepath.Join(m.dir(), "lists")
	_ = os.MkdirAll(dir, 0o755)
	if err := os.WriteFile(filepath.Join(dir, "list-"+hex.EncodeToString(h[:6])+".txt"), []byte("0.0.0.0 ads.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// waehrend der Pause geht die Domain an den Upstream (Antwort egal, nur nicht mehr 0.0.0.0)
	if err := m.Start(ctx); err != nil || m.running() == nil {
		t.Fatalf("start: %v %s", err, m.startError())
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ask := func() *dns.Msg {
		c := &dns.Client{Timeout: 10 * time.Second}
		q := new(dns.Msg)
		q.SetQuestion("ads.example.com.", dns.TypeA)
		r, _, err := c.Exchange(q, addr)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	isBlocked := func(r *dns.Msg) bool {
		a, ok := firstA(r)
		return ok && a == "0.0.0.0"
	}
	if !isBlocked(ask()) {
		t.Fatal("not blocked before pause")
	}
	if err := m.setPaused(ctx, 0, "test"); err != nil || !m.paused() {
		t.Fatal("pause failed")
	}
	if isBlocked(ask()) {
		t.Fatal("still blocked while paused")
	}
	if err := m.setPaused(ctx, -1, "test"); err != nil || m.paused() {
		t.Fatal("resume failed")
	}
	if !isBlocked(ask()) {
		t.Fatal("not blocked again after resume")
	}
	// befristete Pause: endet von selbst, auch ueber einen Neustart gemerkt
	_ = m.core.SetSetting(ctx, setPause, time.Now().Add(-time.Second).UTC().Format(time.RFC3339))
	m.loadPause(ctx)
	if m.paused() {
		t.Fatal("expired pause still active")
	}
	if err := m.setPaused(ctx, 10, "test"); err != nil {
		t.Fatal(err)
	}
	if p := m.pauseState(); !p.Active || p.Forever || time.Until(p.Until) < 9*time.Minute {
		t.Fatalf("10 min pause: %+v", p)
	}
}

func firstA(r *dns.Msg) (string, bool) {
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String(), true
		}
	}
	return "", false
}
