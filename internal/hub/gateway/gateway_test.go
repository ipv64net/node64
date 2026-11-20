package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/hub/store"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/wire"
)

func TestChunkChanges(t *testing.T) {
	if got := chunkChanges(nil, 1000); len(got) != 1 || len(got[0]) != 0 {
		t.Fatalf("empty: %v", got)
	}
	big := json.RawMessage(`"` + strings.Repeat("x", 400) + `"`)
	var changes []wire.Change
	for i := 1; i <= 10; i++ {
		changes = append(changes, wire.Change{Entity: "check", ID: fmt.Sprint(i), Op: "upsert", Revision: int64(i), Data: big})
	}
	parts := chunkChanges(changes, 1000)
	n := 0
	for _, p := range parts {
		b, _ := json.Marshal(p)
		if len(p) == 0 || len(b) > 1000 {
			t.Fatalf("part of %d changes, %d bytes", len(p), len(b))
		}
		n += len(p)
	}
	if n != 10 || len(parts) < 4 {
		t.Fatalf("%d changes in %d parts", n, len(parts))
	}
	// ein Eintrag ueber der Grenze geht allein
	if parts := chunkChanges(changes[:2], 100); len(parts) != 2 {
		t.Fatalf("oversized: %d parts", len(parts))
	}
}

func TestSendConfigChunks(t *testing.T) {
	g := &Gateway{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c := &conn{g: g, node: &store.Node{ID: "n"}, sendQ: make(chan wire.Msg, 100)}
	big := json.RawMessage(`"` + strings.Repeat("x", 300<<10) + `"`)
	var changes []wire.Change
	for i := 1; i <= 5; i++ {
		changes = append(changes, wire.Change{Entity: "check", ID: fmt.Sprint(i), Op: "upsert", Revision: int64(i), Data: big})
	}
	c.sendConfig(changes, 9)
	close(c.sendQ)
	var msgs []map[string]any
	for m := range c.sendQ {
		if m.T != "config" || len(m.Data) > maxConfigChunk+4096 {
			t.Fatalf("message %s with %d bytes", m.T, len(m.Data))
		}
		var x map[string]any
		_ = json.Unmarshal(m.Data, &x)
		msgs = append(msgs, x)
	}
	if len(msgs) < 2 {
		t.Fatalf("expected several messages, got %d", len(msgs))
	}
	last := msgs[len(msgs)-1]
	if last["revision"].(float64) != 9 || last["more"] != nil || msgs[0]["more"] != true {
		t.Fatalf("revisions/more: first %v last %v", msgs[0]["more"], last)
	}
	if c.rev() != 9 {
		t.Fatalf("lastRev %d", c.rev())
	}
}

// lastRev wird von Leser, Worker und fanoutLoop gleichzeitig benutzt (go test -race).
func TestRevConcurrent(t *testing.T) {
	g := &Gateway{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c := &conn{g: g, node: &store.Node{ID: "n"}, sendQ: make(chan wire.Msg, 1000)}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.bumpRev(int64(i*100 + j))
				_ = c.rev()
			}
		}(i)
	}
	wg.Wait()
	if c.rev() != 399 {
		t.Fatalf("rev %d", c.rev())
	}
}

func TestClientIP(t *testing.T) {
	g := New(nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "", "", 1)
	req := func(remote, real string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if real != "" {
			r.Header.Set("X-Real-IP", real)
		}
		return g.clientIP(r)
	}
	if ip := req("127.0.0.1:5000", "203.0.113.5"); ip != "203.0.113.5" {
		t.Fatalf("proxy: %s", ip)
	}
	if ip := req("198.51.100.1:5000", "203.0.113.5"); ip != "198.51.100.1" {
		t.Fatalf("direct: %s", ip)
	}
	if ip := req("127.0.0.1:5000", "x; drop"); ip != "127.0.0.1" {
		t.Fatalf("invalid header: %s", ip)
	}
	g.SetRealIPFrom([]netip.Prefix{netip.MustParsePrefix("127.0.0.2/32")})
	if ip := req("127.0.0.1:5000", "203.0.113.5"); ip != "127.0.0.1" {
		t.Fatalf("local request must not be trusted: %s", ip)
	}
	if ip := req("127.0.0.2:5000", "203.0.113.5"); ip != "203.0.113.5" {
		t.Fatalf("configured proxy: %s", ip)
	}
}

func TestPublicError(t *testing.T) {
	body := errors.New("webhook: HTTP 500: <html>internal admin page secret</html>")
	if s := publicError(notify.TypeWebhook, body); s != "delivery failed: HTTP 500" {
		t.Fatalf("webhook: %q", s)
	}
	if s := publicError(notify.TypeTelegram, errors.New("telegram: chat not found")); s != "telegram: chat not found" {
		t.Fatalf("telegram: %q", s)
	}
	if s := publicError(notify.TypeNtfy, fmt.Errorf("post: %w", context.DeadlineExceeded)); s != "delivery failed: timeout" {
		t.Fatalf("timeout: %q", s)
	}
	if s := publicError(notify.TypeGotify, &net.OpError{Op: "dial", Err: errors.New("connection refused")}); s != "delivery failed: connection failed" {
		t.Fatalf("dial: %q", s)
	}
	if s := publicError(notify.TypeSMTP, errors.New("auth: 535 wrong password for admin@intern")); s != "delivery failed" {
		t.Fatalf("smtp: %q", s)
	}
	if publicError(notify.TypeWebhook, nil) != "" {
		t.Fatal("nil error")
	}
}

// Angenommener Vorschlag der Node (propose) hebt den Stand nur an, wenn sie direkt anschliesst: eine
// fremde Aenderung dazwischen (Portal/API, Revision 11) bleibt offen und kommt mit fanoutLoop (Test 2026-10-29).
func TestBumpRevNext(t *testing.T) {
	c := &conn{g: &Gateway{log: slog.New(slog.NewTextHandler(io.Discard, nil))}, node: &store.Node{ID: "n"}, lastRev: 10}
	if c.bumpRevNext(12) != 10 {
		t.Fatal("gap: own revision 12 must not skip 11")
	}
	if c.bumpRevNext(11) != 11 || c.bumpRevNext(11) != 11 {
		t.Fatal("next revision must be taken once")
	}
}

// Sicherheits-Review HC-1/HC-4: Tokenlaenge, harte Grenze des Limiters, kein Bot-Token in Fehlertexten.
func TestLimiterBoundsAndRedact(t *testing.T) {
	if validToken("") || validToken(strings.Repeat("a", 19)) || validToken(strings.Repeat("a", 51)) || !validToken(strings.Repeat("a", 32)) {
		t.Fatal("validToken")
	}
	l := newIPLimiter()
	for i := 0; i < limiterMax; i++ {
		l.m[fmt.Sprint("k", i)] = &bucket{reset: time.Now().Add(time.Hour)}
	}
	// Tabelle voll: neue Schluessel teilen sich einen Eimer je Art (nicht pauschal alle abgewiesen, Speicher bleibt begrenzt)
	for i := 0; i < 10; i++ {
		if !l.allow(fmt.Sprint("push:neu", i), 10, time.Minute) {
			t.Fatalf("neuer Schluessel %d bei voller Tabelle abgewiesen", i)
		}
	}
	if l.allow("push:neu-x", 10, time.Minute) || len(l.m) > limiterMax+1 {
		t.Fatalf("gemeinsamer Eimer ohne Grenze: %d", len(l.m))
	}
	if !l.allow("auth:198.51.100.1", 10, time.Minute) {
		t.Fatal("andere Art von der vollen Tabelle gesperrt")
	}
	if !l.allow("k1", 10, time.Minute) {
		t.Fatal("bekannter Schluessel abgewiesen")
	}
	for k := range l.m {
		l.m[k].reset = time.Now().Add(-time.Second)
	}
	l.swept = time.Time{}
	if !l.allow("neu", 10, time.Minute) || len(l.m) > 2 {
		t.Fatalf("abgelaufene Schluessel nicht entfernt: %d", len(l.m))
	}
	// Anteil einer Art voll (Flut erfundener Push-Tokens): andere Arten bekommen weiter eigene Eimer
	l = newIPLimiter()
	for i := 0; i < limiterKind; i++ {
		if !l.allow(fmt.Sprintf("push:%030d", i), 60, time.Minute) {
			t.Fatalf("push %d", i)
		}
	}
	if _, ok := l.m["push:*"]; ok || !l.allow("push:extra-token-0000000000", 60, time.Minute) {
		t.Fatal("first push key over the share")
	}
	if _, ok := l.m["push:*"]; !ok {
		t.Fatal("push key over the share must use the shared bucket")
	}
	if !l.allow("auth:198.51.100.1", 1, time.Minute) || l.allow("auth:198.51.100.1", 1, time.Minute) || !l.allow("auth:198.51.100.2", 1, time.Minute) {
		t.Fatal("other kinds must keep their own buckets")
	}
	// IPv6 als /64, IPv4 einzeln
	if limitKey("2001:db8:1:2:aaaa::1") != limitKey("2001:db8:1:2:bbbb::2") || limitKey("2001:db8:1:3::1") == limitKey("2001:db8:1:2::1") ||
		limitKey("198.51.100.1") != "198.51.100.1" || limitKey("::ffff:198.51.100.1") != "::ffff:198.51.100.1" {
		t.Fatal("limitKey")
	}
	err := &url.Error{Op: "Post", URL: "https://api.telegram.org/bot123456:ABCdefGHIjklMNOpqr/sendMessage", Err: errors.New("i/o timeout")}
	if s := publicError(notify.TypeTelegram, err); strings.Contains(s, "ABCdef") {
		t.Fatalf("Token im Fehlertext: %s", s)
	}
}
