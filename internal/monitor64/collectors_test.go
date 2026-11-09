package monitor64

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/transport"
	"github.com/ipv64net/node64/internal/secrets"
)

func colSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// colSSH ist ein kleiner SSH-Server fuer die Sammler-Tests: handler bekommt den Befehl und liefert die Ausgabe.
type colSSH struct {
	addr string
	hk   ssh.Signer
	mu   sync.Mutex
	cmds []string
}

func (f *colSSH) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

func startColSSH(t *testing.T, node ssh.PublicKey, handler func(cmd string) []byte) *colSSH {
	t.Helper()
	f := &colSSH{hk: colSigner(t)}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) == string(node.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("no")
	}}
	cfg.AddHostKey(f.hk)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					_ = c.Close()
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, rq, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer ch.Close()
						for req := range rq {
							if req.Type != "exec" {
								_ = req.Reply(false, nil)
								continue
							}
							var p struct{ Cmd string }
							_ = ssh.Unmarshal(req.Payload, &p)
							_ = req.Reply(true, nil)
							f.mu.Lock()
							f.cmds = append(f.cmds, p.Cmd)
							f.mu.Unlock()
							_, _ = io.Copy(io.Discard, ch) // Skript auf stdin
							_, _ = ch.Write(handler(p.Cmd))
							_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{0}))
							return
						}
					}()
				}
			}()
		}
	}()
	return f
}

// scriptOutputs: Ausgabe mit allen Abschnitten (langsamer Lauf) und ohne SMART/Updates (schneller Lauf).
func scriptOutputs(t *testing.T) (fast, slow []byte) {
	t.Helper()
	b, err := os.ReadFile("../m64linux/testdata/script_debian12_vm.txt")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	i, j := strings.Index(s, "<<<m64:updates:"), strings.Index(s, "<<<m64:end>>>")
	if i < 0 || j < i {
		t.Fatal("testdata layout changed")
	}
	return []byte(s[:i] + s[j:]), []byte(s)
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestSSHCollector(t *testing.T, addr string, node ssh.Signer, smart bool, clock *fakeClock) (*sshCollector, *transport.Pool) {
	t.Helper()
	pool := transport.NewPool(0)
	t.Cleanup(pool.Close)
	ref := &poolRef{pool: pool, key: "acc"}
	s := newSSHCollector(ref, transport.SSHConfig{Addr: addr, User: "u", Signer: node, OnHostKey: ref.learn}, smart)
	if clock != nil {
		s.now = clock.now
	}
	t.Cleanup(s.close)
	return s, pool
}

func (s *sshCollector) waitSlow(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		r := s.running
		s.mu.Unlock()
		if !r {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("slow run did not finish")
}

func hasSecErr(rep *m64proto.Report, sec string) bool {
	for _, e := range rep.Errors {
		if e.Section == sec && strings.Contains(e.Error, "langsame Abfrage") {
			return true
		}
	}
	return false
}

func hasSecNote(rep *m64proto.Report, sec string) bool {
	for _, n := range rep.Notes {
		if n.Section == sec && strings.Contains(n.Note, "langsame Abfrage") {
			return true
		}
	}
	return false
}

// F2-K4/F3-K2: SMART/Updates laufen getrennt vom schnellen Lauf; ein haengender langsamer Lauf kostet die
// schnellen Werte nicht, wird nicht jede Runde wiederholt und bleibt als Hinweis/Fehler sichtbar.
func TestSSHCollectorSlowSeparate(t *testing.T) {
	old := slowTimeout
	slowTimeout = 300 * time.Millisecond
	t.Cleanup(func() { slowTimeout = old })
	fast, slow := scriptOutputs(t)
	node := colSigner(t)
	var hangMu sync.Mutex
	hang := true
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	fs := startColSSH(t, node.PublicKey(), func(cmd string) []byte {
		if !strings.Contains(cmd, "smart") {
			return fast
		}
		hangMu.Lock()
		h := hang
		hangMu.Unlock()
		if h {
			<-release
		}
		return slow
	})
	clock := &fakeClock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	s, _ := newTestSSHCollector(t, fs.addr, node, true, clock)
	round := func() []m64proto.SMART {
		t.Helper()
		cx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		svcs, err := s.collect(cx)
		if len(svcs) == 0 { // Abschnittsfehler kommen als Teilfehler (err mit Diensten)
			t.Fatalf("collect: %d services, err %v", len(svcs), err)
		}
		if err != nil && len(s.prev.Errors) == 0 {
			t.Fatalf("error without section errors: %v", err)
		}
		return s.prev.SMART
	}

	// 1. Runde: schneller Lauf liefert, der langsame haengt bis slowTimeout
	start := time.Now()
	if sm := round(); len(sm) != 0 {
		t.Fatal("no SMART expected yet")
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("round took %v", d)
	}
	s.waitSlow(t)
	round()
	if !hasSecErr(s.prev, m64proto.SecSmart) || !hasSecErr(s.prev, m64proto.SecUpdates) {
		t.Fatalf("slow error not kept: %+v", s.prev.Errors)
	}
	// 2. Runde: kein neuer langsamer Lauf (Rueckoff)
	slowRuns := func() int {
		n := 0
		for _, c := range fs.commands() {
			if strings.Contains(c, "smart") {
				n++
				if !strings.Contains(c, "updates") {
					t.Errorf("slow command without updates: %q", c)
				}
			} else if c != "sh -s" {
				t.Errorf("fast command with arguments: %q", c)
			}
		}
		return n
	}
	if n := slowRuns(); n != 1 {
		t.Fatalf("slow runs = %d, want 1 (no retry every round)", n)
	}

	// Nach dem Intervall: neuer Versuch, diesmal erfolgreich; Werte erscheinen in der folgenden Runde
	hangMu.Lock()
	hang = false
	hangMu.Unlock()
	clock.add(updatesEvery)
	round()
	s.waitSlow(t)
	if sm := round(); len(sm) == 0 || s.prev.Updates == nil {
		t.Fatalf("slow values not merged: smart=%d updates=%v", len(sm), s.prev.Updates)
	}
	if hasSecErr(s.prev, m64proto.SecSmart) || hasSecNote(s.prev, m64proto.SecSmart) {
		t.Fatal("old slow error must be gone")
	}
	if n := slowRuns(); n != 2 {
		t.Fatalf("slow runs = %d, want 2", n)
	}
	round()
	if n := slowRuns(); n != 2 {
		t.Fatalf("slow runs = %d, want 2 (not due)", n)
	}

	// Fehlschlag mit vorhandenen Werten: Werte bleiben, Fehler als Hinweis
	hangMu.Lock()
	hang = true
	hangMu.Unlock()
	clock.add(updatesEvery)
	round()
	s.waitSlow(t)
	if sm := round(); len(sm) == 0 || !hasSecNote(s.prev, m64proto.SecSmart) {
		t.Fatalf("values must stay with a note: smart=%d notes=%+v", len(sm), s.prev.Notes)
	}
	// zu alte Werte werden verworfen, der Hinweis wird zum Fehler
	clock.add(3 * updatesEvery)
	round()
	s.waitSlow(t)
	if sm := round(); len(sm) != 0 || s.prev.Updates != nil {
		t.Fatalf("stale values must be dropped: smart=%d updates=%v", len(sm), s.prev.Updates)
	}
	if !hasSecErr(s.prev, m64proto.SecSmart) {
		t.Fatalf("stale: error expected: %+v", s.prev.Errors)
	}
}

// Erster Lauf: SMART/Updates kommen, wenn sie rechtzeitig fertig sind, schon in der ersten Runde.
func TestSSHCollectorFirstRound(t *testing.T) {
	fast, slow := scriptOutputs(t)
	node := colSigner(t)
	fs := startColSSH(t, node.PublicKey(), func(cmd string) []byte {
		if strings.Contains(cmd, "smart") {
			return slow
		}
		return fast
	})
	s, _ := newTestSSHCollector(t, fs.addr, node, true, nil)
	cx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.collect(cx); err != nil {
		t.Fatal(err)
	}
	if len(s.prev.SMART) == 0 || s.prev.Updates == nil {
		t.Fatalf("first round: smart=%d updates=%v", len(s.prev.SMART), s.prev.Updates)
	}
}

// F2-K1/F7-K1, F2-K3: der Sammler holt den Client je Runde aus dem Pool (verworfener Client wird neu gebaut, der
// gelernte Hostschluessel haelt ihn); close entfernt den Eintrag, danach legt der Sammler keinen neuen an.
func TestCollectorPoolLifecycle(t *testing.T) {
	fast, _ := scriptOutputs(t)
	node := colSigner(t)
	fs := startColSSH(t, node.PublicKey(), func(string) []byte { return fast })
	s, pool := newTestSSHCollector(t, fs.addr, node, false, nil)
	s.lastUpdates = time.Now() // kein langsamer Lauf in diesem Test
	cx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.collect(cx); err != nil {
		t.Fatal(err)
	}
	if s.ref.hostKey != transport.Fingerprint(fs.hk.PublicKey()) {
		t.Fatalf("host key not learned: %q", s.ref.hostKey)
	}
	c1, _ := s.ref.ssh(s.cfg)
	pool.Remove("acc") // wie das Aufraeumen des Pools
	if _, err := s.collect(cx); err != nil {
		t.Fatalf("after pool dropped the client: %v", err)
	}
	c2, _ := s.ref.ssh(s.cfg)
	if c2 == c1 || pool.Len() != 1 {
		t.Fatalf("client not rebuilt (len %d)", pool.Len())
	}
	if c3, _ := s.ref.ssh(s.cfg); c3 != c2 {
		t.Fatal("learned host key must keep the client")
	}
	s.close()
	if pool.Len() != 0 {
		t.Fatal("close must remove the pool entry")
	}
	if _, err := s.collect(cx); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("collect after close: %v", err)
	}
	if pool.Len() != 0 {
		t.Fatal("closed collector must not create a new pool entry")
	}
}

// F11-K7: Adressen mit und ohne Port.
func TestAccessAddr(t *testing.T) {
	for _, tc := range []struct {
		addr      string
		port, def int
		want      string
	}{
		{"nas", 0, 22, "nas:22"},
		{"nas:2222", 0, 22, "nas:2222"},
		{"nas:2222", 2200, 22, "nas:2200"},
		{"2001:db8::1", 0, 22, "[2001:db8::1]:22"},
		{"[2001:db8::1]:2222", 0, 22, "[2001:db8::1]:2222"},
		{"2001:db8::1", 6465, 22, "[2001:db8::1]:6465"},
	} {
		if got := accessAddr(tc.addr, tc.port, tc.def); got != tc.want {
			t.Errorf("accessAddr(%q, %d, %d) = %q, want %q", tc.addr, tc.port, tc.def, got, tc.want)
		}
	}
	if got := hostPort("nas:2222", 8006); got != "nas:2222" {
		t.Errorf("hostPort = %q", got)
	}
}

type fakeSettings struct {
	vals    map[string]string
	readErr error
	writes  int
}

func (f *fakeSettings) Setting(_ context.Context, key string) (string, bool, error) {
	if f.readErr != nil {
		return "", false, f.readErr
	}
	v, ok := f.vals[key]
	return v, ok, nil
}

func (f *fakeSettings) SetSetting(_ context.Context, key, value string) error {
	f.writes++
	f.vals[key] = value
	return nil
}

// Nebenbefund: ein Lesefehler darf den Schluessel der Node nicht ueberschreiben.
func TestLoadNodeKeyReadError(t *testing.T) {
	box, err := secrets.New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st := &fakeSettings{vals: map[string]string{}}
	s1, err := loadNodeKey(ctx, st, box, nil, "node")
	if err != nil || st.writes != 1 {
		t.Fatalf("create: %v (writes %d)", err, st.writes)
	}
	st.readErr = errors.New("database is locked")
	if _, err := loadNodeKey(ctx, st, box, nil, "node"); err == nil {
		t.Fatal("read error must be an error")
	}
	if st.writes != 1 {
		t.Fatal("key overwritten after read error")
	}
	st.readErr = nil
	s2, err := loadNodeKey(ctx, st, box, nil, "node")
	if err != nil || transport.Fingerprint(s2.PublicKey()) != transport.Fingerprint(s1.PublicKey()) || st.writes != 1 {
		t.Fatalf("key changed: %v", err)
	}
}
