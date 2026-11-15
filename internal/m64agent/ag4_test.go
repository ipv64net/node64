package m64agent

import (
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// AG-4 (Sicherheits-Review 2026-11-15): Acht offene Handshakes unbekannter Adressen je 10 s genuegten, um die
// Erstanmeldung jeder Node zu blockieren. Adressen aus from=-Mustern haben jetzt einen eigenen Topf, unbekannte
// Adressen nur eine kurze Handshake-Frist.
func TestAG4ListedPotAndShortHandshake(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	_, la := testSigner(t)
	_, lb := testSigner(t)
	if err := WriteKeysFile(keys, []byte(`from="192.0.2.0/24" `+la+"\n"+lb+"\n")); err != nil {
		t.Fatal(err)
	}
	s, _ := startServer(t, Config{KeysFile: keys, HandshakeTimeout: 10 * time.Second}, nil)
	now := time.Now()
	// allgemeiner Topf voll (z. B. stille Verbindungen aus fremden Netzen)
	for i := 1; i <= preAuthMax; i++ {
		sl, hs := s.admit(testPeer("198.51.100."+strconv.Itoa(i)), nil, now)
		if sl == nil || hs != unknownHandshakeTimeout {
			t.Fatalf("unbekannte Adresse %d: %v %v", i, sl, hs)
		}
	}
	if sl, _ := s.admit(testPeer("203.0.113.7"), nil, now); sl != nil {
		t.Fatal("allgemeiner Topf nicht voll")
	}
	// die Node aus dem from=-Netz kommt trotzdem dran, mit voller Frist
	sl, hs := s.admit(testPeer("192.0.2.5"), nil, now)
	if sl == nil || !sl.listed || hs != 10*time.Second {
		t.Fatalf("Adresse aus from=: %+v %v", sl, hs)
	}
	s.gate.release(sl)
	if s.gate.listedTotal != 0 {
		t.Errorf("Platz nicht freigegeben: %d", s.gate.listedTotal)
	}
	// auch dieser Topf ist begrenzt (je Netz und insgesamt)
	for i := 0; i < preAuthListedPerNet; i++ {
		if sl, _ := s.admit(testPeer("192.0.2.9"), nil, now); sl == nil {
			t.Fatalf("Platz %d im from=-Topf", i)
		}
	}
	if sl, _ := s.admit(testPeer("192.0.2.9"), nil, now); sl != nil {
		t.Error("from=-Topf je Adresse unbegrenzt")
	}
}

// AG-4: Eine stille Verbindung einer unbekannten Adresse wird nach der kurzen Frist geschlossen, nicht nach 10 s.
func TestAG4UnknownHandshakeClosesEarly(t *testing.T) {
	old := unknownHandshakeTimeout
	unknownHandshakeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { unknownHandshakeTimeout = old })
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	_, la := testSigner(t)
	if err := WriteKeysFile(keys, []byte(la+"\n")); err != nil {
		t.Fatal(err)
	}
	_, addr := startServer(t, Config{KeysFile: keys, HandshakeTimeout: 10 * time.Second}, nil)
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	for {
		if _, err := c.Read(buf); err != nil {
			break
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("stille Verbindung erst nach %v geschlossen", d)
	}
}
