package m64agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testKeyLine(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))), sp
}

func TestParseKeys(t *testing.T) {
	k1, _ := testKeyLine(t)
	k2, _ := testKeyLine(t)
	rk, _ := rsa.GenerateKey(rand.Reader, 1024)
	rsp, _ := ssh.NewPublicKey(&rk.PublicKey)
	short := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(rsp)))

	if n, err := ParseKeys([]byte("# comment\n\n" + k1 + " node1\n" + `from="10.0.0.0/8,!10.1.2.3",restrict ` + k2 + " node2\n")); err != nil || n != 2 {
		t.Fatalf("valid list: n=%d err=%v", n, err)
	}
	for name, in := range map[string]string{
		"garbage":     k1 + "\nnot a key\n",
		"short rsa":   short,
		"command opt": `command="/bin/sh" ` + k1,
		"cert-auth":   `cert-authority ` + k1,
	} {
		if _, err := ParseKeys([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// nachsichtig: kaputte Zeilen ueberspringen
	keys, err := parseKeys([]byte(k1+"\nbroken\n"+k2), false)
	if len(keys) != 2 || err == nil {
		t.Errorf("lenient: %d keys, err %v", len(keys), err)
	}
}

func TestFromAllows(t *testing.T) {
	ip := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	cases := []struct {
		pats []string
		ip   string
		want bool
	}{
		{nil, "1.2.3.4", true},
		{[]string{"10.0.0.0/8"}, "10.9.9.9", true},
		{[]string{"10.0.0.0/8"}, "11.0.0.1", false},
		{[]string{"10.0.0.0/8", "!10.1.2.3"}, "10.1.2.3", false},
		{[]string{"192.168.1.*"}, "192.168.1.77", true},
		{[]string{"192.168.1.?"}, "192.168.1.77", false},
		{[]string{"2001:db8::/32"}, "2001:db8::1", true},
		{[]string{"nas.example.com"}, "1.2.3.4", false},
		{[]string{"127.0.0.1"}, "::ffff:127.0.0.1", true},
		// Netz und Muster ohne Zone passen auf jede Zone: verneintes Netz greift auch fuer fe80::1%eth0
		{[]string{"::/0", "!fe80::/10"}, "fe80::1%eth0", false},
		{[]string{"fe80::/10"}, "fe80::1%eth0", true},
		{[]string{"fe80::1"}, "fe80::1%eth0", true},
		// S1-K3: Zone im Muster muss stimmen (nicht verworfen)
		{[]string{"fe80::1%eth1"}, "fe80::1%eth0", false},
		{[]string{"fe80::1%eth0"}, "fe80::1%eth0", true},
		{[]string{"fe80::1%eth0"}, "fe80::1", false},
		{[]string{"::/0", "!fe80::1%eth0"}, "fe80::1%eth1", true},
		{[]string{"::/0", "!fe80::1%eth0"}, "fe80::1%eth0", false},
		// S1-K3: IPv6-Joker werden abgelehnt (Kurzschreibweise), IPv4-Joker passen nur auf IPv4, "*" auf alles
		{[]string{"fe80::*"}, "fe80::1%eth0", false},
		{[]string{"2001:db8:0:0:*"}, "2001:db8::1", false},
		{[]string{"1*"}, "1::1", false},
		{[]string{"1*"}, "10.0.0.1", true},
		{[]string{"*"}, "2001:db8::1", true},
		{[]string{"::/0", "!*"}, "2001:db8::1", false},
		// S1-K3: IPv4-gemappte Netze zaehlen als IPv4
		{[]string{"::ffff:10.0.0.0/104"}, "10.1.2.3", true},
		{[]string{"::ffff:10.0.0.0/104"}, "::ffff:10.1.2.3", true},
		{[]string{"::ffff:10.0.0.0/104"}, "11.0.0.1", false},
		{[]string{"10.0.0.0/8", "!::ffff:10.1.0.0/112"}, "10.1.2.3", false},
		{[]string{"10.0.0.0/8", "!::ffff:10.1.0.0/112"}, "10.2.0.1", true},
		{[]string{"::ffff:0.0.0.0/96"}, "192.0.2.1", true},
		{[]string{"::ffff:0:0/80"}, "192.0.2.1", false},
		// ungueltiges Muster verweigert immer (parseKeyLine laesst es gar nicht durch)
		{[]string{"10.0.0.0/8", "!10.1.2.300"}, "10.9.9.9", false},
	}
	for _, c := range cases {
		if got := fromAllows(c.pats, ip(c.ip)); got != c.want {
			t.Errorf("%v %s: got %v", c.pats, c.ip, got)
		}
	}
	// Zone als Name oder Nummer derselben Schnittstelle
	if ifs, err := net.Interfaces(); err == nil && len(ifs) > 0 {
		n := strconv.Itoa(ifs[0].Index)
		if !zoneEqual(n, ifs[0].Name) || !zoneEqual(ifs[0].Name, n) || zoneEqual(n+"0", ifs[0].Name) {
			t.Errorf("zone %s/%s not matched", n, ifs[0].Name)
		}
	}
	if zoneEqual("eth0", "") || zoneEqual("", "1") || !zoneEqual("", "") {
		t.Error("empty zone")
	}
}

func TestKeyStoreReload(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "keys")
	k1, p1 := testKeyLine(t)
	k2, p2 := testKeyLine(t)
	s := &keyStore{path: p}
	if s.lookup(p1) != nil {
		t.Fatal("missing file must refuse")
	}
	if err := os.WriteFile(p, []byte(k1+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.invalidate()
	if s.lookup(p1) == nil || s.lookup(p2) != nil {
		t.Fatal("k1 expected")
	}
	// Aenderung wird nach spaetestens einer Sekunde erkannt
	if err := os.WriteFile(p, []byte(k2+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(p, future, future)
	time.Sleep(keysRecheckGap + 50*time.Millisecond)
	if s.lookup(p1) != nil || s.lookup(p2) == nil {
		t.Fatal("reload failed")
	}
}

func TestLimiter(t *testing.T) {
	var l limiter
	now := time.Now()
	for i := 0; i < failFree-1; i++ {
		l.fail("1.2.3.4", now)
	}
	if l.blocked("1.2.3.4", now) {
		t.Fatal("blocked too early")
	}
	l.fail("1.2.3.4", now)
	if !l.blocked("1.2.3.4", now) || l.blocked("1.2.3.4", now.Add(failBlockMin+time.Second)) {
		t.Fatal("first block wrong")
	}
	l.fail("1.2.3.4", now)
	if !l.blocked("1.2.3.4", now.Add(failBlockMin+time.Second)) {
		t.Fatal("block must double")
	}
	l.ok("1.2.3.4", now)
	if l.blocked("1.2.3.4", now) {
		t.Fatal("ok must reset")
	}
	if !l.known("1.2.3.4", now) || l.known("1.2.3.4", now.Add(goodForget)) || l.known("5.6.7.8", now) {
		t.Fatal("known address wrong")
	}
	a := peerOf(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:3:4:5:6"), Port: 1})
	b := peerOf(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:ffff::1"), Port: 2})
	if a.net != b.net || a.ip == b.ip || a.net != "2001:db8:1:2::/64" || a.grp != "2001:db8:1::/48" {
		t.Fatalf("IPv6 peer: %+v %+v", a, b)
	}
	v4 := peerOf(&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 1})
	if v4.ip != "192.0.2.1" || v4.net != v4.ip || v4.grp != "" {
		t.Fatalf("IPv4 peer: %+v", v4)
	}
}

// S1-K1: Fehlversuche zaehlen je exakter Adresse und je /64. Ein Angreifer im /64 einer Node wird gesperrt (auch
// wenn er die Adresse wechselt), die Node mit ihrer bekannten Adresse nicht; ihre Anmeldung hebt die Sperre des
// Netzes nicht auf.
func TestLimiterNeighbour(t *testing.T) {
	var l limiter
	now := time.Now()
	pe := func(s string) peer { return peerOf(&net.TCPAddr{IP: net.ParseIP(s), Port: 1}) }
	node, evil := pe("2001:db8:1:2::1"), pe("2001:db8:1:2::bad")
	l.ok(node.ip, now)
	for range failFree {
		l.failPeer(evil, now)
	}
	if !l.refused(evil, now) {
		t.Fatal("attacker in the /64 of a known node not blocked")
	}
	if l.refused(node, now) {
		t.Fatal("known node blocked by its neighbour")
	}
	// neue Adresse des Angreifers im selben /64: das Netz ist gesperrt
	if !l.refused(pe("2001:db8:1:2::bad2"), now) {
		t.Fatal("address change in the /64 escapes the block")
	}
	// Anmeldung der Node hebt die Sperre des Netzes nicht auf
	l.ok(node.ip, now)
	if !l.refused(pe("2001:db8:1:2::bad3"), now) || l.refused(node, now) {
		t.Fatal("login of the node lifted the block of the /64")
	}
	// Fehlversuche der bekannten Adresse zaehlen nicht (NAT: Nachbar hinter derselben Adresse)
	for range 2 * failFree {
		l.failPeer(node, now)
	}
	if l.refused(node, now) || l.blocked(node.ip, now) {
		t.Fatal("known address blocked")
	}
	// anderes /64: unberuehrt
	if l.refused(pe("2001:db8:1:3::1"), now) {
		t.Fatal("other /64 blocked")
	}
}

func TestParseCommand(t *testing.T) {
	ok := map[string]int{"info": 0, "collect": 0, "update": 0, "keys": 0, "collect cpu,mem,fs": 3, "collect cpu,cpu": 1}
	for in, n := range ok {
		if _, secs, err := parseCommand(in); err != nil || len(secs) != n {
			t.Errorf("%q: secs %v err %v", in, secs, err)
		}
	}
	for _, in := range []string{"", "ls", "info ", " info", "collect ", "collect cpu;id", "collect CPU", "collect ../x",
		"collect a,,b", "keys extra", "update now", manySections(40), "sh -c id"} {
		if _, _, err := parseCommand(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestHostKeyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "hostkey")
	s1, err := LoadOrCreateHostKey(p)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := LoadOrCreateHostKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(s1.PublicKey()) != Fingerprint(s2.PublicKey()) {
		t.Fatal("host key changed on reload")
	}
	fp, err := ReadHostKeyFingerprint(p)
	if err != nil || fp != Fingerprint(s1.PublicKey()) || !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("fingerprint %q err %v", fp, err)
	}
	if fi, _ := os.Stat(p); fi != nil && os.PathSeparator == '/' && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func manySections(n int) string {
	var secs []string
	for i := range n {
		secs = append(secs, "s"+strconv.Itoa(i))
	}
	return "collect " + strings.Join(secs, ",")
}

// F1-K6: from= wie OpenSSH: ungueltige Muster (auch verneint) und mehrere from= lehnen die Zeile ab.
func TestParseKeysFrom(t *testing.T) {
	k, _ := testKeyLine(t)
	for _, opt := range []string{
		`from="10.0.0.0/8,!10.1.2.3"`,
		`from="192.168.1.*,!192.168.1.5"`,
		`from="fe80::1%eth0"`,
		`from="2001:db8::/32,!2001:db8::1"`,
		`from="1.2.3.4",restrict`,
		`from="::ffff:10.0.0.0/104"`,
		`from="*"`,
		`from="10.0.*,!10.0.0.?"`,
	} {
		if _, err := ParseKeys([]byte(opt + " " + k)); err != nil {
			t.Errorf("%s refused: %v", opt, err)
		}
	}
	for _, opt := range []string{
		`from="10.0.0.0/33"`,
		`from="10.0.0.0/8,!10.1.2.300"`,
		`from="10.0.0.0/8,!nas.example.com"`,
		`from="nas.example.com"`,
		`from="10.0.0.1/8"`,
		`from="10.0.0.0/8,"`,
		`from="!"`,
		`from=""`,
		`from="1.2.3.[4]"`,
		`from="10.0.0.0/8",from="1.2.3.4"`,
		// S1-K3: was der Abgleich nicht meinen kann, wird schon hier abgelehnt
		`from="fe80::*"`,
		`from="2001:db8::*"`,
		`from="!2001:db8:*"`,
		`from="::ffff:0:0/80"`,
		`from="2001:db8::1%eth0"`,
		`from="!2001:db8::1%eth0"`,
		`from="fe80::*%eth0"`,
	} {
		if _, err := ParseKeys([]byte(opt + " " + k)); err == nil {
			t.Errorf("%s accepted", opt)
		}
	}
	// Datei: Zeile mit ungueltigem Muster wird uebersprungen (Schluessel gar nicht erlaubt), Rest bleibt
	k2, p2 := testKeyLine(t)
	keys, err := parseKeys([]byte(`from="!bad.example" `+k+"\n"+k2+"\n"), false)
	if err == nil || len(keys) != 1 || !bytes.Equal(keys[0].wire, p2.Marshal()) {
		t.Fatalf("lenient: %d keys, err %v", len(keys), err)
	}
}
