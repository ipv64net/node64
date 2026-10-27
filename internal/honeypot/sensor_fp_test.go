package honeypot

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"net"
	"regexp"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ipv64net/node64/internal/fingerprint"
)

// fpU16 haengt eine Liste von 16-Bit-Werten an.
func fpU16(vs ...uint16) []byte {
	var b []byte
	for _, v := range vs {
		b = binary.BigEndian.AppendUint16(b, v)
	}
	return b
}

// fpExt baut eine Extension (Typ, Laenge, Daten).
func fpExt(typ uint16, data []byte) []byte {
	return append(fpU16(typ, uint16(len(data))), data...)
}

// fpLen16 setzt eine 16-Bit-Laenge vor die Daten.
func fpLen16(data []byte) []byte { return append(fpU16(uint16(len(data))), data...) }

// fpClientHello baut ein ClientHello wie Chrome (Beispiel der JA4-Spezifikation: 15 Cipher, 16 Extensions, h2) als
// Handshake-Nachricht mit Kopf. sni/alpn schaltbar.
func fpClientHello(sni bool, alpn [][]byte) []byte {
	body := fpU16(0x0303)
	body = append(body, make([]byte, 32)...)  // Random
	body = append(body, 32)                   // Session-ID
	body = append(body, make([]byte, 32)...)  //
	body = append(body, fpLen16(fpU16(0x2a2a, // GREASE
		0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035))...)
	body = append(body, 1, 0) // Kompression: null
	var ext []byte
	ext = append(ext, fpExt(0x0a0a, nil)...) // GREASE
	if sni {
		name := []byte("example.com")
		ext = append(ext, fpExt(0x0000, fpLen16(append([]byte{0}, fpLen16(name)...)))...)
	}
	for _, x := range [][]byte{
		fpExt(0x0017, nil), fpExt(0xff01, []byte{0}), fpExt(0x000a, fpLen16(fpU16(0x3a3a, 0x001d, 0x0017, 0x0018))),
		fpExt(0x000b, []byte{1, 0}), fpExt(0x0023, nil),
	} {
		ext = append(ext, x...)
	}
	if alpn != nil {
		var l []byte
		for _, p := range alpn {
			l = append(append(l, byte(len(p))), p...)
		}
		ext = append(ext, fpExt(0x0010, fpLen16(l))...)
	}
	for _, x := range [][]byte{
		fpExt(0x0005, []byte{1, 0, 0, 0, 0}),
		fpExt(0x000d, fpLen16(fpU16(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601))),
		fpExt(0x0012, nil), fpExt(0x0033, fpLen16(append(fpU16(0x001d, 32), make([]byte, 32)...))), fpExt(0x002d, []byte{1, 1}),
		fpExt(0x002b, append([]byte{6}, fpU16(0x6a6a, 0x0304, 0x0303)...)), fpExt(0x001b, []byte{2, 0, 2}),
		fpExt(0x4469, fpLen16([]byte{2, 'h', '2'})), fpExt(0x1a1a, []byte{0}), fpExt(0x0015, make([]byte, 20)),
	} {
		ext = append(ext, x...)
	}
	body = append(body, fpLen16(ext)...)
	return append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

// fpRecords verpackt eine Handshake-Nachricht in TLS-Records zu hoechstens size Bytes.
func fpRecords(hs []byte, size int) []byte {
	var out []byte
	for len(hs) > 0 {
		n := min(size, len(hs))
		out = append(append(out, 0x16, 3, 1), fpLen16(hs[:n])...)
		hs = hs[n:]
	}
	return out
}

func TestJA4SpecVector(t *testing.T) {
	// Beispiel aus der JA4-Spezifikation (FoxIO): JA4_r
	// t13d1516h2_002f,…,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,…,0601
	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	hello := fpClientHello(true, [][]byte{[]byte("h2"), []byte("http/1.1")})
	if got := fingerprint.JA4(hello); got != want {
		t.Fatalf("JA4 %q, erwartet %q", got, want)
	}
	// ein Record, auf zwei Records verteilt, byteweise mitgeschnitten
	for _, size := range []int{1 << 14, 100} {
		stream := fpRecords(hello, size)
		if fp, more := sensorFingerprint(stream); fp != "ja4:"+want || more {
			t.Fatalf("Strom (%d): %q more=%v", size, fp, more)
		}
		if fp, more := sensorFingerprint(stream[:len(stream)-1]); fp != "" || !more {
			t.Fatalf("abgeschnitten (%d): %q more=%v", size, fp, more)
		}
		var c sensorFPCap
		for i := range stream {
			c.feed(stream[i : i+1])
		}
		c.feed([]byte("weitere Bytes"))
		if c.get() != "ja4:"+want || c.buf != nil {
			t.Fatalf("Mitschnitt (%d): %q", size, c.get())
		}
	}
}

func TestJA4Variants(t *testing.T) {
	// ohne SNI und ALPN: "i", "00"; Extensions-Zahl ohne die beiden
	if got := fingerprint.JA4(fpClientHello(false, nil)); got != "t13i151400_8daaf6152771_e5627efa2ab1" {
		t.Fatalf("ohne SNI/ALPN: %q", got)
	}
	// ALPN-Zeichen, GREASE und Hilfen: Tests in internal/fingerprint
	// kaputt oder kein ClientHello: kein Fingerabdruck, kein Warten
	for _, b := range [][]byte{
		{0x16, 3, 1, 0, 4, 2, 0, 0, 0},         // ServerHello
		{0x15, 3, 1, 0, 2, 2, 40},              // Alert
		fpRecords([]byte{1, 0, 0, 2, 3, 3}, 9), // ClientHello ohne Random
		[]byte("GET / HTTP/1.1\r\n"),
	} {
		if fp, more := sensorFingerprint(b); fp != "" || more {
			t.Fatalf("%x: %q more=%v", b, fp, more)
		}
	}
	// ClientHello groesser als die Obergrenze: aufgeben
	big := []byte{1, 0, 0x40, 0}
	if fp, more := sensorFingerprint(fpRecords(append(big, make([]byte, 100)...), 1<<14)); fp != "" || more {
		t.Fatalf("zu gross: %q more=%v", fp, more)
	}
}

// fpKexInit baut Versionszeile und KEXINIT-Paket eines Clients.
func fpKexInit(lists [10]string) []byte {
	p := []byte{20}
	p = append(p, make([]byte, 16)...)
	for _, l := range lists {
		p = binary.BigEndian.AppendUint32(p, uint32(len(l)))
		p = append(p, l...)
	}
	p = append(p, 0, 0, 0, 0, 0) // first_kex_packet_follows, reserviert
	pad := 8 - (len(p)+5)%8
	if pad < 4 {
		pad += 8
	}
	pkt := binary.BigEndian.AppendUint32(nil, uint32(1+len(p)+pad))
	pkt = append(append(append(pkt, byte(pad)), p...), make([]byte, pad)...)
	return append([]byte("SSH-2.0-OpenSSH_9.6\r\n"), pkt...)
}

func TestHASSHVector(t *testing.T) {
	// md5("curve25519-sha256,ext-info-c;aes128-ctr;hmac-sha2-256;none") = cafb69eb1dbb2a4a505b5b25342a4940
	b := fpKexInit([10]string{"curve25519-sha256,ext-info-c", "ssh-ed25519", "aes128-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha1", "none", "zlib", "", ""})
	const want = "hassh:cafb69eb1dbb2a4a505b5b25342a4940"
	if fp, more := sensorFingerprint(b); fp != want || more {
		t.Fatalf("HASSH %q more=%v", fp, more)
	}
	for _, n := range []int{2, 10, 30, len(b) - 1} {
		if fp, more := sensorFingerprint(b[:n]); fp != "" || !more {
			t.Fatalf("abgeschnitten (%d): %q more=%v", n, fp, more)
		}
	}
	var c sensorFPCap
	for i := 0; i < len(b); i += 7 {
		c.feed(b[i:min(i+7, len(b))])
	}
	if c.get() != want {
		t.Fatalf("Mitschnitt: %q", c.get())
	}
	// kein KEXINIT, Paketlaenge unsinnig, Versionszeile zu lang
	bad := append([]byte(nil), b...)
	bad[len("SSH-2.0-OpenSSH_9.6\r\n")+5] = 21
	long := append(make([]byte, 0, 300), "SSH-2.0-"...)
	for len(long) < 300 {
		long = append(long, 'x')
	}
	for _, x := range [][]byte{bad, []byte("SSH-2.0-x\r\n\xff\xff\xff\xff\x00"), long, []byte("SSX-")} {
		if fp, more := sensorFingerprint(x); fp != "" || more {
			t.Fatalf("%q: %q more=%v", x, fp, more)
		}
	}
}

var (
	fpReJA4   = regexp.MustCompile(`^ja4:t13d\d{4}h2_[0-9a-f]{12}_[0-9a-f]{12}$`)
	fpReHASSH = regexp.MustCompile(`^hassh:[0-9a-f]{32}$`)
)

func TestSensorFingerprintHTTPS(t *testing.T) {
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcHTTPS, p, ""}}})
	c, err := tls.Dial("tcp", sensorAddrOf(p), &tls.Config{InsecureSkipVerify: true, ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("GET /fp HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"))
	_, _ = bufio.NewReader(c).ReadString('\n')
	c.Close()
	e := rec.wait(t, func(e Event) bool { return e.Path == "/fp" })
	if !fpReJA4.MatchString(e.Fingerprint) {
		t.Fatalf("JA4: %+v", e)
	}
	// gleicher Client, gleicher Fingerabdruck; TLS-Abbruch (Probe) bekommt ihn auch
	c2, err := tls.Dial("tcp", sensorAddrOf(p), &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}})
	if err == nil {
		c2.Close()
	}
	pr := rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Service == SvcHTTPS })
	if len(pr.Fingerprint) < 10 || pr.Fingerprint[:8] != "ja4:t12i" && pr.Fingerprint[:8] != "ja4:t13i" {
		t.Fatalf("Probe: %+v", pr)
	}
}

func TestSensorFingerprintSSH(t *testing.T) {
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcSSH, p, ""}}})
	_, err := ssh.Dial("tcp", sensorAddrOf(p), &ssh.ClientConfig{
		Config:          ssh.Config{KeyExchanges: []string{"curve25519-sha256"}, Ciphers: []string{"aes128-ctr"}, MACs: []string{"hmac-sha2-256"}},
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("fp")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("Login angenommen")
	}
	e := rec.wait(t, func(e Event) bool { return e.Kind == KindSSHBrute && e.Password == "fp" })
	// x/crypto/ssh ergaenzt den Alias curve25519-sha256@libssh.org und beim ersten Schluesseltausch ext-info-c und
	// kex-strict-c-v00@openssh.com (so steht es roh im KEXINIT)
	sum := md5.Sum([]byte("curve25519-sha256,curve25519-sha256@libssh.org,ext-info-c,kex-strict-c-v00@openssh.com;aes128-ctr;hmac-sha2-256;none"))
	if e.Fingerprint != "hassh:"+hex.EncodeToString(sum[:]) || !fpReHASSH.MatchString(e.Fingerprint) {
		t.Fatalf("HASSH: %+v", e)
	}
}

func TestSensorFingerprintTCP(t *testing.T) {
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcTCP, p, ""}}})
	c, err := net.Dial("tcp", sensorAddrOf(p))
	if err != nil {
		t.Fatal(err)
	}
	hello := fpRecords(fpClientHello(true, [][]byte{[]byte("h2"), []byte("http/1.1")}), 1<<14)
	_, _ = c.Write(hello[:100]) // in zwei Teilen
	time.Sleep(50 * time.Millisecond)
	_, _ = c.Write(hello[100:])
	e := rec.wait(t, func(e Event) bool { return e.Service == SvcTCP })
	c.Close()
	if e.Fingerprint != "ja4:t13d1516h2_8daaf6152771_e5627efa2ab1" || e.Host != "example.com" || e.Detail != "tls" {
		t.Fatalf("TCP: %+v", e)
	}
}

func TestStoreFingerprint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	end := time.Now().UTC().Truncate(time.Second) // Stats nur innerhalb der Aufbewahrung
	start := end.Add(-10 * time.Minute)
	ja4 := "ja4:t13d1516h2_8daaf6152771_e5627efa2ab1"
	hassh := "hassh:cafb69eb1dbb2a4a505b5b25342a4940"
	var evs []Event
	for i := 0; i < 3; i++ {
		evs = append(evs, Event{Time: start.Add(time.Minute), Service: SvcHTTPS, Port: 443, Kind: KindHTTPScan, Src: ip("45.83.64." + strconv.Itoa(i+1)), Path: "/", Fingerprint: ja4})
	}
	evs = append(evs,
		Event{Time: start.Add(2 * time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("45.83.64.9"), Username: "root", Password: "x", Fingerprint: hassh},
		Event{Time: start.Add(2 * time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("192.168.1.2"), Username: "root", Password: "x", Fingerprint: "hassh:local"},
		Event{Time: start.Add(3 * time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("45.83.64.10"), Source: SrcLog, Rule: "sshd/bruteforce@1", Fingerprint: "hassh:fromlog"},
	)
	repWrite(t, s, evs...)

	list, err := s.Recent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if list[0].Fingerprint != "" || list[1].Fingerprint != "hassh:local" || list[len(list)-1].Fingerprint != ja4 {
		t.Fatalf("Recent: %+v", list)
	}
	if v := eventView(list[1]); v.Fingerprint != "hassh:local" {
		t.Fatalf("EventView: %+v", v)
	}
	st, err := s.Stats(ctx, time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.TopFingerprints) != 3 || st.TopFingerprints[0].Key != ja4 || st.TopFingerprints[0].Count != 3 {
		t.Fatalf("Stats: %+v", st.TopFingerprints)
	}
	rep, err := s.BuildReport(ctx, start, end)
	if err != nil {
		t.Fatal(err)
	}
	f := rep.Samples.Fingerprints
	if len(f) != 2 || f[0] != (ReportKey{Key: ja4, Count: 3}) || f[1] != (ReportKey{Key: hassh, Count: 1}) {
		t.Fatalf("Proben: %+v", f)
	}
}
