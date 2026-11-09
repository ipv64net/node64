package trap

import (
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/ipv64net/node64/internal/monitor64/snmp"
)

var (
	hostIP    = netip.MustParseAddr("192.0.2.10")
	otherIP   = netip.MustParseAddr("192.0.2.99")
	senderEID = "8000000001020304"
	v3User    = User{Name: "m64trap", Level: "authPriv", AuthProto: "SHA256", PrivProto: "AES", EngineID: "",
		Secret: snmp.Secret{AuthPass: "trapauth123", PrivPass: "trappriv123"}}
)

// capture sendet mit gosnmp an einen lokalen Socket und liefert die Bytes (echte Pakete fuer process).
func capture(t testing.TB, g *gosnmp.GoSNMP, tr gosnmp.SnmpTrap) []byte {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	g.Target, g.Port = "127.0.0.1", uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	g.Timeout, g.Retries = 200*time.Millisecond, 0
	if g.Logger == (gosnmp.Logger{}) {
		g.Logger = gosnmp.NewLogger(nil)
	}
	if err := g.Connect(); err != nil {
		t.Fatal(err)
	}
	defer g.Conn.Close()
	go func() { _, _ = g.SendTrap(tr) }() // Informs warten auf Antwort (laeuft ins Zeitlimit)
	buf := make([]byte, 65535)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buf[:n]...)
}

func v2c(community string) *gosnmp.GoSNMP {
	return &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: community}
}

func v3Client(u User, engine string) *gosnmp.GoSNMP {
	sp, flags, err := snmp.USM(u.Name, u.Level, u.AuthProto, u.PrivProto, u.Secret)
	if err != nil {
		panic(err)
	}
	raw, _ := hex.DecodeString(engine)
	sp.AuthoritativeEngineID, sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = string(raw), 1, 100
	return &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: flags, SecurityParameters: sp}
}

func linkDown(idx int, name string) gosnmp.SnmpTrap {
	return gosnmp.SnmpTrap{Variables: []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(12345)},
		{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.3"},
		{Name: ".1.3.6.1.2.1.2.2.1.1." + itoa(idx), Type: gosnmp.Integer, Value: idx},
		{Name: ".1.3.6.1.2.1.2.2.1.7." + itoa(idx), Type: gosnmp.Integer, Value: 1},
		{Name: ".1.3.6.1.2.1.2.2.1.8." + itoa(idx), Type: gosnmp.Integer, Value: 2},
		{Name: ".1.3.6.1.2.1.31.1.1.1.1." + itoa(idx), Type: gosnmp.OctetString, Value: []byte(name)},
	}}
}

func itoa(n int) string {
	return strings.TrimPrefix(netip.AddrFrom4([4]byte{0, 0, 0, byte(n)}).String(), "0.0.0.")
}

func newRecv(t testing.TB, cfg Config) (*Receiver, *[]Event) {
	t.Helper()
	var mu sync.Mutex
	evs := &[]Event{}
	r, err := New(cfg, func(e Event) { mu.Lock(); *evs = append(*evs, e); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetHosts([]Host{{ID: "h1", Addrs: []netip.Addr{hostIP}, Communities: []string{"trapcomm"}, Users: []User{v3User}}}); err != nil {
		t.Fatal(err)
	}
	return r, evs
}

func TestV2cTrap(t *testing.T) {
	r, _ := newRecv(t, Config{})
	pkt := capture(t, v2c("trapcomm"), linkDown(4, "Gi1/0/4"))
	reply, ev := r.process(pkt, hostIP)
	if reply != nil || ev == nil {
		t.Fatalf("Trap: reply=%v ev=%v", reply, ev)
	}
	if !ev.Known || ev.HostID != "h1" || ev.Version != "2c" || ev.TrapName != "linkDown" || ev.Kind != "link_down" {
		t.Fatalf("Event: %+v", ev)
	}
	if ev.IfIndex != 4 || ev.IfName != "Gi1/0/4" || ev.Service != "if:Gi1/0/4" || ev.Uptime != 12345 {
		t.Fatalf("Zuordnung: %+v", ev)
	}
	if len(ev.Varbinds) != 6 || ev.Varbinds[5].Value != "Gi1/0/4" {
		t.Fatalf("Varbinds: %+v", ev.Varbinds)
	}
	// falsche Community: abgewiesen, ohne Inhalt
	_, ev = r.process(capture(t, v2c("falsch"), linkDown(4, "x")), hostIP)
	if ev == nil || ev.Rejected != "community" || len(ev.Varbinds) > 0 || ev.TrapOID != "" {
		t.Fatalf("falsche Community: %+v", ev)
	}
	// unbekannter Absender: nur Kopfdaten
	_, ev = r.process(pkt, otherIP)
	if ev == nil || ev.Known || ev.TrapOID != ".1.3.6.1.6.3.1.1.5.3" || len(ev.Varbinds) > 0 {
		t.Fatalf("unbekannt: %+v", ev)
	}
	st := r.Stats()
	if st.Accepted != 1 || st.Rejected != 1 || st.Unknown != 1 {
		t.Fatalf("Stats: %+v", st)
	}
}

func TestV2cInform(t *testing.T) {
	r, _ := newRecv(t, Config{})
	tr := linkDown(2, "eth1")
	tr.IsInform = true
	pkt := capture(t, v2c("trapcomm"), tr)
	reply, ev := r.process(pkt, hostIP)
	if ev == nil || !ev.Inform || reply == nil {
		t.Fatalf("Inform: %v %+v", reply, ev)
	}
	p, err := (&gosnmp.GoSNMP{Version: gosnmp.Version2c, Logger: gosnmp.NewLogger(nil)}).SnmpDecodePacket(reply)
	if err != nil || p.PDUType != gosnmp.GetResponse || len(p.Variables) != len(tr.Variables) {
		t.Fatalf("Antwort: %v %+v", err, p)
	}
}

func TestV1Trap(t *testing.T) {
	r, _ := newRecv(t, Config{})
	g := &gosnmp.GoSNMP{Version: gosnmp.Version1, Community: "trapcomm"}
	pkt := capture(t, g, gosnmp.SnmpTrap{Enterprise: ".1.3.6.1.4.1.318", AgentAddress: "192.0.2.10", GenericTrap: 6, SpecificTrap: 5, Timestamp: 99,
		Variables: []gosnmp.SnmpPDU{{Name: ".1.3.6.1.4.1.318.2.3.3.0", Type: gosnmp.OctetString, Value: []byte("UPS: On battery power")}}})
	_, ev := r.process(pkt, hostIP)
	if ev == nil || ev.Version != "1" || ev.TrapOID != ".1.3.6.1.4.1.318.0.5" || ev.Kind != "ups_on_battery" || ev.Service != "ups" || ev.Uptime != 99 {
		t.Fatalf("v1 APC: %+v", ev)
	}
	pkt = capture(t, &gosnmp.GoSNMP{Version: gosnmp.Version1, Community: "trapcomm"}, gosnmp.SnmpTrap{Enterprise: ".1.3.6.1.4.1.8072", AgentAddress: "192.0.2.10", GenericTrap: 0})
	if _, ev = r.process(pkt, hostIP); ev == nil || ev.TrapName != "coldStart" || ev.Service != "uptime" {
		t.Fatalf("coldStart: %+v", ev)
	}
}

func TestV3Trap(t *testing.T) {
	r, _ := newRecv(t, Config{})
	tr := gosnmp.SnmpTrap{Variables: []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(7)},
		{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.2.1.33.2.1"},
		{Name: ".1.3.6.1.2.1.33.1.2.2.0", Type: gosnmp.Integer, Value: 12},
	}}
	pkt := capture(t, v3Client(v3User, senderEID), tr)
	reply, ev := r.process(pkt, hostIP)
	if reply != nil || ev == nil || ev.Rejected != "" || ev.Version != "3" || ev.User != "m64trap" || ev.Kind != "ups_on_battery" || ev.Service != "ups" {
		t.Fatalf("v3: %+v", ev)
	}
	// falsches Passwort
	bad := v3User
	bad.Secret.AuthPass = "falschfalsch"
	_, ev = r.process(capture(t, v3Client(bad, senderEID), tr), hostIP)
	if ev == nil || ev.Rejected != "user" || ev.TrapOID != "" {
		t.Fatalf("falsches Passwort: %+v", ev)
	}
	// unbekannter Benutzer
	other := v3User
	other.Name = "fremd"
	_, ev = r.process(capture(t, v3Client(other, senderEID), tr), hostIP)
	if ev == nil || ev.Rejected != "user" {
		t.Fatalf("unbekannter Benutzer: %+v", ev)
	}
	// ohne Authentifizierung, obwohl der Benutzer sie verlangt
	na := v3User
	na.Level = "noAuthNoPriv"
	_, ev = r.process(capture(t, v3Client(na, senderEID), tr), hostIP)
	if ev == nil || ev.Rejected != "user" {
		t.Fatalf("ohne Auth: %+v", ev)
	}
	// Engine-ID festgelegt: andere Engine abgewiesen, passende angenommen
	pinned := v3User
	pinned.EngineID = "80000000aabbccdd"
	if err := r.SetHosts([]Host{{ID: "h1", Addrs: []netip.Addr{hostIP}, Users: []User{pinned}}}); err != nil {
		t.Fatal(err)
	}
	if _, ev = r.process(pkt, hostIP); ev == nil || ev.Rejected != "engine" {
		t.Fatalf("Engine-ID: %+v", ev)
	}
	if _, ev = r.process(capture(t, v3Client(v3User, "80000000aabbccdd"), tr), hostIP); ev == nil || ev.Rejected != "" || ev.Kind != "ups_on_battery" {
		t.Fatalf("passende Engine-ID: %+v", ev)
	}
	// v3 von unbekanntem Absender: nur Benutzer
	if _, ev = r.process(pkt, otherIP); ev == nil || ev.Known || ev.User != "m64trap" || ev.TrapOID != "" {
		t.Fatalf("unbekannt v3: %+v", ev)
	}
}

func TestLimits(t *testing.T) {
	r, _ := newRecv(t, Config{MaxSize: 300, Rate: 1, Burst: 3, MaxVarbinds: 2})
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	pkt := capture(t, v2c("trapcomm"), linkDown(1, "a"))
	var ok int
	for i := 0; i < 10; i++ {
		if _, ev := r.process(pkt, hostIP); ev != nil {
			ok++
			if !ev.Truncated || len(ev.Varbinds) != 2 || ev.IfName != "a" {
				t.Fatalf("Kuerzen: %+v", ev)
			}
		}
	}
	if ok != 3 || r.Stats().RateLimited != 7 {
		t.Fatalf("Rate: %d %+v", ok, r.Stats())
	}
	now = now.Add(2 * time.Second) // 2 neue Token
	if _, ev := r.process(pkt, hostIP); ev == nil {
		t.Fatal("nach Pause wieder erlaubt")
	}
	big := make([]byte, 400)
	if _, ev := r.process(big, otherIP); ev != nil || r.Stats().TooBig != 1 {
		t.Fatal("zu gross")
	}
	for _, junk := range [][]byte{nil, {0x30}, {0x30, 0x03, 0x02, 0x01, 0x09}, []byte("hello world, kein snmp")} {
		if rep, ev := r.process(junk, otherIP); rep != nil || ev != nil {
			t.Fatalf("Muell: %x", junk)
		}
	}
	// Absender-Tabelle laeuft nicht ueber
	l := newLimiter(10, 5, 1e9, 100)
	for i := 0; i < 1000; i++ {
		l.allow(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), false, now)
	}
	if len(l.m) > 100 {
		t.Fatalf("Limiter: %d", len(l.m))
	}
}

func TestEngineDiscoveryReport(t *testing.T) {
	r, _ := newRecv(t, Config{EngineID: "80000000050102030405060708"})
	// Erkennungs-Paket wie von net-snmp/gosnmp: noAuthNoPriv, reportable, ohne Benutzer und Engine-ID
	probe := &gosnmp.SnmpPacket{Version: gosnmp.Version3, MsgFlags: gosnmp.NoAuthNoPriv | gosnmp.Reportable, SecurityModel: gosnmp.UserSecurityModel,
		SecurityParameters: &gosnmp.UsmSecurityParameters{Logger: gosnmp.NewLogger(nil)}, PDUType: gosnmp.GetRequest, MsgID: 4711, RequestID: 815,
		MsgMaxSize: 65507, Logger: gosnmp.NewLogger(nil)}
	b, err := probe.MarshalMsg()
	if err != nil {
		t.Fatal(err)
	}
	// unbekannter (womoeglich gefaelschter) Absender: keine Antwort (keine Verstaerkung)
	if reply, ev := r.process(b, otherIP); reply != nil || ev != nil {
		t.Fatalf("Report an unbekannten Absender: %v %+v", reply, ev)
	}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	reply, ev := r.process(b, hostIP)
	if ev != nil || reply == nil {
		t.Fatalf("Report erwartet: %v %+v", reply, ev)
	}
	p, _ := decodeV3Header(reply)
	sp, _ := p.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if p.PDUType != gosnmp.Report || p.MsgID != 4711 || sp == nil || hex.EncodeToString([]byte(sp.AuthoritativeEngineID)) != r.EngineID() {
		t.Fatalf("Report: %+v", p)
	}
	if wb, wt := localEngineTime(now); sp.AuthoritativeEngineBoots != wb || sp.AuthoritativeEngineTime != wt || wt == 0 {
		t.Fatalf("Report ohne eigene Boots/Time: %d/%d", sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime)
	}
	if r.EngineID() != "80000000050102030405060708" {
		t.Fatalf("EngineID: %s", r.EngineID())
	}
	if _, err := New(Config{EngineID: "zz"}, func(Event) {}); err == nil {
		t.Fatal("ungueltige Engine-ID")
	}
	if id := GenerateEngineID(); len(id) != 26 || !strings.HasPrefix(id, "8000000005") {
		t.Fatalf("GenerateEngineID: %s", id)
	}
}

// TestRateKnownSenders: ein flutender bekannter Absender und viele (gefaelschte) Unbekannte nehmen einem anderen
// bekannten Absender nicht den gemeinsamen Bucket weg (Bucket je Absender zuerst, gesamt getrennt nach bekannt).
func TestRateKnownSenders(t *testing.T) {
	r, _ := newRecv(t, Config{Rate: 10, Burst: 50, GlobalRate: 100})
	h2 := netip.MustParseAddr("192.0.2.11")
	if err := r.SetHosts([]Host{{ID: "h1", Addrs: []netip.Addr{hostIP}, Communities: []string{"trapcomm"}},
		{ID: "h2", Addrs: []netip.Addr{h2}, Communities: []string{"trapcomm"}}}); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	pkt := capture(t, v2c("trapcomm"), linkDown(1, "a"))
	for i := 0; i < 500; i++ {
		r.process(pkt, hostIP)
	}
	for i := 0; i < 2000; i++ { // gefaelschte Absender, je ein Paket
		r.process(pkt, netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}))
	}
	if _, ev := r.process(pkt, h2); ev == nil || ev.HostID != "h2" || ev.Rejected != "" {
		t.Fatalf("zweiter bekannter Absender blockiert: %+v stats %+v", ev, r.Stats())
	}
}

// TestV3TimeWindow: v3-Traps je Engine-ID und Benutzer nur im Zeitfenster (RFC 3414 3.2.7) – Wiederholungen
// mitgeschnittener Traps werden abgewiesen; v3-Informs muessen die eigene Boots/Time tragen.
func TestV3TimeWindow(t *testing.T) {
	r, _ := newRecv(t, Config{})
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	tr := linkDown(2, "eth2")
	client := func(boots, etime uint32, engine string) *gosnmp.GoSNMP {
		g := v3Client(v3User, engine)
		sp := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
		sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = boots, etime
		return g
	}
	old := capture(t, client(5, 1000, senderEID), tr)
	if _, ev := r.process(old, hostIP); ev == nil || ev.Rejected != "" {
		t.Fatalf("erster Trap: %+v", ev)
	}
	// Wiederholung 200 s spaeter (der Absender ist inzwischen weiter): ausserhalb des Fensters
	now = now.Add(200 * time.Second)
	if _, ev := r.process(old, hostIP); ev == nil || ev.Rejected != "time" || ev.TrapOID != "" {
		t.Fatalf("Wiederholung angenommen: %+v", ev)
	}
	// echter neuer Trap des Absenders
	if _, ev := r.process(capture(t, client(5, 1200, senderEID), tr), hostIP); ev == nil || ev.Rejected != "" {
		t.Fatalf("neuer Trap: %+v", ev)
	}
	// leicht verspaeteter Trap (innerhalb 150 s) bleibt gueltig
	if _, ev := r.process(capture(t, client(5, 1100, senderEID), tr), hostIP); ev == nil || ev.Rejected != "" {
		t.Fatalf("Trap im Fenster: %+v", ev)
	}
	// kleinere Boots: abgewiesen; groessere (Neustart des Absenders): angenommen
	if _, ev := r.process(capture(t, client(4, 99999, senderEID), tr), hostIP); ev == nil || ev.Rejected != "time" {
		t.Fatalf("alte Boots: %+v", ev)
	}
	if _, ev := r.process(capture(t, client(6, 3, senderEID), tr), hostIP); ev == nil || ev.Rejected != "" {
		t.Fatalf("Neustart des Absenders: %+v", ev)
	}
	if _, ev := r.process(capture(t, client(maxEngineBoot, 3, "8000000001020399"), tr), hostIP); ev == nil || ev.Rejected != "time" {
		t.Fatalf("Boots am Ende: %+v", ev)
	}
	// Informs: eigene Engine-ID, eigene Boots/Time
	inf := linkDown(3, "eth3")
	inf.IsInform = true
	lb, lt := localEngineTime(now)
	reply, ev := r.process(capture(t, client(lb, lt+10, r.EngineID()), inf), hostIP)
	if ev == nil || ev.Rejected != "" || reply == nil {
		t.Fatalf("Inform im Fenster: %v %+v", reply, ev)
	}
	reply, ev = r.process(capture(t, client(lb, lt-1000, r.EngineID()), inf), hostIP)
	if reply != nil || ev == nil || ev.Rejected != "time" {
		t.Fatalf("alter Inform angenommen: %v %+v", reply, ev)
	}
	if r.Stats().Rejected != 4 {
		t.Fatalf("Stats: %+v", r.Stats())
	}
}

// Echt ueber UDP: v2c-Trap, v2c-Inform, v3-Trap, v3-Inform (gosnmp erkennt die Engine-ID selbst), Start/Stopp.
func TestUDP(t *testing.T) {
	var mu sync.Mutex
	var evs []Event
	got := make(chan struct{}, 16)
	r, err := New(Config{Listen: "127.0.0.1:0"}, func(e Event) {
		mu.Lock()
		evs = append(evs, e)
		mu.Unlock()
		got <- struct{}{}
	})
	if err != nil {
		t.Fatal(err)
	}
	lo := netip.MustParseAddr("127.0.0.1")
	if err := r.SetHosts([]Host{{ID: "lo", Addrs: []netip.Addr{lo}, Communities: []string{"trapcomm"}, Users: []User{v3User}}}); err != nil {
		t.Fatal(err)
	}
	if r.Running() || r.Addr() != nil {
		t.Fatal("vor Start zu")
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	port := uint16(r.Addr().(*net.UDPAddr).Port)
	send := func(g *gosnmp.GoSNMP, tr gosnmp.SnmpTrap) error {
		g.Target, g.Port, g.Timeout, g.Retries, g.Logger = "127.0.0.1", port, time.Second, 1, gosnmp.NewLogger(nil)
		if err := g.Connect(); err != nil {
			return err
		}
		defer g.Conn.Close()
		_, err := g.SendTrap(tr)
		return err
	}
	wait := func(what string) {
		select {
		case <-got:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: kein Event", what)
		}
	}
	if err := send(v2c("trapcomm"), linkDown(3, "eth3")); err != nil {
		t.Fatal(err)
	}
	wait("v2c-Trap")
	inf := linkDown(3, "eth3")
	inf.IsInform = true
	if err := send(v2c("trapcomm"), inf); err != nil {
		t.Fatalf("v2c-Inform ohne Antwort: %v", err)
	}
	wait("v2c-Inform")
	if err := send(v3Client(v3User, senderEID), linkDown(5, "eth5")); err != nil {
		t.Fatal(err)
	}
	wait("v3-Trap")
	// v3-Inform: Empfaenger ist autoritativ, gosnmp erkennt dessen Engine-ID per Report
	sp, flags, _ := snmp.USM(v3User.Name, v3User.Level, v3User.AuthProto, v3User.PrivProto, v3User.Secret)
	g3 := &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: flags, SecurityParameters: sp}
	if err := send(g3, inf); err != nil {
		t.Fatalf("v3-Inform ohne Antwort: %v", err)
	}
	wait("v3-Inform")
	mu.Lock()
	if len(evs) != 4 || evs[2].Version != "3" || !evs[3].Inform || evs[3].IfName != "eth3" {
		t.Fatalf("Events: %+v", evs)
	}
	mu.Unlock()
	r.Stop()
	if r.Running() {
		t.Fatal("nach Stopp zu")
	}
	if err := r.Start(); err != nil { // wieder startbar
		t.Fatal(err)
	}
}

func TestCallbackPanicDoesNotStop(t *testing.T) {
	calls := make(chan struct{}, 4)
	r, _ := New(Config{Listen: "127.0.0.1:0"}, func(Event) { calls <- struct{}{}; panic("boom") })
	_ = r.SetHosts([]Host{{ID: "lo", Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Communities: []string{"c"}}})
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	port := uint16(r.Addr().(*net.UDPAddr).Port)
	for i := 0; i < 2; i++ {
		g := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: "c", Target: "127.0.0.1", Port: port, Timeout: time.Second, Logger: gosnmp.NewLogger(nil)}
		if err := g.Connect(); err != nil {
			t.Fatal(err)
		}
		_, _ = g.SendTrap(linkDown(1, "x"))
		g.Conn.Close()
		select {
		case <-calls:
		case <-time.After(3 * time.Second):
			t.Fatalf("Rueckruf %d fehlt", i+1)
		}
	}
}

// FuzzProcess: kaputte Pakete duerfen weder Panics noch Antworten an Unbekannte ausloesen.
func FuzzProcess(f *testing.F) {
	r, _ := newRecv(f, Config{Rate: 1e9, Burst: 1 << 30, GlobalRate: 1e9})
	f.Add(capture(f, v2c("trapcomm"), linkDown(4, "Gi1/0/4")))
	inf := linkDown(1, "x")
	inf.IsInform = true
	f.Add(capture(f, v2c("trapcomm"), inf))
	f.Add(capture(f, &gosnmp.GoSNMP{Version: gosnmp.Version1, Community: "trapcomm"}, gosnmp.SnmpTrap{Enterprise: ".1.3.6.1.4.1.318", AgentAddress: "192.0.2.10", GenericTrap: 6, SpecificTrap: 5}))
	f.Add(capture(f, v3Client(v3User, senderEID), linkDown(2, "y")))
	f.Add([]byte{0x30, 0x81, 0x05, 0x02, 0x01, 0x03, 0x30, 0x00})
	var caught any
	panicHook = func(p any) { caught = p }
	defer func() { panicHook = nil }()
	f.Fuzz(func(t *testing.T, b []byte) {
		caught = nil
		for _, from := range []netip.Addr{hostIP, otherIP} {
			reply, ev := r.process(b, from)
			if ev != nil && len(ev.Varbinds) > DefaultMaxVarbinds {
				t.Fatal("Varbinds nicht begrenzt")
			}
			if reply != nil && len(reply) > DefaultMaxSize {
				t.Fatal("Antwort zu gross")
			}
			if reply != nil && from == otherIP {
				t.Fatal("Antwort an unbekannten Absender")
			}
			if caught != nil { // abgefangen (der Empfang laeuft weiter), aber sichtbar machen
				t.Fatalf("Panic im Dekodierer: %v", caught)
			}
		}
	})
}
