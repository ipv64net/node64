package monitor64

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/monitor64/snmp"
	"github.com/ipv64net/node64/internal/monitor64/snmp/trap"
)

// trapRec zaehlt die ausgeloesten Runden und haelt verzoegerte Runden fest (statt echter Timer).
type trapRec struct {
	mu      sync.Mutex
	runs    map[string]int
	pending []func()
	now     time.Time
}

func (r *trapRec) run(uid string) { r.mu.Lock(); r.runs[uid]++; r.mu.Unlock() }
func (r *trapRec) count(uid string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.runs[uid]
}
func (r *trapRec) clock() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }
func (r *trapRec) add(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}
func (r *trapRec) after(_ time.Duration, f func()) *time.Timer {
	r.mu.Lock()
	r.pending = append(r.pending, f)
	r.mu.Unlock()
	t := time.NewTimer(time.Hour)
	t.Stop()
	return t
}
func (r *trapRec) fire() int {
	r.mu.Lock()
	fs := r.pending
	r.pending = nil
	r.mu.Unlock()
	for _, f := range fs {
		f()
	}
	return len(fs)
}

func fakeTraps(m *Module) *trapRec {
	r := &trapRec{runs: map[string]int{}, now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	m.traps.run, m.traps.now, m.traps.after = r.run, r.clock, r.after
	m.traps.start()
	return r
}

// snmpHostWithFake legt einen Host mit SNMP-Zugang (Traps an) an; die Abfrage liefert fake.
func snmpHostWithFake(t *testing.T, m *Module, fake *fakeCol) *hostRT {
	t.Helper()
	ctx := context.Background()
	if err := m.st.SetSetting(ctx, setTrapPort, strconv.Itoa(freeUDPPort(t))); err != nil { // nie Port 162 im Test
		t.Fatal(err)
	}
	h := &Host{Name: "sw1", Address: "192.0.2.40", IntervalSec: 60}
	if err := m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(accessConfig{SNMPVersion: "2c", Traps: true})
	a := &Access{HostUID: h.UID, Type: "snmp", Config: cfg, Secret: m.box.Encrypt(snmp.Secret{Community: "c"}.String()), Enabled: true}
	if err := m.store.SaveAccess(ctx, a, false, SystemActor); err != nil {
		t.Fatal(err)
	}
	m.ReloadHost(ctx, h.UID)
	m.syncTraps(ctx) // Host gilt erst nach dem Abgleich als bekannt
	m.rtMu.Lock()
	rt := m.rts[h.UID]
	m.rtMu.Unlock()
	rt.mu.Lock()
	for _, ar := range rt.accs {
		ar.col.close()
	}
	rt.accs = []*accRT{{row: a, col: fake}}
	rt.mu.Unlock()
	return rt
}

func svcView(rt *hostRT, key string) *SvcView {
	v := rt.getView()
	if v == nil {
		return nil
	}
	for i := range v.Services {
		if v.Services[i].Key == key {
			return &v.Services[i]
		}
	}
	return nil
}

func TestTrapCallback(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	r := fakeTraps(m)
	fake := &fakeCol{svcs: []model.Service{{Key: "uptime", Name: "Laufzeit", Kind: "uptime", Default: true}}}
	rt := snmpHostWithFake(t, m, fake)
	uid := rt.host.UID
	from := netip.MustParseAddr("192.0.2.40")

	// bekannte Art: sofortige Runde, entprellt (eine je 10 s), am Ende der Sperrzeit eine Nachzuegler-Runde
	m.traps.onEvent(trap.Event{From: from, HostID: uid, Known: true, Version: "2c", Kind: "link_down", TrapName: "linkDown", Service: "if:ge-0/0/1"})
	if r.count(uid) != 1 {
		t.Fatalf("known trap: runs %d", r.count(uid))
	}
	r.add(3 * time.Second)
	m.traps.onEvent(trap.Event{From: from, HostID: uid, Known: true, Version: "2c", Kind: "link_up", TrapName: "linkUp"})
	m.traps.onEvent(trap.Event{From: from, HostID: uid, Known: true, Version: "2c", Kind: "ups_on_battery"})
	if r.count(uid) != 1 {
		t.Fatalf("not debounced: runs %d", r.count(uid))
	}
	if n := r.fire(); n != 1 { // genau ein Nachzuegler fuer beide
		t.Fatalf("trailing runs scheduled: %d", n)
	}
	if r.count(uid) != 2 {
		t.Fatalf("trailing run missing: %d", r.count(uid))
	}
	r.add(11 * time.Second)
	m.traps.onEvent(trap.Event{From: from, HostID: uid, Known: true, Version: "2c", Kind: "restart"})
	if r.count(uid) != 3 {
		t.Fatalf("after debounce window: runs %d", r.count(uid))
	}
	if s := m.traps.service(uid); len(s.Facts) != 0 || s.Metrics[0].Value != 0 {
		t.Fatalf("known traps must not warn: %+v", s)
	}

	// erste Runde: Dienst "traps" wird angeboten; uebernehmen
	m.poll(ctx, rt)
	adoptAll(t, m, uid)
	m.poll(ctx, rt)
	if sv := svcView(rt, trapSvcKey); sv == nil || sv.State != eval.OK {
		t.Fatalf("traps service: %+v", sv)
	}

	// unbekannte Art: Dienst "traps" mit Warnung, Problem offen
	r.add(11 * time.Second)
	m.traps.onEvent(trap.Event{From: from, HostID: uid, Known: true, Version: "2c", TrapOID: ".1.3.6.1.4.1.9999.0.1",
		Varbinds: []trap.Varbind{{OID: ".1.3.6.1.4.1.9999.1", Type: "OctetString", Value: "<script>alert(1)</script>"}}})
	if r.count(uid) != 4 {
		t.Fatalf("unknown kind: runs %d", r.count(uid))
	}
	m.poll(ctx, rt)
	sv := svcView(rt, trapSvcKey)
	if sv == nil || sv.State != eval.Warn || !strings.Contains(sv.Cause, "monitor64.detail.traps") {
		t.Fatalf("traps service after unknown trap: %+v", sv)
	}
	if m.loadOpen(ctx, uid)[trapSvcKey] == nil {
		t.Fatal("no problem for traps service")
	}
	if snap := m.traps.snapshot(uid, true); snap.Pending != 1 || snap.Total != 5 || len(snap.List) != 5 {
		t.Fatalf("snapshot: %+v", snap)
	}
	// gespeicherter Stand ohne Varbinds
	if rt.Traps == nil || rt.Traps.Pending != 1 || len(rt.Traps.List[len(rt.Traps.List)-1].Varbinds) != 0 {
		t.Fatalf("runtime copy: %+v", rt.Traps)
	}

	// abgewiesen: nur gezaehlt
	m.traps.onEvent(trap.Event{From: from, HostID: uid, Known: true, Rejected: "community", Version: "2c"})
	if snap := m.traps.snapshot(uid, false); snap.Rejected != 1 || snap.RejectReason != "community" || snap.Pending != 1 {
		t.Fatalf("rejected: %+v", snap)
	}

	// Quittieren setzt den Dienst zurueck, die naechste Runde loest das Problem
	if err := m.Ack(ctx, uid, trapSvcKey, "", SystemActor); err != nil {
		t.Fatal(err)
	}
	if snap := m.traps.snapshot(uid, false); snap.Pending != 0 {
		t.Fatalf("ack did not reset: %+v", snap)
	}
	m.poll(ctx, rt)
	if sv := svcView(rt, trapSvcKey); sv == nil || sv.State != eval.OK {
		t.Fatalf("traps service after ack: %+v", sv)
	}
	if m.loadOpen(ctx, uid)[trapSvcKey] != nil {
		t.Fatal("problem still open after ack")
	}

	// Liste begrenzt
	for i := 0; i < trapKeep+5; i++ {
		m.traps.onEvent(trap.Event{From: from, HostID: uid, Known: true, Version: "2c", Kind: "link_up"})
	}
	if snap := m.traps.snapshot(uid, true); len(snap.List) != trapKeep || snap.Pending != 0 {
		t.Fatalf("list not limited: %d", len(snap.List))
	}

	// Zugang ohne Traps: kein Dienst
	cfg, _ := json.Marshal(accessConfig{SNMPVersion: "2c"})
	rt.mu.Lock()
	rt.accs[0].row.Config = cfg
	_, _, ok := m.trapService(rt)
	rt.mu.Unlock()
	if ok {
		t.Fatal("traps service without traps")
	}
}

func TestTrapUnknownSenders(t *testing.T) {
	m, _, _ := newTestModule(t)
	r := fakeTraps(m)
	for i := 0; i < maxUnknownSenders+5; i++ {
		r.add(time.Second)
		m.traps.onEvent(trap.Event{From: netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), Version: "2c", TrapOID: ".1.3.6.1.6.3.1.1.5.3", TrapName: "linkDown"})
	}
	r.add(time.Second)
	m.traps.onEvent(trap.Event{From: netip.MustParseAddr("198.51.100.104"), Version: "3", User: "mon"}) // zweiter Trap: gezaehlt
	st := m.trapStatus(context.Background())
	if len(st.Unknown) != maxUnknownSenders {
		t.Fatalf("unknown list: %d", len(st.Unknown))
	}
	if st.Unknown[0].Addr != "198.51.100.104" || st.Unknown[0].Count != 2 || st.Unknown[0].User != "mon" {
		t.Fatalf("newest first: %+v", st.Unknown[0])
	}
	for _, u := range st.Unknown {
		if u.Addr == "198.51.100.0" { // der am laengsten stille fiel raus
			t.Fatal("oldest sender not evicted")
		}
	}
	if len(m.traps.hosts) != 0 || len(r.runs) != 0 {
		t.Fatal("unknown sender created host state or triggered a run")
	}
	// API: leeren
	e := newEnv(t)
	e.m.traps.onEvent(trap.Event{From: netip.MustParseAddr("198.51.100.7"), Version: "2c"})
	var ts trapStatus
	decodeBody(t, e.do("GET", "/api/monitor64/traps", nil).Body.Bytes(), &ts)
	if len(ts.Unknown) != 1 || ts.Port != defaultTrapPort || ts.Running {
		t.Fatalf("api traps: %+v", ts)
	}
	e.do("DELETE", "/api/monitor64/traps/unknown", nil)
	decodeBody(t, e.do("GET", "/api/monitor64/traps", nil).Body.Bytes(), &ts)
	if len(ts.Unknown) != 0 || !e.audited("monitor64.traps.unknown_clear") {
		t.Fatalf("clear: %+v", ts)
	}
}

// freeUDPPort sucht einen freien UDP-Port auf 127.0.0.1.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return p
}

// TestSyncTrapsReceiver: Port nur offen, solange ein Zugang Traps nutzt; Engine-ID einmal erzeugt; ein echter
// v2c-Trap von der Host-Adresse landet im Dienst "traps", einer mit falscher Community wird nur gezaehlt.
func TestSyncTrapsReceiver(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	m := e.m
	port := freeUDPPort(t)
	if err := m.st.SetSetting(ctx, setTrapPort, strconv.Itoa(port)); err != nil {
		t.Fatal(err)
	}
	var runMu sync.Mutex
	runs := 0
	m.traps.run = func(string) { runMu.Lock(); runs++; runMu.Unlock() }
	rec := e.do("POST", "/api/monitor64/hosts", map[string]any{"name": "lo", "address": "127.0.0.1", "kind": "snmp", "paused": true,
		"accesses": []map[string]any{{"type": "snmp", "config": map[string]any{"snmp_version": "2c", "traps": true}, "secret": `{"community":"trap-c"}`}}})
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created struct{ UID string }
	decodeBody(t, rec.Body.Bytes(), &created)
	m.syncTraps(ctx)
	st := m.trapStatus(ctx)
	if !st.Running || st.Active != 1 || st.Error != "" || !reEngineID.MatchString(st.EngineID) {
		t.Fatalf("receiver: %+v", st)
	}
	engine := st.EngineID
	send := func(community string) {
		t.Helper()
		g := &gosnmp.GoSNMP{Target: "127.0.0.1", Port: uint16(port), Community: community, Version: gosnmp.Version2c, Timeout: time.Second}
		if err := g.Connect(); err != nil {
			t.Fatal(err)
		}
		defer g.Conn.Close()
		_, err := g.SendTrap(gosnmp.SnmpTrap{Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(100)},
			{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.9999.0.7"},
			{Name: ".1.3.6.1.4.1.9999.1", Type: gosnmp.OctetString, Value: "Tuer offen"}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	send("trap-c")
	send("falsch")
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := m.traps.snapshot(created.UID, true)
		if s != nil && s.Pending == 1 && s.Rejected == 1 {
			if s.List[0].TrapOID != ".1.3.6.1.4.1.9999.0.7" {
				t.Fatalf("entry: %+v", s.List[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("trap not received: %+v stats %+v", s, m.trapStatus(ctx).Stats)
		}
		time.Sleep(20 * time.Millisecond)
	}
	runMu.Lock()
	if runs != 1 {
		t.Errorf("runs: %d", runs)
	}
	runMu.Unlock()
	var ht hostTrapsOut
	decodeBody(t, e.do("GET", "/api/monitor64/hosts/"+created.UID+"/traps", nil).Body.Bytes(), &ht)
	if ht.Pending != 1 || len(ht.List) != 1 || ht.List[0].Varbinds == nil || ht.Rejected != 1 {
		t.Fatalf("host traps: %+v", ht)
	}
	e.do("POST", "/api/monitor64/hosts/"+created.UID+"/traps/reset", nil)
	if s := m.traps.snapshot(created.UID, false); s.Pending != 0 {
		t.Fatal("reset failed")
	}
	// Port aendern: neuer Empfaenger, Engine-ID bleibt
	port2 := freeUDPPort(t)
	if rec := e.do("PUT", "/api/monitor64/settings", map[string]any{"interval": 60, "workers": 16, "trap_port": port2}); rec.Code != 200 {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("PUT", "/api/monitor64/settings", map[string]any{"interval": 60, "workers": 16, "trap_port": 0}); rec.Code != 400 {
		t.Fatalf("bad port accepted: %d", rec.Code)
	}
	m.syncTraps(ctx)
	st = m.trapStatus(ctx)
	if !st.Running || st.Port != port2 || st.EngineID != engine {
		t.Fatalf("port change: %+v", st)
	}
	m.traps.mu.Lock()
	rcv := m.traps.rcv
	m.traps.mu.Unlock()
	if a := rcv.Addr(); a == nil || !strings.HasSuffix(a.String(), fmt.Sprintf(":%d", port2)) {
		t.Fatalf("listening on %v", a)
	}
	// Traps aus: Port zu
	accs, _ := m.store.Accesses(ctx, created.UID)
	if rec := e.do("PUT", "/api/monitor64/access/"+accs[0].UID, map[string]any{"config": map[string]any{"snmp_version": "2c"}}); rec.Code != 200 {
		t.Fatalf("traps off: %d %s", rec.Code, rec.Body)
	}
	m.syncTraps(ctx)
	if st := m.trapStatus(ctx); st.Running || st.Active != 0 {
		t.Fatalf("receiver still open: %+v", st)
	}
	if s := m.traps.snapshot(created.UID, false); s != nil {
		t.Fatal("state of host without traps kept")
	}
	// Ausschalten des Moduls schliesst den Port
	if rec := e.do("PUT", "/api/monitor64/access/"+accs[0].UID, map[string]any{"config": map[string]any{"snmp_version": "2c", "traps": true}}); rec.Code != 200 {
		t.Fatal(rec.Body)
	}
	m.syncTraps(ctx)
	if !m.trapStatus(ctx).Running {
		t.Fatal("not reopened")
	}
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if m.trapStatus(ctx).Running {
		t.Fatal("receiver open after stop")
	}
	m.syncTraps(ctx) // nach dem Stop oeffnet nichts mehr
	if m.trapStatus(ctx).Running {
		t.Fatal("receiver reopened after stop")
	}
}

// TestTrapHostsV3: v3-Benutzer mit gueltigen Verfahren landen beim Empfaenger, fehlerhafte nicht.
func TestTrapHostsV3(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	h := &Host{Name: "ups", Address: "192.0.2.50", IntervalSec: 60}
	if err := m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(accessConfig{SNMPVersion: "3", User: "mon", Level: "authPriv", AuthProto: "SHA256", PrivProto: "AES", Traps: true, TrapEngine: "80001f8880aabbccdd"})
	// alte Community aus v2c-Zeiten im Geheimnis: bei v3 nicht als Community annehmen
	sec := snmp.Secret{Community: "alt-v2c", AuthPass: "auth-pass-1", PrivPass: "priv-pass-1"}.String()
	if err := m.store.SaveAccess(ctx, &Access{HostUID: h.UID, Type: "snmp", Config: cfg, Secret: m.box.Encrypt(sec), Enabled: true}, false, SystemActor); err != nil {
		t.Fatal(err)
	}
	set, err := m.trapHosts(ctx)
	if err != nil || len(set.hosts) != 1 {
		t.Fatalf("hosts: %v %d", err, len(set.hosts))
	}
	th := set.hosts[0]
	if th.ID != h.UID || len(th.Addrs) != 1 || th.Addrs[0] != netip.MustParseAddr("192.0.2.50") || len(th.Users) != 1 || th.Users[0].EngineID != "80001f8880aabbccdd" || len(th.Communities) != 0 {
		t.Fatalf("trap host: %+v", th)
	}
	if got := resolveAddrs(ctx, "[2001:db8::1]:161"); len(got) != 1 || got[0] != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("resolve v6: %v", got)
	}
	if got := resolveAddrs(ctx, "fe80::1%eth0"); len(got) != 1 || got[0].Zone() != "" {
		t.Fatalf("resolve zone: %v", got)
	}
}

// TestTrapDNSFailureKeepsHost: scheitert die Aufloesung des Host-Namens, bleibt der Host bekannt – mit seinem
// Trap-Stand und der zuletzt bekannten Adresse (frueher: Stand geloescht, Traps als "unbekannt"); der Abgleich wird
// wiederholt.
func TestTrapDNSFailureKeepsHost(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	m := e.m
	port := freeUDPPort(t)
	if err := m.st.SetSetting(ctx, setTrapPort, strconv.Itoa(port)); err != nil {
		t.Fatal(err)
	}
	h := &Host{Name: "nas", Address: "m64-trap-test.invalid", IntervalSec: 60, Paused: true}
	if err := m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(accessConfig{SNMPVersion: "2c", Traps: true})
	if err := m.store.SaveAccess(ctx, &Access{HostUID: h.UID, Type: "snmp", Config: cfg, Secret: m.box.Encrypt(snmp.Secret{Community: "dns-c"}.String()), Enabled: true}, false, SystemActor); err != nil {
		t.Fatal(err)
	}
	m.traps.mu.Lock()
	m.traps.addrs[h.UID] = trapAddrs{address: h.Address, list: []netip.Addr{netip.MustParseAddr("127.0.0.1")}} // frueher aufgeloest
	m.traps.mu.Unlock()
	m.traps.restore(h.UID, &hostTraps{Pending: 1, Total: 1, List: []trapEntry{{Time: time.Now(), Version: "2c", TrapOID: ".1.3.6.1.4.1.9999.0.1"}}})
	m.syncTraps(ctx)
	if st := m.trapStatus(ctx); st.Active != 1 || !st.Running {
		t.Fatalf("host with DNS failure dropped: %+v", st)
	}
	if s := m.traps.snapshot(h.UID, false); s == nil || s.Pending != 1 {
		t.Fatalf("trap state lost on DNS failure: %+v", s)
	}
	if !m.traps.syncDue() {
		t.Fatal("no retry after DNS failure")
	}
	g := &gosnmp.GoSNMP{Target: "127.0.0.1", Port: uint16(port), Community: "dns-c", Version: gosnmp.Version2c, Timeout: time.Second}
	if err := g.Connect(); err != nil {
		t.Fatal(err)
	}
	defer g.Conn.Close()
	if _, err := g.SendTrap(gosnmp.SnmpTrap{Variables: []gosnmp.SnmpPDU{{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.9999.0.2"}}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if s := m.traps.snapshot(h.UID, false); s != nil && s.Pending == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("trap from last known address not accepted: %+v", m.trapStatus(ctx))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestTrapPortRetry: ist der Port belegt, oeffnet der Empfaenger ihn, sobald er frei wird (frueher erst beim naechsten
// Anstoss durch eine Aenderung).
func TestTrapPortRetry(t *testing.T) {
	old := trapRetryEvery
	trapRetryEvery = 20 * time.Millisecond
	t.Cleanup(func() { trapRetryEvery = old })
	ctx := context.Background()
	busy, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	port := busy.LocalAddr().(*net.UDPAddr).Port
	e := newEnv(t)
	m := e.m
	if err := m.st.SetSetting(ctx, setTrapPort, strconv.Itoa(port)); err != nil {
		t.Fatal(err)
	}
	h := &Host{Name: "lo", Address: "127.0.0.1", IntervalSec: 60, Paused: true}
	if err := m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(accessConfig{SNMPVersion: "2c", Traps: true})
	if err := m.store.SaveAccess(ctx, &Access{HostUID: h.UID, Type: "snmp", Config: cfg, Secret: m.box.Encrypt(snmp.Secret{Community: "c"}.String()), Enabled: true}, false, SystemActor); err != nil {
		t.Fatal(err)
	}
	m.syncTraps(ctx)
	if st := m.trapStatus(ctx); st.Running || st.Error == "" {
		_ = busy.Close()
		t.Fatalf("busy port: %+v", st)
	}
	_ = busy.Close()
	deadline := time.Now().Add(5 * time.Second)
	for !m.trapStatus(ctx).Running {
		if time.Now().After(deadline) {
			t.Fatalf("receiver not reopened after the port became free: %+v", m.trapStatus(ctx))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if m.traps.syncDue() {
		t.Fatal("retry still pending after success")
	}
}

// TestTrapsForgottenWhenDisabled: Traps aus vergisst auch den gemerkten Stand im Laufzeitstand; beim Wiedereinschalten
// ist nichts Altes offen.
func TestTrapsForgottenWhenDisabled(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	m := e.m
	if err := m.st.SetSetting(ctx, setTrapPort, strconv.Itoa(freeUDPPort(t))); err != nil {
		t.Fatal(err)
	}
	rec := e.do("POST", "/api/monitor64/hosts", map[string]any{"name": "lo", "address": "127.0.0.1", "kind": "snmp", "paused": true,
		"accesses": []map[string]any{{"type": "snmp", "config": map[string]any{"snmp_version": "2c", "traps": true}, "secret": `{"community":"c"}`}}})
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created struct{ UID string }
	decodeBody(t, rec.Body.Bytes(), &created)
	uid := created.UID
	m.syncTraps(ctx)
	rtOf := func() *hostRT {
		m.rtMu.Lock()
		defer m.rtMu.Unlock()
		return m.rts[uid]
	}
	m.traps.onEvent(trap.Event{From: netip.MustParseAddr("127.0.0.1"), HostID: uid, Known: true, Version: "2c", TrapOID: ".1.3.6.1.4.1.9999.0.1"})
	rt := rtOf()
	rt.mu.Lock()
	rt.Traps = m.traps.snapshot(uid, false) // wie nach einer Runde
	rt.mu.Unlock()
	if rt.Traps == nil || rt.Traps.Pending != 1 {
		t.Fatalf("setup: %+v", rt.Traps)
	}
	accs, _ := m.store.Accesses(ctx, uid)
	au := "/api/monitor64/access/" + accs[0].UID
	if rec := e.do("PUT", au, map[string]any{"config": map[string]any{"snmp_version": "2c"}}); rec.Code != 200 {
		t.Fatalf("traps off: %d %s", rec.Code, rec.Body)
	}
	m.syncTraps(ctx)
	rt = rtOf()
	rt.mu.Lock()
	kept := rt.Traps
	rt.mu.Unlock()
	if kept != nil {
		t.Fatalf("runtime copy kept after traps off: %+v", kept)
	}
	if rec := e.do("PUT", au, map[string]any{"config": map[string]any{"snmp_version": "2c", "traps": true}}); rec.Code != 200 {
		t.Fatalf("traps on: %d %s", rec.Code, rec.Body)
	}
	m.syncTraps(ctx)
	if s := m.traps.snapshot(uid, false); s != nil && s.Pending != 0 {
		t.Fatalf("old traps open again: %+v", s)
	}
}

// TestTrapLateEvents: Events aus der Warteschlange nach dem Stopp bzw. von Hosts, die keine Traps (mehr) nutzen,
// legen keinen Stand an.
func TestTrapLateEvents(t *testing.T) {
	m, _, _ := newTestModule(t)
	r := fakeTraps(m)
	const known, gone = "host00000001", "host00000002"
	m.traps.mu.Lock()
	m.traps.known = map[string]bool{known: true}
	m.traps.mu.Unlock()
	from := netip.MustParseAddr("192.0.2.40")
	m.traps.onEvent(trap.Event{From: from, HostID: known, Known: true, Version: "2c", TrapOID: ".1.3.6.1.4.1.9999.0.1"})
	m.traps.onEvent(trap.Event{From: from, HostID: gone, Known: true, Version: "2c", TrapOID: ".1.3.6.1.4.1.9999.0.1"})
	m.traps.onEvent(trap.Event{From: from, HostID: gone, Known: true, Version: "2c", Rejected: "community"})
	if s := m.traps.snapshot(gone, false); s != nil || r.count(gone) != 0 {
		t.Fatalf("state for host without traps: %+v", s)
	}
	if s := m.traps.snapshot(known, false); s == nil || s.Pending != 1 {
		t.Fatalf("known host: %+v", s)
	}
	m.traps.stop()
	m.traps.onEvent(trap.Event{From: from, HostID: known, Known: true, Version: "2c", TrapOID: ".1.3.6.1.4.1.9999.0.1"})
	m.traps.onEvent(trap.Event{From: netip.MustParseAddr("198.51.100.1"), Version: "2c"})
	if s := m.traps.snapshot(known, false); s.Total != 1 || len(m.traps.unknown) != 0 {
		t.Fatalf("event after stop counted: %+v unknown %d", s, len(m.traps.unknown))
	}
	if m.traps.addEntry(known, trapEntry{Version: "2c"}) {
		t.Fatal("entry accepted after stop")
	}
}
