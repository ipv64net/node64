package ipam64

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/store"
	nodesync "github.com/ipv64net/node64/internal/sync"
	"github.com/ipv64net/node64/internal/web"
)

// Grundlage der Tests: Entwurf von UlrichSchwarz (fakeNet, Render-Test), erweitert um Datenmodell v2, IPv6 und Cluster.

var csrfRe = regexp.MustCompile(`name="_csrf" value="([^"]+)"`)

// fakeNet ersetzt Nachbartabelle, Adressen der Node und das Ansprechen der Adressen.
type fakeNet struct {
	tab    map[netip.Addr]Neighbor
	swept  []netip.Prefix
	locals []netip.Prefix
	ifs    map[string]string // Adresse der Node -> Schnittstelle (fehlt: eth0)
}

func modTest(t *testing.T) (*Module, *fakeNet, string) {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	cm, _ := store.CoreMigrations()
	if err := core.Migrate(context.Background(), "core", cm); err != nil {
		t.Fatal(err)
	}
	if err := core.Migrate(context.Background(), Name, Migrations()); err != nil {
		t.Fatal(err)
	}
	m := New(core, log)
	f := &fakeNet{tab: map[netip.Addr]Neighbor{}, locals: []netip.Prefix{netip.MustParsePrefix("192.168.1.2/24"), netip.MustParsePrefix("fd00:10::2/64")}}
	m.neigh = func() (map[netip.Addr]Neighbor, error) { return f.tab, nil }
	m.locals = func() []local {
		var out []local
		for _, p := range f.locals {
			name := "eth0"
			if n, ok := f.ifs[p.String()]; ok {
				name = n
			}
			out = append(out, local{p, name})
		}
		return out
	}
	m.sweep = func(_ context.Context, p netip.Prefix) { f.swept = append(f.swept, p) }
	m.wait = 0
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	return m, f, dir
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func entry(t *testing.T, s *Snapshot, addr string) *Entry {
	t.Helper()
	return s.Entry(ip(addr))
}

func mustPrefix(t *testing.T, m *Module, p Prefix) Prefix {
	t.Helper()
	out, err := m.SavePrefix(context.Background(), p, "test")
	if err != nil {
		t.Fatalf("prefix %s: %v", p.Prefix, err)
	}
	return out
}

// Eingaben pruefen: Praefixe (IPv4/IPv6, verschachtelt, doppelt), Adressen, Bereiche.
func TestStore(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	for _, tc := range []struct {
		in   string
		want error
	}{{"192.168.1.0/33", ErrPrefix}, {"10.0.0.0/7", ErrSize}, {"2001:db8::/12", ErrSize}, {"fe80::1%eth0/64", ErrPrefix}, {"nix", ErrPrefix}} {
		if _, err := m.SavePrefix(ctx, Prefix{Prefix: tc.in}, "t"); !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v", tc.in, err)
		}
	}
	home := mustPrefix(t, m, Prefix{Prefix: "192.168.0.0/16", Status: StatusContainer, Name: "Heim"})
	lan := mustPrefix(t, m, Prefix{Prefix: "192.168.1.7/24", Name: "LAN", VLAN: 10, Tags: []string{"Clients, wlan clients"}})
	if lan.Prefix != "192.168.1.0/24" || lan.Family != 4 || strings.Join(lan.Tags, ",") != "clients,wlan" || lan.UpdatedBy != "test" || lan.UID == home.UID {
		t.Fatalf("lan: %+v", lan)
	}
	v6 := mustPrefix(t, m, Prefix{Prefix: "FD00:10::1/64"})
	if v6.Prefix != "fd00:10::/64" || v6.Family != 6 || v6.Status != StatusActive || v6.Scan != ScanPassive {
		t.Fatalf("v6: %+v", v6)
	}
	if _, err := m.SavePrefix(ctx, Prefix{Prefix: "192.168.1.0/24"}, "t"); !errors.Is(err, ErrDup) {
		t.Fatalf("dup: %v", err)
	}
	if _, err := m.SavePrefix(ctx, Prefix{Prefix: "192.168.2.0/24", VLAN: 4095}, "t"); !errors.Is(err, ErrVLAN) {
		t.Fatalf("vlan: %v", err)
	}
	if _, err := m.SavePrefix(ctx, Prefix{Prefix: "192.168.2.0/24", Name: "<b>"}, "t"); !errors.Is(err, ErrName) {
		t.Fatalf("name: %v", err)
	}
	// Adressen
	for _, tc := range []struct {
		a    Address
		want error
	}{
		{Address{Address: "10.0.0.5"}, ErrNoNet},
		{Address{Address: "192.168.1.0"}, ErrNetAddr},
		{Address{Address: "192.168.1.255"}, ErrNetAddr},
		{Address{Address: "192.168.1.5", Name: "Nas_1"}, ErrHost},
		{Address{Address: "192.168.1.5", MAC: "zz"}, ErrMAC},
		{Address{Address: "192.168.1.5", DHCP: true}, ErrMAC},
		{Address{Address: "fd00:10::5", DHCP: true, MAC: "02:00:00:00:00:05"}, ErrMAC}, // kein DHCPv6
		{Address{Address: "192.168.1.5", Role: "boss"}, ErrRole},
		{Address{Address: "192.168.1.5", Status: StatusContainer}, ErrStatus},
	} {
		if _, err := m.SaveAddress(ctx, tc.a, "t"); !errors.Is(err, tc.want) {
			t.Fatalf("%+v: %v", tc.a, err)
		}
	}
	a, err := m.SaveAddress(ctx, Address{Address: "192.168.1.10", Name: "NAS", MAC: "02-64-03-00-00-0A", Role: "dns"}, "t")
	if err != nil || a.Name != "nas" || a.MAC != "02:64:03:00:00:0a" {
		t.Fatalf("address: %+v %v", a, err)
	}
	if _, err := m.SaveAddress(ctx, Address{Address: "192.168.1.10"}, "t"); !errors.Is(err, ErrTaken) {
		t.Fatalf("taken: %v", err)
	}
	if _, err := m.SaveAddress(ctx, Address{Address: "fd00:10::10", Name: "nas"}, "t"); err != nil {
		t.Fatalf("v6 address: %v", err)
	}
	// Bereiche
	if _, err := m.SaveRange(ctx, Range{Start: "192.168.1.10", End: "192.168.1.5"}, "t"); !errors.Is(err, ErrRange) {
		t.Fatalf("range order: %v", err)
	}
	if _, err := m.SaveRange(ctx, Range{Start: "192.168.1.250", End: "192.168.2.5"}, "t"); err != nil { // liegt im /16
		t.Fatalf("range in container: %v", err)
	}
	if _, err := m.SaveRange(ctx, Range{Start: "10.0.0.1", End: "10.0.0.5"}, "t"); !errors.Is(err, ErrRangeNet) {
		t.Fatalf("range outside: %v", err)
	}
	if _, err := m.SaveRange(ctx, Range{Start: "192.168.1.200", End: "192.168.1.251"}, "t"); !errors.Is(err, ErrOverlap) {
		t.Fatalf("overlap: %v", err)
	}
	if _, err := m.DeletePrefix(ctx, "00000000000000000000000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
}

// Zusammenfuehren: Baum, DHCP-Netze aus DNS64, Quellen, IPv6, Arten, Zustand und Konflikte.
func TestSnapshot(t *testing.T) {
	m, f, _ := modTest(t)
	ctx := context.Background()
	now := time.Now()
	m.SetNetworks(func(context.Context) []NetHint {
		return []NetHint{{Name: "Heimnetz", Iface: "eth0.10", Subnet: netip.MustParsePrefix("192.168.1.0/24"), Router: ip("192.168.1.1"), Start: ip("192.168.1.100"), End: ip("192.168.1.199"), Domain: "home.lan"}}
	})
	m.SetSource(SrcDHCP, func(context.Context) []Sighting {
		return []Sighting{
			{Addr: "192.168.1.10", MAC: "02:64:03:00:00:0A", Name: "nas", Kind: KindFixed},
			{Addr: "192.168.1.150", MAC: "02:64:03:00:00:96", Name: "handy", Kind: KindDHCP, Seen: now.Add(-time.Hour)},
		}
	})
	m.SetSource(SrcDNS, func(context.Context) []Sighting {
		return []Sighting{{Addr: "192.168.1.10", Name: "nas.home.lan"}, {Addr: "fd00:10::10", Name: "nas6.home.lan"}}
	})
	m.SetSource(SrcProxy, func(context.Context) []Sighting {
		return []Sighting{{Addr: "https://nas:5001", Note: "nas.beispiel.ipv64.net"}}
	})
	mustPrefix(t, m, Prefix{Prefix: "192.168.0.0/16", Status: StatusContainer})
	mustPrefix(t, m, Prefix{Prefix: "192.168.1.0/24", VLAN: 0}) // ergaenzt das DHCP-Netz
	mustPrefix(t, m, Prefix{Prefix: "192.168.1.128/28", Name: "Kameras"})
	mustPrefix(t, m, Prefix{Prefix: "fd00:10::/64"})
	if _, err := m.SaveAddress(ctx, Address{Address: "192.168.1.20", Name: "drucker", MAC: "02:64:03:00:00:14", Status: StatusReserved}, "t"); err != nil {
		t.Fatal(err)
	}
	// fremde MAC an der festen Adresse .20 schon seit 10 Minuten (Daempfung: erst ab 5 Minuten ein Konflikt)
	if err := m.saveSeen(ctx, []seenRow{{IP: ip("192.168.1.20"), MAC: "02:64:03:00:00:ff", Last: now.Add(-10 * time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	f.tab = map[netip.Addr]Neighbor{
		ip("192.168.1.20"):  {MAC: "02:64:03:00:00:ff", Age: time.Minute}, // fremde MAC an fester Adresse: Konflikt
		ip("192.168.1.130"): {MAC: "02:64:03:00:00:82", Age: time.Second},
		ip("fd00:10::10"):   {MAC: "02:64:03:00:00:0a", Age: time.Second},
	}
	if err := m.poll(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := m.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Nets) != 4 || s.Nets[0].CIDR != "192.168.0.0/16" || s.Nets[3].CIDR != "fd00:10::/64" || s.Nets[2].Parent != "192.168.1.0/24" || s.Nets[2].Depth != 2 {
		t.Fatalf("tree: %+v", s.Nets)
	}
	lan := s.Net("192.168.1.0/24")
	if !lan.DHCP || lan.VLAN != 10 || lan.DNSZone != "home.lan" || lan.UID == "" || !lan.Attached || lan.PoolStart != "192.168.1.100" || lan.Children != 1 {
		t.Fatalf("lan: %+v", lan)
	}
	if home := s.Net("192.168.0.0/16"); home.Pct < 0.39 || home.Pct > 0.4 { // ein /24 von 256
		t.Fatalf("container cover: %v", home.Pct)
	}
	nas := entry(t, s, "192.168.1.10")
	if nas == nil || nas.Kind != KindFixed || nas.Name != "nas" || strings.Join(nas.Sources, ",") != "dhcp,dns,proxy" {
		t.Fatalf("nas: %+v", nas)
	}
	if e := entry(t, s, "192.168.1.20"); e == nil || e.Kind != KindConflict || e.UID == "" || e.Status != StatusReserved || len(e.MACs) != 2 {
		t.Fatalf("conflict: %+v", e)
	}
	if e := entry(t, s, "192.168.1.150"); e == nil || e.Kind != KindDHCP || e.State != "offline" {
		t.Fatalf("lease: %+v", e)
	}
	if e := entry(t, s, "192.168.1.130"); e == nil || e.State != "online" || s.NetOf(ip("192.168.1.130")).Name != "Kameras" {
		t.Fatalf("child prefix: %+v", e)
	}
	if e := entry(t, s, "192.168.1.2"); e == nil || e.NameKey != "ipam64.note.self" {
		t.Fatalf("self: %+v", e)
	}
	if e := entry(t, s, "fd00:10::10"); e == nil || e.Name != "nas6.home.lan" || e.State != "online" {
		t.Fatalf("v6: %+v", e)
	}
	if lan.Conflicts != 1 || lan.Used != 4 { // .2 .10 .20 .150; .1 nur als Router-Angabe, .130 im Kind-Praefix
		t.Fatalf("lan counts: used %d conflicts %d", lan.Used, lan.Conflicts)
	}
	// zwischengespeichert, nach eigener Aenderung neu
	if s2, _ := m.Snapshot(ctx); s2 != s {
		t.Fatal("snapshot not cached")
	}
	if _, err := m.SaveAddress(ctx, Address{Address: "192.168.1.30"}, "t"); err != nil {
		t.Fatal(err)
	}
	if s2, _ := m.Snapshot(ctx); s2 == s || s2.Entry(ip("192.168.1.30")) == nil {
		t.Fatal("snapshot not rebuilt")
	}
}

// Freie Adressen: nicht im Pool, nicht reserviert, nicht belegt, erst in Bereichen fuer feste Adressen.
func TestAvailable(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	m.SetNetworks(func(context.Context) []NetHint {
		return []NetHint{{Subnet: netip.MustParsePrefix("192.168.1.0/24"), Start: ip("192.168.1.1"), End: ip("192.168.1.9")}}
	})
	mustPrefix(t, m, Prefix{Prefix: "192.168.1.0/24"})
	mustPrefix(t, m, Prefix{Prefix: "fd00:10::/64"})
	if _, err := m.SaveRange(ctx, Range{Start: "192.168.1.10", End: "192.168.1.12", Kind: RangeReserved}, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SaveAddress(ctx, Address{Address: "192.168.1.13"}, "t"); err != nil {
		t.Fatal(err)
	}
	got, err := m.Available(ctx, "192.168.1.0/24", "", 2)
	if err != nil || len(got) != 2 || got[0].String() != "192.168.1.14" || got[1].String() != "192.168.1.15" {
		t.Fatalf("free: %v %v", got, err)
	}
	r, err := m.SaveRange(ctx, Range{Start: "192.168.1.50", End: "192.168.1.51", Kind: RangeFixed}, "t")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Available(ctx, "192.168.1.0/24", "", 5); len(got) != 2 || got[0].String() != "192.168.1.50" {
		t.Fatalf("fixed range first: %v", got)
	}
	if got, _ := m.Available(ctx, "192.168.1.0/24", r.UID, 5); len(got) != 2 {
		t.Fatalf("range: %v", got)
	}
	if got, _ := m.Available(ctx, "fd00:10::/64", "", 1); len(got) != 1 || got[0].String() != "fd00:10::1" {
		t.Fatalf("v6: %v", got)
	}
	if _, err := m.Available(ctx, "10.0.0.0/8", "", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	s, _ := m.Snapshot(ctx)
	blocks := s.FreeBlocks(s.Net("192.168.1.0/24"))
	// .2 ist die Node selbst: Luecken .1 (im Pool), .3-.12, .14-.254
	if len(blocks) != 3 || !blocks[0].Pool || blocks[1].Last.String() != "192.168.1.12" || blocks[2].First.String() != "192.168.1.14" || blocks[2].Count != 241 {
		t.Fatalf("blocks: %+v", blocks)
	}
}

// Netz-Scan: nur private IPv4-Netze bis /22, die IPAM64 kennt und an denen die Node haengt; im Hintergrund.
func TestScan(t *testing.T) {
	for _, tc := range []struct {
		p    string
		want bool
	}{{"192.168.1.0/24", true}, {"10.0.0.0/22", true}, {"10.0.0.0/21", false}, {"100.64.1.0/24", true}, {"8.8.8.0/24", false}, {"fd00::/64", false}, {"172.32.0.0/24", false}} {
		if got := scanAllowed(netip.MustParsePrefix(tc.p)); got != tc.want {
			t.Fatalf("%s: %v", tc.p, got)
		}
	}
	m, f, _ := modTest(t)
	ctx := context.Background()
	mustPrefix(t, m, Prefix{Prefix: "192.168.1.0/24"})
	mustPrefix(t, m, Prefix{Prefix: "192.168.5.0/24"})
	mustPrefix(t, m, Prefix{Prefix: "fd00:10::/64"})
	if err := m.StartScan(ctx, "192.168.1.0/24"); !errors.Is(err, ErrNotFound) { // Modul laeuft nicht
		t.Fatalf("not running: %v", err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.StartScan(ctx, "192.168.5.0/24"); !errors.Is(err, ErrNotAttached) {
		t.Fatalf("not attached: %v", err)
	}
	if err := m.StartScan(ctx, "fd00:10::/64"); !errors.Is(err, ErrNoScan) {
		t.Fatalf("v6: %v", err)
	}
	if err := m.StartScan(ctx, "10.9.0.0/24"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	f.tab = map[netip.Addr]Neighbor{ip("192.168.1.40"): {MAC: "02:64:03:00:00:28", Age: time.Second}, ip("192.168.1.41"): {MAC: "02:64:03:00:00:29", Age: time.Hour}}
	if err := m.StartScan(ctx, "192.168.1.0/24"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for m.Scanning().Running && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	st := m.Scanning()
	if st.Running || st.Found != 1 || st.Prefix != "192.168.1.0/24" || len(f.swept) != 1 || m.LastScan(ctx).IsZero() {
		t.Fatalf("scan: %+v swept %v", st, f.swept)
	}
	p, _ := m.SavePrefix(ctx, Prefix{UID: mustUID(t, m, "192.168.1.0/24"), Prefix: "192.168.1.0/24", Scan: ScanOff}, "t")
	if err := m.StartScan(ctx, p.Prefix); !errors.Is(err, ErrNoScan) {
		t.Fatalf("scan off: %v", err)
	}
}

func mustUID(t *testing.T, m *Module, cidr string) string {
	t.Helper()
	s, err := m.Snapshot(context.Background())
	if err != nil || s.Net(cidr) == nil {
		t.Fatalf("%s: %v", cidr, err)
	}
	return s.Net(cidr).UID
}

func neighMsg(addr netip.Addr, state uint16, mac []byte, ticks uint32) []byte {
	attr := func(typ uint16, v []byte) []byte {
		b := make([]byte, 4, 4+len(v)+3)
		binary.NativeEndian.PutUint16(b[0:2], uint16(4+len(v)))
		binary.NativeEndian.PutUint16(b[2:4], typ)
		b = append(b, v...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	nd := make([]byte, ndMsgLen)
	binary.NativeEndian.PutUint16(nd[8:10], state)
	nd = append(nd, attr(ndaDst, addr.AsSlice())...)
	if mac != nil {
		nd = append(nd, attr(ndaLLAddr, mac)...)
	}
	ci := make([]byte, 16)
	binary.NativeEndian.PutUint32(ci[0:4], ticks)
	nd = append(nd, attr(ndaCacheInfo, ci)...)
	h := make([]byte, nlmsgHdrLen)
	binary.NativeEndian.PutUint32(h[0:4], uint32(nlmsgHdrLen+len(nd)))
	binary.NativeEndian.PutUint16(h[4:6], rtmNewNeigh)
	return append(h, nd...)
}

func TestParseNeigh(t *testing.T) {
	mac := []byte{2, 0x64, 3, 0, 0, 1}
	var b []byte
	b = append(b, neighMsg(ip("192.168.1.1"), nudReachable, mac, 250)...)
	b = append(b, neighMsg(ip("192.168.1.2"), 0x20, mac, 1)...) // failed
	b = append(b, neighMsg(ip("192.168.1.3"), nudStale, nil, 1)...)
	b = append(b, neighMsg(ip("2001:db8::1"), nudStale, mac, 100)...)
	b = append(b, neighMsg(ip("fe80::1"), nudReachable, mac, 1)...) // Link-Local
	got := parseNeigh(b)
	if len(got) != 2 || got[ip("192.168.1.1")].Age != 2500*time.Millisecond || got[ip("2001:db8::1")].MAC != "02:64:03:00:00:01" {
		t.Fatalf("neigh: %+v", got)
	}
}

// Cluster: Stand lesen und uebernehmen, gleicher Wert unter zwei uids (kleinere gewinnt), Aenderungen melden.
func TestCluster(t *testing.T) {
	a, _, _ := modTest(t)
	b, _, _ := modTest(t)
	ctx := context.Background()
	type ch struct {
		item, id string
		del      bool
	}
	var got []ch
	b.SetCluster(ClusterHooks{Change: func(_ context.Context, item, id string, del bool) { got = append(got, ch{item, id, del}) }})
	p := mustPrefix(t, a, Prefix{Prefix: "192.168.1.0/24", Name: "LAN"})
	ad, err := a.SaveAddress(ctx, Address{Address: "192.168.1.10", Name: "nas"}, "anna")
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range []struct{ item, id string }{{ClusterItemPrefixes, p.UID}, {ClusterItemAddresses, ad.UID}} {
		raw, found, err := a.ClusterGet(ctx, it.item, it.id)
		if err != nil || !found {
			t.Fatalf("get %s: %v", it.item, err)
		}
		if err := b.ClusterApply(ctx, it.item, it.id, raw, false); err != nil {
			t.Fatalf("apply %s: %v", it.item, err)
		}
	}
	if len(got) != 0 {
		t.Fatalf("apply reported changes: %+v", got)
	}
	cur, _ := b.AddressByIP(ctx, "192.168.1.10")
	if cur == nil || cur.UID != ad.UID || cur.UpdatedBy != "anna" || !cur.Updated.Equal(ad.Updated) {
		t.Fatalf("applied: %+v", cur)
	}
	ids, _ := b.ClusterIDs(ctx, ClusterItemAddresses)
	if len(ids) != 1 || ids[0] != ad.UID {
		t.Fatalf("ids: %v", ids)
	}
	// gleiches Praefix hier unter groesserer uid: wird durch die fremde (kleinere) ersetzt
	big := Prefix{UID: "ffffffffffffffffffffffffffffffff", Prefix: "10.0.0.0/24", Status: StatusActive, Scan: ScanPassive, Updated: time.Now().UTC().Truncate(time.Second)}
	if err := b.writePrefix(ctx, big); err != nil {
		t.Fatal(err)
	}
	small := big
	small.UID = "00000000000000000000000000000001"
	raw, _ := json.Marshal(small)
	if err := b.ClusterApply(ctx, ClusterItemPrefixes, small.UID, raw, false); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (ch{ClusterItemPrefixes, big.UID, true}) {
		t.Fatalf("double: %+v", got)
	}
	// umgekehrt: eigene kleinere uid bleibt, fremde wird nicht uebernommen
	other := small
	other.UID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	raw, _ = json.Marshal(other)
	if err := b.ClusterApply(ctx, ClusterItemPrefixes, other.UID, raw, false); err != nil {
		t.Fatal(err)
	}
	if p, _ := b.prefixByUID(ctx, other.UID); p != nil {
		t.Fatal("larger uid taken over")
	}
	if err := b.ClusterApply(ctx, ClusterItemAddresses, ad.UID, nil, true); err != nil {
		t.Fatal(err)
	}
	if cur, _ := b.AddressByIP(ctx, "192.168.1.10"); cur != nil {
		t.Fatal("not deleted")
	}
	if err := b.ClusterApply(ctx, "nope", ad.UID, nil, true); err == nil {
		t.Fatal("unknown item accepted")
	}
	// eigene Aenderung wird gemeldet
	if _, err := b.SaveAddress(ctx, Address{Address: "192.168.1.11"}, "t"); err != nil {
		t.Fatal(err)
	}
	if got[len(got)-1].item != ClusterItemAddresses || got[len(got)-1].del {
		t.Fatalf("own change: %+v", got)
	}
}

func TestExportImport(t *testing.T) {
	a, _, _ := modTest(t)
	b, _, _ := modTest(t)
	ctx := context.Background()
	mustPrefix(t, a, Prefix{Prefix: "192.168.1.0/24"})
	if _, err := a.SaveRange(ctx, Range{Start: "192.168.1.10", End: "192.168.1.20"}, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SaveAddress(ctx, Address{Address: "192.168.1.10", Name: "nas"}, "t"); err != nil {
		t.Fatal(err)
	}
	data, err := a.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(data)
	if n, err := b.Import(ctx, raw); err != nil || n != 3 {
		t.Fatalf("import: %d %v", n, err)
	}
	if n, err := b.Import(ctx, raw); err != nil || n != 3 { // zweimal: gleiche uid ersetzt
		t.Fatalf("reimport: %d %v", n, err)
	}
	list, _ := b.Addresses(ctx)
	if len(list) != 1 || list[0].Name != "nas" {
		t.Fatalf("imported: %+v", list)
	}
}

// Blockuebersicht grosser Praefixe: IPv4 /16 je /24, eigenes Praefix, Belegung, Treffer; IPv6 8 Bit tiefer.
func TestBlockMap(t *testing.T) {
	p := netip.MustParsePrefix("10.80.0.0/16")
	n := Net{CIDR: p.String(), Prefix: p, Family: 4}
	s := &Snapshot{Nets: []Net{n, {CIDR: "10.80.5.0/24", Prefix: netip.MustParsePrefix("10.80.5.0/24"), Family: 4, Parent: p.String()}}, entries: map[netip.Prefix][]Entry{}}
	for i := 1; i <= 200; i++ {
		s.entries[p] = append(s.entries[p], Entry{ip: netip.AddrFrom4([4]byte{10, 80, 7, byte(i)}), Name: "h" + strconv.Itoa(i)})
	}
	s.entries[p] = append(s.entries[p], Entry{ip: netip.MustParseAddr("10.80.255.9"), Name: "nas"})
	for i := 1; i <= 254; i++ {
		s.entries[p] = append(s.entries[p], Entry{ip: netip.AddrFrom4([4]byte{10, 80, 9, byte(i)})})
	}
	if mapBits(&n) != 24 {
		t.Fatalf("mapBits v4: %d", mapBits(&n))
	}
	cells := s.blockMap(&n, 24, func(e *Entry) bool { return e.Name == "nas" })
	if len(cells) != 256 || cells[7].Count != 200 || cells[7].Level != "mid" || cells[7].Label != "7" || cells[255].Level != "low" || cells[255].Hits != 1 ||
		cells[5].Level != "child" || cells[9].Level != "full" || cells[0].Level != "empty" || cells[255].CIDR != "10.80.255.0/24" {
		t.Fatalf("v4 map: %+v %+v %+v", cells[7], cells[255], cells[5])
	}
	v6 := netip.MustParsePrefix("2001:db8:1::/48")
	n6 := Net{CIDR: v6.String(), Prefix: v6, Family: 6}
	s.entries[v6] = []Entry{{ip: netip.MustParseAddr("2001:db8:1:a510::1")}}
	if mapBits(&n6) != 56 {
		t.Fatalf("mapBits v6: %d", mapBits(&n6))
	}
	cells = s.blockMap(&n6, 56, nil)
	if len(cells) != 256 || cells[0xa5].Level != "used" || cells[0xa5].Label != "a5" || cells[0xa5].CIDR != "2001:db8:1:a500::/56" || bitsAt(netip.MustParseAddr("10.80.7.1"), 16, 24) != 7 {
		t.Fatalf("v6 map: %+v", cells[0xa5])
	}
}

func TestHelpers(t *testing.T) {
	if vlanOf("eth0.20") != 20 || vlanOf("br-vlan30") != 30 || vlanOf("eth0") != 0 || vlanOf("eth0.5000") != 0 {
		t.Fatal("vlanOf")
	}
	for in, want := range map[string]string{"https://NAS.home.lan:5001/x": "nas.home.lan", "192.168.1.5:80": "192.168.1.5", "[fd00::5]:443": "fd00::5", "fd00::5": "fd00::5", "nas.": "nas"} {
		if got := hostOf(in); got != want {
			t.Fatalf("hostOf(%q) = %q", in, got)
		}
	}
	if lastAddr(netip.MustParsePrefix("192.168.1.0/24")).String() != "192.168.1.255" || lastAddr(netip.MustParsePrefix("fd00::/120")).String() != "fd00::ff" {
		t.Fatal("lastAddr")
	}
	if r := csvRow("=1+1", "nas", "-x"); r[0] != "'=1+1" || r[1] != "nas" || r[2] != "'-x" {
		t.Fatal("csvRow", r)
	}
	if hostCount(netip.MustParsePrefix("10.0.0.0/31")) != 2 || hostCount(netip.MustParsePrefix("10.0.0.0/24")) != 254 {
		t.Fatal("hostCount")
	}
}

// Seiten, Formulare, CSV und API ueber den echten Webserver (Modul aus = 404).
// untranslated meldet einen i18n-Schluessel ipam64.* in einer Seite (das Skript ipam64.js zaehlt nicht).
func untranslated(body string) bool {
	return strings.Contains(strings.NewReplacer("ipam64.js", "", "ipam64.svg", "").Replace(body), "ipam64.")
}

func TestPagesRender(t *testing.T) {
	m, f, dir := modTest(t)
	st := m.core
	logger := logging.New("error", "text", io.Discard)
	bundle, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	m.SetSource(SrcDNS, func(context.Context) []Sighting { return []Sighting{{Addr: "192.168.1.3", Name: "pi<b>hole</b>"}} })
	m.SetNetworks(func(context.Context) []NetHint {
		return []NetHint{{Name: "IoT", Iface: "eth0.20", Subnet: netip.MustParsePrefix("192.168.20.0/24"), Start: ip("192.168.20.50"), End: ip("192.168.20.99")}}
	})
	reg := module.NewRegistry(st, logger.Slog())
	reg.Register(m)
	t.Cleanup(reg.StopAll)
	s, err := web.New(web.Deps{Cfg: &config.Config{DataDir: dir, HTTPPort: 8080, LogLevel: "error"}, Store: st, Log: logger, I18n: bundle, Modules: reg,
		Sync: nodesync.NoOp{}, Version: "test", StartedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var csrfTok string
	do := func(method, path, body, ctype string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		if csrfTok != "" && method != "GET" {
			req.Header.Set("X-CSRF-Token", csrfTok)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	get := func(path string) (int, string) { return do("GET", path, "", "") }
	post := func(path string, form url.Values) (int, string) {
		form.Set("_csrf", csrfTok)
		return do("POST", path, form.Encode(), "application/x-www-form-urlencoded")
	}
	js := func(method, path, body string) (int, string) { return do(method, path, body, "application/json") }
	_, body := get("/setup")
	csrf := csrfRe.FindStringSubmatch(body)
	if csrf == nil {
		t.Fatal("no csrf")
	}
	csrfTok = csrf[1]
	if code, _ := post("/setup", url.Values{"lang": {"de"}, "username": {"admin"}, "password": {"sehr geheimes passwort"},
		"password2": {"sehr geheimes passwort"}, "timezone": {"Europe/Berlin"}, "node_name": {"pi"}}); code != http.StatusSeeOther {
		t.Fatalf("setup: %d", code)
	}
	for _, p := range []string{"/ipam64", "/api/ipam64/prefixes", "/ipam64/export.csv"} {
		if code, _ := get(p); code != http.StatusNotFound {
			t.Fatalf("module off %s: %d", p, code)
		}
	}
	if err := reg.Enable(context.Background(), Name); err != nil {
		t.Fatal(err)
	}
	_, body = get("/")
	if !strings.Contains(body, `href="/ipam64"`) {
		t.Fatal("no menu entry")
	}
	csrfTok = csrfRe.FindStringSubmatch(body)[1]
	code, body := get("/ipam64")
	if code != 200 || !strings.Contains(body, `id="ipam-suggest"`) || !strings.Contains(body, "192.168.20.0/24") || untranslated(body) {
		t.Fatalf("overview start: %d\n%s", code, body)
	}
	if code, body = post("/ipam64/prefix", url.Values{"prefix": {"192.168.1.0/33"}}); code != http.StatusUnprocessableEntity || !strings.Contains(body, `id="ipam-form-error"`) {
		t.Fatalf("bad prefix: %d", code)
	}
	for _, p := range []url.Values{
		{"prefix": {"192.168.0.0/16"}, "status": {"container"}, "name": {"Heim"}},
		{"prefix": {"192.168.1.0/24"}, "name": {"LAN"}, "vlan": {"10"}, "dns_zone": {"home.lan"}, "scan": {"active"}},
		{"prefix": {"fd00:10::/64"}, "name": {"ULA"}},
	} {
		if code, _ := post("/ipam64/prefix", p); code != http.StatusSeeOther {
			t.Fatalf("prefix %v: %d", p, code)
		}
	}
	if code, _ = post("/ipam64/address", url.Values{"address": {"192.168.1.40"}, "name": {"switch-keller"}, "mac": {"02:64:03:00:00:28"}, "description": {"SNMP"}, "role": {"gateway"}}); code != http.StatusSeeOther {
		t.Fatalf("address: %d", code)
	}
	if code, body = post("/ipam64/address", url.Values{"address": {"192.168.1.41"}, "name": {"Bad Name"}}); code != http.StatusUnprocessableEntity || !strings.Contains(body, `id="ipam-form-error"`) {
		t.Fatalf("bad address: %d", code)
	}
	if code, _ = post("/ipam64/range", url.Values{"back": {"192.168.1.0/24"}, "start": {"192.168.1.200"}, "end": {"192.168.1.210"}, "kind": {"reserved"}, "name": {"Test"}}); code != http.StatusSeeOther {
		t.Fatalf("range: %d", code)
	}
	if err := m.saveSeen(context.Background(), []seenRow{{IP: ip("192.168.1.40"), MAC: "02:64:03:00:00:ff", Last: time.Now().Add(-10 * time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	f.tab = map[netip.Addr]Neighbor{ip("192.168.1.1"): {MAC: "02:64:03:00:00:01", Age: time.Second}, ip("192.168.1.40"): {MAC: "02:64:03:00:00:ff", Age: time.Second}}
	if code, _ = post("/ipam64/scan", url.Values{"prefix": {"192.168.1.0/24"}}); code != http.StatusSeeOther {
		t.Fatalf("scan: %d", code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for m.Scanning().Running && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	code, body = get("/ipam64")
	for _, want := range []string{`id="ipam-tree"`, "192.168.0.0/16", "fd00:10::/64", `href="/ipam64/conflicts">1</a>`, "Container", "home.lan"} {
		if code != 200 || !strings.Contains(body, want) {
			t.Fatalf("overview: %d, missing %q\n%s", code, want, body)
		}
	}
	code, body = get("/ipam64/prefix?p=192.168.1.0/24")
	for _, want := range []string{`id="ipam-grid"`, `id="ipam-list"`, `id="ip-192.168.1.40"`, `class="ipam-cell ipam-conflict"`, `class="ipam-cell ipam-reserved"`, `id="ipam-next"`, `id="ipam-scan"`, "ipam64.js"} {
		if code != 200 || !strings.Contains(body, want) {
			t.Fatalf("prefix grid: %d, missing %q\n%s", code, want, body)
		}
	}
	code, body = get("/ipam64/prefix?p=192.168.1.0/24&view=list")
	for _, want := range []string{`id="ip-192.168.1.40"`, "switch-keller", "SNMP", "pi&lt;b&gt;hole&lt;/b&gt;", "diese Node", "Lokaler DNS", `class="ipam-free-row"`} {
		if code != 200 || !strings.Contains(body, want) {
			t.Fatalf("prefix list: %d, missing %q\n%s", code, want, body)
		}
	}
	if untranslated(body) || strings.Contains(body, "<b>hole") {
		t.Fatalf("untranslated key or unescaped name\n%s", body)
	}
	if code, body = get("/ipam64/prefix?p=192.168.1.0/24&view=list&kind=conflict"); code != 200 || !strings.Contains(body, "switch-keller") || strings.Contains(body, `id="ip-192.168.1.3"`) ||
		!strings.Contains(body, "ipam-grid ipam-marking") || !strings.Contains(body, `ipam-conflict ipam-match" data-ip="192.168.1.40"`) || strings.Contains(body, `ipam-static ipam-match`) {
		t.Fatalf("filter: %d\n%s", code, body)
	}
	if code, body = get("/ipam64/prefix?p=192.168.1.0/24&view=ranges"); code != 200 || !strings.Contains(body, "192.168.1.200 – 192.168.1.210") || untranslated(body) {
		t.Fatalf("ranges: %d\n%s", code, body)
	}
	if code, body = get("/ipam64/prefix?p=fd00:10::/64"); code != 200 || strings.Contains(body, `id="ipam-grid"`) || !strings.Contains(body, `id="ipam-list"`) ||
		!strings.Contains(body, `id="ipam-map"`) || strings.Count(body, `<a class="ipam-cell ipam-lvl-`) != 256 || untranslated(body) {
		t.Fatalf("v6 prefix: %d\n%s", code, body)
	}
	// Blockuebersicht: Feld waehlen schraenkt die Liste ein, falsches Teilnetz wird ignoriert
	if code, body = get("/ipam64/prefix?p=fd00:10::/64&part=fd00:10::/72"); code != 200 || !strings.Contains(body, "ipam-active") || !strings.Contains(body, `id="ipam-map-all"`) {
		t.Fatalf("v6 part: %d\n%s", code, body)
	}
	if code, body = get("/ipam64/prefix?p=fd00:10::/64&part=fd00:10::/70"); code != 200 || strings.Contains(body, "ipam-active") {
		t.Fatalf("v6 bad part: %d", code)
	}
	if code, body = get("/ipam64/prefix?p=192.168.20.0/24"); code != 200 || !strings.Contains(body, "aus DNS64") {
		t.Fatalf("dhcp-only prefix: %d", code)
	}
	if code, _ = get("/ipam64/prefix?p=10.0.0.0/8"); code != http.StatusSeeOther {
		t.Fatalf("unknown prefix: %d", code)
	}
	if code, body = get("/ipam64/address?ip=192.168.1.3"); code != 200 || !strings.Contains(body, `name="address" value="192.168.1.3"`) || untranslated(body) {
		t.Fatalf("address page: %d\n%s", code, body)
	}
	if code, body = get("/ipam64/address?ip=192.168.1.40"); code != 200 || !strings.Contains(body, `id="ipam-conflict"`) || !strings.Contains(body, `value="switch-keller"`) {
		t.Fatalf("address edit: %d\n%s", code, body)
	}
	if code, body = get("/ipam64/export.csv?p=192.168.1.0/24"); code != 200 || !strings.HasPrefix(body, "prefix,ip,name,") || !strings.Contains(body, "192.168.1.0/24,192.168.1.40,switch-keller,") {
		t.Fatalf("csv: %d\n%s", code, body)
	}
	// API
	if code, body = get("/api/ipam64/prefixes"); code != 200 || !strings.Contains(body, `"prefix":"192.168.1.0/24"`) || !strings.Contains(body, `"conflicts":1`) {
		t.Fatalf("api prefixes: %d %s", code, body)
	}
	if code, body = get("/api/ipam64/addresses?prefix=192.168.1.0/24&q=switch"); code != 200 || !strings.Contains(body, `"ip":"192.168.1.40"`) || !strings.Contains(body, `"total":1`) {
		t.Fatalf("api addresses: %d %s", code, body)
	}
	if code, _ = get("/api/ipam64/addresses?prefix=10.0.0.0/24"); code != http.StatusNotFound {
		t.Fatalf("api unknown prefix: %d", code)
	}
	if code, body = js("POST", "/api/ipam64/prefixes", `{"prefix":"10.10.0.0/24","nope":1}`); code != http.StatusBadRequest {
		t.Fatalf("strict decode: %d %s", code, body)
	}
	if code, body = js("POST", "/api/ipam64/prefixes", `{"prefix":"10.10.0.0/24","name":"Labor"}`); code != http.StatusCreated || !strings.Contains(body, `"uid":"`) {
		t.Fatalf("api prefix: %d %s", code, body)
	}
	if code, _ = js("POST", "/api/ipam64/prefixes", `{"prefix":"10.10.0.0/24"}`); code != http.StatusConflict {
		t.Fatalf("api dup: %d", code)
	}
	code, body = js("POST", "/api/ipam64/available", `{"prefix":"10.10.0.0/24","name":"neu1"}`)
	if code != http.StatusCreated || !strings.Contains(body, `"address":"10.10.0.1"`) {
		t.Fatalf("allocate: %d %s", code, body)
	}
	if code, body = js("POST", "/api/ipam64/available", `{"prefix":"10.10.0.0/24","name":"neu2"}`); code != http.StatusCreated || !strings.Contains(body, `"address":"10.10.0.2"`) {
		t.Fatalf("allocate 2: %d %s", code, body)
	}
	if code, body = get("/api/ipam64/available?prefix=10.10.0.0/24&count=2"); code != 200 || !strings.Contains(body, `["10.10.0.3","10.10.0.4"]`) {
		t.Fatalf("available: %d %s", code, body)
	}
	var created Address
	_, body = js("POST", "/api/ipam64/addresses", `{"address":"10.10.0.50","name":"api","tags":["a","b"]}`)
	if err := json.Unmarshal([]byte(body), &created); err != nil || created.UID == "" {
		t.Fatalf("api address: %s", body)
	}
	if code, body = js("PUT", "/api/ipam64/addresses/"+created.UID, `{"address":"10.10.0.50","name":"api2","status":"reserved"}`); code != 200 || !strings.Contains(body, `"name":"api2"`) {
		t.Fatalf("api put: %d %s", code, body)
	}
	if code, _ = js("DELETE", "/api/ipam64/addresses/"+created.UID, ""); code != http.StatusNoContent {
		t.Fatalf("api delete: %d", code)
	}
	if code, body = get("/api/ipam64/scan"); code != 200 || !strings.Contains(body, `"prefix":"192.168.1.0/24"`) {
		t.Fatalf("api scan status: %d %s", code, body)
	}
	if code, _ = js("POST", "/api/ipam64/scan", `{"prefix":"8.8.8.0/24"}`); code != http.StatusNotFound {
		t.Fatalf("api scan unknown: %d", code)
	}
	if code, body = get("/"); code != 200 || !strings.Contains(body, `href="/ipam64"`) {
		t.Fatalf("dashboard: %d", code)
	}
	if code, body = get("/ipam64/conflicts"); code != 200 || !strings.Contains(body, `id="ipam-findings"`) || !strings.Contains(body, "Fremdes Gerät an 192.168.1.40") || untranslated(body) {
		t.Fatalf("conflicts: %d\n%s", code, body)
	}
	if code, _ = post("/ipam64/notify", url.Values{"conflicts": {"1"}}); code != http.StatusSeeOther {
		t.Fatalf("notify: %d", code)
	}
	if code, body = get("/api/ipam64/conflicts"); code != 200 || !strings.Contains(body, `"kind":"mac"`) {
		t.Fatalf("api conflicts: %d %s", code, body)
	}
	if code, body = get("/ipam64/import"); code != 200 || !strings.Contains(body, `id="ipam-import-form"`) || untranslated(body) {
		t.Fatalf("import page: %d\n%s", code, body)
	}
	if code, body = post("/ipam64/import", url.Values{"action": {"preview"}, "csv": {"ip;name\n192.168.1.77;csvtest\n10.99.0.1;fremd\n"}}); code != 200 ||
		!strings.Contains(body, `id="ipam-import-preview"`) || !strings.Contains(body, "csvtest") || untranslated(body) {
		t.Fatalf("import preview: %d\n%s", code, body)
	}
	if code, _ = post("/ipam64/import", url.Values{"action": {"apply"}, "csv": {"ip;name\n192.168.1.77;csvtest\n"}}); code != http.StatusSeeOther {
		t.Fatalf("import apply: %d", code)
	}
	if code, body = get("/api/ipam64/addresses?q=csvtest"); code != 200 || !strings.Contains(body, `"total":1`) {
		t.Fatalf("imported: %d %s", code, body)
	}
	if code, body = get("/ipam64/setup"); code != 200 || !strings.Contains(body, `id="ipam-setup-form"`) || !strings.Contains(body, "192.168.20.0/24") || untranslated(body) {
		t.Fatalf("setup: %d\n%s", code, body)
	}
	if code, _ = post("/ipam64/setup", url.Values{"take": {"p:192.168.20.0/24"}}); code != http.StatusSeeOther {
		t.Fatalf("setup apply: %d", code)
	}
	if code, body = get("/ipam64"); code != 200 || strings.Contains(body, "aus DNS64") || untranslated(body) {
		t.Fatalf("after setup: %d\n%s", code, body)
	}
	if code, body = get("/audit?area=ipam64"); code != 200 || !strings.Contains(body, "IPAM64: Präfix gespeichert") {
		t.Fatalf("audit: %d", code)
	}
}
