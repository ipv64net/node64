package groups

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// neighMsg baut eine RTM_NEWNEIGH-Nachricht wie der Kernel.
func neighMsg(family byte, state uint16, ip netip.Addr, mac []byte) []byte {
	attr := func(t uint16, v []byte) []byte {
		b := make([]byte, align4(4+len(v)))
		binary.NativeEndian.PutUint16(b[0:2], uint16(4+len(v)))
		binary.NativeEndian.PutUint16(b[2:4], t)
		copy(b[4:], v)
		return b
	}
	body := make([]byte, ndMsgLen)
	body[0] = family
	binary.NativeEndian.PutUint16(body[8:10], state)
	body = append(body, attr(ndaDst, ip.AsSlice())...)
	if mac != nil {
		body = append(body, attr(ndaLLAddr, mac)...)
	}
	h := make([]byte, nlmsgHdrLen)
	binary.NativeEndian.PutUint32(h[0:4], uint32(nlmsgHdrLen+len(body)))
	binary.NativeEndian.PutUint16(h[4:6], rtmNewNeigh)
	return append(h, body...)
}

func TestParseNeighDump(t *testing.T) {
	mac1 := []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	mac2 := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	var b []byte
	b = append(b, neighMsg(afInet, 0x02, netip.MustParseAddr("192.168.1.20"), mac1)...)            // reachable
	b = append(b, neighMsg(afInet6, 0x04, netip.MustParseAddr("2001:db8::1234"), mac1)...)         // stale
	b = append(b, neighMsg(afInet6, 0x04, netip.MustParseAddr("fe80::1"), mac2)...)                // link-local
	b = append(b, neighMsg(afInet, nudFailed, netip.MustParseAddr("192.168.1.99"), mac2)...)       // gescheitert
	b = append(b, neighMsg(afInet, nudIncomplete, netip.MustParseAddr("192.168.1.98"), nil)...)    // ohne MAC
	b = append(b, neighMsg(afInet, 0x02, netip.MustParseAddr("192.168.1.97"), make([]byte, 6))...) // 00:00:..
	got := parseNeighDump(b)
	want := map[string]string{"192.168.1.20": "02:11:22:33:44:55", "2001:db8::1234": "02:11:22:33:44:55", "fe80::1": "aa:bb:cc:dd:ee:ff"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for ip, mac := range want {
		if got[netip.MustParseAddr(ip)] != mac {
			t.Fatalf("%s = %q, want %q (all: %v)", ip, got[netip.MustParseAddr(ip)], mac, got)
		}
	}
}

// MAC zuerst: das Geraet bleibt in seiner Gruppe, auch mit neuer IPv6; Reihenfolge der Gruppen = Vorrang.
func TestResolver(t *testing.T) {
	neigh := map[netip.Addr]string{
		netip.MustParseAddr("192.168.1.20"):   "02:11:22:33:44:55",
		netip.MustParseAddr("2001:db8::abcd"): "02:11:22:33:44:55", // neue Privacy-Adresse desselben Geraets
	}
	r := NewResolver(nil)
	r.read = func() (map[netip.Addr]string, error) { return neigh, nil }
	m1 := Member{Kind: KindMAC, Value: "02-11-22-33-44-55"}
	m2 := Member{Kind: KindNet, Value: "192.168.30.7/24"}
	m3 := Member{Kind: KindIP, Value: "192.168.1.50"}
	for _, m := range []*Member{&m1, &m2, &m3} {
		if !Normalize(m) {
			t.Fatalf("invalid %+v", m)
		}
	}
	if m1.Value != "02:11:22:33:44:55" || m2.Value != "192.168.30.0/24" {
		t.Fatalf("normalize: %q %q", m1.Value, m2.Value)
	}
	r.Set([]Group{{ID: 1, Name: "Kinder", Members: []Member{m1, m2}}, {ID: 2, Name: "Gäste", Members: []Member{m3, {Kind: KindNet, Value: "192.168.30.0/24"}}}})
	for ip, want := range map[string]string{"192.168.1.20": "Kinder", "2001:db8::abcd": "Kinder", "192.168.30.5": "Kinder", "192.168.1.50": "Gäste", "192.168.1.60": "", "::ffff:192.168.1.20": "Kinder"} {
		if got := r.For(netip.MustParseAddr(ip)); got.Name != want {
			t.Errorf("%s: group %q, want %q", ip, got.Name, want)
		}
	}
	if r.For(netip.MustParseAddr("2001:db8::abcd")).MAC != "02:11:22:33:44:55" {
		t.Fatal("mac missing")
	}
	for _, bad := range []Member{{Kind: KindMAC, Value: "zz"}, {Kind: KindIP, Value: "x"}, {Kind: KindNet, Value: "0.0.0.0/0"}, {Kind: KindNet, Value: "::ffff:0.0.0.0/96"}, {Kind: "other", Value: "1.2.3.4"}} {
		if Normalize(&bad) {
			t.Errorf("accepted %+v", bad)
		}
	}
	// ::ffff:-Netz wird zum IPv4-Netz, sonst traefe es nie
	if m4 := (Member{Kind: KindNet, Value: "::ffff:192.168.40.0/120"}); !Normalize(&m4) || m4.Value != "192.168.40.0/24" {
		t.Errorf("4in6 net: %q", m4.Value)
	}
}

// IPs: alle Adressen einer MAC aus der Nachbartabelle, ohne Link-Local, sortiert.
func TestResolverIPs(t *testing.T) {
	r := NewResolver(nil)
	r.read = func() (map[netip.Addr]string, error) {
		return map[netip.Addr]string{
			netip.MustParseAddr("192.168.1.20"):   "02:11:22:33:44:55",
			netip.MustParseAddr("fe80::1"):        "02:11:22:33:44:55",
			netip.MustParseAddr("2001:db8::abcd"): "02:11:22:33:44:55",
			netip.MustParseAddr("192.168.1.21"):   "02:11:22:33:44:66",
		}, nil
	}
	r.refresh(false)
	got := r.IPs("02:11:22:33:44:55")
	if len(got) != 2 || got[0].String() != "192.168.1.20" || got[1].String() != "2001:db8::abcd" {
		t.Fatalf("IPs = %v", got)
	}
}
