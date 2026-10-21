package netstat

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseProcNet(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1 0 100 0 0 10 0
   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0 100 0 0 10 0
   2: 0100007F:9C40 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 3 1 0 100 0 0 10 0
`
	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4 1 0 100 0 0 10 0
   1: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5 1 0 100 0 0 10 0
`
	udp := `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  1: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 6 2 0 0
  2: 0A00000A:D431 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 7 2 0 0
`
	list := parseProcNet(strings.NewReader(tcp), "tcp")
	if len(list) != 2 || list[0].Port != 8080 || !list[0].Addr.IsUnspecified() || list[1].Addr.String() != "127.0.0.1" || list[1].Port != 53 {
		t.Fatalf("tcp: %+v", list)
	}
	list6 := parseProcNet(strings.NewReader(tcp6), "tcp")
	if len(list6) != 2 || list6[0].Port != 443 || !list6[0].Addr.IsUnspecified() || list6[1].Addr.String() != "::1" || list6[1].Port != 22 {
		t.Fatalf("tcp6: %+v", list6)
	}
	u := parseProcNet(strings.NewReader(udp), "udp")
	if len(u) != 1 || u[0].Port != 53 { // verbundener UDP-Socket (Anfrage an 8.8.8.8) zaehlt nicht
		t.Fatalf("udp: %+v", u)
	}
	l := list[1] // 127.0.0.1:53
	if !l.Covers("tcp", "", 53) || !l.Covers("tcp", "127.0.0.1", 53) || l.Covers("tcp", "192.0.2.1", 53) || l.Covers("udp", "", 53) || l.Covers("tcp", "", 54) {
		t.Fatal("covers")
	}
	if !list6[0].Covers("tcp", "192.0.2.1", 443) || !list6[0].Covers("tcp", "[2001:db8::1]", 443) {
		t.Fatal(":: covers all addresses")
	}
	any4 := Listener{Proto: "tcp", Addr: list[0].Addr, Port: 443} // 0.0.0.0: nur IPv4
	if !any4.Covers("tcp", "192.0.2.1", 443) || any4.Covers("tcp", "2001:db8::1", 443) || any4.Covers("tcp", "[::1]", 443) || !any4.Covers("tcp", "", 443) {
		t.Fatal("0.0.0.0 must not cover IPv6 addresses")
	}

	// ganzes /proc: Dateien lesen, Rechte
	dir := t.TempDir()
	old := procRoot
	procRoot = dir
	defer func() { procRoot = old }()
	if _, ok := Listeners(); ok {
		t.Fatal("no /proc/net: unknown")
	}
	_ = os.MkdirAll(filepath.Join(dir, "net"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "self"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "sys", "net", "ipv4"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "net", "tcp"), []byte(tcp), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "net", "udp"), []byte(udp), 0o644)
	if all, ok := Listeners(); !ok || len(all) != 3 {
		t.Fatalf("listeners: %v %+v", ok, all)
	}
	_ = os.WriteFile(filepath.Join(dir, "self", "status"), []byte("Name:\tnode64\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000400\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "sys", "net", "ipv4", "ip_unprivileged_port_start"), []byte("1024\n"), 0o644)
	p := ReadPrivileges()
	if !p.Known || p.Root || !p.CapNetBind || p.UnprivStart != 1024 || !p.LowPortOK(53) {
		t.Fatalf("privileges: %+v", p)
	}
	p.CapNetBind = false
	if p.LowPortOK(80) || !p.LowPortOK(8080) {
		t.Fatal("without capability no low ports")
	}
	p.UnprivStart = 0
	if !p.LowPortOK(80) {
		t.Fatal("ip_unprivileged_port_start=0 allows all ports")
	}
	// root mit allen Faehigkeiten: darf; root ohne cap_net_bind_service (z. B. --cap-drop): darf nicht
	_ = os.WriteFile(filepath.Join(dir, "self", "status"), []byte("Uid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n"), 0o644)
	if p = ReadPrivileges(); !p.Root || !p.CapNetBind || !p.LowPortOK(80) {
		t.Fatalf("root: %+v", p)
	}
	_ = os.WriteFile(filepath.Join(dir, "self", "status"), []byte("Uid:\t0\t0\t0\t0\nCapEff:\t00000000a80421fb\n"), 0o644)
	if p = ReadPrivileges(); !p.Root || p.CapNetBind || p.LowPortOK(80) {
		t.Fatalf("root without capability: %+v", p)
	}
}
