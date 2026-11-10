//go:build freebsd

package m64bsd

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Tests auf einem echten FreeBSD (Test-Datei bauen mit GOOS=freebsd go test -c ./internal/m64bsd und dort starten):
// sysctl, getfsstat und statfs gegen die Programme des Systems.

func sysctlN(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("sysctl", "-n", name).Output()
	if err != nil {
		t.Skipf("sysctl -n %s: %v", name, err)
	}
	return strings.TrimSpace(string(out))
}

func TestHostSysctl(t *testing.T) {
	sc := defaultSysctl
	cpu, err := readCPU(sc)
	if err != nil || cpu.Cores != int(u64(sysctlN(t, "hw.ncpu"))) || cpu.Idle == 0 {
		t.Fatalf("cpu: %+v %v", cpu, err)
	}
	mem, page, err := readMem(sc)
	if err != nil || mem.Total != u64(sysctlN(t, "hw.physmem")) || page != u64(sysctlN(t, "hw.pagesize")) ||
		mem.Available == 0 || mem.Available > mem.Total {
		t.Fatalf("mem: %+v %d %v", mem, page, err)
	}
	// vm.loadavg: sysctl zeigt "{ 0.18 0.14 0.06 }"; die Werte aendern sich zwischen den Aufrufen nur wenig
	b, err := sc("vm.loadavg")
	if err != nil {
		t.Fatal(err)
	}
	load, err := ParseLoadavg(b, longSize)
	f := strings.Fields(strings.Trim(sysctlN(t, "vm.loadavg"), "{} "))
	if err != nil || len(f) != 3 {
		t.Fatalf("loadavg: %+v %v %v", load, err, f)
	}
	if want, _ := strconv.ParseFloat(f[2], 64); load.L15 < want-0.05 || load.L15 > want+0.05 {
		t.Fatalf("loadavg: %+v, sysctl %v", load, f)
	}
	// kern.boottime: "{ sec = 1794296658, usec = 971942 } ..."
	boot := readBoottime(sc)
	if want := sysctlN(t, "kern.boottime"); boot <= 0 || !strings.Contains(want, "sec = "+strconv.FormatInt(boot, 10)+",") {
		t.Fatalf("boottime: %d, sysctl %s", boot, want)
	}
	// Swap: Summe wie swapinfo -k
	total, free, ok := readSwap(sc, page)
	out, err := exec.Command("swapinfo", "-k").Output()
	if err != nil {
		t.Skipf("swapinfo: %v", err)
	}
	wt, _, err := ParseSwapinfo(out)
	if !ok || err != nil || total != wt || free > total {
		t.Fatalf("swap: %d/%d ok=%v, swapinfo %d (%v)", total, free, ok, wt, err)
	}
	if p, k, bt := HostInfo(); p == "" || k != sysctlN(t, "kern.osrelease") || bt != boot {
		t.Fatalf("HostInfo: %q %q %d", p, k, bt)
	}
}

func TestHostCollect(t *testing.T) {
	cache := NewCache()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := Collect(ctx, Options{Cache: cache})
	cache.Wait()
	r = Collect(ctx, Options{Cache: cache}) // langsame Abschnitte jetzt aus dem Puffer
	b, _ := json.MarshalIndent(r, "", " ")
	t.Logf("%s", b)
	if len(r.Errors) != 0 {
		t.Fatalf("Fehler: %+v", r.Errors)
	}
	if r.CPU == nil || r.Mem == nil || r.Load == nil || r.Uptime <= 0 {
		t.Fatalf("Grundwerte fehlen: %+v", r)
	}
	root := false
	for _, f := range r.FS {
		if f.Mount == "/" && f.Total > 0 && f.Used > 0 && f.Used <= f.Total {
			root = true
		}
		if f.Type == "devfs" || f.Type == "tmpfs" || f.Type == "nfs" {
			t.Errorf("Pseudo-Dateisystem gemeldet: %+v", f)
		}
	}
	if !root {
		t.Fatalf("/ fehlt: %+v", r.FS)
	}
	if len(r.Net) == 0 || len(r.Disks) == 0 {
		t.Fatalf("Netz/Platten fehlen: %+v %+v", r.Net, r.Disks)
	}
	for _, n := range r.Net {
		if n.Kind == "" || n.MTU == 0 {
			t.Errorf("Schnittstelle unvollstaendig: %+v", n)
		}
	}
	caps := Caps(Options{Cache: cache})
	for _, want := range []string{m64proto.SecCPU, m64proto.SecMem, m64proto.SecFS, m64proto.SecNet, m64proto.SecDisk, m64proto.SecReboot} {
		found := false
		for _, c := range caps {
			found = found || c == want
		}
		if !found {
			t.Errorf("caps ohne %s: %v", want, caps)
		}
	}
}
