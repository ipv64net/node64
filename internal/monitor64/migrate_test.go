package monitor64

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/proxmox"
)

// pveLab ist ein Proxmox-Cluster "lab" mit den Nodes pve1 und pve2 (beide online) als Fake der API. VM 101 (web01)
// laeuft auf der Node in where; jede Node beantwortet Fragen zu allen Nodes (wie Proxmox, das weiterreicht).
type pveLab struct {
	mu      sync.Mutex
	cluster string
	where   string // Node von VM 101 ("" = geloescht)
	status  []byte
	hits    map[string]int
}

func newPVELab(t *testing.T) *pveLab {
	t.Helper()
	b, err := os.ReadFile("apis/testdata/pve/node_status.json")
	if err != nil {
		t.Fatal(err)
	}
	return &pveLab{cluster: "lab", where: "pve1", status: b, hits: map[string]int{}}
}

func (l *pveLab) move(node string) { l.mu.Lock(); l.where = node; l.mu.Unlock() }

func (l *pveLab) count(p string) int { l.mu.Lock(); defer l.mu.Unlock(); return l.hits[p] }

func (l *pveLab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/api2/json")
	if r.URL.RawQuery != "" {
		p += "?" + r.URL.RawQuery
	}
	l.mu.Lock()
	l.hits[p]++
	where, cluster := l.where, l.cluster
	l.mu.Unlock()
	vm := map[string]any{"vmid": 101, "name": "web01", "status": "running", "cpu": 0.04, "cpus": 2, "maxcpu": 2, "mem": 2147483648, "maxmem": 4294967296,
		"maxdisk": 34359738368, "netin": 1000000000, "netout": 500000000, "diskread": 2000000000, "diskwrite": 3000000000, "uptime": 86400}
	var data any
	switch {
	case p == "/cluster/status":
		data = []map[string]any{{"type": "cluster", "name": cluster, "quorate": 1, "nodes": 2},
			{"type": "node", "name": "pve1", "ip": "192.0.2.11", "nodeid": 1, "online": 1, "local": 1},
			{"type": "node", "name": "pve2", "ip": "192.0.2.12", "nodeid": 2, "online": 1}}
	case p == "/cluster/resources?type=vm":
		list := []map[string]any{} // Proxmox liefert eine leere Liste, nie null
		if where != "" {
			x := map[string]any{"type": "qemu", "node": where, "id": "qemu/101"}
			for k, v := range vm {
				x[k] = v
			}
			list = append(list, x)
		}
		data = list
	case p == "/cluster/ha/status/current":
		data = []any{}
	case p == "/cluster/ceph/status":
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"data":null,"message":"binary not installed: /usr/bin/ceph-mon"}`))
		return
	case strings.HasSuffix(p, "/status") && strings.HasPrefix(p, "/nodes/"):
		_, _ = w.Write([]byte(`{"data":` + string(l.status) + `}`))
		return
	case strings.HasSuffix(p, "/qemu?full=1"):
		list := []map[string]any{}
		if where != "" && p == "/nodes/"+where+"/qemu?full=1" {
			x := map[string]any{"qmpstatus": "running"}
			for k, v := range vm {
				x[k] = v
			}
			list = append(list, x)
		}
		data = list
	case strings.HasSuffix(p, "/qemu/101/config"):
		data = map[string]any{"onboot": 1}
	case strings.HasSuffix(p, "/lxc"), strings.HasSuffix(p, "/storage"), strings.HasSuffix(p, "/disks/zfs"), strings.HasSuffix(p, "/disks/list"),
		strings.HasSuffix(p, "/apt/update"):
		data = []any{}
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"data":null,"message":"not found"}`))
		return
	}
	b, _ := json.Marshal(map[string]any{"data": data})
	_, _ = w.Write(b)
}

func (l *pveLab) serve(t *testing.T) (addr, pin string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(l)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL, proxmox.CertFingerprint(srv.Certificate().Raw)
}

// pveNodeHost legt einen Proxmox-Host fuer node an (Zugang mit eingetragener Node, wie nach dem ersten Kontakt) und
// setzt den echten Sammler gegen den Fake ein.
func pveNodeHost(t *testing.T, m *Module, addr, pin, node string) *hostRT {
	t.Helper()
	ctx := context.Background()
	h := &Host{Name: node, Address: "192.0.2.1", Kind: "pve", IntervalSec: 60}
	if err := m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	acc := &Access{HostUID: h.UID, Type: "pve", Config: []byte(`{"node":"` + node + `"}`), Enabled: true}
	if err := m.store.SaveAccess(ctx, acc, false, SystemActor); err != nil {
		t.Fatal(err)
	}
	m.ReloadHost(ctx, h.UID)
	m.rtMu.Lock()
	rt := m.rts[h.UID]
	m.rtMu.Unlock()
	c, err := apis.NewPVE(apis.PVEConfig{Addresses: []string{addr}, TokenID: "monitor64@pve!node64", Secret: "geheim-0123456789", Pin: pin, Node: node,
		Seen: m.pveSeen, Tag: acc.UID})
	if err != nil {
		t.Fatal(err)
	}
	rt.mu.Lock()
	rt.accs = []*accRT{{row: acc, col: &apiAdapter{apiCollector: apiCollector{src: c}}}}
	rt.mu.Unlock()
	return rt
}

func svcRow(t *testing.T, m *Module, hostUID, key string) *ServiceRow {
	t.Helper()
	rows, err := m.store.Services(context.Background(), hostUID)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Key == key {
			return r
		}
	}
	return nil
}

func viewSvc(rt *hostRT, key string) *SvcView {
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

func migratedEvents(t *testing.T, m *Module, hostUID string) []string {
	t.Helper()
	rows, err := m.st.Reader().Query(`SELECT text FROM m64_events WHERE host_uid = ? AND kind = 'migrated' ORDER BY id`, hostUID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	return out
}

// #165: Beide Nodes sind als Hosts eingetragen. VM 101 zieht von pve1 nach pve2: pve1 meldet sie nicht als
// verschwunden, pve2 fuehrt sie mit Name, Soll-Zustand und Verlauf weiter (nicht als "neu"), im Ablauf von pve2 steht
// die Migration. Und zurueck.
func TestPVEMigrationHandOver(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	lab := newPVELab(t)
	addr, pin := lab.serve(t)
	rt1 := pveNodeHost(t, m, addr, pin, "pve1")
	rt2 := pveNodeHost(t, m, addr, pin, "pve2")
	h1, h2 := rt1.host.UID, rt2.host.UID

	m.poll(ctx, rt1)
	m.poll(ctx, rt2)
	adoptAll(t, m, h1)
	adoptAll(t, m, h2)
	if _, err := m.st.Writer().Exec(`UPDATE m64_services SET name = 'Webserver', soll = 'run', host_rule = '{"guest.down":{"warn":{"off":true}}}' WHERE host_uid = ? AND key = 'vm:101'`, h1); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		m.poll(ctx, rt1)
		m.poll(ctx, rt2)
	}
	if s := viewSvc(rt1, "vm:101"); s == nil || s.State.String() != "ok" {
		t.Fatalf("vm:101 auf pve1 vor der Migration: %+v", s)
	}
	if svcRow(t, m, h2, "vm:101") != nil {
		t.Fatal("vm:101 schon an pve2")
	}

	// Migration nach pve2 (z. B. HA): pve2 sieht sie zuerst (neu), dann uebergibt pve1
	lab.move("pve2")
	m.poll(ctx, rt2)
	for i := 0; i < vanishRounds+2; i++ {
		m.poll(ctx, rt1)
		m.poll(ctx, rt2)
	}
	if r := svcRow(t, m, h1, "vm:101"); r != nil {
		t.Fatalf("vm:101 an pve1 nach der Migration: %+v", r)
	}
	r2 := svcRow(t, m, h2, "vm:101")
	if r2 == nil || r2.Adopted != 1 || !r2.VanishedAt.IsZero() || r2.Name != "Webserver" || r2.Soll != "run" || !strings.Contains(r2.HostRule, "guest.down") {
		t.Fatalf("vm:101 an pve2 nicht mit den Einstellungen uebernommen: %+v", r2)
	}
	if s := viewSvc(rt2, "vm:101"); s == nil || s.State.String() != "ok" {
		t.Fatalf("vm:101 auf pve2: %+v", s)
	}
	if v := rt2.getView(); v.New != 0 {
		t.Errorf("pve2 zeigt %d neue Dienste", v.New)
	}
	if v := rt1.getView(); viewSvc(rt1, "vm:101") != nil || v.New != 0 || len(m.loadOpen(ctx, h1)) != 0 {
		t.Errorf("pve1 nach der Migration: neu %d, offen %v", v.New, m.loadOpen(ctx, h1))
	}
	ev := migratedEvents(t, m, h2)
	if len(ev) != 1 || !strings.Contains(ev[0], "guest_migrated") || !strings.Contains(ev[0], "pve1") || !strings.Contains(ev[0], "pve2") {
		t.Fatalf("Ereignis an pve2: %q", ev)
	}
	// Verlauf zieht mit
	if err := m.seriesStore().Flush(ctx); err != nil {
		t.Fatal(err)
	}
	q := m.seriesStore().(seriesQuerier)
	now := time.Now()
	s, err := q.Query(ctx, seriesKey(h2, "vm:101", "running"), now.Add(-time.Hour), now.Add(time.Minute), 100)
	if err != nil || len(s.Points) == 0 {
		t.Fatalf("Verlauf an pve2: %v %+v", err, s)
	}
	if old, _ := q.Query(ctx, seriesKey(h1, "vm:101", "running"), now.Add(-time.Hour), now.Add(time.Minute), 100); len(old.Points) != 0 {
		t.Errorf("Verlauf noch an pve1: %d Punkte", len(old.Points))
	}
	// pve1 sucht den Gast nicht weiter (nicht mehr uebernommen)
	before := lab.count("/cluster/resources?type=vm")
	m.poll(ctx, rt1)
	if n := lab.count("/cluster/resources?type=vm"); n != before {
		t.Errorf("pve1 fragt den Cluster weiter ab (%d)", n-before)
	}

	// und zurueck nach pve1
	lab.move("pve1")
	for i := 0; i < 3; i++ {
		m.poll(ctx, rt2)
		m.poll(ctx, rt1)
	}
	if r := svcRow(t, m, h1, "vm:101"); r == nil || r.Adopted != 1 || r.Name != "Webserver" || !r.VanishedAt.IsZero() {
		t.Fatalf("vm:101 nicht zurueck an pve1: %+v", r)
	}
	if r := svcRow(t, m, h2, "vm:101"); r != nil {
		t.Fatalf("vm:101 noch an pve2: %+v", r)
	}
	if ev := migratedEvents(t, m, h1); len(ev) != 1 || !strings.Contains(ev[0], "guest_migrated") {
		t.Fatalf("Ereignis an pve1: %q", ev)
	}
}

// #165: Nur pve1 ist eingetragen (ein Zugang auf den Cluster). Zieht VM 101 nach pve2, fuehrt pve1 sie mit den Werten
// aus dem Cluster weiter ("laeuft auf Node pve2"), statt sie verschwinden zu lassen; Ruckkehr ebenso ohne Meldung.
func TestPVEMigrationFollow(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	lab := newPVELab(t)
	addr, pin := lab.serve(t)
	rt1 := pveNodeHost(t, m, addr, pin, "pve1")
	h1 := rt1.host.UID
	m.poll(ctx, rt1)
	adoptAll(t, m, h1)
	m.poll(ctx, rt1)

	lab.move("pve2")
	for i := 0; i < vanishRounds+3; i++ {
		m.poll(ctx, rt1)
	}
	r := svcRow(t, m, h1, "vm:101")
	if r == nil || !r.VanishedAt.IsZero() || r.Adopted != 1 {
		t.Fatalf("vm:101 an pve1: %+v", r)
	}
	s := viewSvc(rt1, "vm:101")
	if s == nil || s.State.String() != "ok" || !strings.Contains(s.Text, "runs_on_node") || !strings.Contains(s.Text, "pve2") {
		t.Fatalf("vm:101 nach Migration: %+v", s)
	}
	cpu := false
	for _, mt := range s.Metrics {
		cpu = cpu || mt.Name == "cpu"
	}
	if !cpu {
		t.Errorf("keine Werte aus dem Cluster: %+v", s.Metrics)
	}
	if len(m.loadOpen(ctx, h1)) != 0 {
		t.Errorf("Problem offen: %v", m.loadOpen(ctx, h1))
	}
	if ev := migratedEvents(t, m, h1); len(ev) != 1 || !strings.Contains(ev[0], "guest_followed") {
		t.Fatalf("Ereignis: %q", ev)
	}

	lab.move("pve1")
	m.poll(ctx, rt1)
	if s := viewSvc(rt1, "vm:101"); s == nil || strings.Contains(s.Text, "runs_on_node") {
		t.Fatalf("vm:101 zurueck: %+v", s)
	}
	if ev := migratedEvents(t, m, h1); len(ev) != 2 || !strings.Contains(ev[1], "guest_back") {
		t.Fatalf("Ereignis Rueckkehr: %q", ev)
	}

	// geloescht: verschwindet wie bisher
	lab.move("")
	for i := 0; i < vanishRounds; i++ {
		m.poll(ctx, rt1)
	}
	if !vanished(t, m, h1, "vm:101") {
		t.Fatal("geloeschter Gast nicht verschwunden")
	}
}

// #165: Heisst eine Node in einem anderen Cluster genauso (pve2 im Cluster "other"), bekommt deren Host den Gast
// nicht; pve1 fuehrt ihn weiter.
func TestPVEMigrationOtherCluster(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	lab := newPVELab(t)
	addr, pin := lab.serve(t)
	other := newPVELab(t)
	other.cluster, other.where = "other", ""
	addr2, pin2 := other.serve(t)
	rt1 := pveNodeHost(t, m, addr, pin, "pve1")
	rt2 := pveNodeHost(t, m, addr2, pin2, "pve2")
	h1, h2 := rt1.host.UID, rt2.host.UID
	m.poll(ctx, rt1)
	m.poll(ctx, rt2)
	adoptAll(t, m, h1)
	m.poll(ctx, rt1)

	lab.move("pve2")
	for i := 0; i < vanishRounds+1; i++ {
		m.poll(ctx, rt1)
		m.poll(ctx, rt2)
	}
	if r := svcRow(t, m, h2, "vm:101"); r != nil {
		t.Fatalf("Gast an den Host eines anderen Clusters uebergeben: %+v", r)
	}
	if r := svcRow(t, m, h1, "vm:101"); r == nil || !r.VanishedAt.IsZero() {
		t.Fatalf("vm:101 an pve1: %+v", r)
	}
	if s := viewSvc(rt1, "vm:101"); s == nil || !strings.Contains(s.Text, "runs_on_node") {
		t.Fatalf("vm:101 nicht weitergefuehrt: %+v", s)
	}
}
