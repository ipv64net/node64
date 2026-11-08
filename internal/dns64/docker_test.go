package dns64

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeDocker liefert /containers/json aus list (fail = Fehler 500).
type fakeDocker struct {
	mu      sync.Mutex
	list    []map[string]any
	fail    bool
	filters string // zuletzt gefragter Filter
}

func (f *fakeDocker) set(list []map[string]any, fail bool) {
	f.mu.Lock()
	f.list, f.fail = list, fail
	f.mu.Unlock()
}

func (f *fakeDocker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail || !strings.HasSuffix(r.URL.Path, "/containers/json") {
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	}
	f.filters = r.URL.Query().Get("filters")
	_ = json.NewEncoder(w).Encode(f.list)
}

func container(name string, labels map[string]string, ip string) map[string]any {
	return map[string]any{"Names": []string{"/" + name}, "State": "running", "Labels": labels,
		"HostConfig":      map[string]any{"NetworkMode": "lan"},
		"NetworkSettings": map[string]any{"Networks": map[string]any{"lan": map[string]any{"IPAddress": ip}}}}
}

// Docker-Labels node64.dns.* legen Eintraege an, aendern und entfernen sie; fremde Namen und Lesefehler bleiben
// unberuehrt (GitHub #18).
func TestDockerDNS(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	fd := &fakeDocker{}
	srv := httptest.NewServer(fd)
	defer srv.Close()
	oldHost, oldWait := dockerDNSHost, dockerDNSRemoveWait
	dockerDNSHost, dockerDNSRemoveWait = func() string { return srv.URL }, time.Hour
	defer func() { dockerDNSHost, dockerDNSRemoveWait = oldHost, oldWait }()
	_ = m.core.SetSetting(ctx, setDocker, "1")
	_ = m.core.SetSetting(ctx, setDockerIP, "192.168.1.5, fd00::5")
	if _, err := m.AddRecord(ctx, Record{Name: "taken.lan", Type: "A", Value: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	fd.set([]map[string]any{
		container("nas", map[string]string{dockerLabelName: "NAS.lan, files.lan"}, "172.17.0.2"),
		container("mac", map[string]string{dockerLabelName: "mac.lan", dockerLabelIP: "container"}, "192.168.1.50"),
		container("bad", map[string]string{dockerLabelName: "bad.lan", dockerLabelIP: "kein-ip"}, ""),
		container("zz-dup", map[string]string{dockerLabelName: "nas.lan"}, ""),
		container("taker", map[string]string{dockerLabelName: "taken.lan"}, ""),
		container("plain", map[string]string{"other": "x"}, ""),
	}, false)
	m.SetCluster(func(context.Context, string, string, bool) {})
	gen := m.clGen[ItemRecords]
	m.dockerSync(ctx)
	if d := m.clGen[ItemRecords] - gen; d != 1 { // ein Neuladen fuer den ganzen Abgleich, nicht je Eintrag
		t.Fatalf("reloads per sync: %d", d)
	}
	var flt map[string][]string
	if err := json.Unmarshal([]byte(fd.filters), &flt); err != nil || !slices.Equal(flt["label"], []string{dockerLabelName}) {
		t.Fatalf("label filter: %q", fd.filters)
	}

	got := func() map[string]Record {
		recs, err := m.Records(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]Record{}
		for _, r := range recs {
			out[r.Name+" "+r.Type+" "+r.Value] = r
		}
		return out
	}
	recs := got()
	for _, k := range []string{"nas.lan A 192.168.1.5", "nas.lan AAAA fd00::5", "files.lan A 192.168.1.5", "mac.lan A 192.168.1.50", "taken.lan A 10.0.0.1"} {
		if _, ok := recs[k]; !ok {
			t.Fatalf("missing %s in %v", k, recs)
		}
	}
	if r := recs["nas.lan A 192.168.1.5"]; r.Comment != "Docker: nas" || !r.LocalOnly || !r.NoPTR {
		t.Fatalf("docker record: %+v", r)
	}
	if len(recs) != 6 { // nas.lan und files.lan je A und AAAA, mac.lan, eigener Eintrag taken.lan
		t.Fatalf("records: %v", recs)
	}
	v := m.DockerDNS(ctx)
	if !v.Enabled || !v.Connected || len(v.Containers) != 5 {
		t.Fatalf("view: %+v", v)
	}
	problems := map[string]string{}
	for _, c := range v.Containers {
		problems[c.Container] = c.Problem
	}
	if problems["nas"] != "" || problems["mac"] != "" || problems["bad"] != dockerErrBadIP || problems["zz-dup"] != dockerErrTaken || problems["taker"] != dockerErrTaken {
		t.Fatalf("problems: %v", problems)
	}

	// Adresse geaendert: alter Eintrag sofort weg, neuer da
	_ = m.core.SetSetting(ctx, setDockerIP, "192.168.1.6")
	m.dockerSync(ctx)
	recs = got()
	if _, ok := recs["nas.lan A 192.168.1.5"]; ok {
		t.Fatalf("old address kept: %v", recs)
	}
	if _, ok := recs["nas.lan A 192.168.1.6"]; !ok {
		t.Fatalf("new address missing: %v", recs)
	}
	if _, ok := recs["nas.lan AAAA fd00::5"]; ok { // keine IPv6 mehr eingestellt, Container noch da
		t.Fatalf("aaaa kept: %v", recs)
	}

	// Lesefehler: nichts loeschen
	fd.set(nil, true)
	m.dockerSync(ctx)
	if _, ok := got()["nas.lan A 192.168.1.6"]; !ok || m.DockerDNS(ctx).Error == "" {
		t.Fatal("api error removed records or no error shown")
	}

	// Container weg: erst nach der Wartezeit
	fd.set([]map[string]any{container("mac", map[string]string{dockerLabelName: "mac.lan", dockerLabelIP: "container"}, "192.168.1.50")}, false)
	m.dockerSync(ctx)
	if _, ok := got()["nas.lan A 192.168.1.6"]; !ok {
		t.Fatal("removed before the wait")
	}
	dockerDNSRemoveWait = 0
	m.dockerSync(ctx)
	recs = got()
	if _, ok := recs["nas.lan A 192.168.1.6"]; ok {
		t.Fatalf("not removed after the wait: %v", recs)
	}
	if _, ok := recs["mac.lan A 192.168.1.50"]; !ok {
		t.Fatalf("running container lost its record: %v", recs)
	}
	if _, ok := recs["taken.lan A 10.0.0.1"]; !ok {
		t.Fatal("own record removed")
	}

	// Schalter aus: Eintraege bleiben, Stand leer
	_ = m.core.SetSetting(ctx, setDocker, "")
	m.dockerSync(ctx)
	if v := m.DockerDNS(ctx); v.Enabled || len(v.Containers) != 0 {
		t.Fatalf("view after off: %+v", v)
	}
	if _, ok := got()["mac.lan A 192.168.1.50"]; !ok {
		t.Fatal("switch off removed records")
	}
}

// dockerTest startet die Docker-API-Attrappe, schaltet den Abgleich ein und laesst Eintraege sofort entfernen.
func dockerTest(t *testing.T, m *Module) *fakeDocker {
	t.Helper()
	fd := &fakeDocker{}
	srv := httptest.NewServer(fd)
	oldHost, oldWait := dockerDNSHost, dockerDNSRemoveWait
	dockerDNSHost, dockerDNSRemoveWait = func() string { return srv.URL }, 0
	t.Cleanup(func() { srv.Close(); dockerDNSHost, dockerDNSRemoveWait = oldHost, oldWait })
	_ = m.core.SetSetting(context.Background(), setDocker, "1")
	_ = m.core.SetSetting(context.Background(), setDockerIP, "192.168.1.5")
	return fd
}

func recordByName(t *testing.T, m *Module, name string) []Record {
	t.Helper()
	recs, err := m.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []Record
	for _, r := range recs {
		if r.Name == name {
			out = append(out, r)
		}
	}
	return out
}

func dockerProblem(m *Module, container string) string {
	for _, c := range m.DockerDNS(context.Background()).Containers {
		if c.Container == container {
			return c.Problem
		}
	}
	return "?"
}

// Eigen sind nur Eintraege mit Herkunft docker, die nur auf dieser Node gelten: von Hand angelegte mit
// Kommentar "Docker: ..." bleiben (auch cluster-weite), ein geaenderter Kommentar stoert nicht, ein vom Nutzer in den
// Cluster gegebener Eintrag gehoert danach ihm.
func TestDockerDNSOrigin(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	fd := dockerTest(t, m)
	for _, r := range []Record{
		{Name: "hand.lan", Type: "A", Value: "10.0.0.2", Comment: "Docker: hand", LocalOnly: true},
		{Name: "share.lan", Type: "A", Value: "10.0.0.3", Comment: "Docker: share"},
	} {
		if _, err := m.AddRecord(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	fd.set([]map[string]any{container("hand", map[string]string{dockerLabelName: "hand.lan"}, "")}, false)
	m.dockerSync(ctx)
	if p := dockerProblem(m, "hand"); p != dockerErrTaken {
		t.Fatalf("hand-made record not taken: %q", p)
	}
	fd.set([]map[string]any{}, false)
	m.dockerSync(ctx)
	m.dockerSync(ctx) // Wartezeit 0: spaetestens jetzt wuerde geloescht
	if len(recordByName(t, m, "hand.lan")) != 1 || len(recordByName(t, m, "share.lan")) != 1 {
		t.Fatal("hand-made records with docker comment removed")
	}

	// Kommentar geaendert: bleibt eigener Eintrag (kein "vergeben", kein zweiter Eintrag)
	fd.set([]map[string]any{container("web", map[string]string{dockerLabelName: "web.lan"}, "")}, false)
	m.dockerSync(ctx)
	got := recordByName(t, m, "web.lan")
	if len(got) != 1 {
		t.Fatalf("web.lan: %+v", got)
	}
	r := got[0]
	r.Comment = "mein Webserver"
	if _, err := m.UpdateRecord(ctx, r.ID, r); err != nil {
		t.Fatal(err)
	}
	m.dockerSync(ctx)
	if p := dockerProblem(m, "web"); p != "" || len(recordByName(t, m, "web.lan")) != 1 {
		t.Fatalf("comment change: problem %q, records %+v", p, recordByName(t, m, "web.lan"))
	}

	// nur-diese-Node abgewaehlt: gehoert jetzt dem Nutzer, der Abgleich loescht ihn nicht
	r.LocalOnly = false
	if _, err := m.UpdateRecord(ctx, r.ID, r); err != nil {
		t.Fatal(err)
	}
	m.dockerSync(ctx)
	if p := dockerProblem(m, "web"); p != dockerErrTaken {
		t.Fatalf("shared record not taken: %q", p)
	}
	fd.set([]map[string]any{}, false)
	m.dockerSync(ctx)
	m.dockerSync(ctx)
	if len(recordByName(t, m, "web.lan")) != 1 {
		t.Fatal("shared record removed by docker sync")
	}
}

// Docker-Eintraege liefern keinen PTR: die Adresse der Node behaelt ihren Namen, auch wenn der Containername
// alphabetisch vorne liegt; alte Eintraege ohne die Markierung werden angeglichen.
func TestDockerDNSNoPTR(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	fd := dockerTest(t, m)
	if _, err := m.AddRecord(ctx, Record{Name: "node.lan", Type: "A", Value: "192.168.1.5"}); err != nil {
		t.Fatal(err)
	}
	fd.set([]map[string]any{container("aaa", map[string]string{dockerLabelName: "aaa.lan"}, "")}, false)
	m.dockerSync(ctx)
	ptr := func() string {
		rrs, ok := m.Lookup("5.1.168.192.in-addr.arpa", dns.TypePTR)
		if !ok || len(rrs) != 1 {
			return ""
		}
		return rrs[0].(*dns.PTR).Ptr
	}
	got := recordByName(t, m, "aaa.lan")
	if len(got) != 1 || !got[0].NoPTR {
		t.Fatalf("docker record: %+v", got)
	}
	if p := ptr(); p != "node.lan." {
		t.Fatalf("ptr: %q", p)
	}
	if _, err := m.core.Writer().ExecContext(ctx, `UPDATE dns64_records SET no_ptr = 0 WHERE id = ?`, got[0].ID); err != nil {
		t.Fatal(err)
	}
	m.dockerSync(ctx)
	if got := recordByName(t, m, "aaa.lan"); len(got) != 1 || !got[0].NoPTR || ptr() != "node.lan." {
		t.Fatalf("no_ptr not restored: %+v, ptr %q", got, ptr())
	}
}

// Die LAN-Adresse eines Proxmox-Hosts liegt auf vmbr0; Docker-, Podman- und Tunnel-Schnittstellen zaehlen nicht.
func TestDockerVirtualIface(t *testing.T) {
	for name, virt := range map[string]bool{"vmbr0": false, "eth0": false, "enp3s0": false, "docker0": true, "br-1a2b": true,
		"veth12": true, "podman0": true, "cni0": true, "flannel.1": true, "tun0": true, "wg0": true, "tap100i0": true} {
		if virtualIface(name) != virt {
			t.Fatalf("%s: %v", name, !virt)
		}
	}
}

func TestDockerSettingIP(t *testing.T) {
	for in, ok := range map[string]bool{"": true, "192.168.1.5": true, "192.168.1.5, fd00::1": true, "x": false, "192.168.1.5,nope": false, "0.0.0.0": false} {
		if validDockerIP(in) != ok {
			t.Fatalf("%q: %v", in, !ok)
		}
	}
}
