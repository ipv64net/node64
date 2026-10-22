package proxmox

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDocker ist eine Docker-API (nur GET) mit veraenderbarem Stand je Container.
type fakeDocker struct {
	mu      sync.Mutex
	list    []map[string]any
	inspect map[string]map[string]any // ID -> inspect
	stats   map[string]map[string]any // ID -> stats
	hits    map[string]int
	fail    bool
}

func (f *fakeDocker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != http.MethodGet {
		http.Error(w, "read only", http.StatusMethodNotAllowed)
		return
	}
	path := r.URL.Path
	switch {
	case path == "/info":
		f.hits["info"]++
		_ = json.NewEncoder(w).Encode(map[string]any{"Name": "dockerhost", "NCPU": 4, "MemTotal": 8 << 30, "ServerVersion": "27.3.1", "OperatingSystem": "Debian"})
		return
	case path == "/containers/json":
		f.hits["list"]++
		if f.fail {
			http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
			return
		}
		if r.URL.Query().Get("all") != "1" {
			http.Error(w, "all missing", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(f.list)
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, "/containers/"), "/")
	if len(parts) == 2 {
		id := parts[0]
		switch parts[1] {
		case "json":
			f.hits["inspect:"+id]++
			if x, ok := f.inspect[id]; ok {
				_ = json.NewEncoder(w).Encode(x)
				return
			}
		case "stats":
			f.hits["stats:"+id]++
			if r.URL.Query().Get("stream") != "false" || r.URL.Query().Get("one-shot") != "true" {
				http.Error(w, "stream", 400)
				return
			}
			if x, ok := f.stats[id]; ok {
				_ = json.NewEncoder(w).Encode(x)
				return
			}
		}
	}
	http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
}

func (f *fakeDocker) set(fn func(f *fakeDocker)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func dkEntry(id, name, state, status string, labels map[string]string) map[string]any {
	return map[string]any{"Id": id + strings.Repeat("0", 64-len(id)), "Names": []string{"/" + name}, "Image": name + ":latest", "State": state,
		"Status": status, "Created": 1700000000, "Labels": labels,
		"Ports": []map[string]any{{"PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}, {"PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}}}
}

func dkInspect(restarts, exit int, oom bool, started string, health string) map[string]any {
	st := map[string]any{"Status": "running", "ExitCode": exit, "OOMKilled": oom, "StartedAt": started}
	if health != "" {
		st["Health"] = map[string]any{"Status": health}
	}
	return map[string]any{"RestartCount": restarts, "State": st, "HostConfig": map[string]any{"NanoCpus": 0}}
}

func dkStats(cpuTotal, system uint64, mem, inactive, limit uint64, rx, tx, rd, wr uint64) map[string]any {
	return map[string]any{
		"cpu_stats":    map[string]any{"cpu_usage": map[string]any{"total_usage": cpuTotal}, "system_cpu_usage": system, "online_cpus": 4},
		"memory_stats": map[string]any{"usage": mem, "limit": limit, "stats": map[string]any{"inactive_file": inactive}},
		"networks":     map[string]any{"eth0": map[string]any{"rx_bytes": rx, "tx_bytes": tx}, "eth1": map[string]any{"rx_bytes": 0, "tx_bytes": 0}},
		"blkio_stats":  map[string]any{"io_service_bytes_recursive": []map[string]any{{"op": "read", "value": rd}, {"op": "write", "value": wr}}},
	}
}

func dkID(id string) string { return id + strings.Repeat("0", 64-len(id)) }

func newFakeDocker(t *testing.T) (*fakeDocker, *DockerPoller, *time.Time) {
	t.Helper()
	f := &fakeDocker{inspect: map[string]map[string]any{}, stats: map[string]map[string]any{}, hits: map[string]int{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	clock := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	p := NewDockerPollerClient(nil, System{ID: 7, Kind: KindDocker, Name: "Docker", Interval: 30}, nil, srv.Client(), srv.URL)
	p.SetClock(func() time.Time { return clock })
	return f, p, &clock
}

func dkByName(s *Snapshot) map[string]Resource {
	out := map[string]Resource{}
	for _, r := range s.Resources {
		out[r.Name] = r
	}
	return out
}

func TestDockerPollerMapping(t *testing.T) {
	f, p, clock := newFakeDocker(t)
	started := clock.Add(-time.Hour).Format(time.RFC3339Nano)
	f.set(func(f *fakeDocker) {
		f.list = []map[string]any{
			dkEntry("aaa", "web", "running", "Up 1 hour (healthy)", map[string]string{"com.docker.compose.project": "shop"}),
			dkEntry("bbb", "db", "exited", "Exited (1) 2 hours ago", nil),
			dkEntry("ccc", "cache", "running", "Up 5 minutes (unhealthy)", nil),
			dkEntry("ddd", "job", "exited", "Exited (0) 1 day ago", map[string]string{LabelNoMonitor: "true"}),
			dkEntry("eee", "oom", "exited", "Exited (137) 3 minutes ago", nil),
			dkEntry("fff", "pause", "paused", "Up 2 hours (Paused)", nil),
		}
		f.inspect[dkID("aaa")] = dkInspect(0, 0, false, started, "healthy")
		f.inspect[dkID("bbb")] = dkInspect(0, 1, false, "", "")
		f.inspect[dkID("ccc")] = dkInspect(0, 0, false, started, "unhealthy")
		f.inspect[dkID("ddd")] = dkInspect(0, 0, false, "", "")
		f.inspect[dkID("eee")] = dkInspect(0, 137, true, "", "")
		f.inspect[dkID("fff")] = dkInspect(0, 0, false, started, "")
		// 1 GiB Limit (unter dem Host), 2 GiB belegt davon 512 MiB inactive_file
		f.stats[dkID("aaa")] = dkStats(1e9, 100e9, 2<<30, 512<<20, 4<<30, 1000, 2000, 0, 0)
		f.stats[dkID("ccc")] = dkStats(5e9, 100e9, 100<<20, 0, 64<<30, 0, 0, 0, 0) // Limit ueber dem Host: RAM des Hosts
	})
	s := p.Poll(context.Background())
	if !s.OK || s.Docker == nil || s.Docker.NCPU != 4 || s.Version != "27.3.1" {
		t.Fatalf("snapshot: %+v", s)
	}
	r := dkByName(s)
	web := r["web"]
	if web.Key() != "docker/web" || web.State != StateRunning || web.Health != "healthy" || web.ContainerID != "aaa000000000" || web.Image != "web:latest" ||
		len(web.Ports) != 1 || web.Ports[0] != "8080->80/tcp" || len(web.Tags) != 1 || web.Tags[0] != "shop" || web.Node != "dockerhost" {
		t.Fatalf("web: %+v", web)
	}
	if web.Uptime != 3600 || web.CPU != 0 || web.MaxCPU != 4 || web.Mem != (2<<30)-(512<<20) || web.MaxMem != 4<<30 || !web.Measurable() {
		t.Fatalf("web values: uptime=%d cpu=%v max=%v mem=%d/%d", web.Uptime, web.CPU, web.MaxCPU, web.Mem, web.MaxMem)
	}
	if c := r["cache"]; c.State != StateError || c.Detail != DockerUnhealthy || c.MaxMem != 8<<30 {
		t.Fatalf("cache: %+v", c)
	}
	if d := r["db"]; d.State != StateError || d.Detail != DockerExited || d.ExitCode != 1 || d.Measurable() {
		t.Fatalf("db: %+v", d)
	}
	if j := r["job"]; j.State != StateStopped || !j.Excluded() {
		t.Fatalf("job: %+v", j)
	}
	if o := r["oom"]; o.State != StateError || o.Detail != DockerOOM {
		t.Fatalf("oom: %+v", o)
	}
	if x := r["pause"]; x.State != StatePaused {
		t.Fatalf("pause: %+v", x)
	}
	if f.hits["stats:"+dkID("bbb")] != 0 || f.hits["stats:"+dkID("fff")] != 0 {
		t.Fatalf("stats nur fuer laufende: %v", f.hits)
	}

	// zweite Abfrage: CPU, Raten; inspect bleibt gemerkt (Zustand unveraendert)
	*clock = clock.Add(30 * time.Second)
	f.set(func(f *fakeDocker) {
		// 2 s CPU-Zeit in 20 s Systemzeit bei 4 Kernen = 0,4 Kerne = 10 % von 4
		f.stats[dkID("aaa")] = dkStats(3e9, 120e9, 2<<30, 512<<20, 4<<30, 1000+30*1000, 2000+30*500, 30*4096, 30*8192)
	})
	s = p.Poll(context.Background())
	web = dkByName(s)["web"]
	if math.Abs(web.CPU-0.1) > 1e-9 || web.NetIn != 1000 || web.NetOut != 500 || web.DiskRead != 4096 || web.DiskWrite != 8192 {
		t.Fatalf("raten: cpu=%v in=%v out=%v r=%v w=%v", web.CPU, web.NetIn, web.NetOut, web.DiskRead, web.DiskWrite)
	}
	if f.hits["inspect:"+dkID("aaa")] != 1 || f.hits["info"] != 1 {
		t.Fatalf("inspect bzw. info zu oft: %v", f.hits)
	}

	// CPU-Limit 0,5 Kerne: Anteil bezogen auf das Limit
	*clock = clock.Add(30 * time.Second)
	f.set(func(f *fakeDocker) {
		in := dkInspect(0, 0, false, started, "healthy")
		in["HostConfig"] = map[string]any{"NanoCpus": 500000000}
		f.inspect[dkID("aaa")] = in
		f.list[0]["Status"] = "Up 1 hour (unhealthy)" // Zustand anders: inspect neu
		f.stats[dkID("aaa")] = dkStats(3e9+2e8, 140e9, 2<<30, 512<<20, 4<<30, 0, 0, 0, 0)
	})
	s = p.Poll(context.Background())
	web = dkByName(s)["web"]
	if web.MaxCPU != 0.5 || math.Abs(web.CPU-0.08) > 1e-9 || web.State != StateError || web.Detail != DockerUnhealthy || web.NetIn != 0 {
		t.Fatalf("limit: max=%v cpu=%v state=%s net=%v", web.MaxCPU, web.CPU, web.State, web.NetIn)
	}
}

func TestDockerPollerRestartLoop(t *testing.T) {
	f, p, clock := newFakeDocker(t)
	start := *clock
	f.set(func(f *fakeDocker) {
		f.list = []map[string]any{dkEntry("aaa", "app", "running", "Up 1 hour", nil)}
		f.inspect[dkID("aaa")] = dkInspect(0, 0, false, start.Add(-time.Hour).Format(time.RFC3339Nano), "")
		f.stats[dkID("aaa")] = dkStats(10e9, 100e9, 1, 0, 1<<30, 0, 0, 0, 0)
	})
	if r := dkByName(p.Poll(context.Background()))["app"]; r.State != StateRunning || r.Restarted {
		t.Fatalf("start: %+v", r)
	}
	// Neustart zwischen zwei Abfragen: Zaehler springen zurueck -> inspect neu, RestartCount 1
	for i := 1; i <= 3; i++ {
		*clock = clock.Add(30 * time.Second)
		n := i
		f.set(func(f *fakeDocker) {
			f.list[0]["Status"] = "Up 4 seconds"
			f.inspect[dkID("aaa")] = dkInspect(n, 0, false, clock.Add(-5*time.Second).Format(time.RFC3339Nano), "")
			f.stats[dkID("aaa")] = dkStats(uint64(n)*1e6, 100e9+uint64(n)*1e9, 1, 0, 1<<30, 0, 0, 0, 0)
		})
		r := dkByName(p.Poll(context.Background()))["app"]
		if r.Restarts != n {
			t.Fatalf("Neustart %d: restarts=%d", n, r.Restarts)
		}
		if n < 3 && (r.State != StateRunning || !r.Restarted) {
			t.Fatalf("Neustart %d: %s restarted=%v", n, r.State, r.Restarted)
		}
		if n == 3 && (r.State != StateError || r.Detail != DockerRestarting || r.Restarted) {
			t.Fatalf("Schleife: %s %s restarted=%v", r.State, r.Detail, r.Restarted)
		}
	}
	// 10 Minuten ohne Neustart: wieder in Ordnung
	*clock = clock.Add(11 * time.Minute)
	if r := dkByName(p.Poll(context.Background()))["app"]; r.State != StateRunning {
		t.Fatalf("nach Fenster: %s", r.State)
	}
	// Status restarting: sofort Stoerung
	*clock = clock.Add(30 * time.Second)
	f.set(func(f *fakeDocker) { f.list[0]["State"] = "restarting" })
	if r := dkByName(p.Poll(context.Background()))["app"]; r.State != StateError || r.Detail != DockerRestarting {
		t.Fatalf("restarting: %+v", r)
	}
	// gleicher Name, neue ID (neu angelegt): kein Neustart, keine Raten
	*clock = clock.Add(30 * time.Second)
	f.set(func(f *fakeDocker) {
		f.list = []map[string]any{dkEntry("bbb", "app", "running", "Up 2 seconds", nil)}
		f.inspect[dkID("bbb")] = dkInspect(0, 0, false, clock.Add(-2*time.Second).Format(time.RFC3339Nano), "")
		f.stats[dkID("bbb")] = dkStats(1e6, 200e9, 1, 0, 1<<30, 0, 0, 0, 0)
	})
	if r := dkByName(p.Poll(context.Background()))["app"]; r.Restarted || r.ContainerID != "bbb000000000" || r.State != StateRunning {
		t.Fatalf("neu angelegt: %+v", r)
	}
}

func TestDockerUpMax(t *testing.T) {
	for s, want := range map[string]time.Duration{"Up 5 seconds": 6 * time.Second, "Up About a minute": 2 * time.Minute,
		"Up 3 hours (healthy)": 4 * time.Hour, "Up Less than a second": 2 * time.Second, "Up About an hour": 2 * time.Hour} {
		if got, ok := dockerUpMax(s); !ok || got != want {
			t.Errorf("%s: %v %v", s, got, ok)
		}
	}
	if _, ok := dockerUpMax("Exited (0) 2 hours ago"); ok {
		t.Error("exited")
	}
}

func TestDockerPollerError(t *testing.T) {
	f, p, _ := newFakeDocker(t)
	f.set(func(f *fakeDocker) { f.fail = true })
	s := p.Poll(context.Background())
	if s.OK || !strings.Contains(s.Error, "boom") || len(s.Resources) != 0 {
		t.Fatalf("fehler: %+v", s)
	}
	bad := NewDockerPoller(nil, System{Kind: KindDocker, Addresses: []string{"ftp://x"}}, nil)
	if s := bad.Poll(context.Background()); s.OK || s.Error == "" {
		t.Fatalf("ungueltiger Host: %+v", s)
	}
	if _, ok := NewSource(nil, System{Kind: KindDocker}, nil).(*DockerPoller); !ok {
		t.Fatal("NewSource docker")
	}
	if _, ok := NewSource(nil, System{Kind: KindPVE, Addresses: []string{"pve:8006"}}, nil).(*Poller); !ok {
		t.Fatal("NewSource pve")
	}
}

func dkRes(name, status string, st State, detail string) Resource {
	r := Resource{Type: TypeDocker, Node: "h", Name: name, Status: status, State: st, Detail: detail, MaxCPU: 4, MaxMem: 1000}
	if status == "running" {
		r.CPU, r.Mem = 0.1, 100
	}
	if detail == DockerExited {
		r.ExitCode = 1
	}
	return r
}

func TestRulesDocker(t *testing.T) {
	p := newPveRun(t)
	p.set.Kind = KindDocker
	// beendet mit Fehler, nie laufend gesehen: keine Meldung (alte Container)
	p.expect(p.snap(true, dkRes("old", "exited", StateError, DockerExited), dkRes("web", "running", StateRunning, "")), "")
	p.expect(p.snap(true, dkRes("old", "exited", StateError, DockerExited), dkRes("web", "running", StateRunning, "")), "")
	// lief: beendet mit Fehler -> sofort (Verzoegerung 1)
	evs := p.snap(true, dkRes("old", "exited", StateError, DockerExited), dkRes("web", "exited", StateError, DockerExited))
	p.expect(evs, "down:exited:docker/web")
	if evs[0].Detail != "1" || !strings.Contains(evs[0].Text, "Exit-Code 1") {
		t.Fatalf("detail/text: %+v", evs[0])
	}
	p.expect(p.snap(true, dkRes("web", "running", StateRunning, "")), "up:exited:docker/web")
	// unhealthy laeuft: sofort, unabhaengig von „erwartet“
	p.expect(p.snap(true, dkRes("web", "running", StateError, DockerUnhealthy)), "down:unhealthy:docker/web")
	p.expect(p.snap(true, dkRes("web", "running", StateRunning, "")), "up:unhealthy:docker/web")
	// beendet mit 0: wie gestoppt nach Verzoegerung 2
	p.expect(p.snap(true, dkRes("web", "exited", StateStopped, "")), "")
	p.expect(p.snap(true, dkRes("web", "exited", StateStopped, "")), "down:stopped:docker/web")
	p.expect(p.snap(true, dkRes("web", "running", StateRunning, "")), "up:stopped:docker/web")
	// Label nomonitor: nichts
	x := dkRes("web", "running", StateError, DockerUnhealthy)
	x.Labels = map[string]string{LabelNoMonitor: "1"}
	p.expect(p.snap(true, x), "")
	// Absturz-Regel aus: nichts
	off := false
	p.item("").Rules.Crashed = &off
	p.expect(p.snap(true, dkRes("web", "restarting", StateError, DockerRestarting)), "")
	// nicht erreichbar: Text nennt Docker
	p.item("").Rules = RuleSet{}
	p.snap(false)
	evs = p.snap(false)
	p.expect(evs, "down:unreachable:")
	if !strings.HasPrefix(evs[0].Text, "Docker „Lab“") {
		t.Fatalf("text: %q", evs[0].Text)
	}
}

func TestStoreDockerSystem(t *testing.T) {
	ctx := context.Background()
	s, core := pveTestStore(t)
	ds := NewStore(core, nil) // Docker braucht keinen Schluessel
	sys := &System{Kind: KindDocker, Name: "Docker", Enabled: true}
	if err := ds.SaveSystem(ctx, sys); err != nil {
		t.Fatal(err)
	}
	got, err := s.System(ctx, sys.ID)
	if err != nil || got.Kind != KindDocker || len(got.Addresses) != 1 || got.Addresses[0] != DefaultDockerHost() || got.Interval != DefaultInterval || got.Secret != "" {
		t.Fatalf("docker system: %+v %v", got, err)
	}
	pve := pveNewSystem(t, s)
	if got, _ := s.System(ctx, pve.ID); got.Kind != KindPVE {
		t.Fatalf("pve kind: %q", got.Kind)
	}
	for _, a := range []string{"ftp://x", "unix://relative", "tcp://"} {
		if err := ValidateSystem(&System{Kind: KindDocker, Addresses: []string{a}}, true); err == nil {
			t.Errorf("%s: kein Fehler", a)
		}
	}
	if err := ValidateSystem(&System{Kind: "vmware"}, true); err == nil {
		t.Error("unbekannte Art")
	}
	if !ValidKey("docker/my-app_1.web") || ValidKey("docker/") || ValidKey("docker/-x") || ValidKey("docker/a/b") {
		t.Error("ValidKey docker")
	}
	set, err := s.Settings(ctx, sys.ID)
	if err != nil || set.Kind != KindDocker {
		t.Fatalf("settings kind: %+v %v", set, err)
	}
	// Verlauf: nur laufende Container, SeenRunning fuer laufende
	snap := &Snapshot{SystemID: sys.ID, OK: true, Time: time.Now(), Resources: []Resource{
		dkRes("web", "running", StateRunning, ""), dkRes("old", "exited", StateError, DockerExited)}}
	if err := s.Record(ctx, snap); err != nil {
		t.Fatal(err)
	}
	if n := pveCount(t, s, "pve_hist_1m"); n != 1 {
		t.Fatalf("verlauf: %d", n)
	}
	set, _ = s.Settings(ctx, sys.ID)
	if it := set.Item("docker/web"); it == nil || !it.SeenRunning || set.Item("docker/old") != nil {
		t.Fatalf("seen: %+v", set.Items)
	}
}
