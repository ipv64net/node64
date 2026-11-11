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
	case path == "/version":
		_ = json.NewEncoder(w).Encode(map[string]any{"Version": "27.3.1", "Os": "linux"})
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
		// 12 s CPU-Zeit in 120 s Systemzeit (30 s x 4 Kerne) = 0,4 Kerne = 10 % von 4
		f.stats[dkID("aaa")] = dkStats(13e9, 220e9, 2<<30, 512<<20, 4<<30, 1000+30*1000, 2000+30*500, 30*4096, 30*8192)
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
		f.stats[dkID("aaa")] = dkStats(13e9+12e8, 340e9, 2<<30, 512<<20, 4<<30, 0, 0, 0, 0)
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

// Podman meldet in system_cpu_usage nur die verstrichene Zeit (nicht x Kerne): CPU dann ueber die Uhr.
func TestDockerPollerPodmanCPU(t *testing.T) {
	f, p, clock := newFakeDocker(t)
	f.set(func(f *fakeDocker) {
		f.list = []map[string]any{dkEntry("aaa", "web", "running", "Up 1 hour", nil)}
		f.inspect[dkID("aaa")] = dkInspect(0, 0, false, clock.Add(-time.Hour).Format(time.RFC3339Nano), "")
		f.stats[dkID("aaa")] = dkStats(10e9, 100e9, 1, 0, 1<<30, 0, 0, 0, 0)
	})
	p.Poll(context.Background())
	*clock = clock.Add(30 * time.Second)
	// 30 s CPU-Zeit in 30 s (ein Kern voll), system_cpu_usage nur +30 s: 1 von 4 Kernen = 25 %
	f.set(func(f *fakeDocker) { f.stats[dkID("aaa")] = dkStats(40e9, 130e9, 1, 0, 1<<30, 0, 0, 0, 0) })
	web := dkByName(p.Poll(context.Background()))["web"]
	if math.Abs(web.CPU-0.25) > 1e-9 {
		t.Fatalf("podman cpu: %v", web.CPU)
	}
}
