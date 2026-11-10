package apis

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// fakeDocker ist eine Docker Engine API (v1.47, Docker 27) mit aufgezeichneten Antworten.
type fakeDocker struct {
	mu       sync.Mutex
	list     string
	stats    map[string]string // ID -> stats
	inspect  map[string]string // ID -> inspect
	fail     map[string]int    // Pfad -> Status
	redirect map[string]string // Pfad -> Ziel (302)
	hits     map[string]int
}

func (f *fakeDocker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.Path
	id, what := "", ""
	if rest, ok := strings.CutPrefix(p, "/containers/"); ok && rest != "json" {
		id, what, _ = strings.Cut(rest, "/")
		if len(id) == 12 { // Docker nimmt auch die kurze ID (eindeutiger Anfang)
			for full := range f.inspect {
				if strings.HasPrefix(full, id) {
					id = full
				}
			}
		}
		p = "/containers/" + id + "/" + what
	}
	f.hits[p]++
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Api-Version", "1.47")
	if loc, ok := f.redirect[p]; ok {
		http.Redirect(w, r, loc, http.StatusFound)
		return
	}
	if st, ok := f.fail[p]; ok {
		w.WriteHeader(st)
		_, _ = w.Write([]byte(`{"message":"simulated failure"}`))
		return
	}
	var body string
	found := true
	switch {
	case p == "/containers/json":
		body = f.list
	case p == "/info":
		body = `{"ID":"4b1c2d3e-aaaa-bbbb-cccc-0123456789ab","Containers":6,"ContainersRunning":2,"ContainersPaused":0,"ContainersStopped":4,"Images":9,"Driver":"overlay2","Name":"docker01","NCPU":4,"MemTotal":16742334464,"ServerVersion":"27.3.1","OperatingSystem":"Debian GNU/Linux 12 (bookworm)","OSType":"linux","Architecture":"x86_64","KernelVersion":"6.1.0-26-amd64","CgroupVersion":"2"}`
	case p == "/version":
		body = `{"Version":"27.3.1","ApiVersion":"1.47","MinAPIVersion":"1.24","Os":"linux","Arch":"amd64","KernelVersion":"6.1.0-26-amd64"}`
	case what == "stats":
		body, found = f.stats[id]
	case what == "json":
		body, found = f.inspect[id]
	default:
		found = false
	}
	if !found {
		w.WriteHeader(http.StatusNotFound)
		body = `{"message":"No such container"}`
	}
	_, _ = w.Write([]byte(body))
}

func cid(c byte) string { return strings.Repeat(string([]byte{c, c}), 32) }

func listEntry(id, name, image, state, status string, labels string) string {
	if labels == "" {
		labels = "{}"
	}
	return fmt.Sprintf(`{"Id":"%s","Names":["/%s"],"Image":"%s","ImageID":"sha256:%s","Command":"/entrypoint.sh","Created":1730457600,"Ports":[],"Labels":%s,"State":"%s","Status":"%s","HostConfig":{"NetworkMode":"bridge"},"NetworkSettings":{"Networks":{"bridge":{"NetworkID":"n1"}}},"Mounts":[]}`,
		id, name, image, id, labels, state, status)
}

func inspectJSON(id, name, state, started, health, policy string, restarts, exit int, oom bool) string {
	h := "null"
	if health != "" {
		h = fmt.Sprintf(`{"Status":"%s","FailingStreak":0,"Log":[]}`, health)
	}
	return fmt.Sprintf(`{"Id":"%s","Created":"2026-11-01T10:00:00.123456789Z","Path":"/entrypoint.sh","Args":[],
"State":{"Status":"%s","Running":%v,"Paused":false,"Restarting":false,"OOMKilled":%v,"Dead":false,"Pid":1234,"ExitCode":%d,"Error":"","StartedAt":"%s","FinishedAt":"0001-01-01T00:00:00Z","Health":%s},
"Image":"sha256:%s","Name":"/%s","RestartCount":%d,"Driver":"overlay2","Platform":"linux",
"HostConfig":{"NetworkMode":"bridge","RestartPolicy":{"Name":"%s","MaximumRetryCount":0},"NanoCpus":0,"CpuQuota":0,"CpuPeriod":0,"Memory":0},
"Config":{"Hostname":"%s","Image":"x","Labels":{}}}`, id, state, state == "running", oom, exit, started, h, id, name, restarts, policy, id[:12])
}

func statsJSON(cpuTotal, system uint64, mem uint64, rx, tx, rd, wr uint64) string {
	return fmt.Sprintf(`{"read":"2026-11-09T12:00:00.000000000Z","preread":"0001-01-01T00:00:00Z","pids_stats":{"current":12,"limit":18446744073709551615},
"blkio_stats":{"io_service_bytes_recursive":[{"major":8,"minor":0,"op":"read","value":%d},{"major":8,"minor":0,"op":"write","value":%d}]},
"num_procs":0,"cpu_stats":{"cpu_usage":{"total_usage":%d,"usage_in_kernelmode":1000,"usage_in_usermode":2000},"system_cpu_usage":%d,"online_cpus":4,"throttling_data":{"periods":0,"throttled_periods":0,"throttled_time":0}},
"precpu_stats":{"cpu_usage":{"total_usage":0,"usage_in_kernelmode":0,"usage_in_usermode":0},"throttling_data":{"periods":0,"throttled_periods":0,"throttled_time":0}},
"memory_stats":{"usage":%d,"stats":{"active_anon":100000,"anon":400000000,"file":200000000,"inactive_file":104857600,"active_file":95142400},"limit":16742334464},
"name":"/x","id":"x","networks":{"eth0":{"rx_bytes":%d,"rx_packets":1000,"rx_errors":0,"rx_dropped":0,"tx_bytes":%d,"tx_packets":900,"tx_errors":0,"tx_dropped":0}}}`,
		rd, wr, cpuTotal, system, mem, rx, tx)
}

func dockerFake(t *testing.T, now time.Time) (*fakeDocker, string) {
	nc, db, bj, wk, os1, wt := cid('a'), cid('b'), cid('c'), cid('d'), cid('e'), cid('f')
	f := &fakeDocker{stats: map[string]string{}, inspect: map[string]string{}, fail: map[string]int{}, hits: map[string]int{}}
	f.list = "[" + strings.Join([]string{
		listEntry(nc, "nextcloud", "nextcloud:30-apache", "running", "Up 3 days (healthy)", `{"com.docker.compose.project":"cloud"}`),
		listEntry(db, "db", "mariadb:11", "running", "Up 2 hours (unhealthy)", `{"com.docker.compose.project":"cloud"}`),
		listEntry(bj, "backup-job", "restic/restic:0.17.1", "exited", "Exited (0) 3 hours ago", ""),
		listEntry(wk, "worker", "ghcr.io/example/worker:1.4", "exited", "Exited (1) 10 minutes ago", ""),
		listEntry(os1, "oneshot", "alpine:3.20", "exited", "Exited (0) 2 days ago", ""),
		listEntry(wt, "watchtower", "containrrr/watchtower:1.7.1", "exited", "Exited (137) 5 minutes ago", `{"node64.nomonitor":"true"}`),
	}, ",") + "]"
	started := now.Add(-72 * time.Hour).Format(time.RFC3339Nano)
	f.inspect[nc] = inspectJSON(nc, "nextcloud", "running", started, "healthy", "unless-stopped", 0, 0, false)
	f.inspect[db] = inspectJSON(db, "db", "running", now.Add(-2*time.Hour).Format(time.RFC3339Nano), "unhealthy", "always", 2, 0, false)
	f.inspect[bj] = inspectJSON(bj, "backup-job", "exited", started, "", "no", 0, 0, false)
	f.inspect[wk] = inspectJSON(wk, "worker", "exited", started, "", "on-failure", 5, 1, false)
	f.inspect[os1] = inspectJSON(os1, "oneshot", "exited", started, "", "on-failure", 0, 0, false)
	f.inspect[wt] = inspectJSON(wt, "watchtower", "exited", started, "unhealthy", "always", 0, 137, false) // letzter Health-Stand bleibt
	f.stats[nc] = statsJSON(1e12, 1e14, 629145600, 1e9, 1e8, 5e8, 7e8)
	f.stats[db] = statsJSON(5e11, 1e14, 300000000, 2e8, 3e8, 1e8, 2e8)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv.URL
}

func newTestDocker(t *testing.T, host string, now *time.Time) *Docker {
	t.Helper()
	d, err := NewDocker(DockerConfig{Host: host})
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return *now }
	d.poll.SetClock(clock)
	d.now = clock
	t.Cleanup(d.Close)
	return d
}

func TestDockerCollect(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	f, host := dockerFake(t, now)
	d := newTestDocker(t, host, &now)
	svcs, err := d.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(svcs) != 6 {
		t.Fatalf("%d Dienste, erwartet 6", len(svcs))
	}
	nc := svcByKey(t, svcs, "ctr:nextcloud")
	if nc.Kind != "ctr" || len(nc.Facts) != 0 || !strings.Contains(nc.Text, "soll laufen (Neustart-Richtlinie unless-stopped)") || !strings.Contains(nc.Text, "healthy") {
		t.Errorf("nextcloud = %+v", nc)
	}
	if _, ok := metric(nc, "cpu"); ok {
		t.Error("CPU in der ersten Runde (noch keine Differenz)")
	}
	if m := mustMetric(t, nc, "mem_used"); m.Value != 524288000 || m.Max != 16742334464 {
		t.Errorf("nextcloud mem = %+v", m)
	}
	db := svcByKey(t, svcs, "ctr:db")
	if !hasFact(db, "ctr_unhealthy") || hasFact(db, "guest_down") {
		t.Errorf("db = %+v", db)
	}
	if m := mustMetric(t, db, "restarts"); m.Value != 2 {
		t.Errorf("db restarts = %+v", m)
	}
	if bj := svcByKey(t, svcs, "ctr:backup-job"); hasFact(bj, "guest_down") || !strings.Contains(bj.Text, "darf aus sein (Neustart-Richtlinie no)") {
		t.Errorf("backup-job = %+v", bj)
	}
	wk := svcByKey(t, svcs, "ctr:worker")
	if !hasFact(wk, "guest_down") || !strings.Contains(wk.Text, "beendet (Exit 1)") || mustMetric(t, wk, "running").Value != 0 {
		t.Errorf("worker (on-failure, Exit 1) = %+v", wk)
	}
	if os1 := svcByKey(t, svcs, "ctr:oneshot"); hasFact(os1, "guest_down") {
		t.Errorf("oneshot (on-failure, Exit 0) = %+v", os1)
	}
	wt := svcByKey(t, svcs, "ctr:watchtower")
	if wt.Default || !hasFact(wt, "guest_down") || hasFact(wt, "ctr_unhealthy") {
		t.Errorf("watchtower (nomonitor, always) = %+v", wt)
	}

	// Zweite Runde nach 10 s: CPU und Raten; db neu gestartet (RestartCount 2 -> 3, Health starting)
	nci, dbi := cid('a'), cid('b')
	f.mu.Lock()
	f.list = strings.Replace(f.list, "Up 2 hours (unhealthy)", "Up 3 seconds (health: starting)", 1)
	f.inspect[dbi] = inspectJSON(dbi, "db", "running", now.Add(7*time.Second).Format(time.RFC3339Nano), "starting", "always", 3, 0, false)
	f.stats[nci] = statsJSON(1e12+2e9, 1e14+4e10, 629145600, 1e9+12.5e6, 1e8+1.25e6, 5e8+1e7, 7e8+2e7)
	f.stats[dbi] = statsJSON(1e9, 1e14+4e10, 200000000, 1000, 1000, 0, 0)
	f.mu.Unlock()
	now = now.Add(10 * time.Second)
	svcs, err = d.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect 2: %v", err)
	}
	nc = svcByKey(t, svcs, "ctr:nextcloud")
	want := map[string]float64{"cpu": 5, "net_in": 10, "net_out": 1, "read": 1e6, "write": 2e6, "mem": 3.13}
	for name, v := range want {
		if m := mustMetric(t, nc, name); !near(m.Value, v) {
			t.Errorf("nextcloud %s = %v, erwartet %v", name, m.Value, v)
		}
	}
	if m := mustMetric(t, nc, "cpu"); m.Rule != model.RuleCPU {
		t.Errorf("cpu Regel = %q", m.Rule)
	}
	db = svcByKey(t, svcs, "ctr:db")
	if !strings.Contains(db.Text, "neu gestartet (3 Neustarts)") || hasFact(db, "ctr_unhealthy") {
		t.Errorf("db nach Neustart = %+v", db)
	}
	if _, ok := metric(db, "cpu"); ok {
		t.Error("CPU direkt nach Neustart")
	}
	// Neustart-Richtlinie nur einmal gelesen (alle 10 min): backup-job 1x vom Poller + 1x Richtlinie
	if n := f.hits["/containers/"+cid('c')+"/json"]; n != 2 {
		t.Errorf("inspect backup-job %d-mal, erwartet 2", n)
	}
}

func TestDockerPartialAndErrors(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	f, host := dockerFake(t, now)
	f.fail["/containers/"+cid('d')+"/json"] = http.StatusInternalServerError
	d := newTestDocker(t, host, &now)
	svcs, err := d.Collect(context.Background())
	if !IsPartial(err) || !strings.Contains(deErr(err), "inspect (1)") {
		t.Fatalf("erwartet PartialError: %v", err)
	}
	if wk := svcByKey(t, svcs, "ctr:worker"); hasFact(wk, "guest_down") || !strings.Contains(wk.Text, "Soll-Zustand unbekannt") {
		t.Errorf("worker ohne inspect = %+v", wk)
	}
	if !hasFact(svcByKey(t, svcs, "ctr:watchtower"), "guest_down") {
		t.Error("uebrige Container ohne Soll-Zustand")
	}
	f.mu.Lock()
	f.fail["/containers/json"] = http.StatusInternalServerError
	f.mu.Unlock()
	now = now.Add(time.Minute)
	if svcs, err := d.Collect(context.Background()); err == nil || IsPartial(err) || svcs != nil {
		t.Errorf("Liste fehlgeschlagen: %v", err)
	}
}

func TestDockerTest(t *testing.T) {
	now := time.Now()
	_, host := dockerFake(t, now)
	d := newTestDocker(t, host, &now)
	res := deRes(d.Test(context.Background()))
	if !res.OK || res.Version != "27.3.1" || res.Node != "docker01" || res.Summary != "6 Container, 2 laufen" {
		t.Errorf("Test = %+v", res)
	}
	if _, err := NewDocker(DockerConfig{Host: "ftp://x"}); err == nil {
		t.Error("ungueltige Adresse angenommen")
	}
	// ssh ohne Schluessel: Fehler bei jeder Runde, ohne Geheimnisse
	ds, err := NewDocker(DockerConfig{Host: "ssh://monitor@192.0.2.10", Secret: `{"key":"` + testSecret + `"}`})
	if err != nil {
		t.Fatal(err)
	}
	defer ds.Close()
	if _, err := ds.Collect(context.Background()); err == nil || strings.Contains(deErr(err), testSecret) {
		t.Errorf("ssh mit kaputtem Schluessel: %v", err)
	}
	if r := deRes(ds.Test(context.Background())); r.OK || strings.Contains(r.Error, testSecret) {
		t.Errorf("Test ssh: %+v", r)
	}
}

// TestDockerLive fragt einen echten Docker-Host lesend ab (nur mit M64_DOCKER_LIVE, z. B. unix:///var/run/docker.sock).
func TestDockerLive(t *testing.T) {
	host := os.Getenv("M64_DOCKER_LIVE")
	if host == "" {
		t.Skip("M64_DOCKER_LIVE nicht gesetzt")
	}
	d, err := NewDocker(DockerConfig{Host: host})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	r := deRes(d.Test(context.Background()))
	t.Logf("Test: %+v", r)
	if !r.OK {
		t.Fatal(r.Error)
	}
	if _, err := d.Collect(context.Background()); err != nil && !IsPartial(err) {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	svcs, err := d.Collect(context.Background())
	if err != nil && !IsPartial(err) {
		t.Fatal(err)
	}
	t.Logf("Teilfehler: %v", err)
	for _, s := range svcs {
		t.Logf("%-30s def=%v %v | %s | %v", s.Key, s.Default, s.Metrics, s.Text, s.Facts)
	}
}

// stats nicht abrufbar: keine Messgroessen statt falscher Nullwerte (auch nicht in der Runde danach).
func TestDockerStatsFailure(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	f, host := dockerFake(t, now)
	d := newTestDocker(t, host, &now)
	if _, err := d.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	nci := cid('a')
	f.mu.Lock()
	f.fail["/containers/"+nci+"/stats"] = http.StatusInternalServerError
	f.mu.Unlock()
	now = now.Add(10 * time.Second)
	svcs, _ := d.Collect(context.Background())
	nc := svcByKey(t, svcs, "ctr:nextcloud")
	for _, n := range []string{"cpu", "mem", "net_in", "net_out", "read", "write"} {
		if m, ok := metric(nc, n); ok {
			t.Errorf("ohne stats: %s = %v", n, m.Value)
		}
	}
	if mustMetric(t, nc, "running").Value != 1 {
		t.Error("running ohne stats")
	}
	// stats wieder da: erst eine Runde ohne Raten (vorige Runde ohne Zaehler), dann mit
	f.mu.Lock()
	delete(f.fail, "/containers/"+nci+"/stats")
	f.mu.Unlock()
	now = now.Add(10 * time.Second)
	svcs, _ = d.Collect(context.Background())
	if _, ok := metric(svcByKey(t, svcs, "ctr:nextcloud"), "net_in"); ok {
		t.Error("Rate direkt nach dem stats-Ausfall")
	}
	f.mu.Lock()
	f.stats[nci] = statsJSON(1e12+2e9, 1e14+4e10, 629145600, 1e9+12.5e6, 1e8+1.25e6, 5e8+1e7, 7e8+2e7)
	f.mu.Unlock()
	now = now.Add(10 * time.Second)
	svcs, _ = d.Collect(context.Background())
	if m := mustMetric(t, svcByKey(t, svcs, "ctr:nextcloud"), "net_in"); !near(m.Value, 10) {
		t.Errorf("net_in = %v, erwartet 10", m.Value)
	}
}

// Keine Weiterleitungen (Plan): eine Antwort 302 gilt als Fehler, das Ziel wird nicht abgefragt.
func TestDockerNoRedirect(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	f, host := dockerFake(t, now)
	f.mu.Lock()
	f.redirect = map[string]string{"/containers/" + cid('d') + "/json": "/containers/" + cid('a') + "/json"}
	f.mu.Unlock()
	d := newTestDocker(t, host, &now)
	svcs, err := d.Collect(context.Background())
	if !IsPartial(err) || !strings.Contains(deErr(err), "302") {
		t.Fatalf("erwartet Teilfehler mit 302: %v", err)
	}
	if wk := svcByKey(t, svcs, "ctr:worker"); !strings.Contains(wk.Text, "Soll-Zustand unbekannt") {
		t.Errorf("worker ueber Weiterleitung gelesen: %+v", wk)
	}
}
