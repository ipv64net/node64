package proxmox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Docker-Host als System (Kind docker): je Abfrage die Containerliste (GET /containers/json?all=1), fuer laufende
// Container die Werte (GET /containers/{id}/stats?stream=false&one-shot=true) und bei Bedarf inspect
// (GET /containers/{id}/json: Neustarts, Exit-Code, OOM, Startzeit, Health). Hoechstens dockerParallel Anfragen
// gleichzeitig, kurze Zeitlimits. Nur lesende GET-Anfragen. Key je Container ist der Name (bleibt beim Neuanlegen
// gleich), die ID wird mitgefuehrt.
//
// CPU wie docker stats: (total_usage - vorher) / (system_cpu_usage - vorher) × online_cpus = belegte Kerne; Resource.CPU
// ist der Anteil davon an MaxCPU (CPU-Limit des Containers bzw. alle Kerne des Hosts). RAM wie docker stats: usage
// minus inactive_file (cgroup v2) bzw. total_inactive_file (v1), bezogen auf das Limit (ohne Limit der RAM des Hosts).
// Netz (Summe aller Netze) und Block-I/O als Raten aus den Zaehlern.

const (
	LabelNoMonitor       = "node64.nomonitor" // Label =true schliesst einen Container aus (wie Tag nomonitor)
	dockerParallel       = 4
	dockerRequestTimeout = 10 * time.Second
	dockerRoundWait      = 25 * time.Second // alle stats/inspect einer Abfrage zusammen
	dockerInfoEvery      = 10 * time.Minute
	dockerInspectEvery   = 5 * time.Minute
	dockerLoopWindow     = 10 * time.Minute // Neustart-Schleife: so viele Neustarts in diesem Zeitraum
	dockerLoopRestarts   = 3
	dockerMaxLabels      = 64
)

// DockerInfo ist der Stand des Docker-Hosts (/info).
type DockerInfo struct {
	Name     string `json:"name"` // Hostname
	OS       string `json:"os,omitempty"`
	Version  string `json:"version,omitempty"`
	NCPU     int    `json:"ncpu"`
	MemTotal int64  `json:"mem_total"`
}

// dockerInfoRaw ist der benutzte Teil von /info.
type dockerInfoRaw struct {
	Name            string `json:"Name"`
	OperatingSystem string `json:"OperatingSystem"`
	ServerVersion   string `json:"ServerVersion"`
	NCPU            int    `json:"NCPU"`
	MemTotal        int64  `json:"MemTotal"`
}

func (in dockerInfoRaw) toInfo() *DockerInfo {
	return &DockerInfo{Name: in.Name, OS: in.OperatingSystem, Version: in.ServerVersion, NCPU: in.NCPU, MemTotal: in.MemTotal}
}

// DefaultDockerHost: NODE64_DOCKER_HOST oder der uebliche Socket (wie der Check-Typ docker).
func DefaultDockerHost() string {
	if h := strings.TrimSpace(os.Getenv("NODE64_DOCKER_HOST")); h != "" {
		return h
	}
	return "unix:///var/run/docker.sock"
}

// ValidDockerHost: unix:///pfad (lokaler Socket), tcp:// bzw. http(s):// (z. B. docker-socket-proxy, TLS auf 2376) oder
// ssh://user@host[:port][/socket] (docker_remote.go).
func ValidDockerHost(h string) bool {
	switch {
	case strings.HasPrefix(h, "ssh://"):
		_, _, _, err := dockerSSHTarget(h)
		return err == nil
	case strings.HasPrefix(h, "unix://"):
		return strings.HasPrefix(strings.TrimPrefix(h, "unix://"), "/")
	case strings.HasPrefix(h, "tcp://"), strings.HasPrefix(h, "http://"), strings.HasPrefix(h, "https://"):
		u, err := url.Parse(strings.Replace(h, "tcp://", "http://", 1))
		return err == nil && u.Host != "" && u.User == nil
	}
	return false
}

// dockerHTTP baut HTTP-Client (ohne Gesamt-Zeitlimit, das setzen die Anfragen) und Basis-URL fuer einen Host.
func dockerHTTP(host string) (*http.Client, string, error) {
	switch {
	case strings.HasPrefix(host, "unix://"):
		sock := strings.TrimPrefix(host, "unix://")
		tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}, MaxIdleConnsPerHost: dockerParallel}
		return &http.Client{Transport: tr}, "http://docker", nil
	case strings.HasPrefix(host, "tcp://"):
		return &http.Client{}, "http://" + strings.TrimPrefix(host, "tcp://"), nil
	case strings.HasPrefix(host, "http://"), strings.HasPrefix(host, "https://"):
		return &http.Client{}, strings.TrimRight(host, "/"), nil
	}
	return nil, "", fmt.Errorf("unknown docker host %q (use unix://, tcp:// or http(s)://)", host)
}

// DockerClient: HTTP-Client (ohne Gesamt-Zeitlimit) und Basis-URL fuer unix://, tcp:// und http(s):// ohne
// Zugangsdaten (PROXY64 Docker-Labels); ssh:// gibt es dort nicht.
func DockerClient(host string) (*http.Client, string, error) {
	if !ValidDockerHost(host) || DockerScheme(host) == "ssh" {
		return nil, "", fmt.Errorf("unknown docker host %q (use unix://, tcp:// or http(s)://)", host)
	}
	return dockerHTTP(host)
}

// DockerHint erklaert typische Fehler beim Zugriff auf die Docker-API (wie die Docker-Ueberwachung).
func DockerHint(host string, err error) string { return dockerHintFor(host, err) }

// DockerPoller fragt einen Docker-Host ab (Source).
type DockerPoller struct {
	log      *slog.Logger
	sys      System
	fn       SnapshotFunc
	hc       *http.Client
	base     string
	host     string
	initErr  error
	close    func() // Verbindung schliessen (SSH), am Ende von Run
	now      func() time.Time
	interval time.Duration

	mu   sync.Mutex
	last *Snapshot

	// nur von der Abfrage-Schleife benutzt
	info    *DockerInfo
	infoAt  time.Time
	inspect map[string]dockerInspected // Container-ID -> letztes inspect
	prev    map[string]dockerPrev      // Name -> Stand der letzten Abfrage
	failing bool
	paced   bool
}

// dockerPrev ist der Stand eines Containers bei der letzten Abfrage (Raten, CPU, Neustarts).
type dockerPrev struct {
	t                                time.Time
	id                               string
	running                          bool
	started                          time.Time
	restarts                         int
	cpuTotal, cpuSystem              uint64
	netIn, netOut, blkRead, blkWrite uint64
	hasStats                         bool
	restartTimes                     []time.Time // erkannte Neustarts (fuer die Neustart-Schleife)
}

// dockerInspected ist ein gemerktes inspect mit dem Stand beim Abruf (aendert er sich, wird neu gefragt).
type dockerInspected struct {
	at      time.Time
	state   string
	health  string
	started time.Time // State.StartedAt
	in      dockerInspect
}

// NewDockerPoller baut die Abfrage eines Docker-Hosts. fn darf nil sein.
func NewDockerPoller(log *slog.Logger, sys System, fn SnapshotFunc) *DockerPoller {
	host := dockerSysAddr(sys)
	conn, err := dockerConnect(sys, nil)
	if err != nil {
		conn = &dockerConn{hc: &http.Client{}, base: "http://docker", close: func() {}}
	}
	p := NewDockerPollerClient(log, sys, fn, conn.hc, conn.base)
	p.host, p.initErr, p.close = host, err, conn.close
	return p
}

// Client liefert HTTP-Client und Basis-URL der Abfrage (Check-Typ docker fuer Hosts mit Zugangsdaten: dieselbe
// Verbindung); nil bei Fehler in der Einrichtung.
func (p *DockerPoller) Client() (*http.Client, string) {
	if p.initErr != nil {
		return nil, ""
	}
	return p.hc, p.base
}

// Host ist die Adresse des Docker-Hosts.
func (p *DockerPoller) Host() string { return p.host }

// NewDockerPollerClient baut die Abfrage mit eigenem HTTP-Client und Basis-URL (Tests: httptest).
func NewDockerPollerClient(log *slog.Logger, sys System, fn SnapshotFunc, hc *http.Client, base string) *DockerPoller {
	if log == nil {
		log = slog.Default()
	}
	return &DockerPoller{log: log.With("docker", sys.Name, "system_id", sys.ID), sys: sys, fn: fn, hc: hc, base: strings.TrimRight(base, "/"),
		host: base, now: time.Now, interval: ClampInterval(sys.Interval), inspect: map[string]dockerInspected{}, prev: map[string]dockerPrev{}}
}

// SetClock setzt die Uhr (Tests).
func (p *DockerPoller) SetClock(now func() time.Time) { p.now = now }

// Last ist der letzte Snapshot (nil vor der ersten Abfrage).
func (p *DockerPoller) Last() *Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last
}

// Run fragt ab, bis ctx endet. Nach Fehlern wird frueher wiederholt (5 s, verdoppelt bis zum Intervall).
func (p *DockerPoller) Run(ctx context.Context) {
	if p.close != nil {
		defer p.close()
	}
	p.paced = true
	backoff := pveBackoffStart
	for {
		s := p.Poll(ctx)
		if ctx.Err() != nil {
			return
		}
		wait := p.interval
		if !s.OK {
			wait = min(backoff, p.interval)
			backoff = min(backoff*2, p.interval)
		} else {
			backoff = pveBackoffStart
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// Poll ist eine Abfrage (Run ruft sie im Takt; nicht gleichzeitig aufrufen).
func (p *DockerPoller) Poll(ctx context.Context) *Snapshot {
	now := p.now()
	s := &Snapshot{SystemID: p.sys.ID, Time: now, Resources: []Resource{}, Address: p.host}
	err := p.initErr
	if err == nil {
		err = p.collect(ctx, now, s)
	}
	if err != nil {
		s.OK, s.Error, s.Resources = false, dockerHintFor(p.host, err), []Resource{}
		if !p.failing {
			p.log.Warn("docker api failed", "err", s.Error)
		}
		p.failing = true
	} else {
		s.OK = true
		if p.failing {
			p.log.Info("docker api reachable again")
		}
		p.failing = false
	}
	if p.info != nil {
		x := *p.info
		s.Docker, s.Version = &x, x.Version
	}
	if p.paced {
		s.Interval = p.interval
	}
	p.mu.Lock()
	p.last = s
	p.mu.Unlock()
	if p.fn != nil {
		p.fn(ctx, s)
	}
	return s
}

// dockerHint erklaert typische Zugriffsfehler auf den Socket (wie der Check-Typ docker).
func dockerHint(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "permission denied"):
		return msg + " – the node user may not read the socket: add --group-add $(stat -c %g /var/run/docker.sock) (compose: group_add)"
	case strings.Contains(msg, "no such file") || strings.Contains(msg, "connect: connection refused"):
		return msg + " – mount the socket: -v /var/run/docker.sock:/var/run/docker.sock:ro (or set NODE64_DOCKER_HOST)"
	}
	return msg
}

// get fragt einen Pfad ab (JSON, hoechstens 8 MiB).
func (p *DockerPoller) get(ctx context.Context, path string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, dockerRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+path, nil)
	if err != nil {
		return err
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Message == "" {
			e.Message = http.StatusText(resp.StatusCode)
		}
		return fmt.Errorf("docker api %s: %d %s", strings.SplitN(path, "?", 2)[0], resp.StatusCode, strings.TrimSpace(e.Message))
	}
	return json.Unmarshal(b, v)
}

// dockerListEntry ist ein Eintrag aus /containers/json.
type dockerListEntry struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Created int64             `json:"Created"`
	Labels  map[string]string `json:"Labels"`
	Health  *struct {         // neuere APIs liefern den Health-Zustand auch in der Liste
		Status string `json:"Status"`
	} `json:"Health"`
	Ports []struct {
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

// dockerInspect ist der benutzte Teil von /containers/{id}/json.
type dockerInspect struct {
	RestartCount int `json:"RestartCount"`
	State        struct {
		Status    string `json:"Status"`
		OOMKilled bool   `json:"OOMKilled"`
		ExitCode  int    `json:"ExitCode"`
		StartedAt string `json:"StartedAt"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	HostConfig struct {
		NanoCpus  int64 `json:"NanoCpus"`
		CPUQuota  int64 `json:"CpuQuota"`
		CPUPeriod int64 `json:"CpuPeriod"`
	} `json:"HostConfig"`
}

// dockerStats ist der benutzte Teil von /containers/{id}/stats (one-shot, ohne precpu: Differenzen rechnet der Poller).
type dockerStats struct {
	CPU struct {
		Usage struct {
			Total  uint64   `json:"total_usage"`
			PerCPU []uint64 `json:"percpu_usage"`
		} `json:"cpu_usage"`
		System uint64 `json:"system_cpu_usage"`
		Online int    `json:"online_cpus"`
	} `json:"cpu_stats"`
	Memory struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		Rx uint64 `json:"rx_bytes"`
		Tx uint64 `json:"tx_bytes"`
	} `json:"networks"`
	Blkio struct {
		IO []struct {
			Op    string `json:"op"`
			Value uint64 `json:"value"`
		} `json:"io_service_bytes_recursive"`
	} `json:"blkio_stats"`
}

// dockerJob ist die Arbeit fuer einen Container in einer Abfrage.
type dockerJob struct {
	c       *dockerListEntry
	name    string
	health  string // aus der Liste
	stats   *dockerStats
	in      *dockerInspected
	statErr error
}

// collect fuehrt die faelligen Abfragen aus und fuellt s.
func (p *DockerPoller) collect(ctx context.Context, now time.Time, s *Snapshot) error {
	var list []dockerListEntry
	if err := p.get(ctx, "/containers/json?all=1", &list); err != nil {
		return err
	}
	if p.info == nil || now.Sub(p.infoAt) >= dockerInfoEvery {
		var in dockerInfoRaw
		if err := p.get(ctx, "/info", &in); err == nil {
			p.info, p.infoAt = in.toInfo(), now
		} else {
			p.log.Debug("docker info failed", "err", err) // z. B. docker-socket-proxy ohne INFO=1: nicht fatal
			p.infoAt = now
		}
	}
	jobs := make([]*dockerJob, 0, len(list))
	seenIDs := map[string]bool{}
	for i := range list {
		c := &list[i]
		name := dockerShortID(c.ID)
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		if name == "" {
			continue
		}
		j := &dockerJob{c: c, name: name, health: dockerListHealth(c)}
		seenIDs[c.ID] = true
		jobs = append(jobs, j)
	}
	p.fetch(ctx, now, jobs)
	for id := range p.inspect {
		if !seenIDs[id] {
			delete(p.inspect, id) // Container entfernt
		}
	}
	s.Resources = p.build(now, jobs)
	return nil
}

// fetch holt stats (laufende Container) und inspect (wenn noetig) mit hoechstens dockerParallel Anfragen gleichzeitig.
func (p *DockerPoller) fetch(ctx context.Context, now time.Time, jobs []*dockerJob) {
	ctx, cancel := context.WithTimeout(ctx, dockerRoundWait)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	got := map[string]dockerInspected{} // neue inspect (erst nach dem Warten in p.inspect)
	sem := make(chan struct{}, dockerParallel)
	for _, j := range jobs {
		old, cached := p.inspect[j.c.ID]
		prev, hasPrev := p.prev[j.name]
		wg.Add(1)
		sem <- struct{}{}
		go func(j *dockerJob) {
			defer wg.Done()
			defer func() { <-sem }()
			reset := false
			if j.c.State == "running" {
				var st dockerStats
				if err := p.get(ctx, "/containers/"+url.PathEscape(j.c.ID)+"/stats?stream=false&one-shot=true", &st); err != nil {
					j.statErr = err
				} else {
					j.stats = &st
					// Zaehler zurueckgesprungen: Container wurde (zwischen zwei Abfragen) neu gestartet
					reset = hasPrev && prev.hasStats && prev.id == j.c.ID && st.CPU.Usage.Total < prev.cpuTotal
				}
			}
			// Status „Up 5 seconds“ juenger als die gemerkte Startzeit: neu gestartet
			younger := false
			if up, ok := dockerUpMax(j.c.Status); ok && cached && j.c.State == "running" && !old.started.IsZero() {
				younger = up < now.Sub(old.started)-5*time.Second
			}
			need := !cached || old.state != j.c.State || old.health != j.health || reset || younger || now.Sub(old.at) >= dockerInspectEvery
			if !need {
				x := old
				j.in = &x
				return
			}
			var in dockerInspect
			if err := p.get(ctx, "/containers/"+url.PathEscape(j.c.ID)+"/json", &in); err != nil {
				p.log.Debug("docker inspect failed", "container", j.name, "err", err)
				if cached {
					x := old
					j.in = &x
				}
				return
			}
			x := dockerInspected{at: now, state: j.c.State, health: j.health, in: in}
			if t, err := time.Parse(time.RFC3339Nano, in.State.StartedAt); err == nil && t.Year() > 1 {
				x.started = t
			}
			j.in = &x
			mu.Lock()
			got[j.c.ID] = x
			mu.Unlock()
		}(j)
	}
	wg.Wait()
	for id, x := range got {
		p.inspect[id] = x
	}
}

// dockerListHealth liest den Health-Zustand aus der Liste (Feld Health bzw. Text in Status).
func dockerListHealth(c *dockerListEntry) string {
	if c.Health != nil && c.Health.Status != "" && c.Health.Status != "none" {
		return c.Health.Status
	}
	switch {
	case strings.Contains(c.Status, "(unhealthy)"):
		return "unhealthy"
	case strings.Contains(c.Status, "(healthy)"):
		return "healthy"
	case strings.Contains(c.Status, "health: starting"):
		return "starting"
	}
	return ""
}

var dockerUpRe = regexp.MustCompile(`^Up (Less than a|About an?|\d+) (second|minute|hour|day|week|month|year)s?`)

// dockerUpMax liest aus „Up 3 minutes“ die hoechstens moegliche Laufzeit (Docker rundet ab: 3 minutes = unter 4).
func dockerUpMax(status string) (time.Duration, bool) {
	m := dockerUpRe.FindStringSubmatch(status)
	if m == nil {
		return 0, false
	}
	n := 1
	if m[1][0] >= '0' && m[1][0] <= '9' {
		n, _ = strconv.Atoi(m[1])
	}
	unit := map[string]time.Duration{"second": time.Second, "minute": time.Minute, "hour": time.Hour, "day": 24 * time.Hour,
		"week": 7 * 24 * time.Hour, "month": 31 * 24 * time.Hour, "year": 366 * 24 * time.Hour}[m[2]]
	return time.Duration(n+1) * unit, true
}

// dockerExitFromStatus liest den Exit-Code aus „Exited (1) 2 hours ago“ (falls inspect fehlt).
func dockerExitFromStatus(status string) int {
	if i := strings.Index(status, "("); i >= 0 {
		if j := strings.Index(status[i:], ")"); j > 1 {
			if n, err := strconv.Atoi(status[i+1 : i+j]); err == nil {
				return n
			}
		}
	}
	return 0
}

func dockerShortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// dockerPorts: veroeffentlichte Ports, z. B. 8080->80/tcp (IPv4 und IPv6 nur einmal).
func dockerPorts(c *dockerListEntry) []string {
	var out []string
	seen := map[string]bool{}
	for _, pt := range c.Ports {
		s := fmt.Sprintf("%d/%s", pt.PrivatePort, pt.Type)
		if pt.PublicPort > 0 {
			s = fmt.Sprintf("%d->%s", pt.PublicPort, s)
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// dockerLabels kuerzt die Labels (Anzahl, Laenge der Werte).
func dockerLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, min(len(keys), dockerMaxLabels))
	for _, k := range keys {
		if len(out) >= dockerMaxLabels {
			break
		}
		v := in[k]
		if len(v) > 200 {
			v = v[:200]
		}
		out[k] = v
	}
	return out
}

// dockerCPULimit: CPU-Limit des Containers in Kernen (0 = keins).
func dockerCPULimit(in *dockerInspect) float64 {
	if in == nil {
		return 0
	}
	if in.HostConfig.NanoCpus > 0 {
		return float64(in.HostConfig.NanoCpus) / 1e9
	}
	if in.HostConfig.CPUQuota > 0 && in.HostConfig.CPUPeriod > 0 {
		return float64(in.HostConfig.CPUQuota) / float64(in.HostConfig.CPUPeriod)
	}
	return 0
}

// dockerMemUsed: RAM wie docker stats (usage ohne inactive_file bzw. total_inactive_file).
func dockerMemUsed(st *dockerStats) uint64 {
	u := st.Memory.Usage
	if v, ok := st.Memory.Stats["total_inactive_file"]; ok && v < u {
		return u - v
	}
	if v, ok := st.Memory.Stats["inactive_file"]; ok && v < u {
		return u - v
	}
	return u
}

func dockerDelta(old, cur uint64) uint64 {
	if cur < old {
		return 0
	}
	return cur - old
}

// build macht aus der Liste und den abgefragten Werten die Ressourcen (mit Zustand und Raten) und merkt sich den Stand.
func (p *DockerPoller) build(now time.Time, jobs []*dockerJob) []Resource {
	hostName, ncpu, memTotal := "", 0, int64(0)
	if p.info != nil {
		hostName, ncpu, memTotal = p.info.Name, p.info.NCPU, p.info.MemTotal
	}
	out := make([]Resource, 0, len(jobs))
	next := make(map[string]dockerPrev, len(jobs))
	for _, j := range jobs {
		c := j.c
		r := Resource{Type: TypeDocker, Node: hostName, Name: j.name, Status: c.State, ContainerID: dockerShortID(c.ID), Image: c.Image,
			Health: j.health, Created: c.Created, Ports: dockerPorts(c), Labels: dockerLabels(c.Labels)}
		if prj := c.Labels["com.docker.compose.project"]; prj != "" {
			r.Tags = []string{prj}
		}
		var in *dockerInspect
		if j.in != nil {
			in = &j.in.in
			r.Restarts, r.ExitCode, r.OOMKilled = in.RestartCount, in.State.ExitCode, in.State.OOMKilled
			if r.Health == "" && in.State.Health != nil && in.State.Health.Status != "none" {
				r.Health = in.State.Health.Status
			}
		} else if c.State == "exited" {
			r.ExitCode = dockerExitFromStatus(c.Status)
		}
		var started time.Time
		if in != nil {
			if t, err := time.Parse(time.RFC3339Nano, in.State.StartedAt); err == nil && t.Year() > 1 {
				started = t
			}
		}
		running := c.State == "running"
		if running && !started.IsZero() && now.After(started) {
			r.Uptime = int64(now.Sub(started).Seconds())
		}
		cur := dockerPrev{t: now, id: c.ID, running: running, started: started, restarts: r.Restarts}
		old, hasOld := p.prev[j.name]
		if hasOld && old.id != c.ID {
			hasOld = false // neu angelegt (gleicher Name): keine Raten, kein Neustart
		}
		if hasOld {
			cur.restartTimes = old.restartTimes
			n := 0
			if r.Restarts > old.restarts {
				n = r.Restarts - old.restarts
			}
			if n == 0 && old.running && running && !old.started.IsZero() && started.After(old.started) {
				n = 1 // docker restart von Hand: RestartCount bleibt, Startzeit neu
			}
			if j.in == nil {
				cur.restarts = old.restarts // ohne inspect nicht als Neustart werten
				n = 0
			}
			for k := 0; k < n && k < dockerLoopRestarts; k++ {
				cur.restartTimes = append(cur.restartTimes, now)
			}
			r.Restarted = n > 0 && old.running && running
			if started.IsZero() {
				cur.started = old.started
			}
		}
		// Neustarts ausserhalb des Zeitraums vergessen
		keep := cur.restartTimes[:0:0]
		for _, t := range cur.restartTimes {
			if now.Sub(t) < dockerLoopWindow {
				keep = append(keep, t)
			}
		}
		cur.restartTimes = keep
		loop := len(keep) >= dockerLoopRestarts

		// Werte (nur laufende Container mit stats)
		if st := j.stats; st != nil && running {
			online := st.CPU.Online
			if online <= 0 {
				online = len(st.CPU.Usage.PerCPU)
			}
			if online <= 0 {
				online = ncpu
			}
			r.MaxCPU = float64(online)
			if lim := dockerCPULimit(in); lim > 0 && lim < r.MaxCPU {
				r.MaxCPU = lim
			}
			cur.hasStats, cur.cpuTotal, cur.cpuSystem = true, st.CPU.Usage.Total, st.CPU.System
			for _, n := range st.Networks {
				cur.netIn += n.Rx
				cur.netOut += n.Tx
			}
			for _, x := range st.Blkio.IO {
				switch strings.ToLower(x.Op) {
				case "read":
					cur.blkRead += x.Value
				case "write":
					cur.blkWrite += x.Value
				}
			}
			r.Mem = int64(dockerMemUsed(st))
			r.MaxMem = int64(st.Memory.Limit)
			if memTotal > 0 && (r.MaxMem <= 0 || r.MaxMem > memTotal) {
				r.MaxMem = memTotal // ohne Limit meldet Docker (fast) den RAM des Hosts
			}
			if hasOld && old.hasStats {
				dt := now.Sub(old.t).Seconds()
				cpuD := dockerDelta(old.cpuTotal, cur.cpuTotal)
				cores := 0.0
				if sysD := dockerDelta(old.cpuSystem, cur.cpuSystem); sysD > 0 && cur.cpuTotal >= old.cpuTotal {
					cores = float64(cpuD) / float64(sysD) * float64(online)
				} else if dt > 0 && cur.cpuTotal >= old.cpuTotal {
					cores = float64(cpuD) / (dt * 1e9) // ohne system_cpu_usage: Nanosekunden je Sekunde
				}
				if r.MaxCPU > 0 {
					r.CPU = min(cores/r.MaxCPU, 1)
				}
				if dt > 0 {
					r.NetIn = float64(dockerDelta(old.netIn, cur.netIn)) / dt
					r.NetOut = float64(dockerDelta(old.netOut, cur.netOut)) / dt
					r.DiskRead = float64(dockerDelta(old.blkRead, cur.blkRead)) / dt
					r.DiskWrite = float64(dockerDelta(old.blkWrite, cur.blkWrite)) / dt
				}
			}
		}
		r.State, r.Detail = dockerState(&r, loop)
		if r.State == StateError {
			r.Restarted = false // Absturz bzw. Schleife meldet die Regel „Absturz“, nicht jeder Neustart einzeln
		}
		next[j.name] = cur
		out = append(out, r)
	}
	p.prev = next
	sort.SliceStable(out, func(i, k int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[k].Name) })
	return out
}

// Docker-Stoerungen (Resource.Detail bei StateError).
const (
	DockerUnhealthy  = "unhealthy"
	DockerRestarting = "restarting" // Status restarting bzw. Neustart-Schleife
	DockerExited     = "exited"     // beendet mit Exit-Code ungleich 0 (nicht SIGTERM/SIGINT)
	DockerOOM        = "oom"
	DockerDead       = "dead"
)

// dockerState bewertet einen Container: laeuft (healthy, ohne Healthcheck, startet) = running; unhealthy,
// Neustart-Schleife, restarting = error; beendet mit Fehler, OOM, dead = error (die Regeln werten das nur, wenn der
// Container laufen soll); beendet mit 0 bzw. per SIGTERM/SIGINT, created = stopped; paused = paused.
func dockerState(r *Resource, loop bool) (State, string) {
	switch r.Status {
	case "running":
		switch {
		case r.Health == "unhealthy":
			return StateError, DockerUnhealthy
		case loop:
			return StateError, DockerRestarting
		}
		return StateRunning, ""
	case "restarting":
		return StateError, DockerRestarting
	case "paused":
		return StatePaused, ""
	case "exited":
		switch {
		case r.OOMKilled:
			return StateError, DockerOOM
		case r.ExitCode != 0 && r.ExitCode != 130 && r.ExitCode != 143:
			return StateError, DockerExited
		}
		return StateStopped, ""
	case "dead":
		return StateError, DockerDead
	case "created", "removing":
		return StateStopped, ""
	}
	return StateUnknown, ""
}

// DockerDown: Container laeuft nicht (beendet, tot) – eine Stoerung nur, wenn er laufen soll.
func (r *Resource) DockerDown() bool {
	return r.Type == TypeDocker && r.Status != "running" && r.Status != "restarting" && r.Status != "paused"
}
