package apis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Docker (lokaler Socket, tcp://, http(s):// mit TLS bzw. ssh:// wie in internal/proxmox/docker*.go). Die Abfrage der
// Container (Liste, stats, inspect, Raten, Neustarts) uebernimmt der DockerPoller aus internal/proxmox; dazu liest
// der Sammler je Container die Neustart-Richtlinie (GET /containers/{id}/json, alle 10 min bzw. bei neuer ID) fuer
// den Soll-Zustand: always, unless-stopped, on-failure -> soll laufen; no -> darf aus sein.

// DockerConfig sind die Verbindungsdaten eines Docker-Hosts.
type DockerConfig struct {
	Host    string        // unix:///var/run/docker.sock (Standard), tcp://, http(s)://host:2376, ssh://user@host
	Pin     string        // Fingerabdruck des Zertifikats bzw. SSH-Host-Keys (https, ssh)
	Secret  string        // Zugangsdaten (proxmox.DockerCreds als JSON bzw. privater SSH-Schluessel); nie ausgeben
	Timeout time.Duration // ganze Runde (0 = DefaultTimeout)
}

func (c DockerConfig) system() proxmox.System {
	sys := proxmox.System{Kind: proxmox.KindDocker, Secret: c.Secret, PinSHA256: c.Pin}
	if h := strings.TrimSpace(c.Host); h != "" {
		sys.Addresses = []string{h}
	}
	return sys
}

func (c DockerConfig) secrets() []string {
	cr := proxmox.ParseDockerCreds(c.Secret)
	return []string{c.Secret, strings.TrimSpace(cr.Key), strings.TrimSpace(cr.Cert)}
}

// Docker ist der Sammler eines Docker-Hosts.
type Docker struct {
	cfg  DockerConfig
	poll *proxmox.DockerPoller
	hc   *http.Client
	base string

	mu       sync.Mutex
	policies map[string]dockerPolicy // Name -> Neustart-Richtlinie
	restarts map[string]dockerSeen   // Name -> Neustarts der vorigen Runde
	now      func() time.Time
}

type dockerPolicy struct {
	id     string
	at     time.Time
	policy string
}

type dockerSeen struct {
	id       string
	restarts int
	running  bool
	stats    bool // stats lagen vor (sonst keine Raten in der naechsten Runde)
}

// NewDocker baut den Sammler. Close gibt die Verbindung frei (ssh://).
func NewDocker(cfg DockerConfig) (*Docker, error) {
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		host = proxmox.DefaultDockerHost()
	}
	if !proxmox.ValidDockerHost(host) {
		return nil, fmt.Errorf("ungültige Docker-Adresse %q (unix://, tcp://, http(s):// oder ssh://)", host)
	}
	cfg.Host = host
	p := proxmox.NewDockerPoller(slog.New(slog.DiscardHandler), cfg.system(), nil)
	hc, base := p.Client()
	if hc == nil {
		// Einrichtung fehlerhaft (Schluessel, Pin): Poll liefert den Fehler bei jeder Runde
		hc, base = &http.Client{}, "http://docker"
	}
	// keine Weiterleitungen (Plan): der Client gehoert nur diesem Poller, gilt also fuer seine Abfragen und inspect
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return newDocker(cfg, p, hc, base), nil
}

func newDocker(cfg DockerConfig, p *proxmox.DockerPoller, hc *http.Client, base string) *Docker {
	return &Docker{cfg: cfg, poll: p, hc: hc, base: strings.TrimRight(base, "/"), policies: map[string]dockerPolicy{},
		restarts: map[string]dockerSeen{}, now: time.Now}
}

// Close beendet die Verbindung (ssh:// haelt eine SSH-Verbindung offen; bei den anderen Arten nur Leerlauf-
// Verbindungen). Danach Collect nicht mehr aufrufen.
func (d *Docker) Close() {
	// DockerPoller.Run schliesst die Verbindung beim Ende; mit beendetem Kontext endet Run sofort nach einer
	// (sofort scheiternden) Abfrage.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.poll.Run(ctx)
}

func (d *Docker) timeout() time.Duration {
	if d.cfg.Timeout > 0 {
		return d.cfg.Timeout
	}
	return DefaultTimeout
}

// Test prueft die Verbindung im Assistenten (Fingerabdruck bei https/ssh, Version, Containerliste).
func (d *Docker) Test(ctx context.Context) TestResult {
	ctx, cancel := context.WithTimeout(ctx, d.timeout())
	defer cancel()
	pr := proxmox.DockerProbe(ctx, d.cfg.system())
	sec := d.cfg.secrets()
	res := TestResult{OK: pr.OK, Error: scrub(pr.Error, sec...), Warning: scrub(pr.Warning, sec...), Fingerprint: pr.Fingerprint,
		Trusted: pr.Trusted, NeedConfirm: pr.NeedConfirm}
	if pr.Info != nil {
		res.Version, res.Node = pr.Info.Version, pr.Info.Name
	}
	if pr.OK {
		res.Summary = fmt.Sprintf("%d Container, %d laufen", pr.Containers, pr.Running)
	}
	return res
}

// Collect ist eine Abfragerunde (nicht gleichzeitig mit sich selbst aufrufen).
func (d *Docker) Collect(ctx context.Context) ([]model.Service, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, d.timeout())
	defer cancel()
	sec := d.cfg.secrets()
	snap := d.poll.Poll(ctx)
	if !snap.OK {
		return nil, errors.New(scrub(snap.Error, sec...))
	}
	part := &partial{secrets: sec}
	now := d.now()
	d.fetchPolicies(ctx, now, snap.Resources, part)
	out := make([]model.Service, 0, len(snap.Resources))
	seen := map[string]bool{}
	for i := range snap.Resources {
		r := &snap.Resources[i]
		seen[r.Name] = true
		out = append(out, d.containerService(r))
	}
	for k := range d.policies {
		if !seen[k] {
			delete(d.policies, k)
		}
	}
	for k := range d.restarts {
		if !seen[k] {
			delete(d.restarts, k)
		}
	}
	return out, part.result()
}

// fetchPolicies liest die Neustart-Richtlinie der Container, deren Stand fehlt, veraltet ist oder zu einer anderen
// ID gehoert (neu angelegt). Fehler lassen den vorigen Stand stehen.
func (d *Docker) fetchPolicies(ctx context.Context, now time.Time, res []proxmox.Resource, part *partial) {
	var need []proxmox.Resource
	for _, r := range res {
		p, ok := d.policies[r.Name]
		if !ok || p.id != r.ContainerID || now.Sub(p.at) >= configEvery {
			need = append(need, r)
		}
	}
	var mu sync.Mutex
	var errs int
	var first error
	runParallel(ctx, need, func(ctx context.Context, r proxmox.Resource) {
		pol, err := d.inspectPolicy(ctx, r.ContainerID)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs++
			if first == nil {
				first = err
			}
			return
		}
		d.policies[r.Name] = dockerPolicy{id: r.ContainerID, at: now, policy: pol}
	})
	if errs > 0 {
		part.add(fmt.Sprintf("inspect (%d)", errs), first)
	}
}

func (d *Docker) inspectPolicy(ctx context.Context, id string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+"/containers/"+url.PathEscape(id)+"/json", nil)
	if err != nil {
		return "", err
	}
	resp, err := d.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &e)
		return "", fmt.Errorf("docker api /containers/%s/json: %d %s", id, resp.StatusCode, strings.TrimSpace(firstNonEmpty(e.Message, http.StatusText(resp.StatusCode))))
	}
	var in struct {
		HostConfig struct {
			RestartPolicy struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
		} `json:"HostConfig"`
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return "", fmt.Errorf("docker api /containers/%s/json: %w", id, err)
	}
	return firstNonEmpty(strings.TrimSpace(in.HostConfig.RestartPolicy.Name), "no"), nil
}

// shouldRun: Soll-Zustand aus der Neustart-Richtlinie. on-failure: ein mit 0 beendeter
// Container ist fertig (Docker startet ihn auch nicht neu) und darf aus sein.
func shouldRun(policy string, r *proxmox.Resource) bool {
	switch policy {
	case "always", "unless-stopped":
		return true
	case "on-failure":
		return !(r.Status == "exited" && r.ExitCode == 0 && !r.OOMKilled)
	}
	return false
}

var dockerStatusText = map[string]string{"running": "läuft", "exited": "beendet", "paused": "pausiert", "restarting": "startet neu",
	"created": "angelegt", "dead": "tot", "removing": "wird entfernt"}

// containerService: ein Container als Dienst ctr:<name>.
func (d *Docker) containerService(r *proxmox.Resource) model.Service {
	s := model.Service{Key: "ctr:" + r.Name, Name: r.Name, Kind: "ctr", Default: !r.Excluded()}
	running := r.Status == "running"
	run := 0.0
	if running {
		run = 1
	}
	s.Metrics = append(s.Metrics, model.Metric{Name: "running", Value: run}, model.Metric{Name: "restarts", Value: float64(r.Restarts)})
	parts := []string{firstNonEmpty(dockerStatusText[r.Status], r.Status, "unbekannt")}
	switch {
	case r.Status == "exited" && r.OOMKilled:
		parts[0] += " (OOM)"
	case r.Status == "exited":
		parts[0] += fmt.Sprintf(" (Exit %d)", r.ExitCode)
	}
	// Health nur bei laufenden Containern (inspect behaelt nach dem Stoppen den letzten Stand)
	if r.Health != "" && running {
		parts = append(parts, r.Health)
	}
	if r.Health == "unhealthy" && running {
		s.Facts = append(s.Facts, model.Fact{Code: "ctr_unhealthy", Text: "Healthcheck unhealthy"})
	}
	if r.Detail == proxmox.DockerRestarting && running {
		parts = append(parts, "Neustart-Schleife")
	}
	prev, had := d.restarts[r.Name]
	same := had && prev.id == r.ContainerID
	if (same && r.Restarts > prev.restarts) || r.Restarted {
		parts = append(parts, fmt.Sprintf("neu gestartet (%d Neustarts)", r.Restarts))
	}
	// stats nicht abrufbar: der Poller laesst CPU, RAM und Raten auf 0 (MaxCPU 0) – dann keine Messgroessen statt
	// falscher Nullwerte
	hasStats := running && r.MaxCPU > 0
	d.restarts[r.Name] = dockerSeen{id: r.ContainerID, restarts: r.Restarts, running: running, stats: hasStats}
	// CPU und Raten rechnet der DockerPoller aus zwei Runden: erst gueltig, wenn der Container schon lief und beide
	// Runden stats hatten
	rates := hasStats && same && prev.running && prev.stats && !r.Restarted
	if running {
		if rates {
			s.Metrics = append(s.Metrics, model.Metric{Name: "cpu", Value: round2(r.CPU * 100), Unit: "%", Rule: model.RuleCPU})
			parts = append(parts, fmt.Sprintf("CPU %.0f %%", r.CPU*100))
		}
		if r.MaxMem > 0 {
			mx := float64(r.MaxMem)
			s.Metrics = append(s.Metrics, model.Metric{Name: "mem", Value: pct(float64(r.Mem), mx), Unit: "%", Rule: model.RuleMem, Max: mx},
				model.Metric{Name: "mem_used", Value: float64(r.Mem), Unit: "B", Max: mx})
			parts = append(parts, "RAM "+bytesText(float64(r.Mem)))
		}
		if rates {
			in, outb := r.NetIn*8/1e6, r.NetOut*8/1e6
			s.Metrics = append(s.Metrics, model.Metric{Name: "net_in", Value: round2(in), Unit: "Mbit/s"},
				model.Metric{Name: "net_out", Value: round2(outb), Unit: "Mbit/s"},
				model.Metric{Name: "read", Value: float64(int64(r.DiskRead)), Unit: "B/s"},
				model.Metric{Name: "write", Value: float64(int64(r.DiskWrite)), Unit: "B/s"})
			parts = append(parts, fmt.Sprintf("↓ %s · ↑ %s", mbitText(in), mbitText(outb)))
		}
	}
	pol, known := d.policies[r.Name]
	switch {
	case !known:
		parts = append(parts, "Soll-Zustand unbekannt")
	case shouldRun(pol.policy, r):
		parts = append(parts, "soll laufen (Neustart-Richtlinie "+pol.policy+")")
		if !running && r.Status != "paused" {
			s.Facts = append(s.Facts, model.Fact{Code: "guest_down", Text: parts[0] + ", soll laufen (Neustart-Richtlinie " + pol.policy + ")"})
		}
	default:
		parts = append(parts, "darf aus sein (Neustart-Richtlinie "+pol.policy+")")
	}
	if r.Image != "" {
		parts = append(parts, r.Image)
	}
	s.Text = strings.Join(parts, " · ")
	return s
}
