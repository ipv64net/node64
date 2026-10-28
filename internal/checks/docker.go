package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Docker-Container-Check: fragt die Docker-Engine-API ueber den Socket (oder TCP, z. B. einen
// docker-socket-proxy) nach dem Zustand eines Containers. Bewertung wie bei Uptime Kuma:
//   laeuft, ohne Healthcheck        -> up
//   laeuft, Healthcheck healthy     -> up
//   laeuft, Healthcheck starting    -> up (Meldung "health: starting", kein Alarm)
//   laeuft, Healthcheck unhealthy   -> down (container_unhealthy)
//   restarting / paused             -> down (container_restarting / container_paused)
//   exited, created, dead           -> down (container_stopped, mit Exit-Code)
//   nicht vorhanden                 -> down (container_missing)
//   Socket nicht erreichbar         -> down (docker_unavailable, mit Hinweis)
// Nur lesende GET-Anfragen. Laeuft ausschliesslich lokal auf der Node.

const TypeDocker Type = "docker"

const (
	ReasonContainerMissing    Reason = "container_missing"
	ReasonContainerStopped    Reason = "container_stopped"
	ReasonContainerPaused     Reason = "container_paused"
	ReasonContainerRestarting Reason = "container_restarting"
	ReasonContainerUnhealthy  Reason = "container_unhealthy"
	ReasonDockerUnavailable   Reason = "docker_unavailable"
)

// DockerParams sind die Parameter eines Docker-Checks.
type DockerParams struct {
	Host   string `json:"host,omitempty"`   // unix:///var/run/docker.sock (Standard), tcp://host:2375, http(s)://...
	System string `json:"system,omitempty"` // nur Anzeige: Name des Docker-Hosts in der Ueberwachung (Gruppierung, auch im Portal)
}

// DefaultDockerHost: NODE64_DOCKER_HOST oder der uebliche Socket.
func DefaultDockerHost() string {
	if h := strings.TrimSpace(os.Getenv("NODE64_DOCKER_HOST")); h != "" {
		return h
	}
	return "unix:///var/run/docker.sock"
}

var containerRe = regexp.MustCompile(`^/?[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func validDockerHost(h string) bool {
	return h == "" || strings.HasPrefix(h, "unix://") || strings.HasPrefix(h, "tcp://") || strings.HasPrefix(h, "http://") || strings.HasPrefix(h, "https://") || strings.HasPrefix(h, "ssh://")
}

// DockerRemote liefert fuer einen Host der Docker-Ueberwachung deren Verbindung (Zugangsdaten bei https://, ssh://);
// ok=false: dort nicht eingerichtet bzw. ausgeschaltet. Gesetzt von Healthchecks (Runner.Docker).
type DockerRemote func(host string) (hc *http.Client, base string, ok bool)

// unixTransports: ein Transport je Socket (sonst bliebe je Check-Lauf eine Keep-Alive-Verbindung offen, dockerd
// schliesst Leerlauf nicht).
var unixTransports sync.Map

func unixTransport(sock string) *http.Transport {
	if tr, ok := unixTransports.Load(sock); ok {
		return tr.(*http.Transport)
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}, MaxIdleConnsPerHost: 2, IdleConnTimeout: 90 * time.Second}
	got, _ := unixTransports.LoadOrStore(sock, tr)
	return got.(*http.Transport)
}

// dockerClient baut HTTP-Client und Basis-URL fuer einen Docker-Host.
func dockerClient(host string, timeout time.Duration) (*http.Client, string, error) {
	if host == "" {
		host = DefaultDockerHost()
	}
	switch {
	case strings.HasPrefix(host, "unix://"):
		return &http.Client{Transport: unixTransport(strings.TrimPrefix(host, "unix://")), Timeout: timeout}, "http://docker", nil
	case strings.HasPrefix(host, "tcp://"):
		return &http.Client{Timeout: timeout}, "http://" + strings.TrimPrefix(host, "tcp://"), nil
	case strings.HasPrefix(host, "http://"), strings.HasPrefix(host, "https://"):
		return &http.Client{Timeout: timeout}, strings.TrimRight(host, "/"), nil
	}
	return nil, "", fmt.Errorf("unknown docker host %q (use unix://, tcp:// or http(s)://)", host)
}

func dockerGet(ctx context.Context, remote DockerRemote, host, path string, timeout time.Duration, v any) (int, error) {
	cl, base, err := dockerClient(host, timeout)
	if remote != nil && host != "" {
		if hc, b, ok := remote(host); ok {
			c := *hc
			c.Timeout = timeout
			cl, base, err = &c, b, nil
		}
	}
	if err != nil && strings.HasPrefix(host, "ssh://") {
		err = errors.New("ssh docker host is not set up under Healthchecks → Docker (or switched off)")
	}
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &e)
		return resp.StatusCode, errors.New(strings.TrimSpace(e.Message))
	}
	return resp.StatusCode, json.Unmarshal(b, v)
}

// dockerHint erklaert typische Zugriffsfehler auf den Socket.
func dockerHint(host string, err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "permission denied"):
		return msg + " – the node user may not read the socket: add --group-add $(stat -c %g /var/run/docker.sock) (compose: group_add)"
	case strings.Contains(msg, "no such file") || strings.Contains(msg, "connect: connection refused"):
		return msg + " – mount the socket: -v /var/run/docker.sock:/var/run/docker.sock:ro (or set NODE64_DOCKER_HOST)"
	}
	return msg
}

type dockerInspect struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Created string `json:"Created"`
	Config  struct {
		Image string `json:"Image"`
	} `json:"Config"`
	RestartCount int `json:"RestartCount"`
	State        struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		Paused     bool   `json:"Paused"`
		Restarting bool   `json:"Restarting"`
		OOMKilled  bool   `json:"OOMKilled"`
		ExitCode   int    `json:"ExitCode"`
		Error      string `json:"Error"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
		Health     *struct {
			Status        string `json:"Status"`
			FailingStreak int    `json:"FailingStreak"`
			Log           []struct {
				Output string `json:"Output"`
			} `json:"Log"`
		} `json:"Health"`
	} `json:"State"`
	NetworkSettings struct {
		IPAddress         string `json:"IPAddress"`
		GlobalIPv6Address string `json:"GlobalIPv6Address"`
		Networks          map[string]struct {
			IPAddress         string `json:"IPAddress"`
			GlobalIPv6Address string `json:"GlobalIPv6Address"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// containerIP waehlt die Adresse fuer den Ping der Latenz: IPv4 vor IPv6, Standardnetz vor den Netzen nach Namen
// (nil = keine, z. B. Netzmodus host).
func (in *dockerInspect) containerIP() net.IP {
	ns := &in.NetworkSettings
	names := make([]string, 0, len(ns.Networks))
	for n := range ns.Networks {
		names = append(names, n)
	}
	sort.Strings(names)
	v4, v6 := []string{ns.IPAddress}, []string{ns.GlobalIPv6Address}
	for _, n := range names {
		v4, v6 = append(v4, ns.Networks[n].IPAddress), append(v6, ns.Networks[n].GlobalIPv6Address)
	}
	for _, s := range append(v4, v6...) {
		if ip := net.ParseIP(s); ip != nil && !ip.IsUnspecified() {
			return ip
		}
	}
	return nil
}

type dockerChecker struct{ r *Runner }

func (dockerChecker) Type() Type { return TypeDocker }

func (c dockerChecker) Check(ctx context.Context, def Definition, _ net.IP) Result {
	var p DockerParams
	_ = decode(def.Params, &p)
	name := strings.TrimPrefix(strings.TrimSpace(def.Target), "/")
	start := time.Now()
	var in dockerInspect
	var remote DockerRemote
	if c.r != nil {
		remote = c.r.Docker
	}
	code, err := dockerGet(ctx, remote, p.Host, "/containers/"+url.PathEscape(name)+"/json", def.Timeouts.Total, &in)
	lat := time.Since(start)
	res := Result{Latency: lat, Details: map[string]any{"container": name}}
	if err != nil {
		res.Status = Down
		if code == http.StatusNotFound {
			res.Reason, res.Message = ReasonContainerMissing, "container "+name+" not found"
			return res
		}
		if errors.Is(err, context.DeadlineExceeded) {
			res.Reason, res.Message = ReasonTimeout, "docker api did not answer in time"
			return res
		}
		res.Reason, res.Message = ReasonDockerUnavailable, dockerHint(p.Host, err)
		return res
	}
	st := in.State
	res.Details["image"] = in.Config.Image
	res.Details["status"] = st.Status
	res.Details["restart_count"] = in.RestartCount
	res.Details["started_at"] = st.StartedAt
	res.Details["id"] = shortID(in.ID)
	health := ""
	if st.Health != nil {
		health = st.Health.Status
		res.Details["health"] = health
		res.Details["failing_streak"] = st.Health.FailingStreak
	}
	uptime := ""
	if t, err := time.Parse(time.RFC3339Nano, st.StartedAt); err == nil && st.Running {
		uptime = ", up " + time.Since(t).Round(time.Second).String()
	}
	switch {
	case st.Restarting:
		res.Status, res.Reason, res.Message = Down, ReasonContainerRestarting, fmt.Sprintf("restarting (restart count %d)", in.RestartCount)
	case st.Paused:
		res.Status, res.Reason, res.Message = Down, ReasonContainerPaused, "paused"
	case !st.Running:
		msg := fmt.Sprintf("%s (exit code %d)", st.Status, st.ExitCode)
		if st.OOMKilled {
			msg += ", killed: out of memory"
		}
		if st.Error != "" {
			msg += ", " + st.Error
		}
		res.Status, res.Reason, res.Message = Down, ReasonContainerStopped, msg
	case health == "unhealthy":
		out := ""
		if n := len(st.Health.Log); n > 0 {
			out = strings.TrimSpace(st.Health.Log[n-1].Output)
			if len(out) > 200 {
				out = out[:200]
			}
		}
		res.Status, res.Reason, res.Message = Down, ReasonContainerUnhealthy, "unhealthy"+ifNotEmpty(": ", out)
	case health == "healthy":
		res.Status, res.Reason, res.Message = Up, ReasonOK, "running, healthy"+uptime
	case health == "starting":
		res.Status, res.Reason, res.Message = Up, ReasonOK, "running, health: starting"+uptime
	default:
		res.Status, res.Reason, res.Message = Up, ReasonOK, "running (no healthcheck)"+uptime
	}
	// Latenz nur zur Anzeige: Ping zum laufenden Container, sonst die Antwortzeit der Docker-API
	res.Details["latency_source"] = "api"
	if ip := in.containerIP(); ip != nil && st.Running && !st.Paused {
		res.Details["ip"] = ip.String()
		if d, ok := c.r.pingLatency(ctx, ip); ok {
			res.Latency, res.Details["latency_source"] = d, "ping"
		}
	}
	return res
}

func ifNotEmpty(sep, s string) string {
	if s == "" {
		return ""
	}
	return sep + s
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// Container ist ein Eintrag der Containerliste (fuer die Oberflaeche).
type Container struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Image   string   `json:"image"`
	State   string   `json:"state"`  // running, exited, ...
	Status  string   `json:"status"` // "Up 3 hours (healthy)"
	Created int64    `json:"created"`
	Ports   []string `json:"ports,omitempty"` // veroeffentlichte Ports, z. B. "8080->80/tcp"
}

// ListContainers liefert alle Container des Docker-Hosts (auch gestoppte).
func ListContainers(ctx context.Context, host string) ([]Container, error) {
	return ListContainersVia(ctx, nil, host)
}

// ListContainersVia wie ListContainers, fuer Hosts mit Zugangsdaten ueber die Verbindung der Docker-Ueberwachung.
func ListContainersVia(ctx context.Context, remote DockerRemote, host string) ([]Container, error) {
	var raw []struct {
		ID      string   `json:"Id"`
		Names   []string `json:"Names"`
		Image   string   `json:"Image"`
		State   string   `json:"State"`
		Status  string   `json:"Status"`
		Created int64    `json:"Created"`
		Ports   []struct {
			PrivatePort int    `json:"PrivatePort"`
			PublicPort  int    `json:"PublicPort"`
			Type        string `json:"Type"`
		} `json:"Ports"`
	}
	if _, err := dockerGet(ctx, remote, host, "/containers/json?all=1", 5*time.Second, &raw); err != nil {
		return nil, errors.New(dockerHint(host, err))
	}
	out := make([]Container, 0, len(raw))
	for _, c := range raw {
		name := shortID(c.ID)
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		ct := Container{ID: shortID(c.ID), Name: name, Image: c.Image, State: c.State, Status: c.Status, Created: c.Created}
		seen := map[string]bool{} // IPv4 und IPv6 liefern denselben Port doppelt
		for _, p := range c.Ports {
			s := fmt.Sprintf("%d/%s", p.PrivatePort, p.Type)
			if p.PublicPort > 0 {
				s = fmt.Sprintf("%d->%s", p.PublicPort, s)
			}
			if !seen[s] {
				seen[s] = true
				ct.Ports = append(ct.Ports, s)
			}
		}
		sort.Strings(ct.Ports)
		out = append(out, ct)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
