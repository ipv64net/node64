package dns64

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/dns64/localnet"
	"github.com/ipv64net/node64/internal/proxmox"
)

// DNS-Eintraege aus Docker-Labels (GitHub #18): Container mit dem Label node64.dns.name bekommen eigene Eintraege
// (A/AAAA) in DNS64 - nur auf dieser Node (local_only), ohne PTR (meist teilen sie die Adresse der Node), Kommentar
// "Docker: <Container>", Herkunft (Spalte origin) "docker". Nur mit Schalter dns64.docker = 1 (je Node). Die
// Docker-API (nur GET) wird jede Minute gelesen. Fehlt ein Container (bzw. sein Label) in einer erfolgreich gelesenen
// Liste dockerDNSRemoveWait lang, verschwinden seine Eintraege; aendert sich nur die Adresse, sofort. Fehler beim Lesen
// loeschen nie etwas, Schalter aus: die Eintraege bleiben. Eigen sind nur Eintraege mit Herkunft docker, die noch nur
// auf dieser Node gelten (Kommentar egal); Namen mit anderen Eintraegen fasst der Abgleich nicht an.

const (
	setDocker   = "dns64.docker"    // 1 = Docker-Labels node64.dns.* auswerten (je Node)
	setDockerIP = "dns64.docker_ip" // Adressen fuer Labels ohne node64.dns.ip (je Node, Komma; leer = LAN-Adresse der Node)

	dockerLabelName = "node64.dns.name" // Namen, Komma
	dockerLabelIP   = "node64.dns.ip"   // Adressen (Komma) oder "container" = Adressen des Containers (Macvlan/IPvlan)
	dockerComment   = "Docker: "        // Kommentar der Eintraege aus dem Abgleich (nur zur Anzeige)
	dockerOrigin    = "docker"          // Herkunft (dns64_records.origin) der Eintraege aus dem Abgleich
)

// Zeiten (Variablen, damit Tests sie verkuerzen koennen).
var (
	dockerDNSEvery      = time.Minute
	dockerDNSRemoveWait = 2 * time.Minute
	dockerDNSTimeout    = 10 * time.Second
	dockerDNSHost       = proxmox.DefaultDockerHost // Tests ersetzen den Docker-Host
)

// Fehler eines Containers (Schluessel unter dns64.docker.err_).
const (
	dockerErrNoIP   = "no_ip"    // keine Adresse (Label node64.dns.ip setzen oder Adresse in den Einstellungen)
	dockerErrBadIP  = "bad_ip"   // Label node64.dns.ip ungueltig
	dockerErrBadNm  = "bad_name" // Name ungueltig
	dockerErrTaken  = "taken"    // Name hat schon einen anderen eigenen Eintrag bzw. gehoert einem anderen Container
	dockerErrFailed = "failed"   // Eintrag liess sich nicht anlegen
)

// DockerDNSEntry ist ein Container mit node64.dns.*-Labels (Seite und API).
type DockerDNSEntry struct {
	Container   string   `json:"container"`
	State       string   `json:"state"` // wie Docker (running, exited ...)
	Names       []string `json:"names"`
	Addrs       []string `json:"addrs"`
	Problem     string   `json:"problem,omitempty"` // dockerErr* ("" = ok)
	ProblemName string   `json:"problem_name,omitempty"`
}

// DockerDNSView ist der Stand des Abgleichs.
type DockerDNSView struct {
	Enabled    bool             `json:"enabled"`
	Connected  bool             `json:"connected"`
	Host       string           `json:"host"`
	Error      string           `json:"error,omitempty"`
	Synced     time.Time        `json:"synced"` // letzter erfolgreicher Abgleich (Null = noch keiner)
	Containers []DockerDNSEntry `json:"containers"`
}

type dockerDNS struct {
	run  sync.Mutex           // ein Abgleich gleichzeitig
	gone map[string]time.Time // Eintrag (Name Typ Wert) -> Container fehlt seit (unter run)

	mu   sync.Mutex
	view DockerDNSView
}

func (m *Module) dockerOn(ctx context.Context) bool {
	return m.core.SettingOr(ctx, setDocker, "") == "1"
}

// DockerDNS liefert den Stand fuer Seite und API.
func (m *Module) DockerDNS(ctx context.Context) DockerDNSView {
	m.dkd.mu.Lock()
	v := m.dkd.view
	v.Containers = slices.Clone(v.Containers)
	m.dkd.mu.Unlock()
	v.Enabled = m.dockerOn(ctx)
	if !v.Enabled {
		v.Connected, v.Error = false, ""
	}
	if v.Host == "" {
		v.Host = dockerDNSHost()
	}
	if v.Containers == nil {
		v.Containers = []DockerDNSEntry{}
	}
	return v
}

// runDocker gleicht ab, solange der DNS-Dienst laeuft.
func (m *Module) runDocker(ctx context.Context) {
	for {
		m.dockerSync(ctx)
		t := time.NewTimer(dockerDNSEvery)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// dockerC ist der benutzte Teil eines Eintrags aus /containers/json.
type dockerC struct {
	Names      []string          `json:"Names"`
	State      string            `json:"State"`
	Labels     map[string]string `json:"Labels"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress         string `json:"IPAddress"`
			GlobalIPv6Address string `json:"GlobalIPv6Address"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

func (c dockerC) name() string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	return ""
}

// dockerList liest alle Container mit dem Label node64.dns.name (auch gestoppte: ihre Namen bleiben, bis der
// Container entfernt ist). Container ohne das Label wertet der Abgleich ohnehin nicht aus; fehlen sie in der Liste,
// gelten sie wie bisher als verschwunden.
func dockerList(ctx context.Context, host string) ([]dockerC, error) {
	hc, base, err := proxmox.DockerClient(host)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, dockerDNSTimeout)
	defer cancel()
	q := url.Values{"all": {"1"}, "filters": {`{"label":["` + dockerLabelName + `"]}`}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/containers/json?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("docker api: %s %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var list []dockerC
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&list); err != nil {
		return nil, err
	}
	return list, nil
}

// dockerWant ist ein gewuenschter Eintrag.
type dockerWant struct {
	name, typ, value, container string
}

func (w dockerWant) key() string { return w.name + " " + w.typ + " " + w.value }

// dockerSplit: Komma- bzw. Leerzeichen-Liste ohne leere Teile.
func dockerSplit(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\t' })
}

// parseAddrs: Adressen (IPv4/IPv6, ohne Zone); ok = alle gueltig.
func parseAddrs(list []string) ([]netip.Addr, bool) {
	var out []netip.Addr
	for _, s := range list {
		a, err := netip.ParseAddr(strings.Trim(s, "[]"))
		if err != nil || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() {
			return nil, false
		}
		out = append(out, a)
	}
	return out, true
}

// containerAddrs: Adressen des Containers in seinen Netzen (Macvlan/IPvlan mit eigener LAN-Adresse).
func containerAddrs(c dockerC) []netip.Addr {
	var out []netip.Addr
	keys := make([]string, 0, len(c.NetworkSettings.Networks))
	for k := range c.NetworkSettings.Networks {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		n := c.NetworkSettings.Networks[k]
		for _, s := range []string{n.IPAddress, n.GlobalIPv6Address} {
			if a, err := netip.ParseAddr(s); err == nil && !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	return out
}

// lanAddrs: Adressen der Node im LAN (je eine IPv4 und IPv6; im Docker-Bridge-Netz keine - die kennt nur der Host).
func lanAddrs() []netip.Addr {
	if localnet.Bridge() {
		return nil
	}
	var v4, v6 netip.Addr
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || virtualIface(ifc.Name) {
			continue
		}
		list, _ := ifc.Addrs()
		for _, x := range list {
			n, ok := x.(*net.IPNet)
			if !ok {
				continue
			}
			a, ok := netip.AddrFromSlice(n.IP)
			if !ok {
				continue
			}
			a = a.Unmap()
			switch {
			case !v4.IsValid() && a.Is4() && a.IsPrivate():
				v4 = a
			case !v6.IsValid() && a.Is6() && a.IsGlobalUnicast():
				v6 = a
			}
		}
	}
	var out []netip.Addr
	for _, a := range []netip.Addr{v4, v6} {
		if a.IsValid() {
			out = append(out, a)
		}
	}
	return out
}

// virtualIface: Schnittstellen von Docker/Podman, internen Bruecken, VMs und Tunneln (deren Adressen erreicht im
// Heimnetz niemand). vmbr* nicht: auf einem Proxmox-Host liegt die LAN-Adresse auf der Bruecke vmbr0 (wie cdn64).
func virtualIface(name string) bool {
	for _, p := range []string{"docker", "br-", "veth", "virbr", "podman", "lxc", "cni", "flannel", "cali", "tun", "tap", "wg", "zt"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// dockerWants: gewuenschte Eintraege je Container (erster Container gewinnt einen Namen) und die Ansicht.
func dockerWants(list []dockerC, defaults []netip.Addr) ([]dockerWant, []DockerDNSEntry) {
	var wants []dockerWant
	var view []DockerDNSEntry
	owner := map[string]string{} // Name -> Container
	slices.SortFunc(list, func(a, b dockerC) int { return strings.Compare(a.name(), b.name()) })
	for _, c := range list {
		raw, ok := c.Labels[dockerLabelName]
		if !ok {
			continue
		}
		e := DockerDNSEntry{Container: c.name(), State: c.State, Names: []string{}, Addrs: []string{}}
		var addrs []netip.Addr
		switch ip := strings.TrimSpace(c.Labels[dockerLabelIP]); {
		case strings.EqualFold(ip, "container"):
			addrs = containerAddrs(c)
		case ip != "":
			var ok bool
			if addrs, ok = parseAddrs(dockerSplit(ip)); !ok {
				e.Problem = dockerErrBadIP
			}
		default:
			addrs = defaults
		}
		for _, a := range addrs {
			e.Addrs = append(e.Addrs, a.String())
		}
		if e.Problem == "" && len(addrs) == 0 {
			e.Problem = dockerErrNoIP
		}
		for _, n := range dockerSplit(raw) {
			n = hostName(n)
			if !validName(n) || strings.HasPrefix(n, "*") {
				e.Problem, e.ProblemName = dockerErrBadNm, n
				continue
			}
			if o, ok := owner[n]; ok && o != e.Container {
				e.Problem, e.ProblemName = dockerErrTaken, n
				continue
			}
			owner[n] = e.Container
			e.Names = append(e.Names, n)
			if e.Problem == dockerErrBadIP || e.Problem == dockerErrNoIP {
				continue
			}
			for _, a := range addrs {
				typ := "A"
				if a.Is6() {
					typ = "AAAA"
				}
				wants = append(wants, dockerWant{name: n, typ: typ, value: a.String(), container: e.Container})
			}
		}
		view = append(view, e)
	}
	return wants, view
}

// dockerSync: ein Abgleich (Schalter aus: nur den Stand leeren).
func (m *Module) dockerSync(ctx context.Context) {
	m.dkd.run.Lock()
	defer m.dkd.run.Unlock()
	if !m.dockerOn(ctx) {
		m.dkd.gone = nil
		m.dkd.mu.Lock()
		m.dkd.view = DockerDNSView{}
		m.dkd.mu.Unlock()
		return
	}
	host := dockerDNSHost()
	list, err := dockerList(ctx, host)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		msg := proxmox.DockerHint(host, err)
		m.dkd.mu.Lock()
		was := m.dkd.view.Error
		m.dkd.view.Connected, m.dkd.view.Error, m.dkd.view.Host = false, msg, host
		m.dkd.mu.Unlock()
		if was == "" {
			m.log.Warn("dns64 docker: api failed", "host", host, "err", msg)
		}
		return
	}
	defaults, _ := parseAddrs(dockerSplit(m.core.SettingOr(ctx, setDockerIP, "")))
	if len(defaults) == 0 {
		defaults = lanAddrs()
	}
	wants, view := dockerWants(list, defaults)
	if err := m.dockerApply(ctx, wants, view); err != nil {
		m.log.Warn("dns64 docker: sync failed", "err", err)
	}
	m.dkd.mu.Lock()
	m.dkd.view = DockerDNSView{Connected: true, Host: host, Synced: time.Now(), Containers: view}
	m.dkd.mu.Unlock()
}

// dockerApply legt fehlende Eintraege an, passt geaenderte Adressen an und entfernt Eintraege verschwundener Container
// nach dockerDNSRemoveWait. Probleme stehen danach in view. Alle Aenderungen gehen in einer Transaktion in die
// Datenbank; die Momentaufnahme entsteht danach einmal neu (statt je Eintrag).
func (m *Module) dockerApply(ctx context.Context, wants []dockerWant, view []DockerDNSEntry) error {
	type rec struct {
		id               int64
		name, typ, value string
		noPTR, localOnly bool
		origin           string
	}
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT id, name, type, value, no_ptr, local_only, origin FROM dns64_records`)
	if err != nil {
		return err
	}
	mine := map[string]rec{}    // Name Typ Wert -> Eintrag aus dem Abgleich
	others := map[string]bool{} // Namen mit anderen eigenen Eintraegen
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.id, &r.name, &r.typ, &r.value, &r.noPTR, &r.localOnly, &r.origin); err != nil {
			rows.Close()
			return err
		}
		// eigen nur mit Herkunft docker und nur auf dieser Node: von Hand angelegte Eintraege mit gleichem Kommentar
		// und solche, die der Nutzer in den Cluster gegeben hat, bleiben unberuehrt
		if r.origin == dockerOrigin && r.localOnly {
			mine[r.name+" "+r.typ+" "+r.value] = r
		} else {
			others[r.name] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	problem := func(container, code, name string) {
		for i := range view {
			if view[i].Container == container && view[i].Problem == "" {
				view[i].Problem, view[i].ProblemName = code, name
			}
		}
	}
	want := map[string]bool{}
	wantName := map[string]bool{} // Namen, die ein Container noch will (Adresse geaendert: alten Eintrag sofort weg)
	var errs []error
	type add struct {
		r         Record
		container string
	}
	var adds []add
	var noPTR, dels []rec
	for _, w := range wants {
		if others[w.name] {
			problem(w.container, dockerErrTaken, w.name)
			continue
		}
		want[w.key()], wantName[w.name] = true, true
		if r, ok := mine[w.key()]; ok {
			if !r.noPTR { // angleichen: kein PTR aus Docker-Eintraegen
				noPTR = append(noPTR, r)
			}
			continue
		}
		r := Record{Name: w.name, Type: w.typ, Value: w.value, Comment: dockerComment + w.container, NoPTR: true, LocalOnly: true}
		if err := m.checkRecord(ctx, &r, 0); err != nil {
			problem(w.container, dockerErrFailed, w.name)
			errs = append(errs, fmt.Errorf("%s %s: %w", w.name, w.typ, err))
			continue
		}
		adds = append(adds, add{r, w.container})
	}
	now := time.Now()
	if m.dkd.gone == nil {
		m.dkd.gone = map[string]time.Time{}
	}
	for k, r := range mine {
		if want[k] {
			delete(m.dkd.gone, k)
			continue
		}
		if !wantName[r.name] { // Container (bzw. Name) weg: erst nach der Wartezeit
			since, ok := m.dkd.gone[k]
			if !ok {
				m.dkd.gone[k] = now
				continue
			}
			if now.Sub(since) < dockerDNSRemoveWait {
				continue
			}
		}
		delete(m.dkd.gone, k)
		dels = append(dels, r)
	}
	for k := range m.dkd.gone {
		if _, ok := mine[k]; !ok {
			delete(m.dkd.gone, k)
		}
	}
	if len(adds)+len(noPTR)+len(dels) == 0 {
		return errors.Join(errs...)
	}

	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	defer tx.Rollback()
	created := time.Now().UTC().Format(time.RFC3339)
	var added []add
	for _, a := range adds {
		r := a.r
		if _, err := tx.ExecContext(ctx, `INSERT INTO dns64_records (name, type, value, ttl, comment, no_ptr, local_only, origin, enabled, created_at) VALUES (?,?,?,?,?,1,1,?,1,?)`,
			r.Name, r.Type, r.Value, r.TTL, r.Comment, dockerOrigin, created); err != nil {
			problem(a.container, dockerErrFailed, r.Name)
			errs = append(errs, fmt.Errorf("%s %s: %w", r.Name, r.Type, err))
			continue
		}
		added = append(added, a)
	}
	// nur Eintraege, die (noch) dem Abgleich gehoeren: inzwischen von Hand geaenderte bleiben
	for _, r := range noPTR {
		if _, err := tx.ExecContext(ctx, `UPDATE dns64_records SET no_ptr = 1 WHERE id = ? AND origin = ? AND local_only = 1`, r.id, dockerOrigin); err != nil {
			errs = append(errs, err)
		}
	}
	var removed []rec
	for _, r := range dels {
		res, err := tx.ExecContext(ctx, `DELETE FROM dns64_records WHERE id = ? AND origin = ? AND local_only = 1`, r.id, dockerOrigin)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			removed = append(removed, r)
		}
	}
	if err := tx.Commit(); err != nil {
		for _, a := range added {
			problem(a.container, dockerErrFailed, a.r.Name)
		}
		return errors.Join(append(errs, err)...)
	}
	for _, a := range added {
		m.log.Info("dns64 docker: record added", "name", a.r.Name, "type", a.r.Type, "value", a.r.Value, "container", a.container)
	}
	for _, r := range removed {
		m.log.Info("dns64 docker: record removed", "name", r.name, "type", r.typ, "value", r.value)
	}
	if err := m.loadRecords(ctx); err != nil { // einmal fuer den ganzen Abgleich
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// validDockerIP: Einstellung "Adressen fuer Docker-Eintraege" (leer oder Adressen, Komma).
func validDockerIP(s string) bool {
	if strings.TrimSpace(s) == "" {
		return true
	}
	_, ok := parseAddrs(dockerSplit(s))
	return ok
}

// apiDocker: GET /api/dns64/docker - Stand des Abgleichs.
func (m *Module) apiDocker(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.DockerDNS(r.Context()))
}
