package apis

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Proxmox VE (Token mit Rolle PVEAuditor). Ein Host in Monitor64 ist eine Node; die Gaeste dieser Node sind Dienste.
// Je Runde:
//
//	/cluster/status                       Node erkennen (local), Quorum, Nodes online
//	/nodes/{node}/status                  CPU, Load, RAM, Swap, Root-Dateisystem
//	/nodes/{node}/storage                 Speicher (store:<storage>)
//	/nodes/{node}/disks/zfs               ZFS-Pools (zfs:<pool>)
//	/nodes/{node}/qemu, /lxc              Gaeste (vm:<vmid>, ct:<vmid>); Raten aus den Zaehlern zweier Runden
//	/nodes/{node}/{qemu|lxc}/{vmid}/config onboot (Soll-Zustand), je Gast alle 10 min
//	/cluster/ha/status/current            HA (nur mit HA-Ressourcen)
//	/cluster/ceph/status                  Ceph (falls eingerichtet, sonst stuendlich neu versucht)
//
// Seltener: /nodes/{node}/disks/list + /disks/smart?disk= (SMART, 30 min), /nodes/{node}/apt/update (60 min).

// PVEConfig sind die Verbindungsdaten eines Proxmox-VE-Hosts.
type PVEConfig struct {
	Addresses    []string      // https://host:8006 (die Node selbst; weitere Adressen fuer Failover optional)
	TokenID      string        // user@realm!tokenid
	Secret       string        // Token-Secret (nie ausgeben)
	Pin          string        // SHA-256 des Zertifikats (hex); leer = System-CA
	Node         string        // Node-Name; leer = die Node hinter der Adresse (cluster/status, local)
	Timeout      time.Duration // ganze Runde (0 = DefaultTimeout)
	SmartEvery   time.Duration // 0 = DefaultSmartEvery
	UpdatesEvery time.Duration // 0 = DefaultUpdatesEvery
}

func (c PVEConfig) system() proxmox.System {
	return proxmox.System{Kind: proxmox.KindPVE, Addresses: c.Addresses, TokenID: c.TokenID, Secret: c.Secret, PinSHA256: c.Pin}
}

// ClusterNode ist eine Node aus /cluster/status (Vorschlag "als eigene Hosts anlegen").
type ClusterNode struct {
	Name   string `json:"name"`
	IP     string `json:"ip,omitempty"`
	ID     int    `json:"id,omitempty"`
	Online bool   `json:"online"`
	Local  bool   `json:"local,omitempty"` // die Node hinter der abgefragten Adresse
}

// PVE ist der Sammler eines Proxmox-VE-Hosts (eine Node).
type PVE struct {
	cfg    PVEConfig
	client *proxmox.Client
	now    func() time.Time

	mu        sync.Mutex
	node      string              // erkannte Node (cfg.Node leer)
	counters  map[string]*counter // Gast-Schluessel -> Zaehler der vorigen Runde
	configs   map[string]guestCfg // Gast-Schluessel -> onboot
	disks     slowDisks
	updates   slowUpdates
	cephUntil time.Time // kein Ceph: bis dahin nicht neu fragen
}

type guestCfg struct {
	at     time.Time
	onboot bool
}

// NewPVE baut den Sammler (prueft Adressen, Token-Format und Pin; fragt noch nichts ab).
func NewPVE(cfg PVEConfig) (*PVE, error) {
	c, err := proxmox.NewClient(cfg.system())
	if err != nil {
		return nil, scrubErr(err, cfg.Secret)
	}
	return &PVE{cfg: cfg, client: c, now: time.Now, counters: map[string]*counter{}, configs: map[string]guestCfg{}}, nil
}

// pveStatus ist ein Eintrag aus /cluster/status.
type pveStatus struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	NodeID  num    `json:"nodeid"`
	Online  num    `json:"online"`
	Quorate num    `json:"quorate"`
	Local   num    `json:"local"`
}

func parseNodes(st []pveStatus) (cluster string, nodes []ClusterNode) {
	for _, e := range st {
		switch e.Type {
		case "cluster":
			cluster = e.Name
		case "node":
			nodes = append(nodes, ClusterNode{Name: e.Name, IP: e.IP, ID: int(e.NodeID), Online: e.Online != 0, Local: e.Local != 0})
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	return cluster, nodes
}

// Nodes liefert Clustername (leer = Einzel-Node) und alle Nodes mit IP aus /cluster/status (Cluster-Erkennung).
func (p *PVE) Nodes(ctx context.Context) (string, []ClusterNode, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	var st []pveStatus
	if err := p.client.Get(ctx, "/cluster/status", &st); err != nil {
		return "", nil, scrubErr(err, p.cfg.Secret)
	}
	cl, nodes := parseNodes(st)
	return cl, nodes, nil
}

func (p *PVE) timeout() time.Duration {
	if p.cfg.Timeout > 0 {
		return p.cfg.Timeout
	}
	return DefaultTimeout
}

// Test prueft die Verbindung im Assistenten: Zertifikat (Fingerabdruck, ohne Pin und Vertrauen wird das Token nicht
// gesendet), Token, Rechte, Node und Cluster-Nodes.
func (p *PVE) Test(ctx context.Context) TestResult {
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	pr := proxmox.Probe(ctx, p.cfg.system())
	res := TestResult{OK: pr.OK, Error: scrub(pr.Error, p.cfg.Secret), Version: pr.Version, Cluster: pr.Cluster,
		Warning: scrub(pr.PermWarning, p.cfg.Secret), Fingerprint: pr.CertSHA256, CertSubject: pr.CertSubject,
		Trusted: pr.CertTrusted, NeedConfirm: pr.NeedConfirm}
	if !pr.OK {
		return res
	}
	res.Summary = fmt.Sprintf("%d Gäste im Cluster", pr.Guests)
	cl, nodes, err := p.Nodes(ctx)
	if err != nil {
		res.Warning = strings.TrimSpace(res.Warning + " cluster/status: " + err.Error())
		res.Node = p.cfg.Node
		return res
	}
	res.Cluster, res.Nodes = cl, nodes
	res.Node = p.cfg.Node
	if res.Node == "" {
		res.Node = localNode(nodes)
	}
	found := false
	for _, n := range nodes {
		found = found || n.Name == res.Node
	}
	if !found && len(nodes) > 0 {
		res.OK = false
		res.Error = fmt.Sprintf("Node %q nicht gefunden (vorhanden: %s)", res.Node, nodeNames(nodes))
	}
	return res
}

func localNode(nodes []ClusterNode) string {
	for _, n := range nodes {
		if n.Local {
			return n.Name
		}
	}
	if len(nodes) == 1 {
		return nodes[0].Name
	}
	return ""
}

func nodeNames(nodes []ClusterNode) string {
	l := make([]string, 0, len(nodes))
	for _, n := range nodes {
		l = append(l, n.Name)
	}
	return strings.Join(l, ", ")
}

// Collect ist eine Abfragerunde (nicht gleichzeitig mit sich selbst aufrufen; Test darf parallel laufen).
func (p *PVE) Collect(ctx context.Context) ([]model.Service, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	now := p.now()
	part := &partial{secrets: []string{p.cfg.Secret}}

	var st []pveStatus
	stErr := p.client.Get(ctx, "/cluster/status", &st)
	node := p.cfg.Node
	if node == "" {
		if stErr == nil {
			_, nodes := parseNodes(st)
			if n := localNode(nodes); n != "" {
				p.node = n
			}
		}
		node = p.node
		if node == "" {
			if stErr != nil {
				return nil, scrubErr(stErr, p.cfg.Secret)
			}
			return nil, errors.New("Node nicht erkannt (cluster/status ohne lokale Node) – Node-Namen eintragen")
		}
	}
	nodePath := "/nodes/" + url.PathEscape(node)
	var ns nodeStatus
	if err := p.client.Get(ctx, nodePath+"/status", &ns); err != nil {
		return nil, scrubErr(err, p.cfg.Secret)
	}
	out := nodeServices(ns)
	if svc := p.updates.collect(ctx, p.client, node, now, p.cfg.UpdatesEvery, part); svc != nil {
		out = append(out, *svc)
	}
	if stErr != nil {
		part.add("cluster/status", stErr)
	} else if svc, ok := clusterService(st); ok {
		out = append(out, svc)
	}
	out = append(out, p.ha(ctx, part)...)
	out = append(out, p.ceph(ctx, now, part)...)
	out = append(out, p.storages(ctx, nodePath, part)...)
	out = append(out, p.zfs(ctx, nodePath, part)...)
	out = append(out, p.disks.collect(ctx, p.client, node, now, p.cfg.SmartEvery, func(d diskEntry) string {
		return firstNonEmpty(d.DevPath, "/dev/"+d.dev())
	}, part)...)
	out = append(out, p.guests(ctx, nodePath, now, part)...)
	sortServices(out)
	return out, part.result()
}

// clusterService: Quorum und Nodes online (nur im Cluster).
func clusterService(st []pveStatus) (model.Service, bool) {
	cl, nodes := parseNodes(st)
	quorate := false
	isCluster := false
	for _, e := range st {
		if e.Type == "cluster" {
			isCluster, quorate = true, e.Quorate != 0
		}
	}
	if !isCluster {
		return model.Service{}, false
	}
	up := 0
	var down []string
	for _, n := range nodes {
		if n.Online {
			up++
		} else {
			down = append(down, n.Name)
		}
	}
	q := 0.0
	if quorate {
		q = 1
	}
	s := model.Service{Key: "cluster", Name: "Cluster " + cl, Kind: "cluster", Default: true,
		Metrics: []model.Metric{{Name: "nodes_online", Value: float64(up)}, {Name: "nodes", Value: float64(len(nodes))}, {Name: "quorate", Value: q}}}
	s.Text = fmt.Sprintf("%d von %d Nodes online", up, len(nodes))
	if quorate {
		s.Text += " · Quorum ok"
	} else {
		s.Text += " · kein Quorum"
		s.Facts = append(s.Facts, model.Fact{Code: "cluster_no_quorum", Text: "Cluster ohne Quorum"})
	}
	if len(down) > 0 {
		s.Text += " · offline: " + strings.Join(down, ", ")
		s.Facts = append(s.Facts, model.Fact{Code: "cluster_node_down", Text: strings.Join(down, ", ") + " offline"})
	}
	return s, true
}

// haEntry ist ein Eintrag aus /cluster/ha/status/current.
type haEntry struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Node   string `json:"node"`
	Status string `json:"status"`
	State  string `json:"state"`
	SID    string `json:"sid"`
}

// haBad sind Zustaende einer HA-Ressource, die eine Stoerung bedeuten.
var haBad = map[string]bool{"error": true, "fence": true, "recovery": true}

func (p *PVE) ha(ctx context.Context, part *partial) []model.Service {
	var list []haEntry
	if err := p.client.Get(ctx, "/cluster/ha/status/current", &list); err != nil {
		if !absent(err) {
			part.add("cluster/ha/status/current", err)
		}
		return nil
	}
	var res, bad []string
	quorumOK := true
	for _, e := range list {
		switch e.Type {
		case "service":
			res = append(res, e.SID)
			if haBad[strings.ToLower(e.State)] {
				bad = append(bad, e.SID+" "+e.State)
			}
		case "quorum":
			quorumOK = strings.EqualFold(e.Status, "OK")
		}
	}
	if len(res) == 0 {
		return nil // HA nicht benutzt
	}
	s := model.Service{Key: "ha", Name: "HA", Kind: "ha", Default: true,
		Metrics: []model.Metric{{Name: "resources", Value: float64(len(res))}, {Name: "errors", Value: float64(len(bad))}}}
	s.Text = fmt.Sprintf("%d Ressourcen", len(res))
	if len(bad) > 0 {
		s.Text += " · gestört: " + strings.Join(limitList(bad, 5), ", ")
		s.Facts = append(s.Facts, model.Fact{Code: "ha_error", Text: strings.Join(limitList(bad, 5), ", ")})
	} else {
		s.Text += ", alle ok"
	}
	if !quorumOK {
		s.Text += " · HA ohne Quorum"
		s.Facts = append(s.Facts, model.Fact{Code: "ha_error", Text: "HA ohne Quorum"})
	}
	return []model.Service{s}
}

// cephStatus ist der benutzte Teil von /cluster/ceph/status (osdmap flach ab Ceph Quincy, frueher verschachtelt).
type cephStatus struct {
	Health struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Severity string `json:"severity"`
			Summary  struct {
				Message string `json:"message"`
			} `json:"summary"`
		} `json:"checks"`
	} `json:"health"`
	PGMap struct {
		Used  num `json:"bytes_used"`
		Total num `json:"bytes_total"`
		Avail num `json:"bytes_avail"`
	} `json:"pgmap"`
	OSDMap struct {
		Num    num `json:"num_osds"`
		Up     num `json:"num_up_osds"`
		In     num `json:"num_in_osds"`
		OSDMap *struct {
			Num num `json:"num_osds"`
			Up  num `json:"num_up_osds"`
			In  num `json:"num_in_osds"`
		} `json:"osdmap"`
	} `json:"osdmap"`
}

func (p *PVE) ceph(ctx context.Context, now time.Time, part *partial) []model.Service {
	if now.Before(p.cephUntil) {
		return nil
	}
	var cs cephStatus
	if err := p.client.Get(ctx, "/cluster/ceph/status", &cs); err != nil {
		var pe *proxmox.Error
		if errors.As(err, &pe) && pe.Status >= 400 && !authErr(err) {
			p.cephUntil = now.Add(optionalRetry) // kein Ceph eingerichtet
			return nil
		}
		part.add("cluster/ceph/status", err)
		return nil
	}
	if cs.Health.Status == "" {
		p.cephUntil = now.Add(optionalRetry)
		return nil
	}
	osds, up, in := cs.OSDMap.Num, cs.OSDMap.Up, cs.OSDMap.In
	if cs.OSDMap.OSDMap != nil {
		osds, up, in = cs.OSDMap.OSDMap.Num, cs.OSDMap.OSDMap.Up, cs.OSDMap.OSDMap.In
	}
	s := model.Service{Key: "ceph", Name: "Ceph", Kind: "ceph", Default: true,
		Metrics: []model.Metric{{Name: "osds_up", Value: float64(up)}, {Name: "osds_in", Value: float64(in)}, {Name: "osds", Value: float64(osds)}}}
	if tot := float64(cs.PGMap.Total); tot > 0 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "used", Value: pct(float64(cs.PGMap.Used), tot), Unit: "%", Rule: model.RuleStore, Max: tot},
			model.Metric{Name: "free", Value: float64(cs.PGMap.Avail), Unit: "B", Max: tot})
	}
	var msgs []string
	keys := make([]string, 0, len(cs.Health.Checks))
	for k := range cs.Health.Checks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		msgs = append(msgs, firstNonEmpty(cs.Health.Checks[k].Summary.Message, k))
	}
	s.Text = fmt.Sprintf("%s · %.0f von %.0f OSDs up", cs.Health.Status, float64(up), float64(osds))
	if len(msgs) > 0 {
		s.Text += " · " + strings.Join(limitList(msgs, 3), "; ")
	}
	switch cs.Health.Status {
	case "HEALTH_WARN":
		s.Facts = append(s.Facts, model.Fact{Code: "ceph_warn", Text: strings.Join(limitList(msgs, 3), "; ")})
	case "HEALTH_ERR":
		s.Facts = append(s.Facts, model.Fact{Code: "ceph_err", Text: strings.Join(limitList(msgs, 3), "; ")})
	}
	return []model.Service{s}
}

// pveStorage ist ein Eintrag aus /nodes/{node}/storage.
type pveStorage struct {
	Storage string `json:"storage"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Active  num    `json:"active"`
	Enabled num    `json:"enabled"`
	Shared  num    `json:"shared"`
	Total   num    `json:"total"`
	Used    num    `json:"used"`
	Avail   num    `json:"avail"`
}

func (p *PVE) storages(ctx context.Context, nodePath string, part *partial) []model.Service {
	var list []pveStorage
	if err := p.client.Get(ctx, nodePath+"/storage", &list); err != nil {
		part.add("storage", err)
		return nil
	}
	var out []model.Service
	for _, x := range list {
		if x.Storage == "" {
			continue
		}
		s := model.Service{Key: "store:" + x.Storage, Name: "Speicher " + x.Storage, Kind: "store", Default: x.Enabled != 0}
		typ := x.Type
		if x.Shared != 0 {
			typ += ", gemeinsam"
		}
		switch {
		case x.Enabled == 0:
			s.Text = "abgeschaltet (" + typ + ")"
		case x.Active == 0:
			s.Text = "nicht aktiv (" + typ + ")"
			s.Facts = append(s.Facts, model.Fact{Code: "store_inactive", Text: "Speicher " + x.Storage + " nicht aktiv"})
		case x.Total > 0:
			tot := float64(x.Total)
			s.Metrics = []model.Metric{{Name: "used", Value: pct(float64(x.Used), tot), Unit: "%", Rule: model.RuleStore, Max: tot},
				{Name: "free", Value: float64(x.Avail), Unit: "B", Max: tot}}
			s.Text = fmt.Sprintf("%s von %s frei (%s)", bytesText(float64(x.Avail)), bytesText(tot), typ)
		default:
			s.Text = typ
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// pveZFS ist ein Eintrag aus /nodes/{node}/disks/zfs.
type pveZFS struct {
	Name   string `json:"name"`
	Size   num    `json:"size"`
	Alloc  num    `json:"alloc"`
	Free   num    `json:"free"`
	Frag   num    `json:"frag"`
	Health string `json:"health"`
}

func (p *PVE) zfs(ctx context.Context, nodePath string, part *partial) []model.Service {
	var list []pveZFS
	if err := p.client.Get(ctx, nodePath+"/disks/zfs", &list); err != nil {
		if !absent(err) {
			part.add("disks/zfs", err)
		}
		return nil
	}
	var out []model.Service
	for _, z := range list {
		s := model.Service{Key: "zfs:" + z.Name, Name: "ZFS " + z.Name, Kind: "zfs", Default: true}
		if tot := float64(z.Size); tot > 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "used", Value: pct(float64(z.Alloc), tot), Unit: "%", Rule: model.RuleStore, Max: tot},
				model.Metric{Name: "free", Value: float64(z.Free), Unit: "B", Max: tot},
				model.Metric{Name: "frag", Value: float64(z.Frag), Unit: "%"})
		}
		s.Text = fmt.Sprintf("%s · %s frei", z.Health, bytesText(float64(z.Free)))
		if !strings.EqualFold(z.Health, "ONLINE") {
			s.Facts = append(s.Facts, model.Fact{Code: "zfs_degraded", Text: z.Health})
		}
		out = append(out, s)
	}
	return out
}

// pveGuest ist ein Eintrag aus /nodes/{node}/qemu bzw. /lxc (vmid bei LXC als String).
type pveGuest struct {
	VMID      num    `json:"vmid"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Lock      string `json:"lock"`
	Tags      string `json:"tags"`
	Template  num    `json:"template"`
	CPU       num    `json:"cpu"`
	CPUs      num    `json:"cpus"`
	Mem       num    `json:"mem"`
	MaxMem    num    `json:"maxmem"`
	Disk      num    `json:"disk"`
	MaxDisk   num    `json:"maxdisk"`
	Uptime    num    `json:"uptime"`
	NetIn     num    `json:"netin"`
	NetOut    num    `json:"netout"`
	DiskRead  num    `json:"diskread"`
	DiskWrite num    `json:"diskwrite"`
}

type guestItem struct {
	typ  string // qemu, lxc
	key  string // vm:101, ct:200
	vmid int
	g    pveGuest
}

func (p *PVE) guests(ctx context.Context, nodePath string, now time.Time, part *partial) []model.Service {
	var items []guestItem
	failed := map[string]bool{} // Praefix -> Liste fehlgeschlagen (Zaehler und Configs behalten)
	for _, typ := range []string{proxmox.TypeQEMU, proxmox.TypeLXC} {
		var list []pveGuest
		if err := p.client.Get(ctx, nodePath+"/"+typ, &list); err != nil {
			part.add(typ, err)
			failed[guestPrefix(typ)] = true
			continue
		}
		for _, g := range list {
			if g.Template != 0 || g.VMID <= 0 {
				continue
			}
			vmid := int(g.VMID)
			items = append(items, guestItem{typ: typ, key: guestPrefix(typ) + strconv.Itoa(vmid), vmid: vmid, g: g})
		}
	}
	// onboot je Gast (alle configEvery neu)
	var need []guestItem
	for _, it := range items {
		if c, ok := p.configs[it.key]; !ok || now.Sub(c.at) >= configEvery {
			need = append(need, it)
		}
	}
	var mu sync.Mutex
	var cfgErrs int
	var firstErr error
	got := map[string]guestCfg{}
	runParallel(ctx, need, func(ctx context.Context, it guestItem) {
		var cfg struct {
			OnBoot num `json:"onboot"`
		}
		err := p.client.Get(ctx, nodePath+"/"+it.typ+"/"+strconv.Itoa(it.vmid)+"/config", &cfg)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			cfgErrs++
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		got[it.key] = guestCfg{at: now, onboot: cfg.OnBoot != 0}
	})
	for k, v := range got {
		p.configs[k] = v
	}
	if cfgErrs > 0 {
		part.add(fmt.Sprintf("Gast-Config (%d)", cfgErrs), firstErr)
	}
	keep := map[string]bool{}
	var out []model.Service
	for _, it := range items {
		keep[it.key] = true
		cfg, known := p.configs[it.key]
		out = append(out, p.guestService(it, now, cfg, known))
	}
	drop := func(k string) bool {
		pre, _, _ := strings.Cut(k, ":")
		return !keep[k] && !failed[pre+":"]
	}
	for k := range p.counters {
		if drop(k) {
			delete(p.counters, k)
		}
	}
	for k := range p.configs {
		if drop(k) {
			delete(p.configs, k)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind == "vm"
		}
		return guestID(out[i].Key) < guestID(out[j].Key)
	})
	return out
}

func guestPrefix(typ string) string {
	if typ == proxmox.TypeLXC {
		return "ct:"
	}
	return "vm:"
}

func guestID(key string) int {
	_, id, _ := strings.Cut(key, ":")
	n, _ := strconv.Atoi(id)
	return n
}

// guestService: ein Gast als Dienst mit Zustand, CPU, RAM, Platte, Netz- und Disk-Raten und Soll-Zustand (onboot).
func (p *PVE) guestService(it guestItem, now time.Time, cfg guestCfg, cfgKnown bool) model.Service {
	g := it.g
	label, kind := "VM", "vm"
	if it.typ == proxmox.TypeLXC {
		label, kind = "CT", "ct"
	}
	name := fmt.Sprintf("%s %d", label, it.vmid)
	if g.Name != "" {
		name = fmt.Sprintf("%s (%s %d)", g.Name, label, it.vmid)
	}
	s := model.Service{Key: it.key, Name: name, Kind: kind, Default: true}
	for _, t := range strings.FieldsFunc(g.Tags, func(r rune) bool { return r == ';' || r == ',' || r == ' ' }) {
		if strings.EqualFold(t, proxmox.TagNoMonitor) {
			s.Default = false
		}
	}
	running := g.Status == "running"
	run := 0.0
	if running {
		run = 1
	}
	s.Metrics = append(s.Metrics, model.Metric{Name: "running", Value: run})
	var parts []string
	switch g.Status {
	case "running":
		parts = append(parts, "läuft")
	case "stopped":
		parts = append(parts, "gestoppt")
	default:
		parts = append(parts, firstNonEmpty(g.Status, "unbekannt"))
	}
	if g.Lock != "" {
		parts = append(parts, "Sperre "+g.Lock)
	}
	if running {
		s.Metrics = append(s.Metrics, model.Metric{Name: "cpu", Value: round2(float64(g.CPU) * 100), Unit: "%", Rule: model.RuleCPU})
		parts = append(parts, fmt.Sprintf("CPU %.0f %%", float64(g.CPU)*100))
		if mx := float64(g.MaxMem); mx > 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "mem", Value: pct(float64(g.Mem), mx), Unit: "%", Rule: model.RuleMem, Max: mx},
				model.Metric{Name: "mem_used", Value: float64(g.Mem), Unit: "B", Max: mx})
			parts = append(parts, fmt.Sprintf("RAM %s von %s", bytesText(float64(g.Mem)), bytesText(mx)))
		}
		if mx := float64(g.MaxDisk); mx > 0 && g.Disk > 0 { // QEMU ohne Gast-Agent: 0
			s.Metrics = append(s.Metrics, model.Metric{Name: "disk", Value: pct(float64(g.Disk), mx), Unit: "%", Rule: model.RuleFS, Max: mx})
			parts = append(parts, fmt.Sprintf("Platte %.0f %%", pct(float64(g.Disk), mx)))
		}
		prev := p.counters[it.key]
		cur := &counter{t: now, v: map[string]float64{"netin": float64(g.NetIn), "netout": float64(g.NetOut),
			"diskread": float64(g.DiskRead), "diskwrite": float64(g.DiskWrite), "uptime": float64(g.Uptime)}}
		if prev != nil && float64(g.Uptime) < prev.v["uptime"] {
			prev = nil // neu gestartet: Zaehler von vorn
		}
		in, ok1 := rate(prev, now, "netin", float64(g.NetIn))
		outb, ok2 := rate(prev, now, "netout", float64(g.NetOut))
		if ok1 && ok2 {
			in, outb = in*8/1e6, outb*8/1e6
			s.Metrics = append(s.Metrics, model.Metric{Name: "net_in", Value: round2(in), Unit: "Mbit/s"}, model.Metric{Name: "net_out", Value: round2(outb), Unit: "Mbit/s"})
			parts = append(parts, fmt.Sprintf("↓ %s · ↑ %s", mbitText(in), mbitText(outb)))
		}
		rd, ok3 := rate(prev, now, "diskread", float64(g.DiskRead))
		wr, ok4 := rate(prev, now, "diskwrite", float64(g.DiskWrite))
		if ok3 && ok4 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "read", Value: float64(int64(rd)), Unit: "B/s"}, model.Metric{Name: "write", Value: float64(int64(wr)), Unit: "B/s"})
		}
		p.counters[it.key] = cur
	} else {
		delete(p.counters, it.key)
	}
	switch {
	case !cfgKnown:
		parts = append(parts, "Soll-Zustand unbekannt")
	case cfg.onboot:
		parts = append(parts, "soll laufen (beim Booten starten)")
		if !running && g.Lock == "" { // mit Sperre (Backup im Stop-Modus, Migration) absichtlich aus
			s.Facts = append(s.Facts, model.Fact{Code: "guest_down", Text: parts[0] + ", soll laufen (beim Booten starten)"})
		}
	default:
		parts = append(parts, "darf aus sein")
	}
	s.Text = strings.Join(parts, " · ")
	return s
}
