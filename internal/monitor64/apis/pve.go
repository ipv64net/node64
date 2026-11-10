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
//	/nodes/{node}/qemu?full=1, /lxc       Gaeste (vm:<vmid>, ct:<vmid>); Raten aus den Zaehlern zweier Runden,
//	                                      full=1 liefert qmpstatus (io-error, guest-panicked, paused …)
//	/nodes/{node}/{qemu|lxc}/{vmid}/config onboot (Soll-Zustand), je Gast alle 10 min
//	/cluster/ha/status/current            HA (nur mit HA-Ressourcen)
//	/cluster/ceph/status                  Ceph (falls eingerichtet, sonst stuendlich neu versucht)
//
// Seltener: /nodes/{node}/disks/list + /disks/smart?disk= (SMART, 30 min), /nodes/{node}/apt/update (60 min).
//
// Clusterweite Dienste (cluster, ha, ceph) bewertet nur eine Node: die mit der kleinsten Node-ID unter den Nodes,
// die diese Node online sieht (bei getrenntem Cluster je Teil eine). Auf den uebrigen Nodes erscheinen die Dienste
// nur als Hinweis ohne Messgroessen und Zustaende ("gemeldet von Node …"), damit jede Meldung einmal kommt und die
// Dienste beim Wechsel der Zustaendigkeit (Node aus und wieder an) nicht verschwinden.

// PVEConfig sind die Verbindungsdaten eines Proxmox-VE-Hosts.
type PVEConfig struct {
	Addresses    []string      // https://host:8006 (die Node selbst; weitere Adressen fuer Failover optional)
	TokenID      string        // user@realm!tokenid
	Secret       string        // Token-Secret (nie ausgeben)
	Pin          string        // SHA-256 des Zertifikats (hex); leer = System-CA
	Node         string        // Node-Name; leer = die Node hinter der Adresse beim ersten Kontakt (dann fest)
	Timeout      time.Duration // ganze Runde (0 = DefaultTimeout)
	SmartEvery   time.Duration // 0 = DefaultSmartEvery
	UpdatesEvery time.Duration // 0 = DefaultUpdatesEvery
	// Seen: gemeinsam fuer alle PVE-Zugaenge einer Node64 (nil = jede Node online gilt als ueberwacht). Die
	// clusterweiten Dienste bewertet die kleinste Node-ID unter den Nodes, die hier gerade erfolgreich abgefragt
	// werden - nicht eine Node, die in Monitor64 fehlt, pausiert oder deren API nicht antwortet.
	Seen *ClusterSeen
}

// ClusterSeen merkt, welche Proxmox-Nodes zuletzt erfolgreich abgefragt wurden (je Cluster).
type ClusterSeen struct {
	mu sync.Mutex
	at map[string]time.Time
}

// seenFresh: so lange gilt eine Node nach der letzten erfolgreichen Runde als ueberwacht.
const seenFresh = 15 * time.Minute

func (c *ClusterSeen) mark(cluster, node string, at time.Time) {
	if c == nil || cluster == "" || node == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at == nil {
		c.at = map[string]time.Time{}
	}
	c.at[cluster+"/"+node] = at
}

func (c *ClusterSeen) fresh(cluster, node string, now time.Time) bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.at[cluster+"/"+node]
	return ok && now.Sub(t) < seenFresh
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

	nodeMu sync.Mutex
	node   string // erkannte Node (cfg.Node leer): beim ersten Kontakt festgelegt, wechselt bei Failover nicht

	mu        sync.Mutex
	counters  map[string]*counter // Gast-Schluessel -> Zaehler der vorigen Runde
	configs   map[string]guestCfg // Gast-Schluessel -> onboot
	locks     map[string]lockSeen // Gast-Schluessel -> Sperre eines nicht laufenden Gasts seit
	disks     slowDisks
	updates   slowUpdates
	cephUntil time.Time // kein Ceph: bis dahin nicht neu fragen
	cephSeen  bool      // Ceph hat schon geantwortet (Fehler danach = Stoerung, nicht "kein Ceph")
	owner     string    // Node, die die clusterweiten Dienste bewertet ("" = diese bzw. unbekannt)
}

type lockSeen struct {
	lock  string
	since time.Time
}

type guestCfg struct {
	at     time.Time
	onboot bool
}

// NewPVE baut den Sammler (prueft Adressen, Token-Format und Pin; fragt noch nichts ab).
func NewPVE(cfg PVEConfig) (*PVE, error) {
	c, err := proxmox.NewClient(cfg.system())
	if err != nil {
		return nil, foreignErr(err, cfg.Secret)
	}
	return &PVE{cfg: cfg, client: c, now: time.Now, counters: map[string]*counter{}, configs: map[string]guestCfg{},
		locks: map[string]lockSeen{}}, nil
}

// Node ist die Node dieses Hosts: eingestellt bzw. beim ersten Kontakt erkannt ("" = noch nicht bekannt). Der Kern
// speichert sie nach dem ersten Test bzw. der ersten Runde, damit ein Failover nicht still eine andere Node abfragt.
func (p *PVE) Node() string {
	if p.cfg.Node != "" {
		return p.cfg.Node
	}
	p.nodeMu.Lock()
	defer p.nodeMu.Unlock()
	return p.node
}

// fixNode legt die erkannte Node fest, falls noch keine bekannt ist, und liefert die feste Node.
func (p *PVE) fixNode(n string) string {
	p.nodeMu.Lock()
	defer p.nodeMu.Unlock()
	if p.node == "" {
		p.node = n
	}
	return p.node
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
		return "", nil, foreignErr(err, p.cfg.Secret)
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
	res := TestResult{OK: pr.OK, Error: model.Raw(scrub(pr.Error, p.cfg.Secret)), Version: pr.Version, Cluster: pr.Cluster,
		Warning: model.Raw(scrub(pr.PermWarning, p.cfg.Secret)), Fingerprint: pr.CertSHA256, CertSubject: pr.CertSubject,
		Trusted: pr.CertTrusted, NeedConfirm: pr.NeedConfirm}
	if !pr.OK {
		return res
	}
	res.Summary = model.T("monitor64.txt.guests_cluster", "n", pr.Guests)
	cl, nodes, err := p.Nodes(ctx)
	if err != nil {
		res.Warning = strings.TrimSpace(res.Warning + " cluster/status: " + err.Error())
		res.Node = p.Node()
		return res
	}
	res.Cluster, res.Nodes = cl, nodes
	res.Node = p.cfg.Node
	if res.Node == "" {
		// erkannte Node festhalten (Rueckgabe an den Assistenten zum Speichern); spaetere Tests und Runden bleiben
		// bei ihr, auch wenn eine andere Adresse antwortet
		res.Node = p.fixNode(localNode(nodes))
	}
	found := false
	for _, n := range nodes {
		found = found || n.Name == res.Node
	}
	if !found && len(nodes) > 0 {
		res.OK = false
		res.Error = model.T("monitor64.txt.node_missing", "node", res.Node, "list", nodeNames(nodes))
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
	part := &partial{secrets: []string{p.cfg.Secret}, foreign: true}

	var st []pveStatus
	stErr := p.client.Get(ctx, "/cluster/status", &st)
	node := p.Node()
	if node == "" {
		if stErr == nil {
			_, nodes := parseNodes(st)
			node = p.fixNode(localNode(nodes))
		}
		if node == "" {
			if stErr != nil {
				return nil, foreignErr(stErr, p.cfg.Secret)
			}
			return nil, errors.New(model.T("monitor64.txt.node_unknown"))
		}
	}
	nodePath := "/nodes/" + url.PathEscape(node)
	var ns nodeStatus
	if err := p.client.Get(ctx, nodePath+"/status", &ns); err != nil {
		return nil, foreignErr(err, p.cfg.Secret)
	}
	out := nodeServices(ns)
	if svc := p.updates.collect(ctx, p.client, node, now, p.cfg.UpdatesEvery, part); svc != nil {
		out = append(out, *svc)
	}
	var cw []model.Service // clusterweite Dienste
	if stErr != nil {
		part.add("cluster/status", stErr, "cluster")
	} else {
		cl, _ := parseNodes(st)
		p.cfg.Seen.mark(cl, node, now)
		p.owner = clusterOwner(st, node, func(n string) bool { return p.cfg.Seen.fresh(cl, n, now) }) // bei Fehler gilt der vorige Stand
		if svc, ok := clusterService(st); ok {
			cw = append(cw, svc)
		}
	}
	cw = append(cw, p.ha(ctx, part)...)
	cw = append(cw, p.ceph(ctx, now, part)...)
	out = append(out, clusterWide(cw, node, p.owner)...)
	out = append(out, p.storages(ctx, nodePath, part)...)
	out = append(out, p.zfs(ctx, nodePath, part)...)
	out = append(out, p.disks.collect(ctx, p.client, node, now, p.cfg.SmartEvery, func(d diskEntry) string {
		return firstNonEmpty(d.DevPath, "/dev/"+d.dev())
	}, part)...)
	out = append(out, p.guests(ctx, nodePath, now, part)...)
	sortServices(out)
	return out, part.result()
}

// clusterOwner: die Node, die die clusterweiten Dienste bewertet – kleinste Node-ID unter den Nodes online, die
// hier ueberwacht werden (self immer; "" = kein Cluster bzw. keine Angabe: jede Node bewertet selbst).
func clusterOwner(st []pveStatus, self string, watched func(string) bool) string {
	isCluster := false
	for _, e := range st {
		isCluster = isCluster || e.Type == "cluster"
	}
	if !isCluster {
		return ""
	}
	_, nodes := parseNodes(st)
	best := -1
	owner := ""
	for _, n := range nodes {
		if n.Online && (n.Name == self || watched == nil || watched(n.Name)) && (best < 0 || n.ID < best) {
			best, owner = n.ID, n.Name
		}
	}
	return owner
}

// clusterWide: auf der zustaendigen Node die Dienste unveraendert, sonst nur als Hinweis (ohne Messgroessen und
// Zustaende, Schluessel bleiben).
func clusterWide(svcs []model.Service, node, owner string) []model.Service {
	if owner == "" || owner == node {
		return svcs
	}
	for i := range svcs {
		s := &svcs[i]
		s.Metrics, s.Facts = nil, nil
		s.Text = model.Join(model.T("monitor64.txt.reported_by", "node", owner), s.Text)
	}
	return svcs
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
	s := model.Service{Key: "cluster", Name: "Cluster " + model.Raw(cl), Kind: "cluster", Default: true,
		Metrics: []model.Metric{{Name: "nodes_online", Value: float64(up)}, {Name: "nodes", Value: float64(len(nodes))}, {Name: "quorate", Value: q}}}
	s.Text = model.T("monitor64.txt.nodes_online", "n", up, "total", len(nodes))
	if quorate {
		s.Text += " · " + model.T("monitor64.txt.quorum_ok")
	} else {
		s.Text += " · " + model.T("monitor64.txt.no_quorum")
		s.Facts = append(s.Facts, model.Fact{Code: "cluster_no_quorum", Text: model.T("monitor64.txt.cluster_no_quorum")})
	}
	if len(down) > 0 {
		list := model.Raw(strings.Join(down, ", "))
		s.Text += " · offline: " + list
		s.Facts = append(s.Facts, model.Fact{Code: "cluster_node_down", Text: list + " offline"})
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
			part.add("cluster/ha/status/current", err, "ha")
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
	s.Text = model.T("monitor64.txt.resources_ok", "n", len(res))
	if len(bad) > 0 {
		list := strings.Join(limitList(bad, 5), ", ")
		s.Text = model.T("monitor64.txt.resources", "n", len(res)) + " · " + model.T("monitor64.txt.faulty_list", "list", list)
		s.Facts = append(s.Facts, model.Fact{Code: "ha_error", Text: model.Raw(list)})
	}
	if !quorumOK {
		s.Text += " · " + model.T("monitor64.txt.ha_no_quorum")
		s.Facts = append(s.Facts, model.Fact{Code: "ha_error", Text: model.T("monitor64.txt.ha_no_quorum")})
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
		switch {
		case cephMissing(err): // kein Ceph eingerichtet
			p.cephSeen, p.cephUntil = false, now.Add(optionalRetry)
			return nil
		case p.cephSeen && !authErr(err):
			// eingerichtetes Ceph antwortet nicht (Monitore ohne Quorum, Zeitlimit): Stoerung
			msg := model.Raw(scrub(err.Error(), p.cfg.Secret))
			return []model.Service{{Key: "ceph", Name: "Ceph", Kind: "ceph", Default: true, Text: model.T("monitor64.txt.status_unavailable") + ": " + msg,
				Facts: []model.Fact{{Code: "ceph_err", Text: model.T("monitor64.txt.ceph_unavailable") + ": " + msg}}}}
		}
		part.add("cluster/ceph/status", err, "ceph")
		return nil
	}
	if cs.Health.Status == "" {
		p.cephSeen, p.cephUntil = false, now.Add(optionalRetry)
		return nil
	}
	p.cephSeen = true
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
	list := model.Raw(strings.Join(limitList(msgs, 3), "; ")) // Meldungen von Ceph
	s.Text = model.Join(model.Raw(cs.Health.Status), model.T("monitor64.txt.osds_up", "n", fmt.Sprintf("%.0f", float64(up)), "total", fmt.Sprintf("%.0f", float64(osds))), list)
	switch cs.Health.Status {
	case "HEALTH_WARN":
		s.Facts = append(s.Facts, model.Fact{Code: "ceph_warn", Text: list})
	case "HEALTH_ERR":
		s.Facts = append(s.Facts, model.Fact{Code: "ceph_err", Text: list})
	}
	return []model.Service{s}
}

// cephMissing: Ceph ist auf diesem Cluster nicht eingerichtet (Proxmox antwortet dann mit 500 und einem Text wie
// "binary not installed: /usr/bin/ceph-mon" bzw. "pveceph configuration not initialized"). Andere 500er und
// Zeitlimits sind Fehler eines eingerichteten Ceph.
func cephMissing(err error) bool {
	var pe *proxmox.Error
	if !errors.As(err, &pe) || authErr(err) {
		return false
	}
	if absent(err) {
		return true
	}
	if pe.Status != 500 {
		return false
	}
	d := strings.ToLower(pe.Detail)
	for _, m := range []string{"not installed", "not initialized", "not configured", "no such file or directory"} {
		if strings.Contains(d, m) {
			return true
		}
	}
	return false
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
		part.add("storage", err, "store:")
		return nil
	}
	var out []model.Service
	for _, x := range list {
		if x.Storage == "" {
			continue
		}
		s := model.Service{Key: "store:" + x.Storage, Name: model.T("monitor64.svc.store", "name", x.Storage), Kind: "store", Default: x.Enabled != 0}
		typ := model.Raw(x.Type)
		if x.Shared != 0 {
			typ += ", " + model.T("monitor64.txt.shared")
		}
		switch {
		case x.Enabled == 0:
			s.Text = model.T("monitor64.txt.disabled") + " (" + typ + ")"
		case x.Active == 0:
			s.Text = model.T("monitor64.txt.not_active") + " (" + typ + ")"
			s.Facts = append(s.Facts, model.Fact{Code: "store_inactive", Text: model.T("monitor64.txt.store_inactive", "name", x.Storage)})
		case x.Total > 0:
			tot := float64(x.Total)
			s.Metrics = []model.Metric{{Name: "used", Value: pct(float64(x.Used), tot), Unit: "%", Rule: model.RuleStore, Max: tot},
				{Name: "free", Value: float64(x.Avail), Unit: "B", Max: tot}}
			s.Text = model.T("monitor64.txt.free_of", "free", bytesText(float64(x.Avail)), "total", bytesText(tot)) + " (" + typ + ")"
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
			part.add("disks/zfs", err, "zfs:")
		}
		return nil
	}
	var out []model.Service
	for _, z := range list {
		s := model.Service{Key: "zfs:" + z.Name, Name: "ZFS " + model.Raw(z.Name), Kind: "zfs", Default: true}
		if tot := float64(z.Size); tot > 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "used", Value: pct(float64(z.Alloc), tot), Unit: "%", Rule: model.RuleStore, Max: tot},
				model.Metric{Name: "free", Value: float64(z.Free), Unit: "B", Max: tot},
				model.Metric{Name: "frag", Value: float64(z.Frag), Unit: "%"})
		}
		s.Text = model.Join(model.Raw(z.Health), model.T("monitor64.txt.free", "v", bytesText(float64(z.Free))))
		if !strings.EqualFold(z.Health, "ONLINE") {
			s.Facts = append(s.Facts, model.Fact{Code: "zfs_degraded", Text: model.Raw(z.Health)})
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
	QMP       string `json:"qmpstatus"` // nur QEMU mit full=1
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
	at   time.Time // Abrufzeitpunkt der Liste (Raten)
}

func (p *PVE) guests(ctx context.Context, nodePath string, now time.Time, part *partial) []model.Service {
	var items []guestItem
	failed := map[string]bool{} // Praefix -> Liste fehlgeschlagen (Zaehler und Configs behalten)
	for _, typ := range []string{proxmox.TypeQEMU, proxmox.TypeLXC} {
		var list []pveGuest
		path := nodePath + "/" + typ
		if typ == proxmox.TypeQEMU {
			path += "?full=1" // mit qmpstatus
		}
		if err := p.client.Get(ctx, path, &list); err != nil {
			part.add(typ, err, guestPrefix(typ))
			failed[guestPrefix(typ)] = true
			continue
		}
		at := p.now() // Raten mit dem Abrufzeitpunkt (vorher koennen SMART u. a. dauern)
		for _, g := range list {
			if g.Template != 0 || g.VMID <= 0 {
				continue
			}
			vmid := int(g.VMID)
			items = append(items, guestItem{typ: typ, key: guestPrefix(typ) + strconv.Itoa(vmid), vmid: vmid, g: g, at: at})
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
		part.add(model.T("monitor64.txt.guest_config", "n", cfgErrs), firstErr)
	}
	keep := map[string]bool{}
	var out []model.Service
	for _, it := range items {
		keep[it.key] = true
		cfg, known := p.configs[it.key]
		out = append(out, p.guestService(it, cfg, known))
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
	for k := range p.locks {
		if drop(k) {
			delete(p.locks, k)
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

// qmpFault: QEMU-Zustaende, in denen die VM zwar als "running" gilt, aber steht (Speicher voll, Absturz).
var qmpFault = map[string]bool{"io-error": true, "internal-error": true, "guest-panicked": true}

// guestService: ein Gast als Dienst mit Zustand, CPU, RAM, Platte, Netz- und Disk-Raten und Soll-Zustand (onboot).
//
// Messgroessen fuer den Kern: running (1 = laeuft wirklich; 0 auch bei pausierter bzw. gestoerter VM laut
// qmpstatus) und locked (1 = eine Sperre wie Backup im Stopp-Modus oder Migration erklaert, dass der Gast nicht
// laeuft; bei nicht laufenden Gaesten hoechstens lockGrace lang, danach 0). Ein Soll "laeuft" am Dienst soll locked
// beachten.
func (p *PVE) guestService(it guestItem, cfg guestCfg, cfgKnown bool) model.Service {
	g := it.g
	now := it.at
	label, kind := "VM", "vm"
	if it.typ == proxmox.TypeLXC {
		label, kind = "CT", "ct"
	}
	name := fmt.Sprintf("%s %d", label, it.vmid)
	if g.Name != "" {
		name = fmt.Sprintf("%s (%s %d)", model.Raw(g.Name), label, it.vmid)
	}
	s := model.Service{Key: it.key, Name: name, Kind: kind, Default: true}
	for _, t := range strings.FieldsFunc(g.Tags, func(r rune) bool { return r == ';' || r == ',' || r == ' ' }) {
		if strings.EqualFold(t, proxmox.TagNoMonitor) {
			s.Default = false
		}
	}
	running := g.Status == "running" // Prozess laeuft (Werte und Zaehler)
	qmp := strings.ToLower(strings.TrimSpace(g.QMP))
	isQEMU := it.typ == proxmox.TypeQEMU
	fault := running && isQEMU && qmpFault[qmp]
	held := running && isQEMU && !fault && qmp != "" && qmp != "running" // pausiert, suspended …
	active := running && !fault && !held
	run := 0.0
	if active {
		run = 1
	}
	var parts []string
	switch {
	case fault:
		parts = append(parts, model.T("monitor64.txt.guest_fault", "v", qmp))
	case held && qmp == "paused":
		parts = append(parts, model.T("monitor64.txt.paused"))
	case held:
		parts = append(parts, model.T("monitor64.txt.held", "v", qmp))
	case g.Status == "running":
		parts = append(parts, model.T("monitor64.txt.running"))
	case g.Status == "stopped":
		parts = append(parts, model.T("monitor64.txt.stopped"))
	case g.Status != "":
		parts = append(parts, model.Raw(g.Status))
	default:
		parts = append(parts, model.T("monitor64.txt.unknown"))
	}
	// Sperre: bei laufenden Gaesten erklaert (Backup im Snapshot-Modus, Migration), bei nicht laufenden nur
	// lockGrace lang (eine haengende Sperre verdeckt sonst einen gestoppten Gast); eine Stoerung geht vor.
	lockOK := false
	if g.Lock != "" {
		txt := model.T("monitor64.txt.lock", "v", g.Lock)
		switch {
		case fault:
			delete(p.locks, it.key)
		case active:
			lockOK = true
			delete(p.locks, it.key)
		default:
			l, ok := p.locks[it.key]
			if !ok || l.lock != g.Lock {
				l = lockSeen{lock: g.Lock, since: now}
				p.locks[it.key] = l
			}
			if d := now.Sub(l.since); d < lockGrace {
				lockOK = true
			} else {
				txt = model.T("monitor64.txt.lock_since", "v", g.Lock, "d", model.Sub(hoursText(d)))
			}
		}
		parts = append(parts, txt)
	} else {
		delete(p.locks, it.key)
	}
	locked := 0.0
	if lockOK {
		locked = 1
	}
	s.Metrics = append(s.Metrics, model.Metric{Name: "running", Value: run}, model.Metric{Name: "locked", Value: locked})
	if running {
		s.Metrics = append(s.Metrics, model.Metric{Name: "cpu", Value: round2(float64(g.CPU) * 100), Unit: "%", Rule: model.RuleCPU})
		parts = append(parts, fmt.Sprintf("CPU %.0f %%", float64(g.CPU)*100))
		if mx := float64(g.MaxMem); mx > 0 {
			rule := model.RuleMem
			if isQEMU { // Proxmox zaehlt bei VMs den Cache des Gastes mit: eigene Regel, im Standard ohne Schwelle
				rule = model.RuleGuestMem
			}
			s.Metrics = append(s.Metrics, model.Metric{Name: "mem", Value: pct(float64(g.Mem), mx), Unit: "%", Rule: rule, Max: mx},
				model.Metric{Name: "mem_used", Value: float64(g.Mem), Unit: "B", Max: mx})
			parts = append(parts, model.T("monitor64.txt.ram_of", "used", bytesText(float64(g.Mem)), "total", bytesText(mx)))
		}
		if mx := float64(g.MaxDisk); mx > 0 && g.Disk > 0 { // QEMU ohne Gast-Agent: 0
			s.Metrics = append(s.Metrics, model.Metric{Name: "disk", Value: pct(float64(g.Disk), mx), Unit: "%", Rule: model.RuleFS, Max: mx})
			parts = append(parts, model.T("monitor64.txt.disk_pct", "v", fmt.Sprintf("%.0f", pct(float64(g.Disk), mx))))
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
		parts = append(parts, model.T("monitor64.txt.target_unknown"))
	case cfg.onboot:
		parts = append(parts, model.T("monitor64.txt.should_run_onboot"))
	default:
		parts = append(parts, model.T("monitor64.txt.may_be_off"))
	}
	switch {
	case fault: // gestartet, steht aber: unabhaengig vom Soll-Zustand eine Stoerung
		s.Facts = append(s.Facts, model.Fact{Code: "guest_fault", Text: model.T("monitor64.txt.vm_stalled", "v", qmp)}) // gilt auch bei Soll "aus"
	case !active && cfgKnown && cfg.onboot && !lockOK:
		t := parts[0] + ", " + model.T("monitor64.txt.should_run_onboot")
		if g.Lock != "" {
			t = parts[0] + ", " + model.T("monitor64.txt.lock_longer", "v", g.Lock, "d", model.Sub(hoursText(lockGrace))) + ", " + model.T("monitor64.txt.should_run_onboot")
		}
		s.Facts = append(s.Facts, model.Fact{Code: "guest_down", Text: t})
	}
	s.Text = strings.Join(parts, " · ")
	return s
}
