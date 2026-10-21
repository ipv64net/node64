package proxmox

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Abfrage eines Systems im Takt des Plans:
//   cluster/resources  alle sys.Interval Sekunden (Standard 30, 15–300) – ein Aufruf fuer Nodes und Gaeste
//   cluster/status     alle 60 s (Clustername, quorate, Nodes online/IP → gelernte Adressen); frueher, wenn
//                      cluster/resources einen Node anders sieht als der letzte Stand
//   version            beim Start und alle 10 min
//   certificates/info  je Node alle 10 min bzw. bei neuen Nodes, nur bei Systemen mit Pin: Fingerabdruck des
//                      Zertifikats, das der Node benutzt, als Pin fuer seine gelernte Adresse (Failover im Cluster)
//   qmpstatus          laufender VMs alle 2 min (hoechstens 4 gleichzeitig); VMs, deren letzter Wert nicht
//                      „running“ ist, bei jeder Abfrage neu (hoechstens pveQMPRecheck), damit ein alter Wert
//                      (angehalten, abgestuerzt) nach Fortsetzen bzw. Neustart nicht stehen bleibt
// Jede Abfrage ergibt einen Snapshot (auch bei Fehler: OK=false, Error, keine Resources) und geht an fn.

const (
	pveStatusEvery    = 60 * time.Second
	pveVersionEvery   = 10 * time.Minute
	pveCertsEvery     = 10 * time.Minute
	pveQMPEvery       = 2 * time.Minute
	pveQMPParallel    = 4
	pveBackoffStart   = 5 * time.Second
	pveQMPRequestWait = 30 * time.Second // alle qmpstatus-Anfragen einer Runde zusammen
	pveQMPRecheck     = 16               // VMs mit qmpstatus ungleich running je Abfrage neu fragen
	pveLockGrace      = 4 * time.Hour    // gestoppter Gast mit Lock (Backup im Stopp-Modus, Migration): so lange neutral
)

// ClampInterval bringt ein Intervall in die Grenzen (0 = Standard).
func ClampInterval(sec int) time.Duration {
	switch {
	case sec <= 0:
		sec = DefaultInterval
	case sec < MinInterval:
		sec = MinInterval
	case sec > MaxInterval:
		sec = MaxInterval
	}
	return time.Duration(sec) * time.Second
}

// Poller fragt ein System ab (siehe types.go).
type Poller struct {
	log      *slog.Logger
	sys      System
	fn       SnapshotFunc
	client   *Client
	initErr  error
	now      func() time.Time
	interval time.Duration

	mu   sync.Mutex
	last *Snapshot

	// nur von der Abfrage-Schleife benutzt
	version   string
	versionAt time.Time
	statusAt  time.Time
	certsAt   time.Time
	certIPs   string // Nodes/IPs beim letzten Abruf der Zertifikate (neue Nodes -> sofort neu)
	cluster   string
	quorate   *bool
	nodeUp    map[string]bool // aus cluster/status
	qmpAt     time.Time
	qmp       map[string]pveQMP // Key -> qmpstatus mit dem Stand beim Abruf
	prev      map[string]pvePrev
	failing   bool
	warn      string // Rechte-Hinweis aus cluster/status (403)
	paced     bool   // laeuft per Run (Takt mit schnellen Wiederholungen): Snapshot.Interval setzen
}

// pvePrev ist der Stand einer Resource bei der letzten erfolgreichen Abfrage (Raten, Neustart, Lock).
type pvePrev struct {
	t                                 time.Time
	netIn, netOut, diskRead, diskWrit float64
	uptime                            int64
	up                                bool
	node                              string
	lock                              string
	lockSince                         time.Time // gestoppt mit Lock seit (Null = nicht)
}

// pveQMP ist ein abgerufener qmpstatus mit dem Stand der VM beim Abruf: passt der Stand nicht mehr (Node, Lock,
// Uptime zurueckgesprungen), gilt der Wert nicht mehr.
type pveQMP struct {
	status, node, lock string
	uptime             int64
}

// NewPoller baut den Poller eines Systems. fn darf nil sein. Ist das System fehlerhaft eingerichtet (Adresse,
// Token, Pin), liefert Run Snapshots mit OK=false und diesem Fehler.
func NewPoller(log *slog.Logger, sys System, fn SnapshotFunc) *Poller {
	if log == nil {
		log = slog.Default()
	}
	c, err := NewClient(sys)
	return newPoller(log, sys, fn, c, err)
}

func newPoller(log *slog.Logger, sys System, fn SnapshotFunc, c *Client, err error) *Poller {
	return &Poller{
		log:      log.With("proxmox", sys.Name, "system_id", sys.ID),
		sys:      sys,
		fn:       fn,
		client:   c,
		initErr:  err,
		now:      time.Now,
		interval: ClampInterval(sys.Interval),
		nodeUp:   map[string]bool{},
		qmp:      map[string]pveQMP{},
		prev:     map[string]pvePrev{},
	}
}

// Last ist der letzte Snapshot (nil vor der ersten Abfrage).
func (p *Poller) Last() *Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last
}

// Run fragt ab, bis ctx endet. Nach Fehlern wird frueher wiederholt (5 s, verdoppelt bis zum Intervall).
func (p *Poller) Run(ctx context.Context) {
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
func (p *Poller) Poll(ctx context.Context) *Snapshot {
	now := p.now()
	s := &Snapshot{SystemID: p.sys.ID, Time: now, Resources: []Resource{}}
	err := p.initErr
	if err == nil {
		err = p.collect(ctx, now, s)
	}
	if err != nil {
		s.OK = false
		s.Error = err.Error()
		s.Resources = []Resource{}
		if !p.failing {
			p.log.Warn("proxmox api failed", "err", s.Error)
		}
		p.failing = true
	} else {
		s.OK = true
		if p.failing {
			p.log.Info("proxmox api reachable again", "address", s.Address)
		}
		p.failing = false
	}
	if p.client != nil {
		s.Address = p.client.Address()
	}
	s.Version, s.Cluster, s.Quorate = p.version, p.cluster, p.quorate
	s.Warning = p.warn
	if p.paced {
		s.Interval = p.interval // Verzoegerung „nicht erreichbar“ auch zeitlich (Wiederholungen nach Fehlern sind schneller)
	}
	p.mu.Lock()
	p.last = s
	p.mu.Unlock()
	if p.fn != nil {
		p.fn(ctx, s)
	}
	return s
}

// pveNum nimmt Zahlen auch als String oder null an (Proxmox ist da nicht immer gleich).
type pveNum float64

func (n *pveNum) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		*n = 0 // unbekannter Wert: lieber 0 als die ganze Abfrage verwerfen
		return nil
	}
	*n = pveNum(f)
	return nil
}

// pveResource ist ein Eintrag aus cluster/resources.
type pveResource struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Node      string `json:"node"`
	VMID      pveNum `json:"vmid"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Template  pveNum `json:"template"`
	Lock      string `json:"lock"`
	Tags      string `json:"tags"`
	HAState   string `json:"hastate"`
	CPU       pveNum `json:"cpu"`
	MaxCPU    pveNum `json:"maxcpu"`
	Mem       pveNum `json:"mem"`
	MaxMem    pveNum `json:"maxmem"`
	Disk      pveNum `json:"disk"`
	MaxDisk   pveNum `json:"maxdisk"`
	Uptime    pveNum `json:"uptime"`
	NetIn     pveNum `json:"netin"`
	NetOut    pveNum `json:"netout"`
	DiskRead  pveNum `json:"diskread"`
	DiskWrite pveNum `json:"diskwrite"`
}

// pveStatusEntry ist ein Eintrag aus cluster/status (type cluster oder node).
type pveStatusEntry struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Online  pveNum `json:"online"`
	Quorate pveNum `json:"quorate"`
	Local   pveNum `json:"local"`
}

// pveVersion ist die Antwort von /version.
type pveVersion struct {
	Version string `json:"version"`
	Release string `json:"release"`
}

// collect fuehrt die faelligen Abfragen aus und fuellt s.
func (p *Poller) collect(ctx context.Context, now time.Time, s *Snapshot) error {
	var raw []pveResource
	if err := p.client.Get(ctx, "/cluster/resources", &raw); err != nil {
		return err
	}
	// cluster/status: im Takt, oder sofort, wenn die Nodes in cluster/resources anders aussehen als zuletzt.
	statusDue := p.statusAt.IsZero() || now.Sub(p.statusAt) >= pveStatusEvery
	if !statusDue && len(p.nodeUp) > 0 {
		for _, r := range raw {
			if r.Type == TypeNode {
				if up, ok := p.nodeUp[r.Node]; ok && up != (r.Status == "online") {
					statusDue = true
				}
			}
		}
	}
	if statusDue {
		p.statusAt = now
		p.fetchStatus(ctx)
	}
	if p.versionAt.IsZero() || now.Sub(p.versionAt) >= pveVersionEvery {
		var v pveVersion
		if err := p.client.Get(ctx, "/version", &v); err == nil {
			p.version, p.versionAt = v.Version, now
		} else {
			p.log.Debug("proxmox version failed", "err", err)
		}
	}

	res := p.build(raw)
	if p.qmpAt.IsZero() || now.Sub(p.qmpAt) >= pveQMPEvery {
		p.qmpAt = now
		p.fetchQMP(ctx, res, nil)
	} else if only := p.qmpRecheck(res); len(only) > 0 {
		p.fetchQMP(ctx, res, only)
	}
	p.evaluate(now, res)
	s.Resources = res
	return nil
}

// fetchStatus liest cluster/status (Fehler, z. B. 403 ohne Sys.Audit, sind nicht fatal).
func (p *Poller) fetchStatus(ctx context.Context) {
	var st []pveStatusEntry
	if err := p.client.Get(ctx, "/cluster/status", &st); err != nil {
		p.log.Debug("proxmox cluster/status failed", "err", err)
		if errors.Is(err, ErrPermission) {
			p.warn = err.Error() // in der Oberflaeche zeigen: ohne Rechte fehlen Gaeste
		}
		return
	}
	p.warn = ""
	cluster, quorate, up, ips := pveParseStatus(st)
	p.cluster, p.quorate, p.nodeUp = cluster, quorate, up
	p.client.SetLearned(ips)
	p.fetchCerts(ctx, st)
}

// fetchCerts lernt bei Systemen mit Pin die Fingerabdruecke der anderen Nodes ueber die bereits vertrauenswuerdige
// Verbindung (GET /nodes/{node}/certificates/info, Sys.Audit). Ohne Rechte bleibt es beim Pin des Systems.
func (p *Poller) fetchCerts(ctx context.Context, st []pveStatusEntry) {
	if p.client.pin == "" {
		return // System-CA: gelernte Adressen brauchen ein per CA gueltiges Zertifikat
	}
	type node struct{ name, ip string }
	var nodes []node
	var sig []string
	for _, e := range st {
		if e.Type != TypeNode || e.Online == 0 || e.IP == "" {
			continue
		}
		a := p.client.learnedAddr(e.IP)
		if a == "" || p.client.isConfigured(a) {
			continue
		}
		nodes = append(nodes, node{e.Name, e.IP})
		sig = append(sig, e.Name+"="+e.IP)
	}
	sort.Strings(sig)
	key := strings.Join(sig, ",")
	now := p.now()
	if len(nodes) == 0 || (key == p.certIPs && !p.certsAt.IsZero() && now.Sub(p.certsAt) < pveCertsEvery) {
		return
	}
	p.certsAt, p.certIPs = now, key
	pins := map[string][]string{}
	for _, n := range nodes {
		var info []struct {
			Filename    string `json:"filename"`
			Fingerprint string `json:"fingerprint"`
		}
		if err := p.client.Get(ctx, "/nodes/"+url.PathEscape(n.name)+"/certificates/info", &info); err != nil {
			p.log.Debug("proxmox certificates/info failed", "node", n.name, "err", err)
			if errors.Is(err, ErrPermission) || errors.Is(err, ErrToken) {
				break // fehlende Rechte gelten fuer alle Nodes
			}
			continue
		}
		fp := ""
		for _, c := range info {
			switch c.Filename {
			case "pveproxy-ssl.pem": // eigenes Zertifikat (z. B. ACME) hat Vorrang
				fp = c.Fingerprint
			case "pve-ssl.pem":
				if fp == "" {
					fp = c.Fingerprint
				}
			}
		}
		if fp != "" {
			pins[n.ip] = []string{fp}
		}
	}
	p.client.SetLearnedPins(pins)
}

// parseStatus: Clustername, quorate (nil bei Einzel-Node), Nodes online, IPs der Nodes, die online sind.
func pveParseStatus(st []pveStatusEntry) (string, *bool, map[string]bool, []string) {
	cluster := ""
	var quorate *bool
	up := map[string]bool{}
	var ips []string
	for _, e := range st {
		switch e.Type {
		case "cluster":
			cluster = e.Name
			q := e.Quorate != 0
			quorate = &q
		case TypeNode:
			up[e.Name] = e.Online != 0
			if e.Online != 0 && e.IP != "" {
				ips = append(ips, e.IP)
			}
		}
	}
	return cluster, quorate, up, ips
}

// build macht aus cluster/resources die Nodes und Gaeste (ohne Zustand und Raten).
func (p *Poller) build(raw []pveResource) []Resource {
	out := make([]Resource, 0, len(raw))
	for _, r := range raw {
		switch r.Type {
		case TypeNode, TypeQEMU, TypeLXC:
		default:
			continue // storage, pool, sdn …
		}
		x := Resource{
			Type: r.Type, Node: r.Node, Name: r.Name, Status: r.Status, Lock: r.Lock, HAState: r.HAState,
			Template: r.Template != 0, Tags: pveSplitTags(r.Tags),
			CPU: float64(r.CPU), MaxCPU: float64(r.MaxCPU), Mem: int64(r.Mem), MaxMem: int64(r.MaxMem),
			Disk: int64(r.Disk), MaxDisk: int64(r.MaxDisk), Uptime: int64(r.Uptime),
			NetIn: float64(r.NetIn), NetOut: float64(r.NetOut), DiskRead: float64(r.DiskRead), DiskWrite: float64(r.DiskWrite),
		}
		if r.Type == TypeNode {
			if x.Node == "" {
				x.Node = strings.TrimPrefix(r.ID, "node/")
			}
			if x.Name == "" {
				x.Name = x.Node
			}
		} else {
			x.VMID = int(r.VMID)
			if x.VMID == 0 {
				if i := strings.LastIndexByte(r.ID, '/'); i >= 0 {
					x.VMID, _ = strconv.Atoi(r.ID[i+1:])
				}
			}
		}
		out = append(out, x)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.Type == TypeNode) != (b.Type == TypeNode) {
			return a.Type == TypeNode
		}
		if a.Type == TypeNode {
			return a.Node < b.Node
		}
		return a.VMID < b.VMID
	})
	return out
}

// splitTags: Proxmox liefert "a;b" (aeltere Versionen auch mit Komma oder Leerzeichen).
func pveSplitTags(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' || r == ' ' })
	if len(f) == 0 {
		return nil
	}
	return f
}

// nodeOnline: Node laut cluster/resources online und nicht laut cluster/status offline.
func (p *Poller) nodeOnline(r *Resource) bool {
	if r.Status != "online" {
		return false
	}
	if up, ok := p.nodeUp[r.Node]; ok && !up {
		return false
	}
	return true
}

// qmpRecheck: laufende VMs, deren gemerkter qmpstatus nicht „running“ ist (hoechstens pveQMPRecheck).
func (p *Poller) qmpRecheck(res []Resource) map[string]bool {
	var only map[string]bool
	for i := range res {
		r := &res[i]
		if r.Type != TypeQEMU || r.Status != "running" {
			continue
		}
		if q, ok := p.qmp[r.Key()]; ok && q.status != "" && q.status != "running" {
			if only == nil {
				only = map[string]bool{}
			}
			only[r.Key()] = true
			if len(only) >= pveQMPRecheck {
				break
			}
		}
	}
	return only
}

// fetchQMP holt qmpstatus fuer laufende VMs auf Nodes, die online sind (hoechstens pveQMPParallel gleichzeitig).
// Fehler einzelner VMs lassen deren Wert leer. only != nil: nur diese VMs, die uebrigen Werte bleiben.
func (p *Poller) fetchQMP(ctx context.Context, res []Resource, only map[string]bool) {
	nodes := map[string]bool{}
	for i := range res {
		if res[i].Type == TypeNode {
			nodes[res[i].Node] = p.nodeOnline(&res[i])
		}
	}
	type job struct {
		key, path string
		at        pveQMP
	}
	var jobs []job
	for i := range res {
		r := &res[i]
		if r.Type != TypeQEMU || r.Template || r.Status != "running" || (only != nil && !only[r.Key()]) {
			continue
		}
		if up, ok := nodes[r.Node]; ok && !up {
			continue
		}
		jobs = append(jobs, job{r.Key(), "/nodes/" + url.PathEscape(r.Node) + "/qemu/" + strconv.Itoa(r.VMID) + "/status/current",
			pveQMP{node: r.Node, lock: r.Lock, uptime: r.Uptime}})
	}
	ctx, cancel := context.WithTimeout(ctx, pveQMPRequestWait)
	defer cancel()
	got := map[string]pveQMP{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, pveQMPParallel)
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()
			var st struct {
				QMPStatus string `json:"qmpstatus"`
			}
			if err := p.client.Get(ctx, j.path, &st); err != nil {
				p.log.Debug("proxmox qmpstatus failed", "guest", j.key, "err", err)
				return
			}
			q := j.at
			q.status = st.QMPStatus
			mu.Lock()
			got[j.key] = q
			mu.Unlock()
		}(j)
	}
	wg.Wait()
	if only == nil {
		p.qmp = got
		return
	}
	for k := range only {
		if q, ok := got[k]; ok {
			p.qmp[k] = q
		} else {
			delete(p.qmp, k) // Fehler: alter Wert gilt nicht weiter
		}
	}
}

// guestState bewertet einen Gast nach der Plan-Tabelle.
func pveGuestState(r *Resource, nodeUp bool) State {
	if !nodeUp {
		return StateUnknown
	}
	// Absturz/haengt hat Vorrang vor Lock und Pause (Kernfall „Maschine abgestuerzt“).
	if r.Status == "running" {
		switch r.QMP {
		case "internal-error", "guest-panicked", "io-error":
			return StateError
		}
	}
	// Lock zaehlt bei gestoppten Gaesten nur eine Weile (pveLockGrace, evaluate) – ein haengender Lock verdeckt
	// sonst einen gestoppten Gast.
	switch r.Lock {
	case "":
	case "backup":
		return StateBackup
	case "suspended", "suspending":
		return StateSuspended
	default:
		return StateLocked
	}
	switch r.Status {
	case "running":
		switch r.QMP {
		case "paused":
			return StatePaused
		case "suspended":
			return StateSuspended
		}
		return StateRunning
	case "stopped":
		return StateStopped
	case "paused":
		return StatePaused
	case "suspended":
		return StateSuspended
	}
	return StateUnknown
}

// evaluate setzt Zustand, QMP, Raten und Neustart und merkt sich den Stand fuer die naechste Abfrage.
func (p *Poller) evaluate(now time.Time, res []Resource) {
	nodes := map[string]bool{}
	for i := range res {
		r := &res[i]
		if r.Type != TypeNode {
			continue
		}
		up := p.nodeOnline(r)
		nodes[r.Node] = up
		if up {
			r.State = StateOnline
		} else {
			r.State = StateOffline
		}
	}
	next := make(map[string]pvePrev, len(res))
	for i := range res {
		r := &res[i]
		if r.Type != TypeNode {
			nodeUp, known := nodes[r.Node]
			if !known {
				// Node fuer das Token nicht sichtbar: nur cluster/status zaehlt, sonst als online annehmen.
				nodeUp = true
				if up, ok := p.nodeUp[r.Node]; ok {
					nodeUp = up
				}
			}
			if q, ok := p.qmp[r.Key()]; ok && r.Type == TypeQEMU && r.Status == "running" && q.node == r.Node && q.lock == r.Lock && r.Uptime >= q.uptime {
				r.QMP = q.status // nur, solange die VM seit dem Abruf nicht umgezogen, neu gestartet oder gelockt ist
			}
			r.State = pveGuestState(r, nodeUp)
		}
		up := r.Status == "running" || r.State == StateOnline
		cur := pvePrev{t: now, netIn: r.NetIn, netOut: r.NetOut, diskRead: r.DiskRead, diskWrit: r.DiskWrite, uptime: r.Uptime, up: up, node: r.Node, lock: r.Lock}
		if (r.State == StateBackup || r.State == StateLocked) && r.Status == "stopped" {
			cur.lockSince = now
			if old, ok := p.prev[r.Key()]; ok && old.lock == r.Lock && !old.lockSince.IsZero() {
				cur.lockSince = old.lockSince
			}
			if now.Sub(cur.lockSince) >= pveLockGrace {
				r.State = StateStopped // Lock haengt: wie gestoppt (Lock bleibt im Feld)
			}
		}
		// In NetIn usw. stehen bis hier die Zaehler; daraus werden Raten.
		r.NetIn, r.NetOut, r.DiskRead, r.DiskWrite = 0, 0, 0, 0
		if old, ok := p.prev[r.Key()]; ok {
			dt := now.Sub(old.t).Seconds()
			if dt > 0 {
				r.NetIn = pveRate(old.netIn, cur.netIn, dt)
				r.NetOut = pveRate(old.netOut, cur.netOut, dt)
				r.DiskRead = pveRate(old.diskRead, cur.diskRead, dt)
				r.DiskWrite = pveRate(old.diskWrit, cur.diskWrit, dt)
			}
			// Nach einer Migration laeuft der Gast in einem neuen Prozess auf dem anderen Node (Uptime neu) – kein Neustart.
			r.Restarted = old.up && up && r.Uptime < old.uptime && old.node == r.Node
		}
		next[r.Key()] = cur
	}
	p.prev = next
}

// rate in Einheiten je Sekunde; Ruecksprung des Zaehlers (Neustart, Umzug) ergibt 0.
func pveRate(old, cur, dt float64) float64 {
	if cur < old || dt <= 0 {
		return 0
	}
	return (cur - old) / dt
}
