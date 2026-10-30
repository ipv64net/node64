package proxmox

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Proxmox Backup Server als System (Kind pbs): derselbe Client (Token, Pin, Adressen; Port 8007, Kopf PBSAPIToken)
// und dieselbe Weiterverarbeitung (Regeln, Verlauf, Check-Typ proxmox) wie bei Proxmox VE. Ein PBS hat keine Gaeste,
// er ist ein Node (Key node/localhost wie in der PBS-API – den Hostnamen liefert die API mit der Rolle Audit nicht;
// angezeigt wird der Name des Systems) mit CPU, RAM, Root-Disk, Netz und Disk-I/O; dazu Datastores, Backups, Dienste
// und fehlgeschlagene Tasks nur zur Anzeige – keine Regeln und keine Checks dafuer.
// Alles liest die Rolle Audit auf „/“ (Sys.Audit, Datastore.Audit). Je Abfrage (sys.Interval):
//   /nodes/localhost/status    CPU, RAM, Root-Disk, Uptime
//   /nodes/localhost/rrd       letzter Wert der Stunde: netin/netout, read_bytes/write_bytes (Byte/s)
//   /nodes/localhost/services  Dienste proxmox-backup und proxmox-backup-proxy (nur Anzeige)
//   /status/datastore-usage    Datastores (Groesse, Belegung, geschaetzt voll, Dedup aus gc-status)
// Beim Start und alle 10 min (pbsSlowEvery):
//   /version, /nodes/localhost/apt/update (verfuegbare Version von proxmox-backup-server fuer das Badge),
//   je Datastore /admin/datastore/{store}/namespace und /groups?ns= (Gruppen, Snapshots, letztes Backup – die Backups
//   liegen meist in Namespaces), /nodes/localhost/tasks?errors=1 (fehlgeschlagene Tasks der letzten 7 Tage)

const (
	pbsSlowEvery  = 10 * time.Minute
	pbsMaxNS      = 50 // Namespaces je Datastore hoechstens abfragen
	pbsTaskWindow = 7 * 24 * time.Hour
	pbsMaxTasks   = 10
)

// pbsServices sind die Dienste, ohne die der PBS nicht arbeitet (Anzeige).
var pbsServices = []string{"proxmox-backup", "proxmox-backup-proxy"}

// PBSInfo ist der Teil eines Snapshots, den nur ein PBS hat (alles nur Anzeige).
type PBSInfo struct {
	Datastores []PBSDatastore `json:"datastores"`
	Services   []PBSService   `json:"services,omitempty"`
	// Update: verfuegbare Version von proxmox-backup-server laut apt ("" = keine); UpdateOK = apt/update gelesen
	Update   string    `json:"update,omitempty"`
	UpdateOK bool      `json:"update_checked,omitempty"`
	Failed   []PBSTask `json:"failed_tasks"` // fehlgeschlagene Tasks der letzten 7 Tage (neueste zuerst)
}

// PBSService ist ein Dienst aus /nodes/localhost/services.
type PBSService struct {
	Name  string `json:"name"`
	State string `json:"state"` // running, dead …
}

// PBSTask ist ein Task aus /nodes/localhost/tasks.
type PBSTask struct {
	Type   string `json:"type"` // backup, garbage_collection, verify, prune …
	ID     string `json:"id,omitempty"`
	Start  int64  `json:"start"`
	End    int64  `json:"end,omitempty"`
	Status string `json:"status"`
}

// StartTime ist der Start des Tasks.
func (t PBSTask) StartTime() time.Time { return time.Unix(t.Start, 0) }

// ServicesDown: Dienste aus pbsServices, die nicht laufen (nur gelesene).
func (p *PBSInfo) ServicesDown() []string {
	if p == nil {
		return nil
	}
	var out []string
	for _, s := range p.Services {
		if s.State != "running" {
			out = append(out, s.Name)
		}
	}
	return out
}

// PBSDatastore ist ein Datastore aus /status/datastore-usage.
type PBSDatastore struct {
	Store   string  `json:"store"`
	Total   int64   `json:"total"`
	Used    int64   `json:"used"`
	Avail   int64   `json:"avail"`
	Full    int64   `json:"estimated_full,omitempty"` // Unix-Zeit „geschaetzt voll“ (0 = keine Schaetzung)
	Error   string  `json:"error,omitempty"`
	Mount   string  `json:"mount_status,omitempty"` // mounted, notmounted, nonremovable
	Backend string  `json:"backend,omitempty"`      // filesystem, s3
	Dedup   float64 `json:"dedup,omitempty"`        // Dedup-Faktor der letzten Garbage Collection (logisch / auf Disk)
	// aus den Gruppen aller Namespaces (alle 10 min; Known = gelesen)
	Known      bool  `json:"backups_known,omitempty"`
	Groups     int   `json:"groups,omitempty"`
	Snapshots  int   `json:"snapshots,omitempty"`
	LastBackup int64 `json:"last_backup,omitempty"` // Unix-Zeit
}

// UsedPercent: Belegung in Prozent; ok = Groesse bekannt.
func (d PBSDatastore) UsedPercent() (float64, bool) {
	if d.Total <= 0 || d.Used < 0 {
		return 0, false
	}
	return float64(d.Used) * 100 / float64(d.Total), true
}

// FullTime: Zeitpunkt „geschaetzt voll“; ok = in der Zukunft (eine Schaetzung in der Vergangenheit heisst laut API:
// Belegung sinkt oder bleibt gleich).
func (d PBSDatastore) FullTime(now time.Time) (time.Time, bool) {
	if d.Full <= 0 {
		return time.Time{}, false
	}
	t := time.Unix(d.Full, 0)
	return t, t.After(now)
}

// IsPBS sagt, ob das System ein Proxmox Backup Server ist.
func (s *System) IsPBS() bool { return s != nil && s.Kind == KindPBS }

// pbsNodeStatus ist die Antwort von /nodes/localhost/status.
type pbsNodeStatus struct {
	CPU     pveNum `json:"cpu"`
	CPUInfo struct {
		CPUs pveNum `json:"cpus"`
	} `json:"cpuinfo"`
	Memory struct {
		Total pveNum `json:"total"`
		Used  pveNum `json:"used"`
	} `json:"memory"`
	Root struct {
		Total pveNum `json:"total"`
		Used  pveNum `json:"used"`
	} `json:"root"`
	Uptime pveNum `json:"uptime"`
}

// pbsNode ist der Name des einzigen Nodes eines PBS (Key node/localhost).
const pbsNode = "localhost"

// pbsUsage ist ein Eintrag aus /status/datastore-usage (history laesst Node64 weg).
type pbsUsage struct {
	Store   string `json:"store"`
	Total   pveNum `json:"total"`
	Used    pveNum `json:"used"`
	Avail   pveNum `json:"avail"`
	Full    pveNum `json:"estimated-full-date"`
	Error   string `json:"error"`
	Mount   string `json:"mount-status"`
	Backend string `json:"backend-type"`
	GC      struct {
		Disk  pveNum `json:"disk-bytes"`
		Index pveNum `json:"index-data-bytes"`
	} `json:"gc-status"`
}

// pbsBackups sind Gruppen, Snapshots und letztes Backup eines Datastores.
type pbsBackups struct {
	groups, snapshots int
	last              int64
}

// PBSPoller fragt einen Proxmox Backup Server ab (Source).
type PBSPoller struct {
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
	failing   bool
	paced     bool
	prevUp    int64 // Uptime der letzten Abfrage (Neustart erkennen)
	apiLat    time.Duration
	slowAt    time.Time
	update    string
	updateOK  bool
	backups   map[string]pbsBackups // Store -> Gruppen usw. (alle pbsSlowEvery)
	failed    []PBSTask
}

// NewPBSPoller baut die Abfrage eines PBS. fn darf nil sein.
func NewPBSPoller(log *slog.Logger, sys System, fn SnapshotFunc) *PBSPoller {
	if log == nil {
		log = slog.Default()
	}
	c, err := NewClient(sys)
	return newPBSPoller(log, sys, fn, c, err)
}

func newPBSPoller(log *slog.Logger, sys System, fn SnapshotFunc, c *Client, err error) *PBSPoller {
	return &PBSPoller{log: log.With("pbs", sys.Name, "system_id", sys.ID), sys: sys, fn: fn, client: c, initErr: err,
		now: time.Now, interval: ClampInterval(sys.Interval)}
}

// Last ist der letzte Snapshot (nil vor der ersten Abfrage).
func (p *PBSPoller) Last() *Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last
}

// Run fragt ab, bis ctx endet (nach Fehlern frueher, wie Poller.Run).
func (p *PBSPoller) Run(ctx context.Context) {
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

// Poll ist eine Abfrage (nicht gleichzeitig aufrufen).
func (p *PBSPoller) Poll(ctx context.Context) *Snapshot {
	now := p.now()
	s := &Snapshot{SystemID: p.sys.ID, Time: now, Resources: []Resource{}}
	err := p.initErr
	if err == nil {
		err = p.collect(ctx, now, s)
	}
	if err != nil {
		s.OK, s.Error, s.Resources, s.PBS = false, err.Error(), []Resource{}, nil
		if !p.failing {
			p.log.Warn("pbs api failed", "err", s.Error)
		}
		p.failing = true
	} else {
		s.OK = true
		if p.failing {
			p.log.Info("pbs api reachable again", "address", s.Address)
		}
		p.failing = false
	}
	if p.client != nil {
		s.Address = p.client.Address()
	}
	s.Version, s.APILatency = p.version, p.apiLat
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

// pbsVersionText: "4.2" + Release "6" -> "4.2.6" (wie die Paketversion von proxmox-backup-server).
func pbsVersionText(v pveVersion) string {
	ver, rel := strings.TrimSpace(v.Version), strings.TrimSpace(v.Release)
	if ver != "" && rel != "" && strings.Count(ver, ".") == 1 && strings.Trim(rel, "0123456789") == "" {
		return ver + "." + rel
	}
	return ver
}

func (p *PBSPoller) collect(ctx context.Context, now time.Time, s *Snapshot) error {
	if p.version == "" || now.Sub(p.versionAt) >= pveVersionEvery {
		var v pveVersion
		if err := p.client.Get(ctx, "/version", &v); err != nil {
			return err
		}
		p.version, p.versionAt = pbsVersionText(v), now
	}
	t0 := time.Now()
	var st pbsNodeStatus
	if err := p.client.Get(ctx, "/nodes/localhost/status", &st); err != nil {
		if errors.Is(err, ErrPermission) {
			return errors.New("the token may not read the host status (Sys.Audit on /system/status missing): " + err.Error())
		}
		return err
	}
	p.apiLat = time.Since(t0)
	name := strings.TrimSpace(p.sys.Name)
	if name == "" {
		name = pbsNode
	}
	r := Resource{Type: TypeNode, Node: pbsNode, Name: name, State: StateOnline, Status: "online",
		CPU: float64(st.CPU), MaxCPU: float64(st.CPUInfo.CPUs), Mem: int64(st.Memory.Used), MaxMem: int64(st.Memory.Total),
		Disk: int64(st.Root.Used), MaxDisk: int64(st.Root.Total), Uptime: int64(st.Uptime)}
	r.Restarted = p.prevUp > 0 && r.Uptime > 0 && r.Uptime < p.prevUp
	p.prevUp = r.Uptime
	// Netz und Disk-I/O: letzter Wert der RRD (Mittel je Minute, Byte/s); fehlt er, bleiben die Raten 0
	var rrd []map[string]pveNum
	if err := p.client.Get(ctx, "/nodes/localhost/rrd?timeframe=hour&cf=AVERAGE", &rrd); err == nil {
		for i := len(rrd) - 1; i >= 0; i-- { // die juengste Minute ist oft noch leer (null)
			if x := rrd[i]; x["netin"]+x["netout"]+x["read_bytes"]+x["write_bytes"] > 0 {
				r.NetIn, r.NetOut, r.DiskRead, r.DiskWrite = float64(x["netin"]), float64(x["netout"]), float64(x["read_bytes"]), float64(x["write_bytes"])
				break
			}
		}
	} else {
		p.log.Debug("pbs rrd failed", "err", err)
	}
	s.Resources = []Resource{r}
	info := &PBSInfo{Datastores: []PBSDatastore{}, Failed: []PBSTask{}}
	var svc []struct {
		Service string `json:"service"`
		State   string `json:"state"`
	}
	if err := p.client.Get(ctx, "/nodes/localhost/services", &svc); err == nil {
		for _, x := range svc {
			if slices.Contains(pbsServices, x.Service) {
				info.Services = append(info.Services, PBSService{Name: x.Service, State: x.State})
			}
		}
	}
	var use []pbsUsage
	if err := p.client.Get(ctx, "/status/datastore-usage", &use); err != nil {
		s.Warning = "datastore-usage failed: " + err.Error()
	} else {
		for _, u := range use {
			ds := PBSDatastore{Store: u.Store, Total: int64(u.Total), Used: int64(u.Used), Avail: int64(u.Avail), Full: int64(u.Full),
				Error: strings.TrimSpace(u.Error), Mount: u.Mount, Backend: u.Backend}
			if u.GC.Disk > 0 && u.GC.Index > 0 {
				ds.Dedup = float64(u.GC.Index) / float64(u.GC.Disk)
			}
			info.Datastores = append(info.Datastores, ds)
		}
		sort.Slice(info.Datastores, func(i, j int) bool { return info.Datastores[i].Store < info.Datastores[j].Store })
		if len(info.Datastores) == 0 {
			s.Warning = "the token sees no datastores (Datastore.Audit missing, or none configured)"
		}
	}
	if p.slowAt.IsZero() || now.Sub(p.slowAt) >= pbsSlowEvery {
		p.slowAt = now
		p.fetchSlow(ctx, now, info.Datastores)
	}
	for i := range info.Datastores {
		if b, ok := p.backups[info.Datastores[i].Store]; ok {
			ds := &info.Datastores[i]
			ds.Known, ds.Groups, ds.Snapshots, ds.LastBackup = true, b.groups, b.snapshots, b.last
		}
	}
	info.Update, info.UpdateOK = p.update, p.updateOK
	info.Failed = append(info.Failed, p.failed...)
	s.PBS = info
	return nil
}

// pbsNS ist ein Namespace aus /admin/datastore/{store}/namespace ("" = Wurzel).
type pbsNS struct {
	NS string `json:"ns"`
}

// fetchSlow liest die seltenen Angaben (Update, Backups je Datastore, fehlgeschlagene Tasks); Fehler lassen den
// vorigen Stand stehen bzw. die Angabe weg und sind nicht fatal.
func (p *PBSPoller) fetchSlow(ctx context.Context, now time.Time, stores []PBSDatastore) {
	var upd []struct {
		Package string `json:"Package"`
		Version string `json:"Version"`
	}
	if err := p.client.Get(ctx, "/nodes/localhost/apt/update", &upd); err == nil {
		p.update, p.updateOK = "", true
		for _, u := range upd {
			if u.Package == "proxmox-backup-server" {
				p.update = u.Version
			}
		}
	} else {
		p.updateOK = false
		p.log.Debug("pbs apt/update failed", "err", err)
	}
	backups := map[string]pbsBackups{}
	for _, ds := range stores {
		if ds.Error != "" || ds.Mount == "notmounted" {
			continue
		}
		if b, ok := p.storeBackups(ctx, ds.Store); ok {
			backups[ds.Store] = b
		} else if old, have := p.backups[ds.Store]; have {
			backups[ds.Store] = old
		}
	}
	p.backups = backups
	var tasks []struct {
		Type   string `json:"worker_type"`
		ID     string `json:"worker_id"`
		Start  pveNum `json:"starttime"`
		End    pveNum `json:"endtime"`
		Status string `json:"status"`
	}
	since := now.Add(-pbsTaskWindow).Unix()
	if err := p.client.Get(ctx, "/nodes/localhost/tasks?errors=1&limit="+strconv.Itoa(pbsMaxTasks)+"&since="+strconv.FormatInt(since, 10), &tasks); err == nil {
		p.failed = p.failed[:0]
		for _, t := range tasks {
			if t.Status == "" || t.Status == "OK" || int64(t.Start) < since {
				continue // laufend bzw. erfolgreich (errors=1 filtert schon, zur Sicherheit)
			}
			p.failed = append(p.failed, PBSTask{Type: t.Type, ID: t.ID, Start: int64(t.Start), End: int64(t.End), Status: t.Status})
		}
		sort.Slice(p.failed, func(i, j int) bool { return p.failed[i].Start > p.failed[j].Start })
	} else {
		p.log.Debug("pbs tasks failed", "err", err)
	}
}

// storeBackups zaehlt Gruppen und Snapshots eines Datastores ueber alle Namespaces (hoechstens pbsMaxNS).
func (p *PBSPoller) storeBackups(ctx context.Context, store string) (pbsBackups, bool) {
	var b pbsBackups
	base := "/admin/datastore/" + url.PathEscape(store)
	var ns []pbsNS
	if err := p.client.Get(ctx, base+"/namespace", &ns); err != nil {
		p.log.Debug("pbs namespaces failed", "store", store, "err", err)
		return b, false
	}
	if len(ns) == 0 {
		ns = []pbsNS{{}}
	}
	for i, n := range ns {
		if i >= pbsMaxNS {
			break
		}
		var groups []struct {
			Count pveNum `json:"backup-count"`
			Last  pveNum `json:"last-backup"`
		}
		q := ""
		if n.NS != "" {
			q = "?ns=" + url.QueryEscape(n.NS)
		}
		if err := p.client.Get(ctx, base+"/groups"+q, &groups); err != nil {
			p.log.Debug("pbs groups failed", "store", store, "ns", n.NS, "err", err)
			return b, false
		}
		for _, g := range groups {
			b.groups++
			b.snapshots += int(g.Count)
			b.last = max(b.last, int64(g.Last))
		}
	}
	return b, true
}

// pbsProbe ergaenzt den Test im Assistenten (nach Zertifikat und Token wie bei Proxmox VE): Version, Host-Status und
// Zahl der sichtbaren Datastores.
func pbsProbe(ctx context.Context, c *Client, sys System, res *ProbeResult) {
	var v pveVersion
	if err := c.Get(ctx, "/version", &v); err != nil {
		res.Error = err.Error()
		return
	}
	res.OK, res.Version = true, pbsVersionText(v)
	var warn []string
	var st pbsNodeStatus
	if err := c.Get(ctx, "/nodes/localhost/status", &st); err != nil {
		warn = append(warn, "the token may not read the host status (Sys.Audit on /system/status)")
	}
	var use []pbsUsage
	if err := c.Get(ctx, "/status/datastore-usage", &use); err != nil {
		warn = append(warn, "datastore-usage failed: "+err.Error())
	} else if res.Datastores = len(use); res.Datastores == 0 {
		warn = append(warn, "the token sees no datastores (fine if there are none)")
	}
	if len(warn) > 0 {
		res.PermWarning = strings.Join(warn, "; ") + " – grant role Audit on path / to the token (Configuration → Access Control → " +
			"Permissions → Add → API Token Permission, or: proxmox-backup-manager acl update / Audit --auth-id '" + sys.TokenID + "')"
	}
}
