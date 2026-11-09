package apis

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Proxmox Backup Server (Token mit Rolle Audit auf /). Ein PBS hat genau eine Node (localhost). Je Runde:
//
//	/nodes/localhost/status       CPU, Load, RAM, Swap, Root-Dateisystem
//	/status/datastore-usage       Datastores (ds:<store>): Fuellstand und Groesse ("voll in X Tagen" rechnet der Kern)
//	/admin/verify, /admin/prune,  letzter Lauf je Job (job:<art>:<id>)
//	/admin/sync, /admin/gc        (GC aelterer Versionen je Datastore: /admin/datastore/{store}/gc-job-status)
//
// Alle 10 min je Datastore /admin/datastore/{store}/namespace und /groups?ns= (Alter des letzten Backups je Gruppe,
// backup:<store>/[<ns>/]<typ>/<id>); SMART 30 min, Updates 60 min wie bei Proxmox VE.

const pbsNode = "localhost"

// PBSConfig sind die Verbindungsdaten eines Proxmox Backup Servers.
type PBSConfig struct {
	Addresses    []string      // https://host:8007
	TokenID      string        // user@realm!tokenid
	Secret       string        // Token-Secret (nie ausgeben)
	Pin          string        // SHA-256 des Zertifikats (hex); leer = System-CA
	BackupMaxAge time.Duration // letztes Backup einer Gruppe aelter -> backup_old (0 = DefaultBackupMaxAge)
	Timeout      time.Duration
	SmartEvery   time.Duration
	UpdatesEvery time.Duration
}

func (c PBSConfig) system() proxmox.System {
	return proxmox.System{Kind: proxmox.KindPBS, Addresses: c.Addresses, TokenID: c.TokenID, Secret: c.Secret, PinSHA256: c.Pin}
}

// PBS ist der Sammler eines Proxmox Backup Servers.
type PBS struct {
	cfg    PBSConfig
	client *proxmox.Client
	now    func() time.Time

	mu       sync.Mutex
	groupsAt time.Time
	groups   map[string][]pbsGroup // Datastore -> Gruppen (alle Namespaces)
	disks    slowDisks
	updates  slowUpdates
	gcPerDS  bool              // /admin/gc fehlt: GC-Status je Datastore
	gcUntil  time.Time         // GC-Status gar nicht vorhanden: bis dahin nicht fragen
	jobLast  map[string]pbsJob // Job-Schluessel -> letzter beendeter Lauf (waehrend ein Job laeuft)
}

// NewPBS baut den Sammler (prueft Adressen, Token-Format und Pin; fragt noch nichts ab).
func NewPBS(cfg PBSConfig) (*PBS, error) {
	c, err := proxmox.NewClient(cfg.system())
	if err != nil {
		return nil, scrubErr(err, cfg.Secret)
	}
	return &PBS{cfg: cfg, client: c, now: time.Now, groups: map[string][]pbsGroup{}, jobLast: map[string]pbsJob{}}, nil
}

func (p *PBS) timeout() time.Duration {
	if p.cfg.Timeout > 0 {
		return p.cfg.Timeout
	}
	return DefaultTimeout
}

func (p *PBS) maxAge() time.Duration {
	if p.cfg.BackupMaxAge > 0 {
		return p.cfg.BackupMaxAge
	}
	return DefaultBackupMaxAge
}

// Test prueft die Verbindung im Assistenten (Zertifikat, Token, Rechte, Datastores).
func (p *PBS) Test(ctx context.Context) TestResult {
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	pr := proxmox.Probe(ctx, p.cfg.system())
	res := TestResult{OK: pr.OK, Error: scrub(pr.Error, p.cfg.Secret), Version: pr.Version,
		Warning: scrub(pr.PermWarning, p.cfg.Secret), Fingerprint: pr.CertSHA256, CertSubject: pr.CertSubject,
		Trusted: pr.CertTrusted, NeedConfirm: pr.NeedConfirm}
	if pr.OK {
		res.Node = pbsNode
		res.Summary = fmt.Sprintf("%d Datastores", pr.Datastores)
	}
	return res
}

// pbsUsage ist ein Eintrag aus /status/datastore-usage.
type pbsUsage struct {
	Store   string `json:"store"`
	Total   num    `json:"total"`
	Used    num    `json:"used"`
	Avail   num    `json:"avail"`
	Error   string `json:"error"`
	Mount   string `json:"mount-status"`
	Backend string `json:"backend-type"`
}

// pbsGroup ist eine Backup-Gruppe aus /admin/datastore/{store}/groups.
type pbsGroup struct {
	NS      string `json:"-"`
	Type    string `json:"backup-type"`
	ID      string `json:"backup-id"`
	Last    num    `json:"last-backup"`
	Count   num    `json:"backup-count"`
	Comment string `json:"comment"`
}

// pbsJob ist der Status eines Jobs (verify, prune, sync, gc).
type pbsJob struct {
	ID      string `json:"id"`
	Store   string `json:"store"`
	Remote  string `json:"remote"`
	State   string `json:"last-run-state"`
	UPID    string `json:"last-run-upid"`
	End     num    `json:"last-run-endtime"`
	Next    num    `json:"next-run"`
	Sched   string `json:"schedule"`
	Disable bool   `json:"disable"`

	running bool // laeuft gerade (State/End sind dann vom vorigen Lauf)
}

// Collect ist eine Abfragerunde (nicht gleichzeitig mit sich selbst aufrufen).
func (p *PBS) Collect(ctx context.Context) ([]model.Service, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	now := p.now()
	part := &partial{secrets: []string{p.cfg.Secret}}
	var ns nodeStatus
	if err := p.client.Get(ctx, "/nodes/"+pbsNode+"/status", &ns); err != nil {
		return nil, scrubErr(err, p.cfg.Secret)
	}
	out := nodeServices(ns)
	if svc := p.updates.collect(ctx, p.client, pbsNode, now, p.cfg.UpdatesEvery, part); svc != nil {
		out = append(out, *svc)
	}
	var use []pbsUsage
	useErr := p.client.Get(ctx, "/status/datastore-usage", &use)
	if useErr != nil {
		// ohne Datastore-Liste fehlen die Datastores und der GC-Status je Datastore; die Gruppen (Backups) bleiben
		// auf dem vorigen Stand und werden in der naechsten Runde neu gelesen
		part.add("status/datastore-usage", useErr, "ds:", "job:gc:")
		use = nil
	}
	sort.Slice(use, func(i, j int) bool { return use[i].Store < use[j].Store })
	if useErr == nil && (p.groupsAt.IsZero() || now.Sub(p.groupsAt) >= slowEvery) {
		p.fetchGroups(ctx, use, part)
		p.groupsAt = now
	}
	for _, u := range use {
		out = append(out, p.datastoreService(u))
	}
	out = append(out, p.backupServices(now)...)
	out = append(out, p.jobs(ctx, now, use, useErr == nil, part)...)
	out = append(out, p.disks.collect(ctx, p.client, pbsNode, now, p.cfg.SmartEvery, func(d diskEntry) string { return d.dev() }, part)...)
	sortServices(out)
	return out, part.result()
}

func (p *PBS) datastoreService(u pbsUsage) model.Service {
	s := model.Service{Key: "ds:" + u.Store, Name: "Datastore " + u.Store, Kind: "ds", Default: true}
	var parts []string
	switch {
	case strings.TrimSpace(u.Error) != "":
		parts = append(parts, "Fehler: "+strings.TrimSpace(u.Error))
		s.Facts = append(s.Facts, model.Fact{Code: "store_inactive", Text: "Datastore " + u.Store + ": " + strings.TrimSpace(u.Error)})
	case u.Mount == "notmounted":
		parts = append(parts, "nicht eingehängt (Wechseldatenträger)")
	case u.Total > 0:
		tot := float64(u.Total)
		s.Metrics = []model.Metric{{Name: "used", Value: pct(float64(u.Used), tot), Unit: "%", Rule: model.RuleStore, Max: tot},
			{Name: "free", Value: float64(u.Avail), Unit: "B", Max: tot}}
		parts = append(parts, fmt.Sprintf("%s von %s frei", bytesText(float64(u.Avail)), bytesText(tot)))
	}
	if g, ok := p.groups[u.Store]; ok {
		snaps := 0
		for _, x := range g {
			snaps += int(x.Count)
		}
		parts = append(parts, fmt.Sprintf("%d Gruppen, %d Snapshots", len(g), snaps))
	}
	if u.Backend == "s3" {
		parts = append(parts, "S3")
	}
	s.Text = strings.Join(parts, " · ")
	return s
}

// fetchGroups liest die Gruppen aller Namespaces je Datastore; Fehler lassen den vorigen Stand des Datastores stehen.
func (p *PBS) fetchGroups(ctx context.Context, use []pbsUsage, part *partial) {
	next := map[string][]pbsGroup{}
	for _, u := range use {
		if strings.TrimSpace(u.Error) != "" || u.Mount == "notmounted" {
			if old, ok := p.groups[u.Store]; ok {
				next[u.Store] = old
			}
			continue
		}
		g, err := p.storeGroups(ctx, u.Store)
		if err != nil {
			part.add("groups "+u.Store, err, "backup:"+u.Store+"/")
			if old, ok := p.groups[u.Store]; ok {
				next[u.Store] = old
			}
			continue
		}
		next[u.Store] = g
	}
	p.groups = next
}

const pbsMaxNS = 50 // Namespaces je Datastore hoechstens

func (p *PBS) storeGroups(ctx context.Context, store string) ([]pbsGroup, error) {
	base := "/admin/datastore/" + url.PathEscape(store)
	var nss []struct {
		NS string `json:"ns"`
	}
	if err := p.client.Get(ctx, base+"/namespace", &nss); err != nil {
		if !absent(err) {
			return nil, err
		}
		nss = nil // PBS ohne Namespaces (vor 2.2): nur die Wurzel
	}
	if len(nss) == 0 {
		nss = append(nss, struct {
			NS string `json:"ns"`
		}{})
	}
	var out []pbsGroup
	for i, n := range nss {
		if i >= pbsMaxNS {
			break
		}
		q := ""
		if n.NS != "" {
			q = "?ns=" + url.QueryEscape(n.NS)
		}
		var gs []pbsGroup
		if err := p.client.Get(ctx, base+"/groups"+q, &gs); err != nil {
			return nil, err
		}
		for _, g := range gs {
			g.NS = n.NS
			out = append(out, g)
		}
	}
	return out, nil
}

// backupServices: je Gruppe das Alter des letzten Backups (backup_old ueber der Grenze).
func (p *PBS) backupServices(now time.Time) []model.Service {
	maxAge := p.maxAge()
	stores := make([]string, 0, len(p.groups))
	for st := range p.groups {
		stores = append(stores, st)
	}
	sort.Strings(stores)
	var out []model.Service
	for _, st := range stores {
		for _, g := range p.groups[st] {
			if g.Type == "" || g.ID == "" {
				continue
			}
			where := st
			if g.NS != "" {
				where += "/" + g.NS
			}
			key := "backup:" + where + "/" + g.Type + "/" + g.ID
			name := "Backup " + g.Type + "/" + g.ID
			if c := strings.TrimSpace(g.Comment); c != "" {
				name += " " + c
			}
			name += " (" + where + ")"
			s := model.Service{Key: key, Name: name, Kind: "backup", Default: true,
				Metrics: []model.Metric{{Name: "count", Value: float64(g.Count)}}}
			if g.Last <= 0 {
				s.Text = "noch kein Backup"
				out = append(out, s)
				continue
			}
			age := now.Sub(time.Unix(int64(g.Last), 0))
			if age < 0 {
				age = 0
			}
			s.Metrics = append(s.Metrics, model.Metric{Name: "age", Value: round2(age.Hours()), Unit: "h"})
			s.Text = fmt.Sprintf("letztes Backup %s · %.0f Snapshots", agoText(age), float64(g.Count))
			if age > maxAge {
				s.Facts = append(s.Facts, model.Fact{Code: "backup_old",
					Text: fmt.Sprintf("letztes Backup %s (Grenze %s)", agoText(age), hoursText(maxAge))})
			}
			s.Default = age < staleAfter // lange ohne Backup: wohl eine alte Gruppe, beim Erkennen nicht vorgewaehlt
			out = append(out, s)
		}
	}
	return out
}

// jobs: letzter Lauf der Verify-, Prune-, Sync- und GC-Jobs.
func (p *PBS) jobs(ctx context.Context, now time.Time, use []pbsUsage, useOK bool, part *partial) []model.Service {
	var out []model.Service
	seen := map[string]bool{}
	failed := map[string]bool{} // Art -> Liste nicht lesbar (gemerkte Laeufe behalten)
	add := func(kind, id string, j pbsJob) {
		key := "job:" + kind + ":" + id
		seen[key] = true
		out = append(out, jobService(kind, id, p.jobState(key, j), now))
	}
	for _, kind := range []string{"verify", "prune", "sync"} {
		var list []pbsJob
		if err := p.client.Get(ctx, "/admin/"+kind, &list); err != nil {
			if !absent(err) {
				part.add("admin/"+kind, err, "job:"+kind+":")
				failed[kind] = true
			}
			continue
		}
		for _, j := range list {
			if j.ID == "" {
				continue
			}
			add(kind, j.ID, j)
		}
	}
	gc, gcOK := p.gcJobs(ctx, now, use, part)
	failed["gc"] = !gcOK || !useOK // ohne Datastore-Liste fehlt der GC-Status je Datastore
	for _, j := range gc {
		add("gc", j.Store, j)
	}
	for k := range p.jobLast {
		kind, _, _ := strings.Cut(strings.TrimPrefix(k, "job:"), ":")
		if !seen[k] && !failed[kind] {
			delete(p.jobLast, k)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// jobState: Laeuft ein Job gerade, nennt PBS nur last-run-upid (ohne Ende und Ergebnis). Dann gilt der zuletzt
// bekannte beendete Lauf weiter (sonst wuerde ein fehlgeschlagener Job bei jedem Lauf kurz "ok"); beendete Laeufe
// werden gemerkt.
func (p *PBS) jobState(key string, j pbsJob) pbsJob {
	if j.UPID == "" || j.End > 0 || strings.TrimSpace(j.State) != "" {
		if j.End > 0 || strings.TrimSpace(j.State) != "" {
			p.jobLast[key] = j
		}
		return j
	}
	j.running = true
	if last, ok := p.jobLast[key]; ok {
		j.State, j.End = last.State, last.End
	}
	return j
}

// gcJobs liefert den GC-Status; ok false, wenn er (ganz oder teilweise) nicht lesbar war.
func (p *PBS) gcJobs(ctx context.Context, now time.Time, use []pbsUsage, part *partial) ([]pbsJob, bool) {
	if now.Before(p.gcUntil) {
		return nil, true
	}
	if !p.gcPerDS {
		var list []pbsJob
		err := p.client.Get(ctx, "/admin/gc", &list)
		if err == nil {
			return list, true
		}
		if !absent(err) {
			part.add("admin/gc", err, "job:gc:")
			return nil, false
		}
		p.gcPerDS = true
	}
	ok := true
	var out []pbsJob
	for _, u := range use {
		if strings.TrimSpace(u.Error) != "" || u.Mount == "notmounted" {
			continue
		}
		var j pbsJob
		err := p.client.Get(ctx, "/admin/datastore/"+url.PathEscape(u.Store)+"/gc-job-status", &j)
		if err != nil {
			if absent(err) { // zu alte Version: kein GC-Status
				p.gcUntil, p.gcPerDS = now.Add(optionalRetry), false
				return nil, true
			}
			part.add("gc-job-status "+u.Store, err, "job:gc:"+u.Store)
			ok = false
			continue
		}
		j.Store = firstNonEmpty(j.Store, u.Store)
		out = append(out, j)
	}
	return out, ok
}

var jobNames = map[string]string{"verify": "Verify-Job", "prune": "Prune-Job", "sync": "Sync-Job", "gc": "Garbage Collection"}

// jobService: letzter Lauf ok bzw. Fehler (job_failed); WARNINGS zaehlt als gelaufen, "unknown" (abgebrochen, z. B.
// durch einen Neustart des PBS) als Fehler (die Regel job.failed warnt).
func jobService(kind, id string, j pbsJob, now time.Time) model.Service {
	name := jobNames[kind] + " " + id
	if kind != "gc" && j.Store != "" {
		name += " (" + j.Store + ")"
	}
	s := model.Service{Key: "job:" + kind + ":" + id, Name: name, Kind: "job", Default: !j.Disable}
	state := strings.TrimSpace(j.State)
	var parts []string
	if j.running && !j.Disable {
		parts = append(parts, "läuft gerade")
	}
	switch {
	case j.Disable:
		parts = append(parts, "abgeschaltet")
	case j.running && j.End <= 0 && state == "":
		// erster bekannter Lauf: noch kein Ergebnis (keine Messgroesse)
	case j.End <= 0 && state == "":
		parts = append(parts, "noch nicht gelaufen")
	default:
		when := ""
		if j.End > 0 {
			age := max(now.Sub(time.Unix(int64(j.End), 0)), 0)
			when = " " + agoText(age)
			s.Metrics = append(s.Metrics, model.Metric{Name: "age", Value: round2(age.Hours()), Unit: "h"})
		}
		ok := state == "" || strings.EqualFold(state, "OK") || strings.HasPrefix(strings.ToUpper(state), "WARNINGS")
		v := 0.0
		if !ok {
			v = 1
		}
		s.Metrics = append(s.Metrics, model.Metric{Name: "failed", Value: v})
		switch {
		case ok:
			parts = append(parts, "letzter Lauf"+when+": "+firstNonEmpty(state, "OK"))
		case strings.EqualFold(state, "unknown"):
			parts = append(parts, "letzter Lauf"+when+" abgebrochen (unknown)")
			s.Facts = append(s.Facts, model.Fact{Code: "job_failed", Text: "abgebrochen (unknown)"})
		default:
			parts = append(parts, "letzter Lauf"+when+" fehlgeschlagen: "+state)
			s.Facts = append(s.Facts, model.Fact{Code: "job_failed", Text: state})
		}
	}
	if j.Sched != "" {
		parts = append(parts, "Zeitplan "+j.Sched)
	}
	s.Text = strings.Join(parts, " · ")
	return s
}
