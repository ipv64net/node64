// Package cdn64 ist das Modul CDN64: ein Reverse-Proxy-Manager im Funktionsumfang des Nginx Proxy Manager, ohne
// nginx (Go selbst, HTTP/2 und HTTP/3). Hosts melden sich beim gemeinsamen Eingang des Kerns (edge) an,
// Zertifikate kommen aus der Zertifikatsverwaltung des Kerns (certs). Plan: docs/PLAN-NODE64-CDN64.md.
//
// Ausgeschaltet laeuft nichts: keine Routen beim Eingang (der schliesst dann seine Ports), keine Pruefung der
// Ziele, keine Erneuerung der Zertifikate fuer CDN64, Cache freigegeben.
package cdn64

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/ports"
	"github.com/ipv64net/node64/internal/store"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

//go:embed templates
var templateFS embed.FS

// changelog wird unter Einstellungen > Module angezeigt (Version siehe Info).
//
//go:embed CHANGELOG.md
var changelog string

//go:embed CHANGELOG.en.md
var changelogEN string

const (
	Name    = "cdn64"
	Version = "1.38.0"
)

const cacheLimit = 64 << 20 // Asset-Cache aller Hosts zusammen

// Module implementiert module.Module.
type Module struct {
	core    *store.Store
	log     *slog.Logger
	edge    *edge.Edge
	certs   *certs.Manager
	version string
	g       module.Guards

	applyMu    sync.Mutex
	mu         sync.Mutex
	running    bool
	startedAt  time.Time
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	stats      map[int64]*hostStats
	routeErr   map[int64]string
	loopToken  string
	trVerify   *http.Transport
	trInsecure *http.Transport
	cache      *assetCache
	reach      *reacher
	ports      *ports.Registry         // Pruefung der Stream-Ports (nil = keine)
	dataDir    string                  // fuer cdn64.db ("" = keine Statistik)
	stats2     atomic.Pointer[statsDB] // Statistik und Zugriffs-Log (nur bei laufendem Modul)
	acl        map[int64]*guard
	authFail   *failLimiter
	loginKey   atomic.Pointer[[]byte] // Schluessel der Sitzungs-Cookies der Login-Seite (access_login.go)
	loginKeyMu sync.Mutex
	hostTr     map[int64]*http.Transport
	checks     CheckCreator    // Healthcheck anlegen (nil = nicht verfuegbar)
	findChecks CheckFinder     // Healthchecks lesen ("ueberwacht" in der Liste; nil = nicht verfuegbar)
	bl         *blocklists     // ipv64-Blocklisten
	lim        *limiter        // Schutz vor Ueberlastung
	hp         hpState         // Honeypot64: Koeder, Zugriffe, Sofort-Sperre (honeypot.go)
	online     onlineState     // CDN64 online (Tunnel zu srv07/srv08)
	dnsrec     DNSRecords      // DNS-Records bei ipv64 (nil = nicht verfuegbar)
	localDNS   func() LocalDNS // eigene Eintraege in DNS64 (nil bzw. Ergebnis nil = DNS64 aus)
	status     StatusPages     // Statusseiten der Healthchecks (nil = nicht verfuegbar)
	dk         dockerState     // Proxy-Hosts aus Docker-Labels (docker.go)

	sapply sync.Mutex // ein Abgleich der Streams gleichzeitig
	smu    sync.Mutex // Streams (nur kurz halten)
	runs   map[int64]*streamRun
	sstats map[int64]*streamStats
	sreach *reacher
}

// New erzeugt das Modul. edge und certs kommen aus dem Kern (nil nur in Tests ohne Eingang).
func New(core *store.Store, log *slog.Logger, e *edge.Edge, c *certs.Manager, version string) *Module {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	m := &Module{core: core, log: log.With("module", Name), edge: e, certs: c, version: version, stats: map[int64]*hostStats{},
		routeErr: map[int64]string{}, loopToken: hex.EncodeToString(b), trVerify: newTransport(true), trInsecure: newTransport(false),
		cache: newAssetCache(cacheLimit), reach: newReacher(), runs: map[int64]*streamRun{}, sstats: map[int64]*streamStats{}, sreach: newReacher(),
		acl: map[int64]*guard{}, authFail: newFailLimiter(), hostTr: map[int64]*http.Transport{}, bl: newBlocklists(), lim: newLimiter()}
	m.online.kick = make(chan struct{}, 1)
	m.dk.kick = make(chan struct{}, 1)
	m.lim.onBan = func(ip netip.Addr, until time.Time) {
		m.log.Warn("cdn64 limits: address banned", "ip", limShow(ip), "until", until.Format(time.RFC3339))
	}
	return m
}

// SetDataDir legt fest, wo cdn64.db liegt (Statistik, Zugriffs-Log).
func (m *Module) SetDataDir(dir string) { m.dataDir = dir }

// CheckCreator legt einen Healthchecks-Check an (JSON wie POST /api/checks) und liefert seinen Token.
type CheckCreator func(r *http.Request, body []byte) (token string, err error)

// SetCheckCreator haengt das Anlegen von Healthchecks an ("Healthcheck fuer dieses Ziel").
func (m *Module) SetCheckCreator(f CheckCreator) { m.checks = f }

// SetPorts haengt die Port-Verwaltung an (Streams pruefen ihre Ports vor dem Oeffnen).
func (m *Module) SetPorts(r *ports.Registry) { m.ports = r }

func (m *Module) Info() module.Info {
	return module.Info{Name: Name, TitleKey: "nav.proxy", Icon: "bi-diagram-3", Path: "/cdn64", Available: true, Order: 30,
		Version: Version, Changelog: changelog, ChangelogEN: changelogEN}
}

func (m *Module) Migrations() []store.Migration {
	ms, err := store.ReadMigrations(migrationFS, "migrations")
	if err != nil {
		panic(err)
	}
	return ms
}

// Templates liefert die Seiten des Moduls (module.Templater).
func (m *Module) Templates() fs.FS {
	sub, _ := fs.Sub(templateFS, "templates")
	return sub
}

func (m *Module) Routes(mux *http.ServeMux, g module.Guards) {
	m.g = g
	m.uiRoutes(mux, g)
	m.apiRoutes(mux, g)
}

// Start meldet die Hosts beim Eingang an und startet die Pruefung der Ziele.
func (m *Module) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	ctx, m.cancel = context.WithCancel(ctx)
	m.running, m.startedAt = true, time.Now()
	m.wg.Add(1)
	m.mu.Unlock()
	if m.dataDir != "" {
		st, err := openStats(filepath.Join(m.dataDir, Name), m.log, func() int { return m.logDays(context.Background()) },
			func() bool { return m.core.SettingOr(context.Background(), setAnonymize, "off") == "mask" })
		if err != nil {
			m.log.Warn("cdn64 statistics not available", "err", err)
		} else {
			m.stats2.Store(st)
		}
	}
	if m.certs != nil {
		m.certs.SetUsers(Name, m.certUsers)
		m.certs.Acquire(Name)
	}
	m.limLoad(ctx)
	m.apply(ctx)
	m.applyStreams(ctx)
	m.onlineStart(ctx)
	go func() { defer m.wg.Done(); m.reachLoop(ctx) }()
	m.wg.Add(1)
	go func() { defer m.wg.Done(); m.onlineLoop(ctx) }()
	m.wg.Add(1)
	go func() { defer m.wg.Done(); m.onlineMonitor(ctx) }()
	m.wg.Add(1)
	go func() { defer m.wg.Done(); m.blLoop(ctx) }()
	m.wg.Add(1)
	go func() { defer m.wg.Done(); m.limLoop(ctx) }()
	m.wg.Add(1)
	go func() { defer m.wg.Done(); m.dockerLoop(ctx) }()
	if m.edge != nil {
		m.edge.SetBlocker(m.blockedAny)
		m.edge.SetGate(m.gateOpen)
		m.edge.SetTunnelHTTP3(m.onlineHTTP3)
	}
	m.hpStart(ctx)
	m.log.Info("cdn64 started")
	return nil
}

// Stop meldet alles beim Eingang ab und beendet die Pruefung.
func (m *Module) Stop(ctx context.Context) error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = false
	cancel := m.cancel
	m.cancel = nil
	m.mu.Unlock()
	m.onlineStop()
	m.applyMu.Lock() // laufendes apply abwarten, danach meldet keins mehr an
	m.hpStop()
	if m.edge != nil {
		m.edge.Remove(Name)
		m.edge.SetBlocker(nil)
		m.edge.SetGate(nil)
		m.edge.SetTunnelHTTP3(nil)
	}
	m.applyMu.Unlock()
	m.stopStreams()
	if m.certs != nil {
		m.certs.Release(Name)
		m.certs.SetUsers(Name, nil)
	}
	cancel()
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	m.cache.clear()
	st := m.stats2.Swap(nil)
	m.mu.Lock()
	for id, tr := range m.hostTr {
		tr.CloseIdleConnections()
		delete(m.hostTr, id)
	}
	m.mu.Unlock()
	if st != nil {
		st.close()
	}
	m.trVerify.CloseIdleConnections()
	m.trInsecure.CloseIdleConnections()
	m.log.Info("cdn64 stopped")
	return nil
}

// Card liefert die Dashboard-Karte (module.CardProvider).
func (m *Module) Card(ctx context.Context) (*module.Card, error) {
	c := &module.Card{TitleKey: "nav.proxy", Icon: "bi-diagram-3", Path: "/cdn64"} // PROXY64-Logo folgt
	list, err := m.hosts(ctx)
	if err != nil {
		return nil, err
	}
	var on, down int64
	var req int64
	for _, h := range list {
		if !h.Enabled {
			continue
		}
		on++
		if m.reach.get(h.ID).State == ReachDown {
			down++
		}
		req += m.statsOf(h.ID).requests.Load()
	}
	c.Stats = []module.CardStat{{LabelKey: "cdn64.card.hosts", Value: on}}
	if sl, err := m.streams(ctx); err == nil && len(sl) > 0 {
		var son int64
		for _, s := range sl {
			if s.Enabled {
				son++
			}
		}
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "cdn64.card.streams", Value: son})
	}
	if down > 0 {
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "cdn64.card.down", Value: down, Class: "text-danger"})
	} else {
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "cdn64.card.down", Value: 0})
	}
	// Zahlen der letzten 24 Stunden aus der Statistik (sonst Anfragen seit Start)
	if sdb := m.stats2.Load(); sdb != nil {
		if sums, err := sdb.sums(ctx, time.Now().Add(-24*time.Hour)); err == nil {
			var t HostStat
			for _, s := range sums {
				t.Requests += s.Requests
				t.S5 += s.S5
				t.Bytes += s.Bytes
				t.BytesIn += s.BytesIn
				t.Blocked += s.Blocked
			}
			c.Stats = append(c.Stats, module.CardStat{LabelKey: "cdn64.card.requests_24h", Value: t.Requests},
				module.CardStat{LabelKey: "cdn64.card.download_24h", Value: t.Bytes, Bytes: true}, module.CardStat{LabelKey: "cdn64.card.upload_24h", Value: t.BytesIn, Bytes: true})
			e5 := module.CardStat{LabelKey: "cdn64.card.errors_24h", Value: t.S5}
			if t.Requests > 0 && t.S5 > 0 {
				e5.Pct = float64(t.S5) * 100 / float64(t.Requests)
				if e5.Pct >= 5 {
					e5.Class = "text-danger"
				}
			}
			bl := module.CardStat{LabelKey: "cdn64.card.blocked_24h", Value: t.Blocked}
			if t.Blocked > 0 {
				bl.Class = "text-warning-emphasis"
			}
			c.Stats = append(c.Stats, e5, bl)
			req = -1
		}
	}
	if req >= 0 {
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "cdn64.card.requests", Value: req})
	}
	if m.certs != nil {
		var soon int64
		if cl, err := m.certs.List(ctx); err == nil {
			for _, x := range cl {
				if len(x.UsedBy) > 0 && !x.NotAfter.IsZero() && x.DaysLeft() < 14 {
					soon++
				}
			}
		}
		st := module.CardStat{LabelKey: "cdn64.card.certs_soon", Value: soon}
		if soon > 0 {
			st.Class = "text-warning-emphasis"
		}
		c.Stats = append(c.Stats, st)
	}
	// CDN64 online genutzt: Kontingent bei ipv64 (Domains, Traffic im Monat) als Balken wie auf der PROXY64-Seite
	if rm := m.online.remote.Load(); rm != nil && rm.Data != nil && len(rm.Data.Hosts) > 0 {
		c.Stats = append(c.Stats, quotaStats(newOnlineQuota(rm.Data.Quota, time.Now()))...)
	}
	if e := m.edgeError(); e != "" {
		c.Err = e
	}
	return c, nil
}

// quotaStats: Zeilen der Startseiten-Karte zum CDN-Kontingent (x / y mit Balken; gruen, ab 80 % oder wenn der Monat
// laut Prognose nicht reicht gelb, voll rot; dann mit Hinweis bis wann).
func quotaStats(q *onlineQuota) []module.CardStat {
	// Balken und Farbe wie auf der PROXY64-Seite aus newOnlineQuota (dort auch: Limit 0 und belegt = voll)
	row := func(key string, used, limit int64, bar float64, class string) module.CardStat {
		st := module.CardStat{LabelKey: key, Value: used, Max: limit, Bar: true, BarPct: bar, BarClass: class}
		switch st.BarClass {
		case "bg-danger":
			st.Class = "text-danger"
		case "bg-warning":
			st.Class = "text-warning-emphasis"
		}
		return st
	}
	dom := row("cdn64.online.q_domains", int64(q.Used), int64(q.Limit), q.DomBar, q.DomClass)
	tr := row("cdn64.online.q_traffic", q.Traffic, q.TrafficLimit, q.TrafficBar, q.TrafficClass)
	tr.Bytes = true
	if q.Short {
		tr.HintKey, tr.HintDate, tr.HintBytes, tr.HintClass = "cdn64.online.q_short", q.EmptyAt, q.Projected, "text-warning-emphasis"
	}
	return []module.CardStat{dom, tr}
}

// edgeError: ein Port des Eingangs, den CDN64 braucht, ist nicht offen.
func (m *Module) edgeError() string {
	if m.edge == nil {
		return ""
	}
	for _, l := range m.edge.Status().Listeners {
		if l.Needed && !l.Running && l.Error != "" {
			return l.Name + " (" + string(l.Proto) + " " + itoa(l.Port) + "): " + l.Error
		}
	}
	return ""
}

// published: im Docker-Bridge-Netz, ob HTTP/HTTPS des Eingangs auf dem Docker-Host veroeffentlicht sind (leer ohne
// Eingang oder ohne Hosts - dann lauscht der Eingang fuer PROXY64 nicht).
func (m *Module) published(ctx context.Context) edge.Published {
	if m.edge == nil {
		return edge.Published{}
	}
	return m.edge.Published(ctx)
}

// ---------------------------------------------------------------- Export / Import (module.Exporter)

type exportFile struct {
	Hosts       []*Host           `json:"hosts"`
	Streams     []*Stream         `json:"streams,omitempty"`
	AccessLists []*AccessList     `json:"access_lists,omitempty"` // mit Passwort-Hashes (Basic Auth)
	Settings    map[string]string `json:"settings,omitempty"`     // Blocklisten, Ausnahmen, Limits, Zugriffs-Log
	// Feste Zertifikate: Namen des Zertifikats je Host- bzw. Stream-ID der Quelle (IDs gelten nur dort). Beim
	// Import wird das Zertifikat mit genau diesen Namen gesucht (Zertifikate kommen vorher mit dem Backup des Kerns).
	HostCerts   map[int64][]string `json:"host_certs,omitempty"`
	StreamCerts map[int64][]string `json:"stream_certs,omitempty"`
	// Statusseiten: Slug der Seite je Host-ID der Quelle (Hostart status); beim Import auf die Seite gleichen
	// Slugs dieser Node umgehaengt (die Healthchecks kommen vorher mit dem Import).
	HostStatus map[int64]string `json:"host_status,omitempty"`
}

// exportSettings: Einstellungen, die zur Konfiguration gehoeren (nicht CDN64 online: Tunnel und Token gehoeren
// zu dieser Node; nicht das Listen-Token der v64 Blocklist, es gehoert zum Account). setHoneypot: die Schalter der
// Verbindung zum Honeypot (Koeder, Zugriffe, Sofort-Sperre), die Sperrliste selbst bleibt im Speicher.
var exportSettings = []string{setBlocklists, setBlockAllow, setLimits, setLogDays, setAnonymize, setHoneypot}

func (m *Module) Export(ctx context.Context) (any, error) {
	list, err := m.hosts(ctx)
	if err != nil {
		return nil, err
	}
	f := exportFile{Hosts: list, HostCerts: map[int64][]string{}, StreamCerts: map[int64][]string{}, HostStatus: map[int64]string{}, Settings: map[string]string{}}
	slugs := map[int64]string{}
	for _, p := range m.statusPages(ctx) {
		slugs[p.ID] = p.Slug
	}
	certNames := func(id int64) []string {
		if id <= 0 || m.certs == nil {
			return nil
		}
		if c, err := m.certs.Get(ctx, id); err == nil {
			return c.Names
		}
		return nil
	}
	for _, h := range list {
		if h.CertID > 0 { // Kennungen gelten nur auf dieser Node: Namen mitgeben, beim Import passendes suchen
			if n := certNames(h.CertID); len(n) > 0 {
				f.HostCerts[h.ID] = n
			}
			h.CertID = CertAuto
		}
		if h.Kind == KindStatus && slugs[h.StatusPageID] != "" {
			f.HostStatus[h.ID] = slugs[h.StatusPageID]
		}
	}
	if f.Streams, err = m.streams(ctx); err != nil {
		return nil, err
	}
	for _, s := range f.Streams {
		if n := certNames(s.TLSCertID); len(n) > 0 {
			f.StreamCerts[s.ID] = n
		}
		s.TLSCertID = 0
	}
	if f.AccessLists, err = m.accessLists(ctx); err != nil {
		return nil, err
	}
	for _, k := range exportSettings {
		if v := m.core.SettingOr(ctx, k, ""); v != "" {
			f.Settings[k] = v
		}
	}
	return f, nil
}

// Import legt Zugriffslisten, Hosts und Streams an, deren Namen bzw. Ports es hier noch nicht gibt, und setzt
// Einstellungen, die hier noch leer sind (nichts wird geaendert oder geloescht). Verweise auf Zugriffslisten werden
// auf die Listen dieser Node umgeschrieben, feste Zertifikate nach Namen gesucht.
func (m *Module) Import(ctx context.Context, raw json.RawMessage) (int, error) {
	var f exportFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, err
	}
	n := 0
	var firstErr error
	keep := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	acl, err := m.importACLs(ctx, f.AccessLists)
	if err != nil {
		return 0, err
	}
	n += acl.added
	certByNames := m.certIndex(ctx)
	pageBySlug := map[string]int64{}
	for _, p := range m.statusPages(ctx) {
		pageBySlug[p.Slug] = p.ID
	}
	for _, h := range f.Hosts {
		oldID := h.ID
		h.ID = 0
		h.AccessListID = acl.ids[h.AccessListID] // unbekannt -> 0 (keine)
		for i := range h.Locations {
			h.Locations[i].AccessListID = acl.ids[h.Locations[i].AccessListID]
		}
		if id := certByNames[nameKey(f.HostCerts[oldID])]; id > 0 {
			h.CertID = id
		}
		// Statusseite: die ID gilt nur auf der Quelle, daher ueber den Slug umhaengen. Fehlt die Seite hier, wird
		// der Host ausgeschaltet angelegt (sonst zeigte er womoeglich eine fremde Seite dieser Node). Ohne Slug im
		// Export (vor 1.21.4 oder Healthchecks dort aus) ist die Seite unbekannt: ebenso ausgeschaltet.
		if h.Kind == KindStatus {
			slug, ok := f.HostStatus[oldID]
			if id := pageBySlug[slug]; ok && id > 0 {
				h.StatusPageID = id
			} else if ok {
				h.Enabled = false
				keep(fmt.Errorf("cdn64: status page %q of %s not found – host switched off", slug, strings.Join(h.Names, ",")))
			} else if h.Enabled {
				h.Enabled = false
				keep(fmt.Errorf("cdn64: status page of %s unknown in export – host switched off", strings.Join(h.Names, ",")))
			}
		}
		if err := m.saveHost(ctx, h); err != nil {
			var fe *FieldError
			if errors.As(err, &fe) && fe.Key == "cdn64.err.name_taken" {
				continue // gibt es schon
			}
			keep(err)
			continue
		}
		n++
	}
	for _, s := range f.Streams {
		oldID := s.ID
		s.ID = 0
		s.OnlineName = "" // CDN64 gehoert zu dieser Node (wie Tunnel und Namen)
		s.TLSCertID = certByNames[nameKey(f.StreamCerts[oldID])]
		if err := m.saveStream(ctx, s); err != nil {
			var fe *FieldError
			if errors.As(err, &fe) && fe.Key == "cdn64.err.stream_port_taken" {
				continue // gibt es schon
			}
			keep(err)
			continue
		}
		n++
	}
	for _, k := range exportSettings {
		if v, ok := f.Settings[k]; ok && v != "" && m.core.SettingOr(ctx, k, "") == "" {
			if err := m.core.SetSetting(ctx, k, v); err != nil {
				keep(err)
			}
		}
	}
	m.hpLoad(ctx) // Honeypot-Schalter gleich wirksam
	m.apply(ctx)
	return n, firstErr
}

type aclImport struct {
	ids   map[int64]int64 // ID der Quelle -> ID hier (0 bleibt 0)
	added int
}

// importACLs: gleichnamige Liste hier wiederverwenden, sonst mit den Hashes der Quelle anlegen.
func (m *Module) importACLs(ctx context.Context, lists []*AccessList) (aclImport, error) {
	res := aclImport{ids: map[int64]int64{0: 0}}
	have, err := m.accessLists(ctx)
	if err != nil {
		return res, err
	}
	byName := map[string]int64{}
	for _, a := range have {
		byName[a.Name] = a.ID
	}
	for _, a := range lists {
		if a == nil || strings.TrimSpace(a.Name) == "" {
			continue
		}
		if id, ok := byName[a.Name]; ok {
			res.ids[a.ID] = id
			continue
		}
		ub, _ := json.Marshal(a.Users)
		rb, _ := json.Marshal(a.Rules)
		fb, _ := json.Marshal(a.Forward)
		if a.Keys == nil {
			a.Keys = []AccessKey{}
		}
		kb, _ := json.Marshal(a.Keys)
		now := store.Now()
		r, err := m.core.Writer().ExecContext(ctx, `INSERT INTO cdn_access_lists (name, satisfy_any, pass_auth, login_page, users, rules, auth, forward, pass_user, api_keys, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			a.Name, a.SatisfyAny, a.PassAuth, a.LoginPage, string(ub), string(rb), a.Auth, string(fb), a.PassUser, string(kb), now, now)
		if err != nil {
			return res, err
		}
		id, _ := r.LastInsertId()
		res.ids[a.ID], byName[a.Name] = id, id
		res.added++
	}
	return res, nil
}

// certIndex: Zertifikate dieser Node nach ihren Namen (sortiert, Komma).
func (m *Module) certIndex(ctx context.Context) map[string]int64 {
	out := map[string]int64{}
	if m.certs == nil {
		return out
	}
	list, err := m.certs.List(ctx)
	if err != nil {
		return out
	}
	for _, c := range list {
		if k := nameKey(c.Names); k != "" {
			if old, ok := out[k]; !ok || c.ID > old { // mehrere gleiche: das neueste
				out[k] = c.ID
			}
		}
	}
	return out
}

func nameKey(names []string) string {
	if len(names) == 0 {
		return ""
	}
	s := slices.Clone(names)
	slices.Sort(s)
	return strings.Join(s, ",")
}

// logDays: Aufbewahrung des Zugriffs-Logs in Tagen (1-90, Standard 7).
func (m *Module) logDays(ctx context.Context) int {
	n, err := strconv.Atoi(m.core.SettingOr(ctx, setLogDays, "7"))
	if err != nil || n < 1 || n > 90 {
		return 7
	}
	return n
}
