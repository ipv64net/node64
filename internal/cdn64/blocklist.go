package cdn64

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/shield"
)

// ipv64-Blocklisten: gepflegte Listen schadhafter IPs von ipv64.net (Spamhaus, FireHOL, DShield, Tor, blocklist.de
// und die zusammengefasste Gesamtliste), per Klick fuer den ganzen Reverse-Proxy eingeschaltet. Abgewiesen wird an
// erster Stelle: im gemeinsamen Eingang gleich nach dem Annehmen der Verbindung (vor TLS), in Streams beim Annehmen
// bzw. beim ersten Paket, und im Proxy zusaetzlich nach der echten Client-IP hinter vertrauenswuerdigen Proxys.
// Die Listen werden alle 30 Minuten nur bei Aenderung geladen (ETag) und unter /data/cdn64/blocklists
// zwischengespeichert, damit der Schutz nach einem Neustart sofort gilt. Private Netze stehen nie in den Listen.

const (
	setBlocklists  = "cdn64.blocklists"      // eingeschaltete Listen (Komma)
	setBlockAllow  = "cdn64.blocklist_allow" // Freigabeliste: Ausnahmen (Netze, Zeilen)
	setBlockDeny   = "cdn64.blocklist_deny"  // eigene Sperrliste (Netze, Zeilen; Reiter Zugriffslisten)
	blockNetsMax   = 5000                    // Zeilen je Freigabe-/Sperrliste
	blocklistBase  = "https://ipv64.net/blocklists/"
	blocklistEvery = 30 * time.Minute
	blocklistMax   = 32 << 20 // je Liste
)

// BlocklistInfo beschreibt eine Liste von ipv64.net.
type BlocklistInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	File string `json:"file"`
	Desc string `json:"desc"` // i18n-Schluessel cdn64.bl.desc.<id> (bekannte Listen), sonst leer
	// aus index.json (leer, solange sie nicht geladen ist)
	Category string `json:"category,omitempty"` // attack | botnet | tor | cloud | honeypot
	Text     string `json:"text,omitempty"`     // Beschreibung von ipv64.net (englisch), fuer Listen ohne Uebersetzung
	License  string `json:"license,omitempty"`
	Source   string `json:"source,omitempty"`
}

// Blocklists: die Listen auf ipv64.net (Dateinamen wie im Generator create_blocklists_v2.php). Gilt, bis
// blocklists/index.json geladen ist; danach kommt die Auswahl von dort (neue Listen ohne Update von Node64).
var Blocklists = []BlocklistInfo{
	{ID: "all", Name: "IPv64 Gesamtliste", File: "ipv64_blocklist_all.txt"},
	{ID: "spamhaus_drop", Name: "Spamhaus DROP", File: "ipv64_blocklist_spamhaus_drop.txt"},
	{ID: "firehole_l1", Name: "FireHOL Level 1", File: "ipv64_blocklist_firehole_l1.txt"},
	{ID: "blocklistde_all", Name: "blocklist.de (alle)", File: "ipv64_blocklist_blocklistde_all.txt"},
	{ID: "dshield1", Name: "DShield", File: "ipv64_blocklist_dshield1.txt"},
	{ID: "tor_exit", Name: "Tor Exit-Nodes", File: "ipv64_blocklist_tor_exit.txt"},
}

// blKnown: Listen mit eigenem Namen und Uebersetzung (cdn64.bl.desc.<id>); andere zeigen Name und Text aus index.json.
var blKnown = map[string]string{"all": "IPv64 Gesamtliste", "all_notor": "IPv64 Gesamtliste ohne Tor", "spamhaus_drop": "Spamhaus DROP",
	"firehole_l1": "FireHOL Level 1", "blocklistde_all": "blocklist.de (alle)", "dshield1": "DShield", "tor_exit": "Tor Exit-Nodes",
	"tor_all": "Tor (alle Relays)", "feodo": "abuse.ch Feodo Tracker", "et_compromised": "ET Compromised", "cins_army": "CINS Army",
	"ipsum_l3": "IPsum Level 3", "aws": "Amazon AWS", "gcp": "Google Cloud", "cloudflare": "Cloudflare",
	// ipv64 Honeypot (Kategorie honeypot, mit Listen-Token live); nur die eine Liste, keine Teillisten mehr
	"v64": "v64 Blocklist",
	// offizielle Netze von KI-Crawlern (Kategorie ai, aibots.go fuer die User-Agent-Liste)
	"ai_bots": "v64 KI-Bots (IP)"}

// list: Auswahl aus index.json, sonst die feste Liste (b.mu gehalten).
func (b *blocklists) list() []BlocklistInfo {
	if len(b.catalog) > 0 {
		return b.catalog
	}
	return Blocklists
}

// byID sucht eine Liste in der aktuellen Auswahl (b.mu gehalten).
func (b *blocklists) byID(id string) (BlocklistInfo, bool) {
	for _, x := range b.list() {
		if x.ID == id {
			return x, true
		}
	}
	return BlocklistInfo{}, false
}

func (b *blocklists) known(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.byID(id)
	return ok
}

// BlocklistState ist der Stand einer Liste (fuer Seite und API).
type BlocklistState struct {
	BlocklistInfo
	Enabled bool      `json:"enabled"`
	Entries int64     `json:"entries"`
	Updated time.Time `json:"updated,omitzero"` // zuletzt geladen bzw. bestaetigt
	Changed time.Time `json:"changed,omitzero"` // Inhalt zuletzt geaendert
	Error   string    `json:"error,omitempty"`

	// Kategorie honeypot (blocklist_live.go): geladene Fassung live | daily, Token ohne Berechtigung (ipv64 lieferte
	// den Tagesstand), Fehler des Live-Abrufs (dann Tagesstand geladen; ohne Token)
	Edition    string `json:"edition,omitempty"`
	LiveDenied bool   `json:"live_denied,omitempty"`
	LiveError  string `json:"live_error,omitempty"`
}

// blocklists ist der Zustand im Modul.
type blocklists struct {
	mu      sync.Mutex
	set     atomic.Pointer[shield.Set]
	nets    map[string][]netip.Prefix // je Liste (geladen)
	state   map[string]*BlocklistState
	etag    map[string]string
	blocked atomic.Int64               // abgewiesene Verbindungen/Anfragen seit dem Start
	deny    atomic.Pointer[shield.Set] // eigene Sperrliste (ohne Freigabeliste; nil = leer)
	denied  atomic.Int64               // davon abgewiesen seit dem Start
	kick    chan struct{}
	base    string // Basis-URL (Tests setzen einen eigenen Server)
	client  *http.Client

	// index.json und Laendersperre
	catalog   []BlocklistInfo // aus index.json (leer = feste Liste)
	countries []geoCountry    // Laender aus index.json (Auswahl im Formular)
	geo       geoSets         // Laenderlisten fuer die Laendersperre je Host

	src map[string]string // je Liste: Pfad, von dem sie geladen wurde (ETag gilt nur dafuer; live/daily)

	ai aiBots // User-Agent-Liste der KI-Bots (aibots.go)
}

func newBlocklists() *blocklists {
	return &blocklists{nets: map[string][]netip.Prefix{}, state: map[string]*BlocklistState{}, etag: map[string]string{}, kick: make(chan struct{}, 1),
		base: blocklistBase, client: &http.Client{Timeout: 60 * time.Second}}
}

// Blocked: Adresse steht in einer eingeschalteten Liste (und nicht in den Ausnahmen); zaehlt mit.
func (b *blocklists) Blocked(a netip.Addr) bool {
	if b.set.Load().Has(a) {
		b.blocked.Add(1)
		return true
	}
	return false
}

// Denied: Adresse steht in der eigenen Sperrliste (und nicht in der Freigabeliste).
func (b *blocklists) Denied(a netip.Addr) bool {
	if b.deny.Load().Has(a) {
		b.denied.Add(1)
		return true
	}
	return false
}

func (m *Module) blEnabled(ctx context.Context) []string {
	var out []string
	for _, id := range strings.Split(m.core.SettingOr(ctx, setBlocklists, ""), ",") {
		id = ipv64api.V64ListID(strings.TrimSpace(id)) // fruehere Teilliste der v64 Blocklist: die Hauptliste
		if m.bl.known(id) && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

func (m *Module) blAllow(ctx context.Context) []netip.Prefix { return m.blNets(ctx, setBlockAllow) }

func (m *Module) blDeny(ctx context.Context) []netip.Prefix { return m.blNets(ctx, setBlockDeny) }

func (m *Module) blNets(ctx context.Context, key string) []netip.Prefix {
	var out []netip.Prefix
	for _, l := range strings.Fields(m.core.SettingOr(ctx, key, "")) {
		if p, err := netip.ParsePrefix(l); err == nil {
			if p, ok := shield.NormPrefix(p); ok { // ::ffff:a.b.c.d/n gilt fuer IPv4
				out = append(out, p)
			}
		} else if a, err := netip.ParseAddr(l); err == nil {
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		}
	}
	return out
}

func (m *Module) blCacheDir() string {
	if m.dataDir == "" {
		return ""
	}
	return filepath.Join(m.dataDir, Name, "blocklists")
}

// rebuild baut die Sperrliste aus den geladenen Listen neu (eingeschaltete und Ausnahmen aus den Einstellungen).
func (m *Module) blRebuild(ctx context.Context) {
	b := m.bl
	enabled := m.blEnabled(ctx)
	b.mu.Lock()
	var lists [][]netip.Prefix
	for _, id := range enabled {
		lists = append(lists, b.nets[id])
	}
	b.mu.Unlock()
	allow := m.blAllow(ctx)
	b.geo.mu.Lock()
	b.geo.allow = allow // Ausnahmen gelten auch fuer die Laendersperre
	b.geo.mu.Unlock()
	set := shield.BuildSet(lists, allow)
	if set.Total() == 0 { // nichts eingeschaltet oder noch nichts geladen: nicht "aktiv"
		set = nil
	}
	b.set.Store(set)
	deny := shield.BuildSet([][]netip.Prefix{m.blDeny(ctx)}, allow) // die Freigabeliste geht vor
	if deny.Total() == 0 {
		deny = nil
	}
	b.deny.Store(deny)
}

// blLoadCache liest die zwischengespeicherten Listen (beim Start: Schutz sofort, ohne auf ipv64 zu warten).
func (m *Module) blLoadCache(ctx context.Context) {
	dir := m.blCacheDir()
	if dir == "" {
		return
	}
	m.blLoadIndexCache()
	m.geoLoadCache(ctx)
	m.aiLoadCache()
	for _, id := range m.blEnabled(ctx) {
		f, err := os.Open(filepath.Join(dir, id+".txt"))
		if err != nil {
			continue
		}
		nets, err := shield.ParseList(io.LimitReader(f, blocklistMax))
		fi, _ := f.Stat()
		f.Close()
		if err != nil {
			continue
		}
		m.bl.mu.Lock()
		m.bl.nets[id] = nets
		st := m.bl.stateOf(id)
		st.Entries = int64(len(nets))
		if fi != nil {
			st.Changed = fi.ModTime()
		}
		m.bl.mu.Unlock()
	}
	m.blRebuild(ctx)
}

func (b *blocklists) stateOf(id string) *BlocklistState {
	st := b.state[id]
	if st == nil {
		info, _ := b.byID(id)
		st = &BlocklistState{BlocklistInfo: info}
		b.state[id] = st
	}
	return st
}

// blFetch laedt eine Liste (nur bei Aenderung) und speichert sie zwischen. Listen der Kategorie honeypot kommen mit
// Listen-Token live (blocklist_live.go).
func (m *Module) blFetch(ctx context.Context, id string) error {
	m.bl.mu.Lock()
	info, _ := m.bl.byID(id)
	m.bl.mu.Unlock()
	if info.Category == blCatHoneypot {
		return m.blFetchHoneypot(ctx, id, info.File)
	}
	_, _, err := m.blFetchFrom(ctx, id, info.File)
	return err
}

// blFetchFrom laedt rel (relativ zur Basis-URL) als Liste id, nur bei Aenderung. list = Kopfzeile X-IPv64-List.
func (m *Module) blFetchFrom(ctx context.Context, id, rel string) (list string, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.bl.base+rel, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("User-Agent", "Node64/"+m.version)
	m.bl.mu.Lock()
	if e := m.bl.etag[id]; e != "" && len(m.bl.nets[id]) > 0 && m.bl.src[id] == rel {
		req.Header.Set("If-None-Match", e)
	}
	m.bl.mu.Unlock()
	resp, err := m.bl.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	now := time.Now()
	list = resp.Header.Get(blListHeader)
	if resp.StatusCode == http.StatusNotModified {
		m.bl.mu.Lock()
		m.bl.stateOf(id).Updated, m.bl.stateOf(id).Error = now, ""
		m.bl.mu.Unlock()
		return list, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, blHTTPError(resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "html") {
		return "", false, errors.New("no list (html answer)")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, blocklistMax+1))
	if err != nil {
		return "", false, err
	}
	if len(raw) > blocklistMax {
		return "", false, errors.New("list too large")
	}
	nets, err := shield.ParseList(bytes.NewReader(raw))
	if err != nil {
		return "", false, err
	}
	if len(nets) == 0 && len(bytes.TrimSpace(raw)) > 0 {
		return "", false, errors.New("no addresses in the list")
	}
	if dir := m.blCacheDir(); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err == nil {
			tmp := filepath.Join(dir, id+".txt.tmp")
			if os.WriteFile(tmp, raw, 0o640) == nil {
				_ = os.Rename(tmp, filepath.Join(dir, id+".txt"))
			}
		}
	}
	m.bl.mu.Lock()
	m.bl.nets[id] = nets
	m.bl.etag[id] = resp.Header.Get("ETag")
	if m.bl.src == nil {
		m.bl.src = map[string]string{}
	}
	m.bl.src[id] = rel
	st := m.bl.stateOf(id)
	st.Entries, st.Updated, st.Changed, st.Error = int64(len(nets)), now, now, ""
	m.bl.mu.Unlock()
	return list, false, nil
}

// blRefresh laedt alle eingeschalteten Listen und baut die Sperrliste neu.
func (m *Module) blRefresh(ctx context.Context) {
	if err := m.blFetchIndex(ctx); err != nil && ctx.Err() == nil {
		m.log.Warn("cdn64 blocklist index not loaded", "err", err)
	}
	m.blAutoToken(ctx) // Live-Fassung der v64 Blocklist ohne Token von Hand
	for _, id := range m.blEnabled(ctx) {
		if err := m.blFetch(ctx, id); err != nil && ctx.Err() == nil {
			m.log.Warn("cdn64 blocklist not loaded", "list", id, "err", err)
			m.bl.mu.Lock()
			m.bl.stateOf(id).Error = err.Error()
			m.bl.mu.Unlock()
		}
	}
	m.geoRefresh(ctx)
	m.aiRefresh(ctx)
	m.blRebuild(ctx)
}

// blLoop: beim Start aus dem Zwischenspeicher, dann laden, danach alle 30 Minuten oder nach einer Aenderung.
func (m *Module) blLoop(ctx context.Context) {
	m.blLoadCache(ctx)
	m.blRefresh(ctx)
	t := time.NewTicker(blocklistEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.bl.kick:
		}
		m.blRefresh(ctx)
	}
}

// blKick: Einstellungen geaendert oder "jetzt aktualisieren".
func (m *Module) blKick(ctx context.Context) {
	m.blRebuild(ctx) // ausgeschaltete Listen sofort weg
	select {
	case m.bl.kick <- struct{}{}:
	default:
	}
}

// blStates liefert den Stand aller Listen.
func (m *Module) blStates(ctx context.Context) []BlocklistState {
	on := map[string]bool{}
	for _, id := range m.blEnabled(ctx) {
		on[id] = true
	}
	m.bl.mu.Lock()
	defer m.bl.mu.Unlock()
	out := make([]BlocklistState, 0, len(m.bl.list()))
	for _, info := range m.bl.list() {
		st := *m.bl.stateOf(info.ID)
		st.BlocklistInfo = info // Name und Text koennen sich mit index.json aendern
		st.Enabled = on[info.ID]
		out = append(out, st)
	}
	return out
}

// blSave speichert eingeschaltete Listen und Ausnahmen.
func (m *Module) blSave(ctx context.Context, enabled []string, allow string) error {
	var ids []string
	for _, id := range enabled {
		id = ipv64api.V64ListID(id)
		if !m.bl.known(id) {
			return ferr("blocklists", "cdn64.bl.err_list")
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	lines, ok := netLines(allow)
	if !ok {
		return ferr("allow", "cdn64.bl.err_allow")
	}
	if err := m.core.SetSetting(ctx, setBlocklists, strings.Join(ids, ",")); err != nil {
		return err
	}
	if err := m.core.SetSetting(ctx, setBlockAllow, strings.Join(lines, "\n")); err != nil {
		return err
	}
	m.blKick(ctx)
	if list, err := m.hosts(ctx); err == nil { // Ausnahmen gelten auch fuer die Limits
		m.limExempt(ctx, list)
	}
	m.onlineKick() // Freigabeliste auch auf die CDN64-Server
	return nil
}

// netLines: Adressen oder Netze je Zeile; false bei einer ungueltigen Zeile oder zu vielen. Adressen mit Zone
// (fe80::1%eth0) sind ungueltig (das Portal lehnte sonst die ganze Liste ab), gemappte Netze kuerzer als /96 auch.
func netLines(s string) ([]string, bool) {
	var lines []string
	for _, l := range strings.Fields(s) {
		if p, err := netip.ParsePrefix(l); err == nil {
			if _, ok := shield.NormPrefix(p); !ok {
				return nil, false
			}
		} else if a, err := netip.ParseAddr(l); err != nil || a.Zone() != "" {
			return nil, false
		}
		if !slices.Contains(lines, l) {
			lines = append(lines, l)
		}
	}
	return lines, len(lines) <= blockNetsMax
}

// blListsSave speichert Freigabeliste und eigene Sperrliste (nil = unveraendert) und baut die Sperren neu.
func (m *Module) blListsSave(ctx context.Context, allow, deny *string) error {
	for _, l := range []struct {
		in        *string
		key, form string
	}{{allow, setBlockAllow, "allow"}, {deny, setBlockDeny, "deny"}} {
		if l.in == nil {
			continue
		}
		lines, ok := netLines(*l.in)
		if !ok {
			return ferr(l.form, "cdn64.sec.err_nets")
		}
		if err := m.core.SetSetting(ctx, l.key, strings.Join(lines, "\n")); err != nil {
			return err
		}
	}
	m.blRebuild(ctx)
	if list, err := m.hosts(ctx); err == nil { // die Freigabeliste gilt auch fuer die Limits
		m.limExempt(ctx, list)
	}
	m.onlineKick() // auch auf die CDN64-Server
	return nil
}

// blAllowAdd traegt eine Adresse oder ein Netz in die Freigabeliste ein (Freigeben einer automatischen Sperre).
func (m *Module) blAllowAdd(ctx context.Context, s string) error {
	cur := m.core.SettingOr(ctx, setBlockAllow, "")
	if slices.Contains(strings.Fields(cur), s) {
		return nil
	}
	cur = strings.TrimSpace(cur + "\n" + s)
	return m.blListsSave(ctx, &cur, nil)
}
