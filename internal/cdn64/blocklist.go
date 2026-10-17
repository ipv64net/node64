package cdn64

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ipv64-Blocklisten: gepflegte Listen schadhafter IPs von ipv64.net (Spamhaus, FireHOL, DShield, Tor, blocklist.de
// und die zusammengefasste Gesamtliste), per Klick fuer den ganzen Reverse-Proxy eingeschaltet. Abgewiesen wird an
// erster Stelle: im gemeinsamen Eingang gleich nach dem Annehmen der Verbindung (vor TLS), in Streams beim Annehmen
// bzw. beim ersten Paket, und im Proxy zusaetzlich nach der echten Client-IP hinter vertrauenswuerdigen Proxys.
// Die Listen werden alle 30 Minuten nur bei Aenderung geladen (ETag) und unter /data/cdn64/blocklists
// zwischengespeichert, damit der Schutz nach einem Neustart sofort gilt. Private Netze stehen nie in den Listen.

const (
	setBlocklists  = "cdn64.blocklists"      // eingeschaltete Listen (Komma)
	setBlockAllow  = "cdn64.blocklist_allow" // Ausnahmen (Netze, Zeilen)
	blocklistBase  = "https://ipv64.net/blocklists/"
	blocklistEvery = 30 * time.Minute
	blocklistMax   = 32 << 20 // je Liste
)

// BlocklistInfo beschreibt eine Liste von ipv64.net.
type BlocklistInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	File string `json:"file"`
	Desc string `json:"desc"` // i18n-Schluessel cdn64.bl.desc.<id>
}

// Blocklists: die Listen auf ipv64.net (Dateinamen wie im Generator create_blocklists_v2.php).
var Blocklists = []BlocklistInfo{
	{ID: "all", Name: "IPv64 Gesamtliste", File: "ipv64_blocklist_all.txt"},
	{ID: "spamhaus_drop", Name: "Spamhaus DROP", File: "ipv64_blocklist_spamhaus_drop.txt"},
	{ID: "firehole_l1", Name: "FireHOL Level 1", File: "ipv64_blocklist_firehole_l1.txt"},
	{ID: "blocklistde_all", Name: "blocklist.de (alle)", File: "ipv64_blocklist_blocklistde_all.txt"},
	{ID: "dshield1", Name: "DShield", File: "ipv64_blocklist_dshield1.txt"},
	{ID: "tor_exit", Name: "Tor Exit-Nodes", File: "ipv64_blocklist_tor_exit.txt"},
}

func blocklistByID(id string) (BlocklistInfo, bool) {
	for _, b := range Blocklists {
		if b.ID == id {
			return b, true
		}
	}
	return BlocklistInfo{}, false
}

// BlocklistState ist der Stand einer Liste (fuer Seite und API).
type BlocklistState struct {
	BlocklistInfo
	Enabled bool      `json:"enabled"`
	Entries int64     `json:"entries"`
	Updated time.Time `json:"updated,omitzero"` // zuletzt geladen bzw. bestaetigt
	Changed time.Time `json:"changed,omitzero"` // Inhalt zuletzt geaendert
	Error   string    `json:"error,omitempty"`
}

type v4Range struct{ lo, hi uint32 }

// blockSet ist die zusammengefasste Sperrliste (nur lesend nach dem Bau).
type blockSet struct {
	v4    []v4Range      // sortiert, zusammengefasst
	v6    []netip.Prefix // sortiert
	allow []netip.Prefix // Ausnahmen
	total int            // Eintraege vor dem Zusammenfassen
}

func v4u(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func (s *blockSet) has(a netip.Addr) bool {
	if s == nil || !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, p := range s.allow {
		if p.Contains(a) {
			return false
		}
	}
	if a.Is4() {
		x := v4u(a)
		i, _ := slices.BinarySearchFunc(s.v4, x, func(r v4Range, x uint32) int {
			switch {
			case r.hi < x:
				return -1
			case r.lo > x:
				return 1
			}
			return 0
		})
		return i < len(s.v4) && s.v4[i].lo <= x && x <= s.v4[i].hi
	}
	// IPv6: wenige Netze; das letzte Netz mit Startadresse <= a pruefen (enthaltene sind beim Bau entfernt)
	i, _ := slices.BinarySearchFunc(s.v6, a, func(p netip.Prefix, a netip.Addr) int { return p.Addr().Compare(a) })
	if i < len(s.v6) && s.v6[i].Contains(a) {
		return true
	}
	return i > 0 && s.v6[i-1].Contains(a)
}

// buildSet fasst die Netze aller Listen zusammen.
func buildSet(lists [][]netip.Prefix, allow []netip.Prefix) *blockSet {
	s := &blockSet{allow: allow}
	var v4 []v4Range
	var v6 []netip.Prefix
	for _, l := range lists {
		s.total += len(l)
		for _, p := range l {
			p = p.Masked()
			if p.Addr().Is4() {
				lo := v4u(p.Addr())
				hi := lo | (uint32(1)<<(32-p.Bits()) - 1)
				if p.Bits() == 0 {
					hi = ^uint32(0)
				}
				v4 = append(v4, v4Range{lo, hi})
			} else {
				v6 = append(v6, p)
			}
		}
	}
	slices.SortFunc(v4, func(a, b v4Range) int {
		if a.lo != b.lo {
			if a.lo < b.lo {
				return -1
			}
			return 1
		}
		return 0
	})
	for _, r := range v4 {
		if n := len(s.v4); n > 0 && r.lo <= s.v4[n-1].hi+1 && s.v4[n-1].hi != ^uint32(0) {
			if r.hi > s.v4[n-1].hi {
				s.v4[n-1].hi = r.hi
			}
			continue
		}
		s.v4 = append(s.v4, r)
	}
	slices.SortFunc(v6, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	for _, p := range v6 { // enthaltene Netze weglassen
		if n := len(s.v6); n > 0 && s.v6[n-1].Contains(p.Addr()) && s.v6[n-1].Bits() <= p.Bits() {
			continue
		}
		s.v6 = append(s.v6, p)
	}
	return s
}

// parseList liest eine Liste (ein Netz bzw. eine IP je Zeile, # Kommentare).
func parseList(r io.Reader) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if f := strings.Fields(line); len(f) > 0 {
			line = f[0]
		}
		if p, err := netip.ParsePrefix(line); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(line); err == nil {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out, sc.Err()
}

// blocklists ist der Zustand im Modul.
type blocklists struct {
	mu      sync.Mutex
	set     atomic.Pointer[blockSet]
	nets    map[string][]netip.Prefix // je Liste (geladen)
	state   map[string]*BlocklistState
	etag    map[string]string
	blocked atomic.Int64 // abgewiesene Verbindungen/Anfragen seit dem Start
	kick    chan struct{}
	base    string // Basis-URL (Tests setzen einen eigenen Server)
	client  *http.Client
}

func newBlocklists() *blocklists {
	return &blocklists{nets: map[string][]netip.Prefix{}, state: map[string]*BlocklistState{}, etag: map[string]string{}, kick: make(chan struct{}, 1),
		base: blocklistBase, client: &http.Client{Timeout: 60 * time.Second}}
}

// Blocked: Adresse steht in einer eingeschalteten Liste (und nicht in den Ausnahmen); zaehlt mit.
func (b *blocklists) Blocked(a netip.Addr) bool {
	if b.set.Load().has(a) {
		b.blocked.Add(1)
		return true
	}
	return false
}

func (b *blocklists) blockedAddr(a net.Addr) bool {
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return b.Blocked(ap.Addr())
	}
	return false
}

func (m *Module) blEnabled(ctx context.Context) []string {
	var out []string
	for _, id := range strings.Split(m.core.SettingOr(ctx, setBlocklists, ""), ",") {
		if _, ok := blocklistByID(strings.TrimSpace(id)); ok {
			out = append(out, strings.TrimSpace(id))
		}
	}
	return out
}

func (m *Module) blAllow(ctx context.Context) []netip.Prefix {
	var out []netip.Prefix
	for _, l := range strings.Fields(m.core.SettingOr(ctx, setBlockAllow, "")) {
		if p, err := netip.ParsePrefix(l); err == nil {
			out = append(out, p.Masked())
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
	set := buildSet(lists, m.blAllow(ctx))
	if set.total == 0 { // nichts eingeschaltet oder noch nichts geladen: nicht "aktiv"
		set = nil
	}
	b.set.Store(set)
}

// blLoadCache liest die zwischengespeicherten Listen (beim Start: Schutz sofort, ohne auf ipv64 zu warten).
func (m *Module) blLoadCache(ctx context.Context) {
	dir := m.blCacheDir()
	if dir == "" {
		return
	}
	for _, id := range m.blEnabled(ctx) {
		f, err := os.Open(filepath.Join(dir, id+".txt"))
		if err != nil {
			continue
		}
		nets, err := parseList(io.LimitReader(f, blocklistMax))
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
		info, _ := blocklistByID(id)
		st = &BlocklistState{BlocklistInfo: info}
		b.state[id] = st
	}
	return st
}

// blFetch laedt eine Liste (nur bei Aenderung) und speichert sie zwischen.
func (m *Module) blFetch(ctx context.Context, id string) error {
	info, _ := blocklistByID(id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.bl.base+info.File, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Node64/"+m.version)
	m.bl.mu.Lock()
	if e := m.bl.etag[id]; e != "" && len(m.bl.nets[id]) > 0 {
		req.Header.Set("If-None-Match", e)
	}
	m.bl.mu.Unlock()
	resp, err := m.bl.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	now := time.Now()
	if resp.StatusCode == http.StatusNotModified {
		m.bl.mu.Lock()
		m.bl.stateOf(id).Updated, m.bl.stateOf(id).Error = now, ""
		m.bl.mu.Unlock()
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "html") {
		return errors.New("no list (html answer)")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, blocklistMax+1))
	if err != nil {
		return err
	}
	if len(raw) > blocklistMax {
		return errors.New("list too large")
	}
	nets, err := parseList(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if len(nets) == 0 && len(bytes.TrimSpace(raw)) > 0 {
		return errors.New("no addresses in the list")
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
	st := m.bl.stateOf(id)
	st.Entries, st.Updated, st.Changed, st.Error = int64(len(nets)), now, now, ""
	m.bl.mu.Unlock()
	return nil
}

// blRefresh laedt alle eingeschalteten Listen und baut die Sperrliste neu.
func (m *Module) blRefresh(ctx context.Context) {
	for _, id := range m.blEnabled(ctx) {
		if err := m.blFetch(ctx, id); err != nil && ctx.Err() == nil {
			m.log.Warn("cdn64 blocklist not loaded", "list", id, "err", err)
			m.bl.mu.Lock()
			m.bl.stateOf(id).Error = err.Error()
			m.bl.mu.Unlock()
		}
	}
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
	out := make([]BlocklistState, 0, len(Blocklists))
	for _, info := range Blocklists {
		st := *m.bl.stateOf(info.ID)
		st.Enabled = on[info.ID]
		out = append(out, st)
	}
	return out
}

// blSave speichert eingeschaltete Listen und Ausnahmen.
func (m *Module) blSave(ctx context.Context, enabled []string, allow string) error {
	var ids []string
	for _, id := range enabled {
		if _, ok := blocklistByID(id); !ok {
			return ferr("blocklists", "cdn64.bl.err_list")
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	var lines []string
	for _, l := range strings.Fields(allow) {
		if _, err := netip.ParsePrefix(l); err != nil {
			if _, err := netip.ParseAddr(l); err != nil {
				return ferr("allow", "cdn64.bl.err_allow")
			}
		}
		lines = append(lines, l)
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
	return nil
}
