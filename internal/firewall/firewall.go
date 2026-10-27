// Package firewall: Node64 als Firewall-Helfer (Honeypot64 H6, docs/PLAN-NODE64-HONEYPOT64.md Abschnitt 7). Node64
// traegt die v64 Blocklist in nftables des Hosts ein, wie ein Firewall-Bouncer: eigene Tabelle "inet node64" mit je
// einem Set fuer IPv4 und IPv6 (flags interval) und den Ketten input und forward (vor filter, policy accept), die
// Pakete von Adressen in den Sets verwerfen. Die Listen kommen von ipv64.net (ohne Listen-Token Tagesstand, mit
// Token live), werden alle 30 Minuten nur bei Aenderung geladen und in einer Transaktion in die Sets geschrieben.
// Eigene, private und reservierte Netze werden nie gesperrt. Beim Beenden wird die Tabelle geloescht (Keep laesst
// sie stehen).
//
// Plattformunabhaengig: Listen laden, filtern, zusammenfassen, Differenz (ranges.go, fetch.go). Der Netlink-Teil
// steckt hinter Backend (nft_linux.go; auf anderen Systemen nft_other.go mit Fehler "nur Linux").
package firewall

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/metrics"
)

// Feste Namen in nftables.
const (
	ModeNFTables = "nftables"
	Table        = "node64"       // Tabelle (Familie inet)
	SetV4        = "blocklist_v4" // ipv4_addr, flags interval
	SetV6        = "blocklist_v6" // ipv6_addr, flags interval
	Priority     = -10            // Hook-Prioritaet der Ketten input und forward (filter = 0)

	DefaultList  = "v64"
	DefaultBase  = "https://ipv64.net/blocklists/"
	Interval     = 30 * time.Minute
	retryAfter   = 5 * time.Minute
	maxRanges    = 2_000_000 // je Familie; mehr ist keine sinnvolle Liste
	fetchTimeout = 3 * time.Minute
)

// Backend ist der Netlink-Teil (nftables). Jede Methode ist eine Transaktion.
type Backend interface {
	// Apply legt die Tabelle neu an (eine vorhandene node64-Tabelle wird ersetzt): Sets, Ketten, Regeln und
	// Elemente in einer Transaktion.
	Apply(v4, v6 []Range) error
	// Update leert die angegebenen Sets und fuellt sie neu (eine Transaktion); nil-Zeiger = Set bleibt.
	Update(v4, v6 *[]Range) error
	// Exists: die Tabelle steht (z. B. nach "nft flush ruleset" nicht mehr).
	Exists() (bool, error)
	// Remove loescht die Tabelle (fehlt sie, ist das kein Fehler).
	Remove() error
}

// Config ist die Einstellung des Helfers.
type Config struct {
	Mode     string         // "nftables"
	Lists    []string       // IDs aus index.json (Standard v64)
	Token    string         // Listen-Token (leer = Tagesstand)
	Allow    []netip.Prefix // eigene Netze, nie sperren
	Keep     bool           // Tabelle beim Beenden stehen lassen
	CacheDir string         // letzte Fassung der Listen (leer = kein Cache)
	Version  string         // fuer den User-Agent
	Base     string         // Basis-URL (leer = DefaultBase; Tests)
	Interval time.Duration  // Abruf-Takt (0 = Interval)
	Log      *slog.Logger

	Backend   Backend             // nil = nftables (nur Linux)
	HostAddrs func() []netip.Addr // eigene Adressen (nil = Schnittstellen des Hosts)
	Client    *http.Client        // nil = eigener Client
}

// ListStatus ist der Stand einer Liste.
type ListStatus struct {
	ID         string    `json:"id"`
	Edition    string    `json:"edition,omitempty"` // live | daily | cache
	LiveDenied bool      `json:"live_denied,omitempty"`
	LiveError  string    `json:"live_error,omitempty"`
	Entries    int       `json:"entries"`
	Updated    time.Time `json:"updated,omitzero"`
	Error      string    `json:"error,omitempty"`
}

// Status ist der Zustand des Helfers (Info-Seite, Metriken).
type Status struct {
	Mode        string       `json:"mode"`
	Keep        bool         `json:"keep"`
	Live        bool         `json:"live"`   // Listen-Token gesetzt
	Active      bool         `json:"active"` // Tabelle steht und ist gefuellt
	V4          int          `json:"v4"`     // Bereiche im IPv4-Set
	V6          int          `json:"v6"`     // Bereiche im IPv6-Set
	Addresses4  uint64       `json:"addresses_v4"`
	Skipped     int          `json:"skipped"` // zu grosse Netze, verworfen
	Allow       int          `json:"allow"`   // Ausnahmen (NODE64_FIREWALL_ALLOW)
	Updated     time.Time    `json:"updated,omitzero"`
	Changed     time.Time    `json:"changed,omitzero"`
	Errors      int64        `json:"errors"`
	LastError   string       `json:"last_error,omitempty"`
	LastErrorAt time.Time    `json:"last_error_at,omitzero"`
	Lists       []ListStatus `json:"lists"`
}

// Helper laedt die Listen und haelt die Sets aktuell.
type Helper struct {
	cfg    Config
	be     Backend
	log    *slog.Logger
	client *http.Client
	now    func() time.Time
	kick   chan struct{}

	errs atomic.Int64

	mu      sync.Mutex
	index   map[string]indexEntry
	valid   map[string]validator
	nets    map[string][]netip.Prefix
	lists   map[string]*ListStatus
	applied bool // Tabelle mit v4/v6 angelegt
	v4, v6  []Range
	st      Status
}

// New prueft die Einstellung und baut den Helfer (auf anderen Systemen als Linux ohne Backend: Fehler).
func New(cfg Config) (*Helper, error) {
	if cfg.Mode != ModeNFTables {
		return nil, fmt.Errorf("firewall mode %q is not supported (nftables)", cfg.Mode)
	}
	if len(cfg.Lists) == 0 {
		cfg.Lists = []string{DefaultList}
	}
	for _, id := range cfg.Lists {
		if !IDRe.MatchString(id) {
			return nil, fmt.Errorf("firewall list %q is not a list id", id)
		}
	}
	if cfg.Token != "" && !TokenRe.MatchString(cfg.Token) {
		return nil, errors.New("list token must be 32 letters and digits")
	}
	if cfg.Base == "" {
		cfg.Base = DefaultBase
	}
	if cfg.Interval <= 0 {
		cfg.Interval = Interval
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.HostAddrs == nil {
		cfg.HostAddrs = hostAddrs
	}
	be := cfg.Backend
	if be == nil {
		var err error
		if be, err = newNFT(); err != nil {
			return nil, err
		}
	}
	h := &Helper{cfg: cfg, be: be, log: cfg.Log, client: cfg.Client, now: time.Now, kick: make(chan struct{}, 1),
		valid: map[string]validator{}, nets: map[string][]netip.Prefix{}, lists: map[string]*ListStatus{}}
	if h.client == nil {
		h.client = &http.Client{Timeout: 60 * time.Second}
	}
	h.st = Status{Mode: cfg.Mode, Keep: cfg.Keep, Live: cfg.Token != "", Allow: len(cfg.Allow)}
	for _, id := range cfg.Lists {
		h.listState(id)
	}
	return h, nil
}

// Probe prueft, ob nftables erreichbar ist (Rechte); fuer eine klare Meldung beim Start.
func (h *Helper) Probe() error {
	_, err := h.be.Exists()
	return err
}

// listState liefert den Stand einer Liste (h.mu gehalten).
func (h *Helper) listState(id string) *ListStatus {
	ls := h.lists[id]
	if ls == nil {
		ls = &ListStatus{ID: id}
		h.lists[id] = ls
	}
	return ls
}

// Run laeuft bis ctx endet: Cache laden, sofort abrufen, dann alle 30 Minuten (nach Fehlern nach 5 Minuten).
// Danach wird die Tabelle geloescht (ausser Keep).
func (h *Helper) Run(ctx context.Context) {
	defer h.stop()
	h.loadCache()
	for {
		ok := h.Refresh(ctx)
		wait := h.cfg.Interval
		if !ok {
			wait = min(wait, retryAfter)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-h.kick:
			t.Stop()
		case <-t.C:
		}
	}
}

// Kick loest einen Abruf sofort aus.
func (h *Helper) Kick() {
	select {
	case h.kick <- struct{}{}:
	default:
	}
}

// stop raeumt beim Beenden auf.
func (h *Helper) stop() {
	h.mu.Lock()
	applied := h.applied
	h.mu.Unlock()
	if h.cfg.Keep {
		h.log.Info("firewall: table kept (NODE64_FIREWALL_KEEP=1)", "table", "inet "+Table)
		return
	}
	if err := h.be.Remove(); err != nil {
		h.log.Error("firewall: table not removed", "table", "inet "+Table, "err", err)
		return
	}
	if applied {
		h.log.Info("firewall: table removed", "table", "inet "+Table)
	}
	h.mu.Lock()
	h.applied, h.st.Active = false, false
	h.mu.Unlock()
}

// fail zaehlt einen Fehler und merkt ihn fuer die Anzeige.
func (h *Helper) fail(msg string, err error) {
	h.errs.Add(1)
	h.mu.Lock()
	h.st.LastError, h.st.LastErrorAt = msg+": "+err.Error(), h.now()
	h.mu.Unlock()
}

// Refresh laedt die Listen und bringt die Sets auf den Stand. Rueckgabe: alles ohne Fehler.
func (h *Helper) Refresh(ctx context.Context) bool {
	fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	ok := true
	if err := h.fetchIndex(fctx); err != nil && ctx.Err() == nil {
		h.log.Warn("firewall: blocklist index not loaded", "err", mask(err, h.cfg.Token))
	}
	for _, id := range h.cfg.Lists {
		if err := h.fetchList(fctx, id); err != nil {
			if ctx.Err() != nil {
				return false
			}
			ok = false
			err = mask(err, h.cfg.Token)
			h.log.Warn("firewall: blocklist not loaded", "list", id, "err", err)
			h.fail("list "+id, err)
			h.mu.Lock()
			h.listState(id).Error = err.Error()
			h.mu.Unlock()
		}
	}
	if err := h.apply(); err != nil {
		h.log.Error("firewall: nftables not updated", "err", err)
		h.fail("nftables", err)
		return false
	}
	return ok
}

// exclusions: Reserved, Ausnahmen und die eigenen Adressen des Hosts.
func (h *Helper) exclusions() []netip.Prefix {
	ex := slices.Concat(Reserved, h.cfg.Allow)
	for _, a := range h.cfg.HostAddrs() {
		a = a.Unmap()
		if a.IsValid() {
			ex = append(ex, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return ex
}

// apply baut die Bereiche und schreibt sie: beim ersten Mal (oder wenn die Tabelle fehlt) die ganze Tabelle, sonst
// nur geaenderte Sets. Ohne geladene Liste bleibt alles, wie es ist (auch eine stehengelassene Tabelle).
func (h *Helper) apply() error {
	h.mu.Lock()
	var lists [][]netip.Prefix
	for _, id := range h.cfg.Lists {
		if n, ok := h.nets[id]; ok { // auch leer: geladen ist geladen (z. B. v64 ohne Eintraege)
			lists = append(lists, n)
		}
	}
	applied, prev4, prev6 := h.applied, h.v4, h.v6
	h.mu.Unlock()
	if len(lists) == 0 {
		return errors.New("no list loaded yet")
	}
	v4, v6, skipped := Build(lists, h.exclusions())
	if len(v4) > maxRanges || len(v6) > maxRanges {
		return fmt.Errorf("too many entries (%d IPv4, %d IPv6 ranges)", len(v4), len(v6))
	}
	if applied {
		ok, err := h.be.Exists()
		if err != nil {
			return err
		}
		if !ok {
			h.log.Warn("firewall: table vanished, creating it again", "table", "inet "+Table)
			applied = false
		}
	}
	now := h.now()
	changed := false
	if !applied {
		if err := h.be.Apply(v4, v6); err != nil {
			h.mu.Lock()
			h.applied, h.st.Active = false, false
			h.mu.Unlock()
			return err
		}
		h.log.Info("firewall: nftables table set up", "table", "inet "+Table, "ipv4_ranges", len(v4), "ipv6_ranges", len(v6),
			"skipped_too_large", skipped, "hooks", "input, forward", "priority", Priority)
		changed = true
	} else {
		a4, r4 := Diff(prev4, v4)
		a6, r6 := Diff(prev6, v6)
		var u4, u6 *[]Range
		if len(a4)+len(r4) > 0 {
			u4 = &v4
		}
		if len(a6)+len(r6) > 0 {
			u6 = &v6
		}
		if u4 != nil || u6 != nil {
			if err := h.be.Update(u4, u6); err != nil {
				h.mu.Lock()
				h.applied = false // naechstes Mal die ganze Tabelle neu
				h.mu.Unlock()
				return err
			}
			changed = true
			h.log.Info("firewall: blocklist updated", "ipv4_ranges", len(v4), "ipv6_ranges", len(v6),
				"ipv4_added", len(a4), "ipv4_removed", len(r4), "ipv6_added", len(a6), "ipv6_removed", len(r6))
		} else {
			h.log.Debug("firewall: blocklist unchanged", "ipv4_ranges", len(v4), "ipv6_ranges", len(v6))
		}
	}
	h.mu.Lock()
	h.applied, h.v4, h.v6 = true, v4, v6
	h.st.Active, h.st.V4, h.st.V6, h.st.Skipped, h.st.Updated = true, len(v4), len(v6), skipped, now
	h.st.Addresses4 = Addresses(v4)
	if changed {
		h.st.Changed = now
	}
	h.mu.Unlock()
	return nil
}

// Status liefert eine Kopie des Zustands.
func (h *Helper) Status() Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.st
	st.Errors = h.errs.Load()
	st.Lists = make([]ListStatus, 0, len(h.cfg.Lists))
	for _, id := range h.cfg.Lists {
		st.Lists = append(st.Lists, *h.listState(id))
	}
	return st
}

// WriteMetrics schreibt die Kennzahlen des Helfers.
func (h *Helper) WriteMetrics(w *metrics.Writer) {
	st := h.Status()
	w.Gauge("node64_firewall_active", "Firewall-Helfer: Tabelle inet node64 steht und ist gefuellt.", metrics.Bool(st.Active), "mode", st.Mode)
	w.Gauge("node64_firewall_entries", "Firewall-Helfer: Bereiche in den nftables-Sets.", float64(st.V4), "family", "ipv4")
	w.Gauge("node64_firewall_entries", "Firewall-Helfer: Bereiche in den nftables-Sets.", float64(st.V6), "family", "ipv6")
	var ts float64
	if !st.Updated.IsZero() {
		ts = float64(st.Updated.Unix())
	}
	w.Gauge("node64_firewall_last_update_timestamp", "Firewall-Helfer: letzte erfolgreiche Pruefung bzw. Aktualisierung (Unix-Zeit, 0 = noch keine).", ts)
	w.Counter("node64_firewall_errors_total", "Firewall-Helfer: Fehler seit dem Start (Abruf oder nftables).", float64(st.Errors))
	for _, l := range st.Lists {
		ed := l.Edition
		if ed == "" {
			ed = "none"
		}
		w.Gauge("node64_firewall_list_entries", "Firewall-Helfer: Eintraege je Liste (vor dem Filtern).", float64(l.Entries), "list", l.ID, "edition", ed)
	}
}

// hostAddrs: oeffentliche Adressen der Schnittstellen (im Host-Netz die des Hosts) - nie sich selbst sperren.
func hostAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap().IsGlobalUnicast() {
			out = append(out, ip.Unmap())
		}
	}
	return out
}

// ParseAllow liest eine Liste von IPs bzw. Netzen (Komma, Leerzeichen oder Semikolon getrennt).
func ParseAllow(v string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '\n' }) {
		if p, err := netip.ParsePrefix(item); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(item); err == nil {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		} else {
			return nil, fmt.Errorf("%q is not an IP address or network (CIDR)", item)
		}
	}
	return out, nil
}

// ParseLists liest "v64,ai_bots" (leer = v64); fruehere Teillisten der v64 Blocklist (v64_ssh u. a.) gelten als v64.
func ParseLists(v string) ([]string, error) {
	var out []string
	for _, item := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		id := strings.ToLower(item)
		if !IDRe.MatchString(id) {
			return nil, fmt.Errorf("%q is not a list id (letters, digits, _)", item)
		}
		id = ipv64api.V64ListID(id)
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		out = []string{DefaultList}
	}
	return out, nil
}
