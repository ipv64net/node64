package cdn64

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/shield"
)

// Laendersperre je Host und Stream: Besucher aus bestimmten Laendern sperren oder nur sie zulassen. Die Laenderlisten kommen
// von ipv64.net (taeglich aus den Daten der Registrierungsstellen) und werden nur fuer Laender geladen, die ein
// eingeschalteter Host oder Stream benutzt; Zwischenspeicher wie bei den Blocklisten. Private Netze, CGNAT und die Ausnahmen
// der Blocklisten werden nie gesperrt. "Nur zulassen" sperrt erst, wenn mindestens eine der Listen geladen ist.

const (
	geoBlock  = "block" // Laender sperren
	geoAllow  = "allow" // nur diese Laender zulassen
	geoMax    = 60      // Laender je Host
	geoMaxRaw = 16 << 20
	rejGeo    = "geo" // Laendersperre
)

var errNoAddr = errors.New("no addresses in the list")

var (
	geoCodeRe = regexp.MustCompile(`^[A-Z]{2}$`)
	cgnat     = netip.MustParsePrefix("100.64.0.0/10")
)

// GeoState ist der Stand einer Laenderliste (fuer Seite und API).
type GeoState struct {
	Code    string    `json:"code"`
	Entries int64     `json:"entries"`
	Updated time.Time `json:"updated,omitzero"`
	Error   string    `json:"error,omitempty"`
}

// geoSets: geladene Laenderlisten.
type geoSets struct {
	mu      sync.RWMutex
	sets    map[string]*shield.Set
	state   map[string]*GeoState
	need    []string       // Laender der eingeschalteten Hosts und Streams
	allow   []netip.Prefix // Ausnahmen der Blocklisten
	blocked atomic.Int64   // abgewiesen seit dem Start

	needBy map[string][]string // Laender je Quelle ("hosts", "streams")
}

// normalizeGeo prueft Modus und Laender (Grossbuchstaben, ohne Doppelte); ohne Modus keine Laender.
func (a *Advanced) normalizeGeo() error { return normalizeGeo(&a.GeoMode, &a.GeoCountries) }

func normalizeGeo(mode *string, countries *[]string) error {
	if *mode != geoBlock && *mode != geoAllow {
		*mode, *countries = "", nil
		return nil
	}
	var out []string
	for _, c := range *countries {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" || slices.Contains(out, c) {
			continue
		}
		if !geoCodeRe.MatchString(c) {
			return &FieldError{Field: "geo", Key: "cdn64.err.geo_country", Name: c}
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return ferr("geo", "cdn64.err.geo_none")
	}
	if len(out) > geoMax {
		return ferr("geo", "cdn64.err.geo_many")
	}
	*countries = out
	return nil
}

// geoBlocked: Besucher ip wird von der Laendersperre des Hosts abgewiesen (zaehlt mit).
func (m *Module) geoBlocked(a *Advanced, ip netip.Addr) bool {
	return m.geoBlockedBy(a.GeoMode, a.GeoCountries, ip)
}

// geoBlockedBy: wie geoBlocked, fuer Modus und Laender eines Hosts oder Streams.
func (m *Module) geoBlockedBy(mode string, countries []string, ip netip.Addr) bool {
	if mode == "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || cgnat.Contains(ip) {
		return false
	}
	g := &m.bl.geo
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, p := range g.allow {
		if p.Contains(ip) {
			return false
		}
	}
	in, loaded := false, false
	for _, c := range countries {
		if s := g.sets[c]; s != nil {
			loaded = true
			if s.Has(ip) {
				in = true
				break
			}
		}
	}
	block := in
	if mode == geoAllow {
		block = loaded && !in
	}
	if block {
		g.blocked.Add(1)
	}
	return block
}

// geoNeed merkt sich die Laender der eingeschalteten Hosts (bei jedem apply); fehlt eine Liste, wird geladen.
func (m *Module) geoNeed(active []*Host) {
	var codes []string
	for _, h := range active {
		if h.Advanced.GeoMode != "" {
			codes = append(codes, h.Advanced.GeoCountries...)
		}
	}
	m.geoNeedFrom("hosts", codes)
}

// geoNeedStreams: dasselbe fuer die eingeschalteten Streams (bei jedem applyStreams).
func (m *Module) geoNeedStreams(active []*Stream) {
	var codes []string
	for _, s := range active {
		if s.GeoMode != "" {
			codes = append(codes, s.GeoCountries...)
		}
	}
	m.geoNeedFrom("streams", codes)
}

func (m *Module) geoNeedFrom(src string, codes []string) {
	g := &m.bl.geo
	g.mu.Lock()
	if g.needBy == nil {
		g.needBy = map[string][]string{}
	}
	g.needBy[src] = codes
	var need []string
	for _, list := range g.needBy {
		for _, c := range list {
			if !slices.Contains(need, c) {
				need = append(need, c)
			}
		}
	}
	slices.Sort(need)
	g.need = need
	missing := false
	for _, c := range need {
		if g.sets[c] == nil {
			missing = true
		}
	}
	g.mu.Unlock()
	if missing {
		select {
		case m.bl.kick <- struct{}{}:
		default:
		}
	}
}

func (m *Module) geoNeeded() []string {
	g := &m.bl.geo
	g.mu.RLock()
	defer g.mu.RUnlock()
	return slices.Clone(g.need)
}

func (g *geoSets) put(code string, nets []netip.Prefix, changed time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sets == nil {
		g.sets, g.state = map[string]*shield.Set{}, map[string]*GeoState{}
	}
	g.sets[code] = shield.BuildSet([][]netip.Prefix{nets}, nil)
	g.state[code] = &GeoState{Code: code, Entries: int64(len(nets)), Updated: changed}
}

// geoLoadCache: zwischengespeicherte Laenderlisten (beim Start).
func (m *Module) geoLoadCache(ctx context.Context) {
	dir := m.blCacheDir()
	if dir == "" {
		return
	}
	if list, err := m.hosts(ctx); err == nil {
		var active []*Host
		for _, h := range list {
			if h.Enabled {
				active = append(active, h)
			}
		}
		m.geoNeed(active)
	}
	if list, err := m.streams(ctx); err == nil {
		var active []*Stream
		for _, s := range list {
			if s.Enabled {
				active = append(active, s)
			}
		}
		m.geoNeedStreams(active)
	}
	for _, c := range m.geoNeeded() {
		p := filepath.Join(dir, "countries", c+".txt")
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		nets, err := shield.ParseList(io.LimitReader(f, geoMaxRaw))
		fi, _ := f.Stat()
		f.Close()
		if err == nil && len(nets) > 0 && fi != nil {
			m.bl.geo.put(c, nets, fi.ModTime())
		}
	}
}

// geoRefresh laedt die benoetigten Laenderlisten (nur bei Aenderung) und wirft nicht mehr benoetigte weg.
func (m *Module) geoRefresh(ctx context.Context) {
	need := m.geoNeeded()
	g := &m.bl.geo
	for _, c := range need {
		g.mu.RLock()
		have := g.sets[c] != nil
		g.mu.RUnlock()
		raw, same, err := m.blGet(ctx, "countries/ipv64_blocklist_"+c+".txt", "geo:"+c, have, geoMaxRaw)
		if err == nil && !same {
			var nets []netip.Prefix
			if nets, err = shield.ParseList(bytes.NewReader(raw)); err == nil {
				if len(nets) == 0 {
					err = errNoAddr
				} else {
					m.blCacheWrite("countries/"+c+".txt", raw)
					g.put(c, nets, time.Now())
				}
			}
		}
		if err != nil && ctx.Err() == nil {
			m.log.Warn("cdn64 country list not loaded", "country", c, "err", err)
			g.mu.Lock()
			if g.state == nil {
				g.sets, g.state = map[string]*shield.Set{}, map[string]*GeoState{}
			}
			if st := g.state[c]; st != nil {
				st.Error = err.Error()
			} else {
				g.state[c] = &GeoState{Code: c, Error: err.Error()}
			}
			g.mu.Unlock()
		} else if err == nil {
			g.mu.Lock()
			if st := g.state[c]; st != nil {
				st.Error = ""
				if same {
					st.Updated = time.Now()
				}
			}
			g.mu.Unlock()
		}
	}
	g.mu.Lock()
	for c := range g.sets {
		if !slices.Contains(need, c) {
			delete(g.sets, c)
			delete(g.state, c)
		}
	}
	g.mu.Unlock()
}

// geoStates liefert den Stand der geladenen Laenderlisten.
func (m *Module) geoStates() []GeoState {
	g := &m.bl.geo
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := []GeoState{}
	for _, c := range g.need {
		if st := g.state[c]; st != nil {
			out = append(out, *st)
		} else {
			out = append(out, GeoState{Code: c})
		}
	}
	return out
}
