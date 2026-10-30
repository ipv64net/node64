package honeypot

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/geoip"
	"github.com/ipv64net/node64/internal/honeypot/worldmap"
	"golang.org/x/text/collate"
	"golang.org/x/text/language"
)

// Live-Karte (Wunsch Dennis 2026-10-26): auf der Laenderkarte der Uebersicht fliegen Boegen von der Quelle eines
// Angriffs zum eigenen Sensor. Daten aus GET /api/honeypot/live (Ereignisse der letzten Minuten mit Land und
// Kartenpunkt); das Zeichnen und das Wiederholen aelterer Eintraege bei wenig Verkehr macht honeypot-live.js. Ziel
// ist das Land der oeffentlichen IPv4 der Node, ohne IPv4 der IPv6 (bei ipv64.net erfragt wie im DynDNS-Modul,
// 6 Stunden gemerkt).

const (
	liveDefaultMin = 60
	liveMaxMin     = 24 * 60
	liveMax        = 500 // hoechstens so viele Ereignisse je Abruf
)

// LiveEvent ist ein Angriff auf der Live-Karte.
type LiveEvent struct {
	Time    int64   `json:"t"` // Unix-Millisekunden
	Country string  `json:"cc"`
	Flag    string  `json:"flag"`
	Name    string  `json:"name"`
	X       float64 `json:"x"`
	Y       float64 `json:"y"`
	IP      string  `json:"ip"`
	Kind    string  `json:"kind"`
	Group   string  `json:"group"` // KindGroups (Farbe)
	Service string  `json:"service"`
	Port    int     `json:"port"`
	Source  string  `json:"source"`
}

// LivePoint ist das Ziel der Boegen (eigener Standort).
type LivePoint struct {
	Country string  `json:"cc"`
	Flag    string  `json:"flag"`
	Name    string  `json:"name"`
	X       float64 `json:"x"`
	Y       float64 `json:"y"`
	Known   bool    `json:"known"`  // false = Land unbekannt, Ziel ist die Kartenmitte
	Manual  bool    `json:"manual"` // Standort eingestellt (sonst aus der oeffentlichen IPv4)
}

// ownCountry: Land der oeffentlichen IPv4, ohne IPv4 der IPv6 (gemerkt; Fehler eine Minute, Erfolg 6 Stunden).
// Abgerufen wird ausserhalb der Sperre (je Adressfamilie bis 6 s): cached() und gleichzeitige Aufrufe warten nicht,
// sie bekommen den bisherigen Stand.
type ownCountry struct {
	mu       sync.Mutex
	cc       string
	at       time.Time
	err      bool
	fetching bool
	from     func(ctx context.Context) (netip.Addr, error)
}

var ownCC = &ownCountry{from: fetchOwnAddr}

func (o *ownCountry) get(ctx context.Context) string {
	o.mu.Lock()
	if o.fetching || (!o.at.IsZero() && (time.Since(o.at) < time.Minute || (!o.err && time.Since(o.at) < 6*time.Hour))) {
		cc := o.cc
		o.mu.Unlock()
		return cc
	}
	o.fetching = true
	o.mu.Unlock()
	a, err := o.from(ctx)
	cc := ""
	if err == nil {
		cc, _ = lookupCountry(a)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.at, o.err, o.fetching = time.Now(), err != nil, false
	if err == nil {
		o.cc = cc
	}
	return o.cc
}

// fetchOwnAddr fragt die oeffentliche IPv4 bei ipv64.net ab; ohne IPv4 (reiner IPv6-Anschluss) einmal die IPv6.
func fetchOwnAddr(ctx context.Context) (netip.Addr, error) {
	a, err := fetchOwnIP(ctx, "tcp4", "https://ipv4.ipv64.net/ipcheck.php?ipv4")
	if err != nil {
		a, err = fetchOwnIP(ctx, "tcp6", "https://ipv6.ipv64.net/ipcheck.php?ipv6")
	}
	return a, err
}

// OwnAddrs liefert die eigenen oeffentlichen Adressen (IPv4 und IPv6, je was erreichbar ist) fuer die Meldung
// (ReporterConfig.OwnAddrs): gemerkt 30 Minuten, nach einem Fehlschlag 5 Minuten; bis dahin gilt der bisherige Stand.
func OwnAddrs() func(ctx context.Context) []netip.Addr {
	var mu sync.Mutex
	var addrs []netip.Addr
	var next time.Time
	return func(ctx context.Context) []netip.Addr {
		mu.Lock()
		defer mu.Unlock()
		if time.Now().Before(next) {
			return addrs
		}
		var got []netip.Addr
		if a, err := fetchOwnIP(ctx, "tcp4", "https://ipv4.ipv64.net/ipcheck.php?ipv4"); err == nil {
			got = append(got, a)
		}
		if a, err := fetchOwnIP(ctx, "tcp6", "https://ipv6.ipv64.net/ipcheck.php?ipv6"); err == nil {
			got = append(got, a)
		}
		next = time.Now().Add(30 * time.Minute)
		if len(got) == 0 {
			next = time.Now().Add(5 * time.Minute)
			return addrs
		}
		addrs = got
		return addrs
	}
}

// fetchOwnIP fragt die oeffentliche Adresse bei ipv64.net ab (erzwungen ueber network "tcp4" bzw. "tcp6").
func fetchOwnIP(ctx context.Context, network, url string) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	d := &net.Dialer{Timeout: 5 * time.Second}
	cl := &http.Client{Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, network, addr) }}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	req.Header.Set("User-Agent", "node64")
	resp, err := cl.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	hex := func(r rune) bool { return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' }
	for _, f := range strings.FieldsFunc(string(b), func(r rune) bool { return !(hex(r) || r == '.' || r == ':') }) {
		if a, err := netip.ParseAddr(f); err == nil && a.Unmap().Is4() == (network == "tcp4") {
			return a.Unmap(), nil
		}
	}
	return netip.Addr{}, io.ErrUnexpectedEOF
}

// ValidCountry: Laendercode, den die Karte kennt (Standort des Sensors).
func ValidCountry(cc string) bool {
	_, _, ok := worldmap.Centroid(cc)
	return ok
}

// cached: zuletzt ermitteltes Land ohne neuen Abruf ("" = noch keins).
func (o *ownCountry) cached() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.cc
}

// countryOpt ist ein Land in der Auswahl "Standort".
type countryOpt struct{ Code, Flag, Name string }

// countryOptions: alle Laender der Karte (Flaechen und feste Punkte), nach Namen sortiert.
func countryOptions(lang string) []countryOpt {
	var out []countryOpt
	add := func(cc string) {
		out = append(out, countryOpt{Code: cc, Flag: geoip.Flag(cc), Name: geoip.Name(cc, lang)})
	}
	for _, c := range worldmap.Countries() {
		add(c.Code)
	}
	for cc := range worldmap.Points() {
		add(cc)
	}
	// nach Sprache sortiert (Oesterreich bei O, nicht hinter Zypern)
	col := collate.New(language.Make(lang))
	sort.Slice(out, func(i, j int) bool { return col.CompareString(out[i].Name, out[j].Name) < 0 })
	return out
}

// liveTarget: Ziel der Boegen (eingestellter Standort, sonst Land der oeffentlichen IPv4, sonst Kartenmitte).
func liveTarget(ctx context.Context, lang, manual string) LivePoint {
	cc := manual
	if cc == "" {
		cc = ownCC.get(ctx)
	}
	if x, y, ok := worldmap.Centroid(cc); ok {
		return LivePoint{Country: cc, Flag: geoip.Flag(cc), Name: geoip.Name(cc, lang), X: x, Y: y, Known: true, Manual: manual != ""}
	}
	vb := strings.Fields(worldmap.ViewBox())
	w, h := 1000.0, 436.0
	if len(vb) == 4 {
		w, _ = strconv.ParseFloat(vb[2], 64)
		h, _ = strconv.ParseFloat(vb[3], 64)
	}
	return LivePoint{X: w / 2, Y: h / 2}
}

// liveEvents: Ereignisse der letzten minutes Minuten mit bekanntem Land (neueste zuerst).
func (m *Module) liveEvents(ctx context.Context, minutes int, lang string) ([]LiveEvent, error) {
	list, err := m.st.RecentIn(ctx, liveMax, "", "")
	if err != nil {
		return nil, err
	}
	since := time.Now().Add(-time.Duration(minutes) * time.Minute)
	out := []LiveEvent{}
	for _, e := range list {
		if e.Time.Before(since) {
			continue // Liste nach id sortiert, nicht nach Zeit (Log-Zeilen mit eigener Zeit, Nachmeldungen)
		}
		cc := countryOf(e.Src.String())
		x, y, ok := worldmap.Centroid(cc)
		if !ok {
			continue
		}
		src := e.Source
		if src == "" {
			src = SrcHoneypot
		}
		out = append(out, LiveEvent{Time: e.Time.UnixMilli(), Country: cc, Flag: geoip.Flag(cc), Name: geoip.Name(cc, lang), X: x, Y: y,
			IP: e.Src.String(), Kind: e.Kind, Group: KindGroup(e.Kind, src), Service: e.Service, Port: e.Port, Source: src})
	}
	return out, nil
}

// apiLive: GET /api/honeypot/live?minutes=60 – Ereignisse fuer die Live-Karte und das Ziel der Boegen.
func (m *Module) apiLive(w http.ResponseWriter, r *http.Request) {
	minutes, _ := strconv.Atoi(r.URL.Query().Get("minutes"))
	if minutes <= 0 {
		minutes = liveDefaultMin
	}
	minutes = min(minutes, liveMaxMin)
	lang := m.lang(r)
	ev, err := m.liveEvents(r.Context(), minutes, lang)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	apiJSON(w, http.StatusOK, map[string]any{"minutes": minutes, "target": liveTarget(r.Context(), lang, m.loadConfig(r.Context()).Country), "events": ev, "now": time.Now().UnixMilli()})
}
