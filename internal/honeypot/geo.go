package honeypot

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/geoip"
)

// Herkunft der Angreifer (Plan „Herkunft der Angreifer“): Land je Quell-IP aus den Laenderdaten von ipv64.net
// (internal/geoip). Gespeichert wird kein Land; es wird beim Auswerten nachgeschlagen (keine Migration, neue Daten
// gelten sofort auch fuer alte Ereignisse). Dazu die farbige Uebersicht „Was wurde angegriffen“: je Dienst, Port und
// Art nach Art-Gruppe aufgeteilt, und die Rangliste der Koeder und Geraete.

// lookupCountry schlaegt das Land einer Adresse nach (Tests ersetzen es).
var lookupCountry = geoip.Lookup

// countryOf: Land einer Quell-IP als Text ("" = unbekannt, privat oder keine Daten).
func countryOf(src string) string {
	a, err := netip.ParseAddr(src)
	if err != nil {
		return ""
	}
	cc, _ := lookupCountry(a)
	return cc
}

// geoStart fordert die Laenderdaten an (Modulstart und Modus ohne Oberflaeche); Tests ersetzen es.
var geoStart = geoip.Start

// StartGeo fordert die Laenderdaten fuer den Modus ohne Oberflaeche an (Cache unter <dataDir>/geoip). Die gelieferte
// Funktion gibt sie beim Beenden zurueck.
func StartGeo(dataDir, userAgent string, log *slog.Logger) (release func()) {
	return geoStart(dataDir, userAgent, log)
}

// CountryCount ist ein Land der Rangliste „Herkunft nach Land“.
type CountryCount struct {
	Key     string    `json:"key"`     // ISO 3166 alpha-2 (gross)
	Count   int64     `json:"count"`   // Ereignisse
	Sources int64     `json:"sources"` // verschiedene Quell-IPs
	Last    time.Time `json:"last,omitzero"`
}

// maxCountries begrenzt die Laender (es gibt knapp 250; mehr waere ein Fehler der Daten).
const maxCountries = 250

// byCountry zaehlt Ereignisse und Quellen je Land ab from (eine Abfrage je Quell-IP, Nachschlagen per
// Binaersuche). unknown = Ereignisse ohne Land (privat, unbekannt oder noch keine Daten).
func (s *Store) byCountry(ctx context.Context, from string) ([]CountryCount, int64, error) {
	rows, err := s.st.Reader().QueryContext(ctx, `SELECT src, COUNT(*), MAX(ts) FROM hp_events WHERE ts >= ? AND src <> '' GROUP BY src`, from)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	type agg struct {
		n, src int64
		last   string
	}
	by := map[string]*agg{}
	var unknown int64
	for rows.Next() {
		var src, last string
		var n int64
		if err := rows.Scan(&src, &n, &last); err != nil {
			return nil, 0, err
		}
		cc := countryOf(src)
		if cc == "" {
			unknown += n
			continue
		}
		a := by[cc]
		if a == nil {
			if len(by) >= maxCountries {
				unknown += n
				continue
			}
			a = &agg{}
			by[cc] = a
		}
		a.n += n
		a.src++
		if last > a.last {
			a.last = last
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	out := make([]CountryCount, 0, len(by))
	for cc, a := range by {
		out = append(out, CountryCount{Key: cc, Count: a.n, Sources: a.src, Last: storeParseTime(a.last)})
	}
	slices.SortFunc(out, func(a, b CountryCount) int {
		if a.Count != b.Count {
			if a.Count > b.Count {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Key, b.Key)
	})
	return out, unknown, nil
}

// byDecoy zaehlt Koeder ("page:<koeder>") und erkannte Geraete ("device:<name>" aus Detail device=…) ab from.
func (s *Store) byDecoy(ctx context.Context, from string, top int) ([]Count, error) {
	pages, err := s.counts(ctx, `SELECT page AS k, COUNT(*) AS n, MAX(ts) FROM hp_events WHERE ts >= ? AND page <> '' GROUP BY k`, from)
	if err != nil {
		return nil, err
	}
	details, err := s.counts(ctx, `SELECT detail AS k, COUNT(*) AS n, MAX(ts) FROM hp_events WHERE ts >= ? AND detail LIKE '%device=%' GROUP BY k`, from)
	if err != nil {
		return nil, err
	}
	by := map[string]*Count{}
	add := func(key string, c Count) {
		if x := by[key]; x != nil {
			x.Count += c.Count
			if c.Last.After(x.Last) {
				x.Last = c.Last
			}
			return
		}
		by[key] = &Count{Key: key, Count: c.Count, Last: c.Last}
	}
	for _, c := range pages {
		add("page:"+c.Key, c)
	}
	for _, c := range details {
		for _, tag := range strings.Split(c.Key, ",") {
			if name, ok := strings.CutPrefix(strings.TrimSpace(tag), "device="); ok && name != "" {
				add("device:"+name, c)
				break
			}
		}
	}
	out := make([]Count, 0, len(by))
	for _, c := range by {
		out = append(out, *c)
	}
	slices.SortFunc(out, func(a, b Count) int {
		if a.Count != b.Count {
			if a.Count > b.Count {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Key, b.Key)
	})
	if top > 0 && len(out) > top {
		out = out[:top]
	}
	return out, nil
}

// Art-Gruppen fuer die Farben der Uebersicht (feste Reihenfolge = Legende).
const (
	GroupLogin   = "login"   // Login/Bruteforce
	GroupExploit = "exploit" // Exploits
	GroupScan    = "scan"    // Scans
	GroupProbe   = "probe"   // Sondierung, erste Bytes, auffaellige User-Agents
	GroupLog     = "log"     // aus echten Logs bzw. Syslog
)

// KindGroups ist die Reihenfolge der Gruppen.
var KindGroups = []string{GroupLogin, GroupExploit, GroupScan, GroupProbe, GroupLog}

// KindGroup ordnet ein Ereignis einer Gruppe zu: Ereignisse aus Logs/Syslog sind immer GroupLog.
func KindGroup(kind, source string) string {
	if source != "" && source != SrcHoneypot {
		return GroupLog
	}
	switch {
	case strings.Contains(kind, "bruteforce"):
		return GroupLogin
	case strings.Contains(kind, "exploit"):
		return GroupExploit
	case strings.Contains(kind, "scan"):
		return GroupScan
	}
	return GroupProbe
}

// targetRow ist eine Zeile der Auswertung „Was wurde angegriffen“.
type targetRow struct {
	Service, Kind, Source string
	Port                  int
	Count                 int64
}

// targets zaehlt Ereignisse je Dienst, Port, Art und Quelle ab from (fuer die Balken je Gruppe).
func (s *Store) targets(ctx context.Context, from string) ([]targetRow, error) {
	rows, err := s.st.Reader().QueryContext(ctx, `SELECT service, port, kind, source, COUNT(*) FROM hp_events WHERE ts >= ?
		GROUP BY service, port, kind, source`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []targetRow
	for rows.Next() {
		var r targetRow
		if err := rows.Scan(&r.Service, &r.Port, &r.Kind, &r.Source, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- Anzeige

// uiCountry ist Flagge, Code und Name eines Landes fuer die Seiten ("" Code = unbekannt).
type uiCountry struct {
	Code, Flag, Name string
}

func countryView(cc, lang string) uiCountry {
	if cc == "" {
		return uiCountry{}
	}
	return uiCountry{Code: cc, Flag: geoip.Flag(cc), Name: geoip.Name(cc, lang)}
}

// uiCountryRank ist ein Land der Rangliste mit Farbe (feste Palette nach Rang).
type uiCountryRank struct {
	uiCountry
	Count, Sources int64
	Pct            int // Breite relativ zum groessten Land
	Share          int // Anteil an allen Ereignissen mit Land (Prozent, fuer den Anteilsbalken)
	Color          string
}

// countryColors: Palette der Rangliste (Bootstrap, hell und dunkel lesbar).
var countryColors = []string{"bg-primary", "bg-danger", "bg-warning", "bg-success", "bg-info", "bg-secondary"}

func countryRanks(list []CountryCount, lang string, top int) []uiCountryRank {
	var max, sum int64
	for _, c := range list {
		max = maxInt64(max, c.Count)
		sum += c.Count
	}
	out := []uiCountryRank{}
	for i, c := range list {
		if top > 0 && i == top {
			break
		}
		r := uiCountryRank{uiCountry: countryView(c.Key, lang), Count: c.Count, Sources: c.Sources, Color: countryColors[i%len(countryColors)]}
		if max > 0 {
			r.Pct = int(c.Count * 100 / max)
		}
		if sum > 0 {
			r.Share = int(c.Count * 100 / sum)
		}
		out = append(out, r)
	}
	return out
}

// uiSeg ist ein Teil eines gestapelten Balkens (eine Art-Gruppe).
type uiSeg struct {
	Group string
	Count int64
	Pct   int // Breite in Prozent der ganzen Zeile (relativ zum groessten Eintrag)
}

// uiTarget ist ein Eintrag von „Was wurde angegriffen“ (Dienst, Port oder Art).
type uiTarget struct {
	Key, Sub string // z. B. "ssh" / Port "22" mit Dienst "ssh"
	Count    int64
	Segs     []uiSeg
}

// uiTargetCol ist eine Spalte von „Was wurde angegriffen“ (Dienste, Ports, Arten).
type uiTargetCol struct {
	ID, TitleKey string
	Mono         bool
	Items        []uiTarget
}

// uiTargets sind die drei Spalten mit Legende.
type uiTargets struct {
	Cols   []uiTargetCol
	Groups []string // Legende (nur Gruppen mit Ereignissen)
}

// groupColor ist die feste Farbe einer Art-Gruppe (Template-Funktion ueber uiTargets.Color).
func (uiTargets) Color(group string) string {
	switch group {
	case GroupLogin:
		return "bg-danger"
	case GroupExploit:
		return "bg-warning"
	case GroupScan:
		return "bg-info"
	case GroupLog:
		return "bg-primary"
	}
	return "bg-secondary"
}

// buildTargets fasst die Zeilen je Dienst, Port und Art zusammen (Top top, nach Anzahl).
func buildTargets(rows []targetRow, top int) uiTargets {
	type acc struct {
		key, sub string
		total    int64
		groups   map[string]int64
		subs     map[string]int64 // Port: Dienste
	}
	mk := func() map[string]*acc { return map[string]*acc{} }
	svc, port, kind := mk(), mk(), mk()
	seen := map[string]bool{}
	add := func(m map[string]*acc, key, group string, n int64, sub string) {
		a := m[key]
		if a == nil {
			a = &acc{key: key, groups: map[string]int64{}, subs: map[string]int64{}}
			m[key] = a
		}
		a.total += n
		a.groups[group] += n
		if sub != "" {
			a.subs[sub] += n
		}
	}
	for _, r := range rows {
		g := KindGroup(r.Kind, r.Source)
		seen[g] = true
		add(svc, r.Service, g, r.Count, "")
		add(port, strconv.Itoa(r.Port), g, r.Count, r.Service)
		add(kind, r.Kind, g, r.Count, "")
	}
	list := func(m map[string]*acc) []uiTarget {
		as := make([]*acc, 0, len(m))
		for _, a := range m {
			as = append(as, a)
		}
		slices.SortFunc(as, func(a, b *acc) int {
			if a.total != b.total {
				if a.total > b.total {
					return -1
				}
				return 1
			}
			return strings.Compare(a.key, b.key)
		})
		if top > 0 && len(as) > top {
			as = as[:top]
		}
		var max int64
		for _, a := range as {
			max = maxInt64(max, a.total)
		}
		out := make([]uiTarget, 0, len(as))
		for _, a := range as {
			t := uiTarget{Key: a.key, Count: a.total}
			var best int64
			for s, n := range a.subs {
				if n > best || (n == best && s < t.Sub) {
					t.Sub, best = s, n
				}
			}
			for _, g := range KindGroups {
				if n := a.groups[g]; n > 0 && max > 0 {
					p := int(n * 100 / max)
					if p < 1 {
						p = 1 // sichtbar
					}
					t.Segs = append(t.Segs, uiSeg{Group: g, Count: n, Pct: p})
				}
			}
			out = append(out, t)
		}
		return out
	}
	if len(rows) == 0 {
		return uiTargets{}
	}
	out := uiTargets{Cols: []uiTargetCol{{"services", "honeypot.top.services", false, list(svc)}, {"ports", "honeypot.top.ports", true, list(port)},
		{"kinds", "honeypot.top.kinds", true, list(kind)}}}
	for _, g := range KindGroups {
		if seen[g] {
			out.Groups = append(out.Groups, g)
		}
	}
	return out
}

// uiDecoy ist ein Koeder bzw. Geraet der kleinen Rangliste (nach Anzahl sortiert).
type uiDecoy struct {
	Kind, Name string // Kind "page" (Koeder) oder "device" (erkanntes Geraet)
	Count      int64
}

func decoyRanks(list []Count) []uiDecoy {
	out := []uiDecoy{}
	for _, c := range list {
		k, name, _ := strings.Cut(c.Key, ":")
		out = append(out, uiDecoy{Kind: k, Name: name, Count: c.Count})
	}
	return out
}
