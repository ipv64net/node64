package honeypot

import (
	"context"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/ports"
)

// Dienste-Katalog (Einstellungen > Fallen-Dienste, GET /api/honeypot/catalog): alle Fallen-Dienste als Tabelle mit
// Schalter, Port, Koeder und Zustand. Der Katalog ist die Vereinigung der Eintraege des Profils "full" und je
// angemeldetem Dienst (sensor_proto.go) eines Standardeintrags; neue Dienste erscheinen so ohne Aenderung hier
// (fehlt ihr Standardport in catalogPorts, faellt das im Test auf). Gespeichert wird die Auswahl als eigene
// Dienste-Liste (custom) oder, wenn sie genau einem Profil entspricht, als dieses Profil (MatchProfile).

// CatalogGroups ist die Reihenfolge der Gruppen (Fernzugriff, Web, Mail, Datenbanken, Router/IoT, Sonstiges).
var CatalogGroups = []string{"remote", "web", "mail", "db", "iot", "other"}

// catalogPorts: Standardports je Dienst (fuer Dienste ohne Eintrag im Profil full und als Vorschlag).
var catalogPorts = map[string]int{SvcSSH: 22, SvcTelnet: 23, SvcHTTP: 80, SvcHTTPS: 443, SvcTCP: 445, SvcFTP: 21, SvcSMTP: 25,
	SvcIMAP: 143, SvcPOP3: 110, SvcMySQL: 3306, SvcPostgre: 5432, SvcMSSQL: 1433, SvcRedis: 6379, SvcVNC: 5900, SvcMQTT: 1883,
	SvcMTAPI: 8728, SvcSNMP: 161, SvcSIP: 5060, SvcRDP: 3389, SvcWinbox: 8291, SvcSMTPS: 465, SvcIMAPS: 993, SvcPOP3S: 995}

// catalogTCP: beliebige TCP-Ports, die im Katalog fuer einen bestimmten Dienst stehen (Gruppe, Beschreibung).
var catalogTCP = map[int]string{445: "other", 27017: "db", 8291: "iot"}

// CatalogEntry ist ein Eintrag des Katalogs.
type CatalogEntry struct {
	Service  string   `json:"service"`
	Port     int      `json:"default_port"` // Standardport
	Page     string   `json:"page,omitempty"`
	Proto    string   `json:"proto"` // tcp oder udp
	Group    string   `json:"group"`
	Profiles []string `json:"profiles,omitempty"` // Profile, die genau diesen Eintrag enthalten
	DescKey  string   `json:"-"`                  // i18n-Schluessel der Beschreibung
}

// KnownServices liefert alle Dienste, die der Sensor oeffnen kann (ohne scan), sortiert nach Gruppe und Name.
func KnownServices() []string {
	out := []string{SvcSSH, SvcTelnet, SvcHTTP, SvcHTTPS, SvcTCP}
	for s := range tcpProtos {
		out = append(out, s)
	}
	for s := range udpProtos {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		gi, gj := catalogGroupIndex(Service{Service: out[i]}), catalogGroupIndex(Service{Service: out[j]})
		if gi != gj {
			return gi < gj
		}
		return out[i] < out[j]
	})
	return slices.Compact(out)
}

// catalogGroup ordnet einen Eintrag einer Gruppe zu.
func catalogGroup(s Service) string {
	switch s.Service {
	case SvcSSH, SvcTelnet, SvcRDP, SvcVNC:
		return "remote"
	case SvcHTTP, SvcHTTPS:
		return "web"
	case SvcSMTP, SvcIMAP, SvcPOP3, SvcSMTPS, SvcIMAPS, SvcPOP3S:
		return "mail"
	case SvcMySQL, SvcPostgre, SvcMSSQL, SvcRedis:
		return "db"
	case SvcMTAPI, SvcSNMP, SvcSIP, SvcMQTT, SvcWinbox:
		return "iot"
	case SvcTCP:
		if g := catalogTCP[s.Port]; g != "" {
			return g
		}
	}
	return "other"
}

func catalogGroupIndex(s Service) int { return slices.Index(CatalogGroups, catalogGroup(s)) }

// catalogDesc liefert den i18n-Schluessel der Beschreibung (Koeder, bekannter TCP-Port oder Dienst; "-" wird "_").
func catalogDesc(s Service) string {
	switch {
	case (s.Service == SvcHTTP || s.Service == SvcHTTPS) && s.Page != "":
		return "honeypot.cat.page." + strings.ReplaceAll(s.Page, "-", "_")
	case s.Service == SvcTCP && catalogTCP[s.Port] != "":
		return "honeypot.cat.tcp." + strconv.Itoa(s.Port)
	}
	return "honeypot.cat.svc." + strings.ReplaceAll(s.Service, "-", "_")
}

// Catalog liefert den Katalog, stabil sortiert nach Gruppe, Dienst und Port.
func Catalog() []CatalogEntry {
	var out []CatalogEntry
	have := map[string]bool{}
	add := func(s Service) {
		e := CatalogEntry{Service: s.Service, Port: s.Port, Page: s.Page, Proto: string(svcProto(s.Service)), Group: catalogGroup(s), DescKey: catalogDesc(s)}
		for _, p := range []string{ProfileMinimal, ProfileStandard, ProfileFull} {
			if slices.Contains(Profiles[p], s) {
				e.Profiles = append(e.Profiles, p)
			}
		}
		out = append(out, e)
		have[s.Service] = true
	}
	seen := map[Service]bool{}
	for _, s := range Profiles[ProfileFull] {
		if !seen[s] {
			seen[s] = true
			add(s)
		}
	}
	for _, s := range KnownServices() {
		if !have[s] {
			add(Service{Service: s, Port: catalogPorts[s]})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ga, gb := slices.Index(CatalogGroups, a.Group), slices.Index(CatalogGroups, b.Group); ga != gb {
			return ga < gb
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		return a.Port < b.Port
	})
	return out
}

// normService bringt einen Eintrag in die Vergleichsform (klein, Koeder nur bei http/https).
func normService(s Service) Service {
	s.Service = strings.ToLower(strings.TrimSpace(s.Service))
	s.Page = strings.ToLower(strings.TrimSpace(s.Page))
	if s.Service != SvcHTTP && s.Service != SvcHTTPS {
		s.Page = ""
	}
	return s
}

// MatchProfile liefert das Profil, das genau die Auswahl enthaelt (Reihenfolge egal), sonst "".
func MatchProfile(sel []Service) string {
	count := map[Service]int{}
	for _, s := range sel {
		count[normService(s)]++
	}
	for _, p := range []string{ProfileMinimal, ProfileStandard, ProfileFull} {
		list := Profiles[p]
		if len(list) != len(sel) {
			continue
		}
		c := map[Service]int{}
		for _, s := range list {
			c[normService(s)]++
		}
		same := len(c) == len(count)
		for k, v := range c {
			if count[k] != v {
				same = false
				break
			}
		}
		if same {
			return p
		}
	}
	return ""
}

// selectionConfig setzt Profil und Dienste aus einer Auswahl: genau ein Profil = dieses Profil (dann wachsen neue
// Dienste kuenftiger Versionen mit; die eigene Liste bleibt unveraendert), sonst eigene Auswahl.
func selectionConfig(c *ModuleConfig, sel []Service) {
	if p := MatchProfile(sel); p != "" {
		c.Profile = p
		return
	}
	c.Profile, c.Services = ProfileCustom, sel
}

// effectiveServices liefert die eingestellte Auswahl (Profil oder eigene Liste).
func effectiveServices(c ModuleConfig) []Service {
	if c.Profile != ProfileCustom {
		return Profiles[c.Profile]
	}
	return c.Services
}

// catRow ist eine Zeile des Katalogs im Formular, so wie eingegeben (Port als Text, damit Fehler sichtbar bleiben).
type catRow struct {
	On      bool
	Service string
	Port    string
	Page    string
	Persona string // Dienst-Profil ("" = Standard fuer Port und Koeder)
	Old     bool   // „verwundbar wirken“ (Config.Vulnerable)
}

// catForm ist der Katalog im Formular: Rows in Katalog-Reihenfolge, Extras = eigene Eintraege.
type catForm struct {
	Rows   []catRow
	Extras []catRow
}

// catMaxExtras begrenzt die eigenen Zeilen im Formular.
const catMaxExtras = 64

// catalogMatch ordnet eine Auswahl den Katalogzeilen zu: zuerst genau (Dienst, Port, Koeder), dann gleicher Dienst
// und Port mit anderem Koeder, dann gleicher Dienst und Koeder auf anderem Port (nicht bei tcp: dort sagt der Port,
// wofuer die Zeile steht). Liefert je Zeile die Auswahl (Index in sel, -1 = aus) und den Rest (eigene Eintraege).
func catalogMatch(cat []CatalogEntry, sel []Service) ([]int, []Service) {
	rows := make([]int, len(cat))
	for i := range rows {
		rows[i] = -1
	}
	used := make([]bool, len(sel))
	passes := []func(e CatalogEntry, s Service) bool{
		func(e CatalogEntry, s Service) bool {
			return e.Service == s.Service && e.Port == s.Port && e.Page == s.Page
		},
		func(e CatalogEntry, s Service) bool { return e.Service == s.Service && e.Port == s.Port },
		func(e CatalogEntry, s Service) bool {
			return e.Service == s.Service && e.Page == s.Page && s.Service != SvcTCP
		},
	}
	for _, match := range passes {
		for i, e := range cat {
			if rows[i] >= 0 {
				continue
			}
			for j, s := range sel {
				if !used[j] && match(e, normService(s)) {
					rows[i], used[j] = j, true
					break
				}
			}
		}
	}
	var rest []Service
	for j, s := range sel {
		if !used[j] {
			rest = append(rest, s)
		}
	}
	return rows, rest
}

// catFormFrom fuellt das Formular aus einer Auswahl (nicht ausgewaehlte Zeilen mit Standardport, aus).
func catFormFrom(sel []Service) catForm {
	cat := Catalog()
	rows, rest := catalogMatch(cat, sel)
	f := catForm{Rows: make([]catRow, len(cat))}
	for i, e := range cat {
		r := catRow{Service: e.Service, Port: strconv.Itoa(e.Port), Page: e.Page}
		if j := rows[i]; j >= 0 {
			s := normService(sel[j])
			r = catRow{On: true, Service: e.Service, Port: strconv.Itoa(s.Port), Page: s.Page}
		}
		f.Rows[i] = r
	}
	for _, s := range rest {
		s = normService(s)
		f.Extras = append(f.Extras, catRow{On: true, Service: s.Service, Port: strconv.Itoa(s.Port), Page: s.Page})
	}
	return f
}

// withPersonas traegt die eingestellten Dienst-Profile (Schluessel dienst:port) in die Zeilen ein.
func (f *catForm) withPersonas(set map[string]string) {
	for _, rows := range [][]catRow{f.Rows, f.Extras} {
		for i := range rows {
			if p, err := strconv.Atoi(rows[i].Port); err == nil {
				rows[i].Persona = set[PersonaKey(rows[i].Service, p)]
			}
		}
	}
}

// withOld traegt „verwundbar wirken“ (Schluessel dienst:port) in die Zeilen ein.
func (f *catForm) withOld(list []string) {
	set := map[string]bool{}
	for _, k := range list {
		set[k] = true
	}
	for _, rows := range [][]catRow{f.Rows, f.Extras} {
		for i := range rows {
			if p, err := strconv.Atoi(rows[i].Port); err == nil {
				rows[i].Old = set[PersonaKey(rows[i].Service, p)]
			}
		}
	}
}

// vulnerable liefert die eingeschalteten Zeilen, die verwundbar wirken sollen (nil = keine).
func (f catForm) vulnerable() []string {
	var out []string
	for _, r := range append(append([]catRow(nil), f.Rows...), f.Extras...) {
		if p, err := strconv.Atoi(r.Port); err == nil && r.On && r.Old && OldVersions(r.Service) && !slices.Contains(out, PersonaKey(r.Service, p)) {
			out = append(out, PersonaKey(r.Service, p))
		}
	}
	sort.Strings(out)
	return out
}

// personas liefert die Profile der eingeschalteten Zeilen, die vom Standard abweichen (nil = alle Standard).
func (f catForm) personas() map[string]string {
	out := map[string]string{}
	for _, r := range append(append([]catRow(nil), f.Rows...), f.Extras...) {
		p, err := strconv.Atoi(r.Port)
		if !r.On || err != nil || !personaValid(r.Service, r.Persona) || r.Persona == DefaultPersona(r.Service, p, r.Page) {
			continue
		}
		out[PersonaKey(r.Service, p)] = r.Persona
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseCatForm liest den Katalog aus dem Formular: je Zeile on_<i>, port_<i>, page_<i>, persona_<i>, old_<i>; eigene
// Zeilen xsvc_<j>, xport_<j>, xpage_<j>, xpersona_<j>, xold_<j> (Anzahl in xn). Der Dienst einer Zeile kommt aus dem Katalog.
func parseCatForm(r *http.Request) catForm {
	cat := Catalog()
	f := catForm{Rows: make([]catRow, len(cat))}
	for i, e := range cat {
		n := strconv.Itoa(i)
		f.Rows[i] = catRow{On: r.PostFormValue("on_"+n) != "", Service: e.Service, Port: strings.TrimSpace(r.PostFormValue("port_" + n)),
			Page: strings.ToLower(strings.TrimSpace(r.PostFormValue("page_" + n))), Persona: strings.ToLower(strings.TrimSpace(r.PostFormValue("persona_" + n))),
			Old: r.PostFormValue("old_"+n) != ""}
		if e.Service != SvcHTTP && e.Service != SvcHTTPS {
			f.Rows[i].Page = ""
		}
	}
	xn, _ := strconv.Atoi(r.PostFormValue("xn"))
	for j := 0; j < min(xn, catMaxExtras); j++ {
		n := strconv.Itoa(j)
		x := catRow{On: true, Service: strings.ToLower(strings.TrimSpace(r.PostFormValue("xsvc_" + n))), Port: strings.TrimSpace(r.PostFormValue("xport_" + n)),
			Page: strings.ToLower(strings.TrimSpace(r.PostFormValue("xpage_" + n))), Persona: strings.ToLower(strings.TrimSpace(r.PostFormValue("xpersona_" + n))),
			Old: r.PostFormValue("xold_"+n) != ""}
		if x.Service != "" || x.Port != "" {
			f.Extras = append(f.Extras, x)
		}
	}
	return f
}

// services liefert die Auswahl des Formulars (eingeschaltete Zeilen und eigene Eintraege). Unlesbare Ports kommen
// als 0 an und fallen in validate auf.
func (f catForm) services() []Service {
	out := []Service{}
	for _, r := range append(append([]catRow(nil), f.Rows...), f.Extras...) {
		if !r.On {
			continue
		}
		p, err := strconv.Atoi(r.Port)
		if err != nil {
			p = 0
		}
		out = append(out, normService(Service{Service: r.Service, Port: p, Page: r.Page}))
	}
	return out
}

// catPresets sind die Vorlagen-Knoepfe (Profile, "free" = alle freien einschalten, "none" = alle aus).
var catPresets = []string{ProfileProxy, ProfileMinimal, ProfileStandard, ProfileFull, "free", "none"}

// preset wendet eine Vorlage auf das Formular an (ohne zu speichern). false = unbekannte Vorlage.
func (f *catForm) preset(name string, st catStates) bool {
	switch name {
	case ProfileMinimal, ProfileStandard, ProfileFull, ProfileProxy:
		*f = catFormFrom(Profiles[name])
	case "free":
		for i := range f.Rows {
			r := &f.Rows[i]
			if p, err := strconv.Atoi(r.Port); err == nil {
				if s := st.state(r.Service, p); s.State == "free" || s.State == "open" {
					r.On = true
				}
			}
		}
	case "none":
		for i := range f.Rows {
			f.Rows[i].On = false
		}
		f.Extras = nil
	default:
		return false
	}
	return true
}

// catStates sind die Daten fuer den Zustand der Zeilen (einmal je Seite bzw. Anfrage geholt).
type catStates struct {
	status []ServiceStatus // laufender Sensor (leer = aus)
	others []ports.Claim   // Ports der anderen Teile
}

func (m *Module) catStates(ctx context.Context) catStates {
	return catStates{status: m.Status(), others: m.others(ctx)}
}

// CatalogState ist der Zustand eines Ports fuer einen Dienst.
type CatalogState struct {
	State   string `json:"state"`             // free, open, error, used (anderer Teil hat ihn offen), reserved (eingestellt, nicht offen)
	Owner   string `json:"owner,omitempty"`   // anderer Teil (web, edge, dns64, cdn64, honeypot …)
	Purpose string `json:"purpose,omitempty"` // z. B. HTTPS
	Error   string `json:"error,omitempty"`   // Fehler des Sensors
	Conns   int64  `json:"conns,omitempty"`   // Verbindungen seit dem Start (offen)
}

// state: zuerst der laufende Sensor (offen/Fehler), dann ein anderer eigener Dienst auf Port und Protokoll, dann die
// Port-Verwaltung (TCP und UDP getrennt, aktiv vor eingestellt).
func (cs catStates) state(service string, port int) CatalogState {
	if port < 1 || port > 65535 {
		return CatalogState{}
	}
	proto := svcProto(service)
	for _, s := range cs.status {
		if s.Service == service && s.Port == port {
			if s.Listen {
				return CatalogState{State: "open", Conns: s.Conns}
			}
			if s.Error != "" {
				return CatalogState{State: "error", Error: s.Error}
			}
		}
	}
	for _, s := range cs.status {
		if s.Listen && s.Port == port && s.Service != service && svcProto(s.Service) == proto {
			return CatalogState{State: "used", Owner: Name, Purpose: "Honeypot " + strings.ToUpper(s.Service)}
		}
	}
	if o, ok := portConflictProto(cs.others, proto, port); ok {
		st := "reserved"
		if o.Active {
			st = "used"
		}
		return CatalogState{State: st, Owner: o.Owner, Purpose: o.Purpose}
	}
	return CatalogState{State: "free"}
}

// CatalogItem ist eine Zeile des Katalogs mit Auswahl und Zustand (API).
type CatalogItem struct {
	Service     string   `json:"service"`
	Port        int      `json:"port"`                   // eingestellter bzw. Standardport
	DefaultPort int      `json:"default_port,omitempty"` // 0 = eigener Eintrag ausserhalb des Katalogs
	Page        string   `json:"page,omitempty"`
	Proto       string   `json:"proto"`
	Group       string   `json:"group"`
	Description string   `json:"description,omitempty"`
	Profiles    []string `json:"profiles,omitempty"`
	On          bool     `json:"on"`
	// Dienst-Profil: eingestellt bzw. Standard, Standard fuer Port und Koeder, Auswahl (leer = keine)
	Persona        string   `json:"persona,omitempty"`
	DefaultPersona string   `json:"default_persona,omitempty"`
	Personas       []string `json:"personas,omitempty"`
	// „verwundbar wirken“: eingeschaltet bzw. fuer den Dienst moeglich
	Vulnerable     bool `json:"vulnerable,omitempty"`
	VulnerableAble bool `json:"vulnerable_available,omitempty"`
	CatalogState
}

// personaItem fuellt die Profil-Felder einer Zeile der API.
func (it *CatalogItem) personaItem(persona string) {
	it.DefaultPersona, it.Personas = DefaultPersona(it.Service, it.Port, it.Page), PersonasFor(it.Service)
	it.Persona = persona
	if it.Persona == "" {
		it.Persona = it.DefaultPersona
	}
}

// CatalogInfo ist die Antwort von GET /api/honeypot/catalog.
type CatalogInfo struct {
	Profile  string               `json:"profile"`  // gespeichertes Profil (custom = eigene Auswahl)
	Hostname string               `json:"hostname"` // Hostname der Fallen (eingestellt oder erzeugt)
	Running  bool                 `json:"running"`  // Modul laeuft (sonst kein Zustand offen/Fehler)
	Entries  []CatalogItem        `json:"entries"`  // Katalog
	Extra    []CatalogItem        `json:"extra"`    // ausgewaehlte Dienste ausserhalb des Katalogs (z. B. ssh 2200)
	Services []string             `json:"services"` // Dienste fuer eigene Eintraege
	Pages    []string             `json:"pages"`    // Koeder (http/https)
	Groups   []string             `json:"groups"`
	Presets  map[string][]Service `json:"presets"` // Profile als Vorlage
}

// catalogInfo baut den Katalog mit Auswahl und Zustand (tr uebersetzt die Beschreibung, nil = Schluessel).
func (m *Module) catalogInfo(ctx context.Context, tr func(string) string) CatalogInfo {
	c := m.loadConfig(ctx)
	f := catFormFrom(effectiveServices(c))
	f.withPersonas(c.Personas)
	f.withOld(c.Vulnerable)
	st := m.catStates(ctx)
	if tr == nil {
		tr = func(k string) string { return k }
	}
	out := CatalogInfo{Profile: c.Profile, Hostname: m.ident(ctx, c).host, Running: m.running() != nil, Entries: []CatalogItem{}, Extra: []CatalogItem{}, Services: KnownServices(),
		Pages: Pages, Groups: CatalogGroups, Presets: map[string][]Service{}}
	for _, p := range []string{ProfileMinimal, ProfileStandard, ProfileFull} {
		out.Presets[p] = Profiles[p]
	}
	for i, e := range Catalog() {
		r := f.Rows[i]
		p, _ := strconv.Atoi(r.Port)
		it := CatalogItem{Service: e.Service, Port: p, DefaultPort: e.Port, Page: r.Page, Proto: e.Proto, Group: e.Group,
			Description: tr(e.DescKey), Profiles: e.Profiles, On: r.On, CatalogState: st.state(e.Service, p)}
		it.personaItem(r.Persona)
		it.Vulnerable, it.VulnerableAble = r.Old && OldVersions(e.Service), OldVersions(e.Service)
		out.Entries = append(out.Entries, it)
	}
	for _, r := range f.Extras {
		p, _ := strconv.Atoi(r.Port)
		s := Service{Service: r.Service, Port: p, Page: r.Page}
		it := CatalogItem{Service: s.Service, Port: p, Page: s.Page, Proto: string(svcProto(s.Service)), Group: catalogGroup(s),
			Description: tr(catalogDesc(s)), On: true, CatalogState: st.state(s.Service, p)}
		it.personaItem(r.Persona)
		it.Vulnerable, it.VulnerableAble = r.Old && OldVersions(s.Service), OldVersions(s.Service)
		out.Extra = append(out.Extra, it)
	}
	return out
}

// uiCatRow ist eine Zeile der Tabelle in den Einstellungen.
type uiCatRow struct {
	Index int
	catRow
	Group      string // Gruppe (Ueberschrift, wenn GroupStart)
	GroupStart bool
	DescKey    string
	Proto      string
	Web        bool // http/https: Koeder-Auswahl
	Low        bool // Port unter 1024 (cap_net_bind_service)
	CatalogState
	OwnerName  string
	Personas   []uiPersona // Auswahl des Dienst-Profils (leer = keine)
	PersonaSel string      // ausgewaehltes Profil (eingestellt oder Standard)
	OldAble    bool        // „verwundbar wirken“ moeglich
}

// uiPersona ist ein Eintrag der Profil-Auswahl.
type uiPersona struct {
	Key, Label string
	Default    bool
}

// catView baut die Zeilen der Tabelle (Katalog und eigene Eintraege, dazu leere Zeilen zum Ergaenzen).
func (m *Module) catView(r *http.Request, f catForm, st catStates) (rows, extras []uiCatRow, low bool) {
	row := func(i int, cr catRow, group, desc string) uiCatRow {
		u := uiCatRow{Index: i, catRow: cr, Group: group, DescKey: desc, Proto: string(svcProto(cr.Service)), Web: cr.Service == SvcHTTP || cr.Service == SvcHTTPS,
			OldAble: OldVersions(cr.Service)}
		if p, err := strconv.Atoi(cr.Port); err == nil && cr.Service != "" {
			u.CatalogState = st.state(cr.Service, p)
			u.Low = p > 0 && p < 1024
			low = low || (u.Low && cr.On)
			def := DefaultPersona(cr.Service, p, cr.Page)
			u.PersonaSel = cr.Persona
			if !personaValid(cr.Service, u.PersonaSel) {
				u.PersonaSel = def
			}
			for _, k := range PersonasFor(cr.Service) {
				u.Personas = append(u.Personas, uiPersona{Key: k, Label: PersonaLabels[k], Default: k == def})
			}
		}
		if u.Owner != "" {
			u.OwnerName = m.ownerName(r, u.Owner)
		}
		return u
	}
	last := ""
	for i, e := range Catalog() {
		if i >= len(f.Rows) {
			break
		}
		u := row(i, f.Rows[i], e.Group, e.DescKey)
		u.GroupStart, last = e.Group != last, e.Group
		rows = append(rows, u)
	}
	for j, x := range f.Extras {
		if j >= catMaxExtras {
			break
		}
		s := Service{Service: x.Service}
		if p, err := strconv.Atoi(x.Port); err == nil {
			s.Port = p
		}
		extras = append(extras, row(j, x, catalogGroup(s), catalogDesc(s)))
	}
	for k := 0; k < 3 && len(extras) < catMaxExtras; k++ { // leere Zeilen zum Ergaenzen
		extras = append(extras, uiCatRow{Index: len(extras), Web: true})
	}
	return rows, extras, low
}

// uiPorts liefert die Ports der Oberflaeche von Node64 (Teil "web" der Port-Verwaltung), "" = unbekannt.
func (m *Module) uiPorts(ctx context.Context) string {
	var ps []string
	for _, c := range m.othersProto(ctx, ports.TCP) {
		if c.Owner == "web" {
			ps = append(ps, strconv.Itoa(c.Port))
		}
	}
	return strings.Join(ps, ", ")
}
