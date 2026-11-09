package snmp

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Geraete-Profile: Datendateien profiles/*.json (Format in profiles/README.md). Die Node waehlt sie selbst ueber
// sysObjectID/sysDescr (und optional eine Probe-OID); mehrere passende Profile gelten zusammen.

//go:embed profiles/*.json
var profileFS embed.FS

// Profile ist ein Geraete-Profil.
type Profile struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Device   string      `json:"device,omitempty"` // nas, ups, printer, switch, router, ap, server
	Verified bool        `json:"verified"`         // an einem echten Geraet geprueft
	Source   string      `json:"source,omitempty"` // MIB/Version/Geraet, aus dem die OIDs stammen
	Match    Match       `json:"match"`
	Scalars  []ScalarDef `json:"scalars,omitempty"`
	Tables   []TableDef  `json:"tables,omitempty"`
}

// Match waehlt das Profil: (sysObjectID beginnt mit einem Eintrag ODER sysDescr enthaelt einen Eintrag) UND (keine
// Probe ODER die Probe-OID liefert einen Wert). Ohne object_ids und descr entscheidet nur die Probe.
type Match struct {
	ObjectIDs []string `json:"object_ids,omitempty"`
	Descr     []string `json:"descr,omitempty"` // Teiltext, ohne Gross-/Kleinschreibung
	Probe     string   `json:"probe,omitempty"`
}

// Target ist der Dienst, in den ein Wert geht.
type Target struct {
	Key     string `json:"key"`               // Dienst-Schluessel, z. B. "ups" oder "disk:{name}"
	Service string `json:"service,omitempty"` // Anzeigename (Platzhalter wie key)
	Kind    string `json:"kind"`              // Dienst-Art (if, fs, disk, raid, temp, ups ...)
	Default *bool  `json:"default,omitempty"` // beim Erkennen vorgeschlagen (Standard: ja)
}

// Value beschreibt, was aus einem Wert wird: Messgroesse, Fact und/oder Anzeigetext.
type Value struct {
	Metric  string            `json:"metric,omitempty"`  // Name der Messgroesse
	Unit    string            `json:"unit,omitempty"`    // %, °C, B, s ...
	Factor  float64           `json:"factor,omitempty"`  // Wert = Roh * Faktor + Offset (0 = 1)
	Offset  float64           `json:"offset,omitempty"`  //
	Rule    string            `json:"rule,omitempty"`    // Art fuer Standard-Schwellen
	Counter bool              `json:"counter,omitempty"` // Zaehler: Rate je Sekunde (vor dem Faktor)
	Leading bool              `json:"leading,omitempty"` // Zahl am Textanfang ("37 C/98 F")
	Min     *float64          `json:"min,omitempty"`     // gueltiger Rohwert (sonst verworfen)
	Max     *float64          `json:"max,omitempty"`     //
	Fact    *FactDef          `json:"fact,omitempty"`    //
	Text    map[string]string `json:"text,omitempty"`    // Rohwert -> Anzeige ("1": "Normal")
	Label   string            `json:"label,omitempty"`   // Rohtext mit diesem Vorsatz in den Dienst-Text ("Modell")
	Hide    bool              `json:"hide,omitempty"`    // Messwert nicht im Dienst-Text
	Pct     *PctDef           `json:"pct,omitempty"`     // Belegung in % aus zwei Werten (Metric = Name)
}

// FactDef: Fact, wenn der Wert passt. when/ok fuer Zahlen, when_text/ok_text fuer Texte (Teiltext, ohne
// Gross-/Kleinschreibung), above/below fuer Grenzen.
type FactDef struct {
	Code     string    `json:"code"`
	When     []float64 `json:"when,omitempty"`
	OK       []float64 `json:"ok,omitempty"`
	WhenText []string  `json:"when_text,omitempty"`
	OKText   []string  `json:"ok_text,omitempty"`
	Above    *float64  `json:"above,omitempty"`
	Below    *float64  `json:"below,omitempty"`
	Text     string    `json:"text,omitempty"` // Text des Facts (Standard: Anzeige aus "text" bzw. Rohwert)
}

// PctDef: Belegung = (Gesamt - Frei) / Gesamt bzw. Belegt / Gesamt. Skalare: OIDs, Tabellen: Spaltennummern.
type PctDef struct {
	Total string  `json:"total"`
	Used  string  `json:"used,omitempty"`
	Free  string  `json:"free,omitempty"`
	Unit  float64 `json:"unit,omitempty"` // Bytes je Einheit fuer Max/free (0 = 1)
}

// ScalarDef ist ein einzelner Wert (GET).
type ScalarDef struct {
	Target
	OID string `json:"oid"`
	Value
}

// TableDef ist eine Tabelle (GETBULK); je Zeile ein Dienst.
type TableDef struct {
	Target
	OID     string   `json:"oid"`                // Entry-OID (…Table.1), Spalten = OID.<col>
	NameCol int      `json:"name_col,omitempty"` // Spalte fuer {name}
	Filter  *Filter  `json:"filter,omitempty"`
	Columns []ColDef `json:"columns"`
}

// Filter: nur Zeilen, deren Spalte einen der Werte hat.
type Filter struct {
	Col    int       `json:"col"`
	Values []float64 `json:"values"`
}

// ColDef ist eine Spalte einer Tabelle.
type ColDef struct {
	Col int `json:"col"`
	Value
}

var (
	profOnce sync.Once
	profList []*Profile
	profByID map[string]*Profile
	profErr  error
)

// Profiles liefert alle eingebauten Profile (geprueft); fehlerhafte fehlen, ProfilesError nennt sie.
func Profiles() []*Profile {
	profOnce.Do(loadProfiles)
	return profList
}

// ProfileByID liefert ein Profil (nil = unbekannt).
func ProfileByID(id string) *Profile {
	profOnce.Do(loadProfiles)
	return profByID[id]
}

// ProfilesError nennt Fehler beim Laden der Profile (nil = alle in Ordnung).
func ProfilesError() error {
	profOnce.Do(loadProfiles)
	return profErr
}

func loadProfiles() {
	profByID = map[string]*Profile{}
	var errs []string
	_ = fs.WalkDir(profileFS, "profiles", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		b, err := profileFS.ReadFile(path)
		if err != nil {
			errs = append(errs, path+": "+err.Error())
			return nil
		}
		p, err := ParseProfile(b)
		if err != nil {
			errs = append(errs, path+": "+err.Error())
			return nil
		}
		if profByID[p.ID] != nil {
			errs = append(errs, path+": Profil-ID doppelt: "+p.ID)
			return nil
		}
		profByID[p.ID] = p
		profList = append(profList, p)
		return nil
	})
	sort.Slice(profList, func(i, j int) bool { return profList[i].ID < profList[j].ID })
	if len(errs) > 0 {
		profErr = errors.New(strings.Join(errs, "; "))
	}
}

var (
	reID     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	reKind   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,15}$`)
	reMetric = regexp.MustCompile(`^[a-z][a-z0-9_]{0,23}$`)
	reKey    = regexp.MustCompile(`^[a-z][a-z0-9_-]*(:[^{}]*(\{(name|index)\}[^{}]*)*)?$`)
	reDevice = regexp.MustCompile(`^(|nas|ups|printer|switch|router|ap|server|pdu|device)$`)
)

// ParseProfile liest und prueft ein Profil (unbekannte Felder sind Fehler).
func ParseProfile(b []byte) (*Profile, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var p Profile
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Profile) validate() error {
	if !reID.MatchString(p.ID) {
		return fmt.Errorf("ungueltige id %q", p.ID)
	}
	if strings.TrimSpace(p.Name) == "" || len(p.Name) > 64 {
		return errors.New("name fehlt oder zu lang")
	}
	if !reDevice.MatchString(p.Device) {
		return fmt.Errorf("unbekanntes device %q", p.Device)
	}
	if len(p.Match.ObjectIDs) == 0 && len(p.Match.Descr) == 0 && p.Match.Probe == "" {
		return errors.New("match leer")
	}
	for i, o := range p.Match.ObjectIDs {
		if normOID(o) == "" {
			return fmt.Errorf("match.object_ids: ungueltige OID %q", o)
		}
		p.Match.ObjectIDs[i] = normOID(o)
	}
	for _, d := range p.Match.Descr {
		if strings.TrimSpace(d) == "" {
			return errors.New("match.descr: leerer Eintrag")
		}
	}
	if p.Match.Probe != "" {
		if normOID(p.Match.Probe) == "" {
			return fmt.Errorf("match.probe: ungueltige OID %q", p.Match.Probe)
		}
		p.Match.Probe = normOID(p.Match.Probe)
	}
	for i := range p.Scalars {
		s := &p.Scalars[i]
		where := fmt.Sprintf("scalars[%d]", i)
		if err := s.Target.validate(false); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if normOID(s.OID) == "" {
			return fmt.Errorf("%s: ungueltige oid %q", where, s.OID)
		}
		s.OID = normOID(s.OID)
		if err := s.Value.validate(false); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
	}
	for i := range p.Tables {
		t := &p.Tables[i]
		where := fmt.Sprintf("tables[%d]", i)
		if err := t.Target.validate(true); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if normOID(t.OID) == "" {
			return fmt.Errorf("%s: ungueltige oid %q", where, t.OID)
		}
		t.OID = normOID(t.OID)
		if strings.Contains(t.Key+t.Service, "{name}") && t.NameCol <= 0 {
			return fmt.Errorf("%s: {name} ohne name_col", where)
		}
		if t.NameCol < 0 || t.NameCol > 1000 {
			return fmt.Errorf("%s: ungueltige name_col", where)
		}
		if !strings.Contains(t.Key, "{name}") && !strings.Contains(t.Key, "{index}") {
			return fmt.Errorf("%s: key braucht {name} oder {index}", where)
		}
		if t.Filter != nil && (t.Filter.Col <= 0 || t.Filter.Col > 1000 || len(t.Filter.Values) == 0) {
			return fmt.Errorf("%s: ungueltiger filter", where)
		}
		if len(t.Columns) == 0 {
			return fmt.Errorf("%s: keine columns", where)
		}
		for j := range t.Columns {
			c := &t.Columns[j]
			if c.Col <= 0 || c.Col > 1000 {
				return fmt.Errorf("%s.columns[%d]: ungueltige col", where, j)
			}
			if err := c.Value.validate(true); err != nil {
				return fmt.Errorf("%s.columns[%d]: %w", where, j, err)
			}
		}
	}
	if len(p.Scalars) == 0 && len(p.Tables) == 0 && p.Device == "" {
		return errors.New("weder Werte noch device")
	}
	return nil
}

func (t *Target) validate(table bool) error {
	if len(t.Key) > 64 || !reKey.MatchString(t.Key) {
		return fmt.Errorf("ungueltiger key %q", t.Key)
	}
	if !table && strings.Contains(t.Key+t.Service, "{") {
		return errors.New("Platzhalter nur in Tabellen")
	}
	if !reKind.MatchString(t.Kind) {
		return fmt.Errorf("ungueltige kind %q", t.Kind)
	}
	if len(t.Service) > 64 {
		return errors.New("service zu lang")
	}
	return nil
}

func (v *Value) validate(table bool) error {
	if v.Metric == "" && v.Fact == nil && len(v.Text) == 0 && v.Label == "" {
		return errors.New("weder metric noch fact, text oder label")
	}
	if v.Metric != "" && !reMetric.MatchString(v.Metric) {
		return fmt.Errorf("ungueltige metric %q", v.Metric)
	}
	if v.Pct != nil && v.Metric == "" {
		return errors.New("pct braucht metric")
	}
	if v.Rule != "" && (v.Metric == "" || !validRule(v.Rule)) {
		return fmt.Errorf("ungueltige rule %q", v.Rule)
	}
	if !validUnit(v.Unit) {
		return fmt.Errorf("unbekannte unit %q", v.Unit)
	}
	if !finite(v.Factor) || !finite(v.Offset) {
		return errors.New("ungueltiger factor/offset")
	}
	if (v.Min != nil && !finite(*v.Min)) || (v.Max != nil && !finite(*v.Max)) {
		return errors.New("ungueltiges min/max")
	}
	if len(v.Label) > 32 {
		return errors.New("label zu lang")
	}
	for k, t := range v.Text {
		if len(k) > 64 || len(t) > 64 {
			return errors.New("text-Eintrag zu lang")
		}
	}
	if f := v.Fact; f != nil {
		if !knownFacts[f.Code] {
			return fmt.Errorf("unbekannter fact.code %q", f.Code)
		}
		n := 0
		for _, set := range []bool{len(f.When) > 0, len(f.OK) > 0, len(f.WhenText) > 0, len(f.OKText) > 0, f.Above != nil, f.Below != nil} {
			if set {
				n++
			}
		}
		if n != 1 {
			return errors.New("fact braucht genau eine Bedingung (when, ok, when_text, ok_text, above, below)")
		}
		if len(f.Text) > 64 {
			return errors.New("fact.text zu lang")
		}
	}
	if pc := v.Pct; pc != nil {
		if (pc.Used == "") == (pc.Free == "") {
			return errors.New("pct braucht used oder free")
		}
		if !finite(pc.Unit) || pc.Unit < 0 {
			return errors.New("pct.unit ungueltig")
		}
		for _, ref := range []string{pc.Total, pc.Used, pc.Free} {
			if ref == "" {
				continue
			}
			if table {
				if n, err := strconv.Atoi(ref); err != nil || n <= 0 || n > 1000 {
					return fmt.Errorf("pct: Spaltennummer erwartet, nicht %q", ref)
				}
			} else if normOID(ref) == "" {
				return fmt.Errorf("pct: OID erwartet, nicht %q", ref)
			}
		}
		if pc.Total == "" {
			return errors.New("pct.total fehlt")
		}
	}
	return nil
}

// oids nennt die abgefragten OIDs bzw. Tabellen (fuer "Was wird abgefragt?").
func (p *Profile) oids() []string {
	var out []string
	for _, s := range p.Scalars {
		out = append(out, s.OID)
	}
	for _, t := range p.Tables {
		out = append(out, t.OID+" (Tabelle)")
	}
	return out
}

// keyPrefixes: Schluessel bzw. Praefixe der Dienste des Profils (fuer Teilfehler).
func (p *Profile) keyPrefixes() []string {
	var pre []string
	for _, s := range p.Scalars {
		pre = append(pre, s.Key)
	}
	for _, t := range p.Tables {
		pre = append(pre, keyPrefix(t.Key))
	}
	return pre
}

// matches prueft object_ids/descr (ohne Probe).
func (p *Profile) matches(objectID, descr string) bool {
	if len(p.Match.ObjectIDs) == 0 && len(p.Match.Descr) == 0 {
		return true // nur Probe
	}
	o, _ := parseOID(objectID)
	for _, pre := range p.Match.ObjectIDs {
		po, _ := parseOID(pre)
		if o != nil && (cmpOID(o, po) == 0 || o.hasPrefix(po)) {
			return true
		}
	}
	d := strings.ToLower(descr)
	for _, s := range p.Match.Descr {
		if strings.Contains(d, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// selectProfiles waehlt die Profile (fest eingestellt oder ueber sysObjectID/sysDescr/Probe; stuendlich neu).
func (c *Collector) selectProfiles(r *round) {
	if len(c.cfg.Profiles) > 0 {
		if c.profiles == nil {
			for _, id := range c.cfg.Profiles {
				if p := ProfileByID(id); p != nil {
					c.profiles = append(c.profiles, p)
				}
			}
		}
		return
	}
	of := r.sys.objectID + "|" + r.sys.descr
	if c.profiles != nil && of == c.profileOf && r.now.Sub(c.profileAt) < profileEvery {
		return
	}
	var cand []*Profile
	var probes []string
	for _, p := range Profiles() {
		if p.matches(r.sys.objectID, r.sys.descr) {
			cand = append(cand, p)
			if p.Match.Probe != "" {
				probes = append(probes, p.Match.Probe)
			}
		}
	}
	var res map[string]pdu
	if len(probes) > 0 {
		var err error
		res, err = getScalars(r.ctx, r.c, probes)
		if err != nil {
			var pre []string
			for _, p := range cand {
				pre = append(pre, p.keyPrefixes()...)
			}
			r.part.add("Profil-Erkennung", err, pre...)
			if c.profiles != nil {
				return // bisherige Auswahl behalten
			}
		}
	}
	sel := []*Profile{}
	for _, p := range cand {
		if p.Match.Probe != "" {
			if _, ok := res[p.Match.Probe]; !ok {
				continue
			}
		}
		sel = append(sel, p)
	}
	c.profiles, c.profileOf, c.profileAt = sel, of, r.now
}

// collectProfiles wertet die Werte der gewaehlten Profile aus.
func (c *Collector) collectProfiles(r *round) {
	for _, p := range c.profiles {
		c.collectProfile(r, p)
	}
}

// acc sammelt die Werte eines Dienstes aus einem Profil.
type acc struct {
	s     model.Service
	parts []string
}

func (c *Collector) collectProfile(r *round, p *Profile) {
	accs := map[string]*acc{}
	var order []string
	get := func(t Target, name, index string) *acc {
		key := fill(t.Key, name, index)
		a, ok := accs[key]
		if !ok {
			def := true
			if t.Default != nil {
				def = *t.Default
			}
			a = &acc{s: model.Service{Key: key, Name: firstNonEmpty(fill(t.Service, name, index), key), Kind: t.Kind, Default: def}}
			accs[key] = a
			order = append(order, key)
		}
		return a
	}
	// Skalare
	if len(p.Scalars) > 0 {
		oids := map[string]bool{}
		var list []string
		add := func(o string) {
			if o != "" && !oids[o] {
				oids[o] = true
				list = append(list, o)
			}
		}
		for _, s := range p.Scalars {
			add(s.OID)
			if s.Pct != nil {
				add(normOID(s.Pct.Total))
				add(normOID(s.Pct.Used))
				add(normOID(s.Pct.Free))
			}
		}
		res, err := getScalars(r.ctx, r.c, list)
		if err != nil {
			r.part.add("Profil "+p.Name, err, p.keyPrefixes()...)
			return
		}
		for _, s := range p.Scalars {
			pv, ok := res[s.OID]
			if !ok {
				continue
			}
			a := get(s.Target, "", "")
			look := func(ref string) (pdu, bool) { v, ok := res[normOID(ref)]; return v, ok }
			c.applyValue(r, a, s.Value, pv, look, "prof|"+p.ID+"|"+s.OID)
		}
	}
	// Tabellen
	for ti, t := range p.Tables {
		colSet := map[int]bool{}
		for _, cd := range t.Columns {
			colSet[cd.Col] = true
			if cd.Pct != nil {
				for _, ref := range []string{cd.Pct.Total, cd.Pct.Used, cd.Pct.Free} {
					if n, err := strconv.Atoi(ref); err == nil {
						colSet[n] = true
					}
				}
			}
		}
		if t.NameCol > 0 {
			colSet[t.NameCol] = true
		}
		if t.Filter != nil {
			colSet[t.Filter.Col] = true
		}
		var cols []string
		for n := range colSet {
			cols = append(cols, t.OID+"."+strconv.Itoa(n))
		}
		sort.Strings(cols)
		tab, err := walkColumns(r.ctx, r.c, cols, c.cfg.MaxRep)
		if err != nil {
			r.part.add(fmt.Sprintf("Profil %s Tabelle %d", p.Name, ti+1), err, keyPrefix(t.Key))
			continue
		}
		colOID := func(n int) string { return t.OID + "." + strconv.Itoa(n) }
		for _, idx := range tab.rows() {
			if t.Filter != nil {
				v, ok := num(tab.col(colOID(t.Filter.Col))[idx])
				if !ok || !containsF(t.Filter.Values, v) {
					continue
				}
			}
			name := ""
			if t.NameCol > 0 {
				name = keyPart(text(tab.col(colOID(t.NameCol))[idx]))
				if name == "" {
					name = idx
				}
			}
			var a *acc
			for _, cd := range t.Columns {
				pv, ok := tab.col(colOID(cd.Col))[idx]
				if !ok {
					continue
				}
				if a == nil {
					a = get(t.Target, name, idx)
				}
				look := func(ref string) (pdu, bool) {
					n, err := strconv.Atoi(ref)
					if err != nil {
						return pdu{}, false
					}
					v, ok := tab.col(colOID(n))[idx]
					return v, ok
				}
				c.applyValue(r, a, cd.Value, pv, look, fmt.Sprintf("prof|%s|%d|%s|%d", p.ID, ti, idx, cd.Col))
			}
		}
	}
	for _, k := range order {
		a := accs[k]
		a.s.Text = strings.Join(a.parts, " · ")
		r.out = append(r.out, a.s)
	}
}

// applyValue wertet einen Wert nach der Definition aus und traegt ihn in den Dienst ein.
func (c *Collector) applyValue(r *round, a *acc, v Value, p pdu, look func(string) (pdu, bool), ctrKey string) {
	raw := text(p)
	f, okNum := num(p)
	if !okNum && v.Leading {
		f, okNum = parseNumText(raw, true)
	}
	if okNum && ((v.Min != nil && f < *v.Min) || (v.Max != nil && f > *v.Max)) {
		return // ungueltiger Wert (z. B. -1 = nicht unterstuetzt)
	}
	display := raw
	if t, ok := v.Text[raw]; ok {
		display = t
	} else if okNum {
		if t, ok := v.Text[strconv.FormatFloat(f, 'f', -1, 64)]; ok {
			display = t
		}
	}
	factor := v.Factor
	if factor == 0 {
		factor = 1
	}
	if v.Metric != "" {
		switch {
		case v.Pct != nil:
			if m, ok := pctMetric(v, look); ok {
				a.s.Metrics = append(a.s.Metrics, m...)
				if !v.Hide {
					a.parts = append(a.parts, fmt.Sprintf("%.0f %% belegt", m[0].Value))
				}
			}
		case v.Counter:
			if rt, ok := c.rate(ctrKey, p, r.now); ok {
				val := rt*factor + v.Offset
				if finite(val) {
					a.s.Metrics = append(a.s.Metrics, model.Metric{Name: v.Metric, Value: round4(val), Unit: v.Unit, Rule: v.Rule})
					if !v.Hide {
						a.parts = append(a.parts, valueText(val, v.Unit))
					}
				}
			}
		case okNum:
			val := f*factor + v.Offset
			if finite(val) {
				a.s.Metrics = append(a.s.Metrics, model.Metric{Name: v.Metric, Value: round4(val), Unit: v.Unit, Rule: v.Rule})
				if !v.Hide && len(v.Text) == 0 {
					a.parts = append(a.parts, valueText(val, v.Unit))
				}
			}
		}
	}
	if len(v.Text) > 0 && display != "" {
		a.parts = append(a.parts, display)
	}
	if v.Label != "" && raw != "" {
		a.parts = append(a.parts, v.Label+" "+raw)
	}
	if fd := v.Fact; fd != nil && factHit(fd, f, okNum, raw) {
		txt := fd.Text
		if txt == "" {
			txt = display
		}
		for _, x := range a.s.Facts {
			if x.Code == fd.Code {
				return
			}
		}
		a.s.Facts = append(a.s.Facts, model.Fact{Code: fd.Code, Text: txt})
	}
}

func factHit(fd *FactDef, f float64, okNum bool, raw string) bool {
	lr := strings.ToLower(raw)
	containsAny := func(l []string) bool {
		for _, s := range l {
			if strings.Contains(lr, strings.ToLower(s)) {
				return true
			}
		}
		return false
	}
	switch {
	case len(fd.When) > 0:
		return okNum && containsF(fd.When, f)
	case len(fd.OK) > 0:
		return okNum && !containsF(fd.OK, f)
	case len(fd.WhenText) > 0:
		return raw != "" && containsAny(fd.WhenText)
	case len(fd.OKText) > 0:
		return raw != "" && !containsAny(fd.OKText)
	case fd.Above != nil:
		return okNum && f > *fd.Above
	case fd.Below != nil:
		return okNum && f < *fd.Below
	}
	return false
}

// pctMetric: Belegung in % (Regel aus der Definition) und frei in Bytes.
func pctMetric(v Value, look func(string) (pdu, bool)) ([]model.Metric, bool) {
	tp, ok := look(v.Pct.Total)
	if !ok {
		return nil, false
	}
	total, ok := num(tp)
	if !ok || total <= 0 {
		return nil, false
	}
	var used float64
	if v.Pct.Used != "" {
		up, ok := look(v.Pct.Used)
		if !ok {
			return nil, false
		}
		if used, ok = num(up); !ok {
			return nil, false
		}
	} else {
		fp, ok := look(v.Pct.Free)
		if !ok {
			return nil, false
		}
		free, ok := num(fp)
		if !ok {
			return nil, false
		}
		used = total - free
	}
	unit := v.Pct.Unit
	if unit == 0 {
		unit = 1
	}
	used = max(0, min(used, total))
	out := []model.Metric{{Name: v.Metric, Value: pct(used, total), Unit: "%", Rule: v.Rule, Max: total * unit}}
	out = append(out, model.Metric{Name: "free", Value: (total - used) * unit, Unit: "B", Max: total * unit})
	return out, true
}

func fill(tpl, name, index string) string {
	return strings.NewReplacer("{name}", name, "{index}", index).Replace(tpl)
}

// keyPrefix: Schluessel bis zum ersten Platzhalter ("disk:{name}" -> "disk:").
func keyPrefix(k string) string {
	if i := strings.Index(k, "{"); i >= 0 {
		return k[:i]
	}
	return k
}

func containsF(l []float64, v float64) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}
