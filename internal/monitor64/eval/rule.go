package eval

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// Direction gibt an, in welche Richtung eine Schwelle wirkt.
type Direction string

const (
	Up   Direction = "up"   // Problem ab Schwelle aufwaerts (Wert >= Schwelle), z. B. Belegung
	Down Direction = "down" // Problem unter der Schwelle (Wert < Schwelle), z. B. Toner, USV-Restlaufzeit
)

// Mode waehlt bei Fuellstaenden zwischen "Prozent belegt" und "weniger als X GB frei".
type Mode string

const (
	ModeUsed Mode = "used" // Warn/Crit in Prozent belegt
	ModeFree Mode = "free" // WarnFree/CritFree in GB frei (Richtung immer unten)
)

// GB ist die Einheit fuer den Modus "GB frei" (Dezimal-GB wie bei Plattengroessen).
const GB = 1e9

// Report: melden oder nur anzeigen.
type Report string

const (
	ReportNotify Report = "notify" // Standard: Zustand, Verlauf und Benachrichtigung
	ReportShow   Report = "show"   // nur anzeigen: keine Benachrichtigung, nicht in der Problemliste oben
)

// Severity ist die Schwere einer Zustandsregel (feste Regel ohne Zahl).
type Severity string

const (
	SevCrit Severity = "crit"
	SevWarn Severity = "warn"
	SevOff  Severity = "off" // nicht melden: die Bedingung macht den Dienst nicht schlechter
)

func (d *Direction) UnmarshalText(b []byte) error {
	return enumText(b, (*string)(d), string(Up), string(Down))
}
func (m *Mode) UnmarshalText(b []byte) error {
	return enumText(b, (*string)(m), string(ModeUsed), string(ModeFree))
}
func (r *Report) UnmarshalText(b []byte) error {
	return enumText(b, (*string)(r), string(ReportNotify), string(ReportShow))
}
func (s *Severity) UnmarshalText(b []byte) error {
	return enumText(b, (*string)(s), string(SevCrit), string(SevWarn), string(SevOff))
}

func enumText(b []byte, dst *string, allowed ...string) error {
	v := strings.ToLower(strings.TrimSpace(string(b)))
	for _, a := range allowed {
		if v == a {
			*dst = a
			return nil
		}
	}
	return fmt.Errorf("eval: unbekannter Wert %q (erlaubt: %s)", b, strings.Join(allowed, ", "))
}

// Limit ist eine Schwelle. Off = ausdruecklich keine Schwelle (z. B. "nur Kritisch"). JSON: Zahl oder "off".
type Limit struct {
	V   float64
	Off bool
}

// L ist eine Kurzform fuer eine gesetzte Schwelle.
func L(v float64) *Limit { return &Limit{V: v} }

// LOff ist eine ausdruecklich abgeschaltete Schwelle.
func LOff() *Limit { return &Limit{Off: true} }

func (l Limit) MarshalJSON() ([]byte, error) {
	if l.Off {
		return []byte(`"off"`), nil
	}
	if math.IsNaN(l.V) || math.IsInf(l.V, 0) {
		return nil, errors.New("eval: Schwelle ist keine endliche Zahl")
	}
	return json.Marshal(l.V)
}

func (l *Limit) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		if strings.EqualFold(strings.TrimSpace(s), "off") {
			*l = Limit{Off: true}
			return nil
		}
		return fmt.Errorf("eval: Schwelle %q ist weder Zahl noch \"off\"", s)
	}
	var v float64
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("eval: Schwelle: %w", err)
	}
	*l = Limit{V: v}
	return nil
}

// Dur ist eine Dauer, im JSON in ganzen Sekunden.
type Dur time.Duration

// D ist eine Kurzform fuer eine gesetzte Dauer.
func D(d time.Duration) *Dur { v := Dur(d); return &v }

func (d Dur) MarshalJSON() ([]byte, error) {
	return json.Marshal(int64(time.Duration(d) / time.Second))
}

func (d *Dur) UnmarshalJSON(b []byte) error {
	var s float64
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("eval: Dauer in Sekunden: %w", err)
	}
	if math.IsNaN(s) || math.IsInf(s, 0) || s < 0 || s > 366*24*3600 {
		return fmt.Errorf("eval: Dauer %v s ausserhalb des erlaubten Bereichs", s)
	}
	*d = Dur(time.Duration(math.Round(s)) * time.Second)
	return nil
}

// F ist eine Kurzform fuer eine gesetzte Zahl (z. B. Hysterese).
func F(v float64) *float64 { return &v }

// Rule ist eine Regel auf einer Stufe. nil-Felder erben von der Stufe darunter (jedes Feld einzeln).
// Zahlenwerte nutzen Warn/Crit (bzw. WarnFree/CritFree im Modus "GB frei"), Dir, For, Hyst;
// Zustandsregeln nutzen Severity und For. Report gilt fuer beide.
type Rule struct {
	Warn     *Limit     `json:"warn,omitempty"`
	Crit     *Limit     `json:"crit,omitempty"`
	WarnFree *Limit     `json:"warn_free,omitempty"` // GB frei (Modus free)
	CritFree *Limit     `json:"crit_free,omitempty"`
	Dir      *Direction `json:"dir,omitempty"`
	For      *Dur       `json:"for,omitempty"`  // Dauer: alle Messungen im Zeitraum ueber der Schwelle
	Hyst     *float64   `json:"hyst,omitempty"` // Hysterese in Einheiten des Werts
	Mode     *Mode      `json:"mode,omitempty"`
	Report   *Report    `json:"report,omitempty"`
	Severity *Severity  `json:"severity,omitempty"`
}

// Validate prueft eine Regel auf offensichtliche Fehler (nicht endliche Zahlen, negative Werte).
func (r Rule) Validate() error {
	for name, l := range map[string]*Limit{FieldWarn: r.Warn, FieldCrit: r.Crit, FieldWarnFree: r.WarnFree, FieldCritFree: r.CritFree} {
		if l != nil && !l.Off && (math.IsNaN(l.V) || math.IsInf(l.V, 0)) {
			return fmt.Errorf("eval: %s ist keine endliche Zahl", name)
		}
	}
	if r.Hyst != nil && (math.IsNaN(*r.Hyst) || math.IsInf(*r.Hyst, 0) || *r.Hyst < 0) {
		return errors.New("eval: Hysterese muss >= 0 sein")
	}
	if r.For != nil && *r.For < 0 {
		return errors.New("eval: Dauer muss >= 0 sein")
	}
	return nil
}

// Empty meldet, ob die Regel kein Feld setzt.
func (r Rule) Empty() bool { return r == Rule{} }

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// Clone liefert eine tiefe Kopie (eigene Zeiger je Feld).
func (r Rule) Clone() Rule {
	return Rule{Warn: clonePtr(r.Warn), Crit: clonePtr(r.Crit), WarnFree: clonePtr(r.WarnFree),
		CritFree: clonePtr(r.CritFree), Dir: clonePtr(r.Dir), For: clonePtr(r.For), Hyst: clonePtr(r.Hyst),
		Mode: clonePtr(r.Mode), Report: clonePtr(r.Report), Severity: clonePtr(r.Severity)}
}

// Overlay legt o ueber r: gesetzte Felder von o gewinnen, alle anderen kommen aus r. Das Ergebnis ist eine
// tiefe Kopie und teilt keine Zeiger mit r oder o (z. B. gespeicherte Felder ueber die Standard-Regel legen).
func (r Rule) Overlay(o Rule) Rule {
	out := r.Clone()
	o = o.Clone()
	if o.Warn != nil {
		out.Warn = o.Warn
	}
	if o.Crit != nil {
		out.Crit = o.Crit
	}
	if o.WarnFree != nil {
		out.WarnFree = o.WarnFree
	}
	if o.CritFree != nil {
		out.CritFree = o.CritFree
	}
	if o.Dir != nil {
		out.Dir = o.Dir
	}
	if o.For != nil {
		out.For = o.For
	}
	if o.Hyst != nil {
		out.Hyst = o.Hyst
	}
	if o.Mode != nil {
		out.Mode = o.Mode
	}
	if o.Report != nil {
		out.Report = o.Report
	}
	if o.Severity != nil {
		out.Severity = o.Severity
	}
	return out
}

// Feldnamen fuer die Herkunft (Effective.Origin), gleich den JSON-Namen.
const (
	FieldWarn     = "warn"
	FieldCrit     = "crit"
	FieldWarnFree = "warn_free"
	FieldCritFree = "crit_free"
	FieldDir      = "dir"
	FieldFor      = "for"
	FieldHyst     = "hyst"
	FieldMode     = "mode"
	FieldReport   = "report"
	FieldSeverity = "severity"
)

// Stage ist die Stufe, aus der ein Feld stammt.
type Stage string

const (
	StageDefault  Stage = "default"  // Standard-Tabelle
	StageOverride Stage = "override" // Abweichung fuer Gruppe oder Tag
	StageHostKind Stage = "host"     // dieser Host, alle Dienste dieser Art
	StageService  Stage = "service"  // dieser Host, nur dieser Dienst
)

// HostRef beschreibt einen Host fuer Regeln, Routing und Wartung.
type HostRef struct {
	ID    string   `json:"id"`
	Name  string   `json:"name,omitempty"`
	Group string   `json:"group,omitempty"`
	Tags  []string `json:"tags,omitempty"`
}

// HasTag meldet, ob der Host den Tag traegt (Gross-/Kleinschreibung egal).
func (h HostRef) HasTag(tag string) bool {
	for _, t := range h.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

// matchScope: gesetzte Bedingungen (Gruppe, Tag) muessen alle passen; ohne Bedingung passt nichts.
func matchScope(h HostRef, group, tag string) bool {
	if group == "" && tag == "" {
		return false
	}
	if group != "" && !strings.EqualFold(h.Group, group) {
		return false
	}
	if tag != "" && !h.HasTag(tag) {
		return false
	}
	return true
}

// Override ist eine Abweichung fuer eine Gruppe oder einen Tag (Stufe 2). Die Liste wird von oben gelesen,
// die erste passende Abweichung fuer Host und Art gilt allein (kein Mischen mehrerer Treffer).
type Override struct {
	ID    string `json:"id,omitempty"`
	Group string `json:"group,omitempty"`
	Tag   string `json:"tag,omitempty"`
	Kind  string `json:"kind"`
	Rule  Rule   `json:"rule"`
}

// Matches meldet, ob die Abweichung fuer Host und Art gilt.
func (o Override) Matches(h HostRef, kind string) bool {
	return o.Kind == kind && matchScope(h, o.Group, o.Tag)
}

// HostLevel ist die Einstellung am Host (Stufe 3): fuer alle Dienste der Art und fuer genau diesen Dienst.
// Der Dienst gewinnt vor der Art.
type HostLevel struct {
	Kind    *Rule `json:"kind,omitempty"`
	Service *Rule `json:"service,omitempty"`
}

// Table ist die Standard-Tabelle je Art.
type Table map[string]Rule

// Clone liefert eine tiefe Kopie der Tabelle (nil bleibt nil).
func (t Table) Clone() Table {
	if t == nil {
		return nil
	}
	out := make(Table, len(t))
	for k, r := range t {
		out[k] = r.Clone()
	}
	return out
}

// Effective ist die wirksame Regel nach Aufloesung der drei Stufen, mit Herkunft je Feld.
type Effective struct {
	Kind       string           `json:"kind"`
	Known      bool             `json:"known"`    // Art steht in der Standard-Tabelle
	IsState    bool             `json:"is_state"` // Zustandsregel (Severity statt Zahlen)
	Warn       Limit            `json:"warn"`
	Crit       Limit            `json:"crit"`
	WarnFree   Limit            `json:"warn_free"`
	CritFree   Limit            `json:"crit_free"`
	Dir        Direction        `json:"dir"`
	For        Dur              `json:"for"`
	Hyst       float64          `json:"hyst"`
	Mode       Mode             `json:"mode"`
	Report     Report           `json:"report"`
	Severity   Severity         `json:"severity,omitempty"`
	Origin     map[string]Stage `json:"origin"`                // Feld -> Stufe
	Override   int              `json:"override"`              // Index der wirksamen Abweichung, -1 = keine
	OverrideID string           `json:"override_id,omitempty"` // deren ID
}

// Resolve loest Standard -> erste passende Abweichung -> Host (Art, dann Dienst) auf. Jedes Feld erbt einzeln.
// Fehlt die Art in der Tabelle, gibt es keine Schwellen (Known=false).
func Resolve(std Table, overrides []Override, host HostRef, hl HostLevel, kind string) Effective {
	e := Effective{
		Kind: kind, Warn: Limit{Off: true}, Crit: Limit{Off: true}, WarnFree: Limit{Off: true},
		CritFree: Limit{Off: true}, Dir: Up, Mode: ModeUsed, Report: ReportNotify, Override: -1,
		Origin: map[string]Stage{},
	}
	for _, f := range []string{FieldWarn, FieldCrit, FieldWarnFree, FieldCritFree, FieldDir, FieldFor, FieldHyst, FieldMode, FieldReport} {
		e.Origin[f] = StageDefault
	}
	if base, ok := std[kind]; ok {
		e.Known = true
		e.IsState = base.Severity != nil
		if e.IsState {
			e.Origin[FieldSeverity] = StageDefault
		}
		e.apply(base, StageDefault)
	}
	for i, o := range overrides {
		if o.Matches(host, kind) {
			e.Override, e.OverrideID = i, o.ID
			e.apply(o.Rule, StageOverride)
			break
		}
	}
	if hl.Kind != nil {
		e.apply(*hl.Kind, StageHostKind)
	}
	if hl.Service != nil {
		e.apply(*hl.Service, StageService)
	}
	return e
}

func (e *Effective) apply(r Rule, st Stage) {
	set := func(f string) { e.Origin[f] = st }
	if r.Warn != nil {
		e.Warn = *r.Warn
		set(FieldWarn)
	}
	if r.Crit != nil {
		e.Crit = *r.Crit
		set(FieldCrit)
	}
	if r.WarnFree != nil {
		e.WarnFree = *r.WarnFree
		set(FieldWarnFree)
	}
	if r.CritFree != nil {
		e.CritFree = *r.CritFree
		set(FieldCritFree)
	}
	if r.Dir != nil {
		e.Dir = *r.Dir
		set(FieldDir)
	}
	if r.For != nil {
		e.For = *r.For
		set(FieldFor)
	}
	if r.Hyst != nil {
		e.Hyst = *r.Hyst
		set(FieldHyst)
	}
	if r.Mode != nil {
		e.Mode = *r.Mode
		set(FieldMode)
	}
	if r.Report != nil {
		e.Report = *r.Report
		set(FieldReport)
	}
	// Severity nur bei Zustandsregeln; bei Zahlenwerten wird sie ignoriert.
	if r.Severity != nil && e.IsState {
		e.Severity = *r.Severity
		set(FieldSeverity)
	}
}

// Levels liefert die Schwellen, mit denen der Tracker rechnet: Zahlenwerte direkt (Modus "GB frei": die
// GB-Schwellen, Richtung unten), Zustandsregeln als Wert 1 = Bedingung erfuellt.
func (e Effective) Levels() (warn, crit Limit, dir Direction, hyst float64) {
	off := Limit{Off: true}
	switch {
	case e.IsState:
		switch e.Severity {
		case SevCrit:
			return off, Limit{V: 1}, Up, 0
		case SevWarn:
			return Limit{V: 1}, off, Up, 0
		}
		return off, off, Up, 0
	case e.Mode == ModeFree:
		return e.WarnFree, e.CritFree, Down, e.Hyst
	}
	return e.Warn, e.Crit, e.Dir, e.Hyst
}

// Validate prueft die Reihenfolge der Schwellen (oben: Warnung <= Kritisch, unten: Warnung >= Kritisch).
// Fuer die Vorschau beim Speichern einer Regel.
func (e Effective) Validate() error {
	w, c, dir, h := e.Levels()
	if h < 0 {
		return errors.New("eval: Hysterese muss >= 0 sein")
	}
	if w.Off || c.Off {
		return nil
	}
	if dir == Up && w.V > c.V {
		return fmt.Errorf("eval: Warnung (%g) liegt ueber Kritisch (%g)", w.V, c.V)
	}
	if dir == Down && w.V < c.V {
		return fmt.Errorf("eval: Warnung (%g) liegt unter Kritisch (%g)", w.V, c.V)
	}
	return nil
}

// Notify meldet, ob die Regel Benachrichtigungen ausloest (nicht "nur anzeigen").
func (e Effective) Notify() bool { return e.Report != ReportShow }
