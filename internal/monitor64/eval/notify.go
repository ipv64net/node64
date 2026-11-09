package eval

import (
	"fmt"
	"slices"
	"time"
)

// Flattern (Plan "Wann gemeldet wird"): mehr als FlapChanges Wechsel in FlapWindow -> eine Meldung, danach
// Ruhe, bis der Dienst FlapWindow lang stabil ist; dann eine Meldung mit dem aktuellen Zustand.
const (
	FlapChanges = 5
	FlapWindow  = 30 * time.Minute
)

// ---------------------------------------------------------------------------------------------------------
// Routing: Kanaele x Schwere, Abweichungen je Gruppe/Tag

// ChannelRoute: ein Kanal bekommt Warnung und/oder Kritisch (nicht erreichbar zaehlt als Kritisch).
type ChannelRoute struct {
	ID   string `json:"id"`
	Warn bool   `json:"warn"`
	Crit bool   `json:"crit"`
}

// NotifyConfig ist die Grundeinstellung der Benachrichtigung.
type NotifyConfig struct {
	Channels    []ChannelRoute `json:"channels"`
	RemindWarn  Dur            `json:"remind_warn"`   // 0 = nie (Standard)
	RemindCrit  Dur            `json:"remind_crit"`   // Standard taeglich
	CritInQuiet bool           `json:"crit_in_quiet"` // Kritisch auch in der Ruhezeit sofort
}

// DefaultNotifyConfig: ohne Auswahl die Standardkanaele von Node64 mit Warnung und Kritisch, Erinnerung
// bei Kritisch taeglich, bei Warnung nie.
func DefaultNotifyConfig(defaultChannels []string) NotifyConfig {
	c := NotifyConfig{RemindCrit: Dur(24 * time.Hour)}
	for _, id := range defaultChannels {
		c.Channels = append(c.Channels, ChannelRoute{ID: id, Warn: true, Crit: true})
	}
	return c
}

// NotifyOverride ist eine Abweichung je Gruppe oder Tag (Liste, oben gewinnt). nil-Felder erben.
type NotifyOverride struct {
	ID          string         `json:"id,omitempty"`
	Group       string         `json:"group,omitempty"`
	Tag         string         `json:"tag,omitempty"`
	Channels    []ChannelRoute `json:"channels,omitempty"`
	Replace     bool           `json:"replace"`                 // true: Kanaele statt, false: zusaetzlich
	OnlyCrit    *bool          `json:"only_crit,omitempty"`     // nur Kritisch melden
	CritInQuiet *bool          `json:"crit_in_quiet,omitempty"` //
	RemindWarn  *Dur           `json:"remind_warn,omitempty"`   //
	RemindCrit  *Dur           `json:"remind_crit,omitempty"`   //
}

// Routing ist die wirksame Benachrichtigung fuer einen Host.
type Routing struct {
	Channels    []ChannelRoute `json:"channels"`
	OnlyCrit    bool           `json:"only_crit"`
	CritInQuiet bool           `json:"crit_in_quiet"`
	RemindWarn  Dur            `json:"remind_warn"`
	RemindCrit  Dur            `json:"remind_crit"`
	Override    int            `json:"override"` // Index der wirksamen Abweichung, -1 = keine
	OverrideID  string         `json:"override_id,omitempty"`
}

// ResolveRouting wendet die erste passende Abweichung auf die Grundeinstellung an.
func ResolveRouting(base NotifyConfig, ovs []NotifyOverride, h HostRef) Routing {
	rt := Routing{Channels: slices.Clone(base.Channels), CritInQuiet: base.CritInQuiet,
		RemindWarn: base.RemindWarn, RemindCrit: base.RemindCrit, Override: -1}
	for i, o := range ovs {
		if !matchScope(h, o.Group, o.Tag) {
			continue
		}
		rt.Override, rt.OverrideID = i, o.ID
		if o.Replace {
			rt.Channels = slices.Clone(o.Channels)
		} else {
			for _, c := range o.Channels {
				if j := slices.IndexFunc(rt.Channels, func(x ChannelRoute) bool { return x.ID == c.ID }); j >= 0 {
					rt.Channels[j] = c
				} else {
					rt.Channels = append(rt.Channels, c)
				}
			}
		}
		if o.OnlyCrit != nil {
			rt.OnlyCrit = *o.OnlyCrit
		}
		if o.CritInQuiet != nil {
			rt.CritInQuiet = *o.CritInQuiet
		}
		if o.RemindWarn != nil {
			rt.RemindWarn = *o.RemindWarn
		}
		if o.RemindCrit != nil {
			rt.RemindCrit = *o.RemindCrit
		}
		break
	}
	return rt
}

// Route liefert die Kanaele fuer eine Schwere (Unbekannt wie Warnung), sortiert.
func (rt Routing) Route(s State) []string {
	s = s.NotifySeverity()
	var out []string
	for _, c := range rt.Channels {
		if c.ID == "" {
			continue
		}
		if (s == Crit && c.Crit) || (s == Warn && c.Warn && !rt.OnlyCrit) {
			out = union(out, []string{c.ID})
		}
	}
	return out
}

func (rt Routing) remind(s State) time.Duration {
	if s == Crit {
		return time.Duration(rt.RemindCrit)
	}
	return time.Duration(rt.RemindWarn)
}

// union fuegt sortiert und ohne Doppelte zusammen.
func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	slices.Sort(out)
	return out
}

// ---------------------------------------------------------------------------------------------------------
// Eingaben und Ausgaben

// ServiceInput ist der Zustand eines Dienstes in einer Runde.
type ServiceInput struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	State    State  `json:"state"`     // ServiceResult.Notify
	ShowOnly bool   `json:"show_only"` // nur anzeigen: nie melden
	Acked    bool   `json:"acked"`     // quittiert
	Detail   string `json:"detail"`    // vom Kern formatiert ("Fehlerrate 0,3 % (Schwelle 0,1 %)")
}

// Round ist alles, was in einer Abfragerunde an einem Host bekannt ist.
type Round struct {
	At          time.Time      `json:"at"`
	Host        HostRef        `json:"host"`
	Unreachable bool           `json:"unreachable"`
	Maintenance bool           `json:"maintenance"`
	Quiet       bool           `json:"quiet"` // Ruhezeit (nur fuer Erinnerungen; Rest macht der Dispatcher)
	Services    []ServiceInput `json:"services"`
}

// LineKind ist die Art einer Zeile.
type LineKind string

const (
	LineProblem     LineKind = "problem"     // Verschlechterung
	LineBetter      LineKind = "better"      // besser, aber noch nicht OK (zaehlt als Entwarnung)
	LineOK          LineKind = "ok"          // Entwarnung
	LineFlapping    LineKind = "flapping"    // flattert
	LineFlapEnd     LineKind = "flap_end"    // nach dem Flattern stabil, aktueller Zustand
	LineReminder    LineKind = "reminder"    // Erinnerung
	LineOpen        LineKind = "open"        // noch offen (nach Wartung oder wieder erreichbar)
	LineUnreachable LineKind = "unreachable" // Host nicht erreichbar
	LineReachable   LineKind = "reachable"   // Host wieder erreichbar
)

// Line ist eine Zeile einer Meldung (ein Dienst oder der Host selbst; Key leer = Host).
type Line struct {
	Kind     LineKind  `json:"kind"`
	Key      string    `json:"key,omitempty"`
	Name     string    `json:"name,omitempty"`
	State    State     `json:"state"`
	Prev     State     `json:"prev"`
	Since    time.Time `json:"since,omitzero"` // Problem bzw. "nicht erreichbar" seit (Entwarnung: Dauer)
	Detail   string    `json:"detail,omitempty"`
	Gone     bool      `json:"gone,omitzero"`      // Entwarnung, weil der Dienst nicht mehr geliefert wird (entfernt)
	Channels []string  `json:"channels,omitempty"` // nur in Result.Lines: an wen gemeldet
}

// Event ist die Art einer Meldung (Arten des Dispatchers).
type Event string

const (
	EvProblem     Event = "monitor_problem"
	EvOK          Event = "monitor_ok"
	EvUnreachable Event = "monitor_unreachable"
	EvReachable   Event = "monitor_reachable"
	EvFlapping    Event = "monitor_flapping"
	EvReminder    Event = "monitor_reminder"
)

// Counts zaehlt die Dienst-Zeilen einer Meldung nach Zustand ("nas01: 1 Kritisch, 2 Warnung").
type Counts struct {
	Crit    int `json:"crit"`
	Warn    int `json:"warn"`
	Unknown int `json:"unknown"`
	OK      int `json:"ok"`
}

// Message ist eine gebuendelte Meldung eines Hosts an eine Gruppe von Kanaelen.
type Message struct {
	At               time.Time `json:"at"`
	Host             HostRef   `json:"host"`
	Event            Event     `json:"event"`
	Severity         State     `json:"severity"`        // schlimmste Zeile (nicht erreichbar = Kritisch; wieder erreichbar: schlimmste offene)
	Better           bool      `json:"better,omitzero"` // EvOK mit Zeile "besser, aber noch nicht OK": Betreff nicht "wieder OK"
	Counts           Counts    `json:"counts"`
	Lines            []Line    `json:"lines"`
	Channels         []string  `json:"channels"`
	CritInQuiet      bool      `json:"crit_in_quiet"`     // Kritisch auch in der Ruhezeit sofort senden
	AfterMaintenance bool      `json:"after_maintenance"` // "nach der Wartung noch offen"
}

// Result ist das Ergebnis einer Runde.
type Result struct {
	Messages []Message `json:"messages"`
	Lines    []Line    `json:"lines"` // alle Zeilen mit Kanaelen (fuer die Problem-Historie "an wen gemeldet")
	Unack    []string  `json:"unack"` // Dienste, deren Quittierung durch Verschlechterung aufgehoben ist
}

// ---------------------------------------------------------------------------------------------------------
// Notifier

// ServiceMemory ist der gespeicherte Stand eines Dienstes.
type ServiceMemory struct {
	Name       string      `json:"name,omitempty"`       // letzter Name (fuer die Entwarnung, wenn der Dienst verschwindet)
	Cur        State       `json:"cur"`                  // letzter beobachteter Zustand
	Sent       State       `json:"sent"`                 // zuletzt gemeldeter Zustand
	Since      time.Time   `json:"since,omitzero"`       // nicht OK seit
	Chans      []string    `json:"chans,omitempty"`      // Kanaele, die das offene Problem kennen
	Changes    []time.Time `json:"changes,omitempty"`    // Wechsel in FlapWindow
	LastChange time.Time   `json:"last_change,omitzero"` //
	Flapping   bool        `json:"flapping,omitzero"`    //
	LastSent   time.Time   `json:"last_sent,omitzero"`   // letzte Meldung/Erinnerung
}

// HostMemory ist der gespeicherte Stand eines Hosts.
type HostMemory struct {
	Unreach   bool                      `json:"unreach,omitzero"`    // "nicht erreichbar" gemeldet
	UnreachAt time.Time                 `json:"unreach_at,omitzero"` //
	HostChans []string                  `json:"host_chans,omitempty"`
	Maint     bool                      `json:"maint,omitzero"` // letzte Runde in Wartung
	Svcs      map[string]*ServiceMemory `json:"svcs,omitempty"`
}

// Notifier leitet aus Zustandswechseln Meldungen ab. Er ist als JSON serialisierbar und nicht
// nebenlaeufig sicher (der Kern ruft ihn je Host aus einer Goroutine bzw. unter seiner Sperre auf).
type Notifier struct {
	Hosts map[string]*HostMemory `json:"hosts"`
}

// Forget vergisst einen entfernten Host.
func (n *Notifier) Forget(hostID string) { delete(n.Hosts, hostID) }

func (s *ServiceMemory) observe(st State, at time.Time, count bool) {
	if s.LastChange.After(at) {
		s.LastChange = at // Uhr rueckwaerts
	}
	if s.LastSent.After(at) {
		s.LastSent = at
	}
	if st != s.Cur {
		if s.Cur == OK {
			s.Since = at
		}
		s.Cur, s.LastChange = st, at
		if count {
			s.Changes = append(s.Changes, at)
		}
	}
	s.Changes = slices.DeleteFunc(s.Changes, func(c time.Time) bool {
		return c.After(at) || at.Sub(c) > FlapWindow
	})
}

func (s *ServiceMemory) sent(st State, at time.Time, chans []string) {
	s.Sent, s.LastSent = st, at
	if st == OK {
		s.Chans = nil
	} else {
		s.Chans = union(s.Chans, chans)
	}
}

// Round wertet eine Abfragerunde eines Hosts aus. rt ist die Routing-Einstellung des Hosts (ResolveRouting).
func (n *Notifier) Round(r Round, rt Routing) Result {
	if n.Hosts == nil {
		n.Hosts = map[string]*HostMemory{}
	}
	hm := n.Hosts[r.Host.ID]
	if hm == nil {
		hm = &HostMemory{}
		n.Hosts[r.Host.ID] = hm
	}
	if hm.Svcs == nil {
		hm.Svcs = map[string]*ServiceMemory{}
	}
	seen := make(map[string]bool, len(r.Services))
	for _, in := range r.Services {
		seen[in.Key] = true
		if hm.Svcs[in.Key] == nil {
			hm.Svcs[in.Key] = &ServiceMemory{}
		}
		hm.Svcs[in.Key].Name = in.Name
	}
	// Dienste, die der Kern nicht mehr liefert, sind entfernt (bei nicht erreichbarem Host fehlen sie nur; in
	// der Wartung bleiben sie bis zur ersten Runde danach, damit die Entwarnung nicht verloren geht).
	var gone []string
	if !r.Unreachable && !r.Maintenance {
		for k := range hm.Svcs {
			if !seen[k] {
				gone = append(gone, k)
			}
		}
		slices.Sort(gone)
	}

	var res Result
	var lines []Line
	at := r.At
	add := func(l Line, chans []string) {
		l.Channels = chans
		lines = append(lines, l)
	}

	afterMaint := false
	switch {
	case r.Maintenance:
		// Weiter aufzeichnen, nichts melden.
		hm.Maint = true
		if !r.Unreachable {
			for _, in := range r.Services {
				hm.Svcs[in.Key].observe(in.State, at, false)
			}
		}
		return res
	case hm.Maint:
		hm.Maint, afterMaint = false, true
		for _, s := range hm.Svcs {
			s.Flapping, s.Changes = false, nil
		}
	}

	switch {
	case r.Unreachable:
		// Dienste (Unbekannt) werden nicht gemeldet und nicht mitgeschrieben.
		if !hm.Unreach {
			chans := rt.Route(Crit)
			hm.Unreach, hm.UnreachAt, hm.HostChans = true, at, chans
			add(Line{Kind: LineUnreachable, State: Crit, Since: at}, chans)
		}

	case hm.Unreach || afterMaint:
		// Wieder erreichbar bzw. Ende der Wartung: eine Meldung mit allem, was noch offen ist.
		base := []string(nil)
		if hm.Unreach {
			base = hm.HostChans
			add(Line{Kind: LineReachable, State: OK, Prev: Crit, Since: hm.UnreachAt}, hm.HostChans)
			hm.Unreach, hm.UnreachAt, hm.HostChans = false, time.Time{}, nil
		}
		for _, in := range r.Services {
			s := hm.Svcs[in.Key]
			prev := s.Sent
			s.observe(in.State, at, false)
			s.Flapping, s.Changes = false, nil
			worse := s.Cur.Worse(prev)
			switch {
			case s.Cur == OK || in.ShowOnly || (in.Acked && !worse):
				s.Sent = s.Cur
				if s.Cur == OK {
					s.Chans = nil
				}
			default:
				if in.Acked {
					// Verschlechterung hebt die Quittierung auch hier auf.
					res.Unack = append(res.Unack, in.Key)
				}
				chans := union(union(base, rt.Route(s.Cur)), s.Chans)
				add(Line{Kind: LineOpen, Key: in.Key, Name: in.Name, State: s.Cur, Prev: prev, Since: s.Since, Detail: in.Detail}, chans)
				s.sent(s.Cur, at, chans)
			}
		}

	default:
		for _, in := range r.Services {
			s := hm.Svcs[in.Key]
			s.observe(in.State, at, true)
			l := Line{Key: in.Key, Name: in.Name, State: s.Cur, Prev: s.Sent, Since: s.Since, Detail: in.Detail}
			switch {
			case in.ShowOnly:
				s.Sent, s.Flapping = s.Cur, false
				if s.Cur == OK {
					s.Chans = nil
				}

			case s.Flapping:
				if at.Sub(s.LastChange) >= FlapWindow {
					s.Flapping, s.Changes = false, nil
					chans := s.Chans
					if s.Cur != OK {
						chans = union(chans, rt.Route(s.Cur))
					}
					l.Kind = LineFlapEnd
					add(l, chans)
					s.sent(s.Cur, at, chans)
				}

			case len(s.Changes) > FlapChanges:
				s.Flapping = true
				chans := union(s.Chans, rt.Route(Worst(s.Cur, s.Sent)))
				l.Kind = LineFlapping
				add(l, chans)
				s.Chans, s.LastSent = union(s.Chans, chans), at

			case s.Cur == s.Sent:
				iv := rt.remind(s.Cur)
				if s.Cur == OK || in.Acked || iv <= 0 || at.Sub(s.LastSent) < iv {
					break
				}
				if r.Quiet {
					// In der Ruhezeit keine Erinnerung; das Offene steht in der Sammelmeldung.
					s.LastSent = at
					break
				}
				chans := s.Chans
				if len(chans) == 0 {
					chans = rt.Route(s.Cur)
				}
				l.Kind = LineReminder
				add(l, chans)
				s.sent(s.Cur, at, chans)

			case s.Cur == OK:
				l.Kind = LineOK
				add(l, s.Chans)
				s.sent(OK, at, nil)

			case s.Cur.Worse(s.Sent):
				if in.Acked {
					res.Unack = append(res.Unack, in.Key)
				}
				chans := rt.Route(s.Cur)
				l.Kind = LineProblem
				add(l, chans)
				s.sent(s.Cur, at, chans)

			default: // besser, aber noch nicht OK
				if in.Acked {
					s.Sent = s.Cur
					break
				}
				chans := union(s.Chans, rt.Route(s.Cur))
				l.Kind = LineBetter
				add(l, chans)
				s.sent(s.Cur, at, chans)
			}
		}
	}

	// Verschwundene Dienste: Kanaele, die ein offenes Problem kennen, bekommen eine Entwarnung.
	for _, k := range gone {
		if s := hm.Svcs[k]; len(s.Chans) > 0 {
			add(Line{Kind: LineOK, Key: k, Name: s.Name, State: OK, Prev: Worst(s.Sent, s.Cur), Since: s.Since, Gone: true}, s.Chans)
		}
		delete(hm.Svcs, k)
	}

	res.Lines = lines
	res.Messages = bundle(lines, r, rt, afterMaint)
	return res
}

// bundle fasst die Zeilen eines Hosts zu Meldungen zusammen: jeder Kanal bekommt genau seine Zeilen,
// Kanaele mit denselben Zeilen teilen sich eine Meldung.
func bundle(lines []Line, r Round, rt Routing, afterMaint bool) []Message {
	perChan := map[string][]int{}
	var order []string
	for i, l := range lines {
		for _, c := range l.Channels {
			if _, ok := perChan[c]; !ok {
				order = append(order, c)
			}
			perChan[c] = append(perChan[c], i)
		}
	}
	slices.Sort(order)
	var msgs []Message
	idx := map[string]int{}
	for _, c := range order {
		key := fmt.Sprint(perChan[c])
		if j, ok := idx[key]; ok {
			msgs[j].Channels = append(msgs[j].Channels, c)
			continue
		}
		m := Message{At: r.At, Host: r.Host, Channels: []string{c}, AfterMaintenance: afterMaint}
		for _, i := range perChan[c] {
			l := lines[i]
			l.Channels = nil
			m.Lines = append(m.Lines, l)
		}
		m.finish(rt)
		idx[key] = len(msgs)
		msgs = append(msgs, m)
	}
	return msgs
}

func (m *Message) finish(rt Routing) {
	has := map[LineKind]bool{}
	problem := false
	for _, l := range m.Lines {
		has[l.Kind] = true
		m.Severity = Worst(m.Severity, l.State)
		if l.Kind == LineProblem || l.Kind == LineOpen || (l.Kind == LineFlapEnd && l.State != OK) {
			problem = true
		}
		if l.Key == "" {
			continue
		}
		switch l.State {
		case Crit:
			m.Counts.Crit++
		case Warn:
			m.Counts.Warn++
		case Unknown:
			m.Counts.Unknown++
		default:
			m.Counts.OK++
		}
	}
	switch {
	case has[LineUnreachable]:
		m.Event = EvUnreachable
	case has[LineReachable]:
		m.Event = EvReachable
	case problem:
		m.Event = EvProblem
	case has[LineFlapping]:
		m.Event = EvFlapping
	case has[LineOK] || has[LineBetter] || has[LineFlapEnd]:
		m.Event = EvOK
		m.Better = has[LineBetter]
	default:
		m.Event = EvReminder
	}
	m.CritInQuiet = rt.CritInQuiet && m.Severity == Crit
}
