package dnsserver

import (
	"time"

	"github.com/miekg/dns"
)

// Zeitplaene und Sofort-Knoepfe je Geraetegruppe (Phase G4). "Internet aus": es antworten nur eigene Eintraege,
// lokale Namen und Freigaben der Gruppe; alles andere bekommt die Adresse der Node (Hinweisseite ueber den
// Eingang, Port 80) mit kurzer TTL, damit das Ende der Sperre sofort greift.

// ReasonOff: "off:hold" (Knopf Sperren) bzw. "off:schedule:<Name>" (Zeitplan).
const ReasonOff = "off:"

// Forever steht fuer "bis zum Aufheben".
var Forever = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

const offTTL = 10

// TimeRule ist ein Zeitplan: Days als Bits (Bit 0 = Montag ... Bit 6 = Sonntag), Start/End in Minuten seit
// Mitternacht (End < Start = ueber Mitternacht, gleich = ganzer Tag).
type TimeRule struct {
	Label      string
	Days       uint8
	Start, End int
	Off        bool       // Internet aus
	Cats       []Category // sonst: diese Kategorien zusaetzlich sperren
}

// State ist der Zustand einer Gruppe zu einem Zeitpunkt.
type State struct {
	Off   bool       // Internet aus
	Free  bool       // Knopf Frei: Zeitplaene und Kategorien ausgesetzt
	Until time.Time  // Ende von Off bzw. Free (Forever = bis zum Aufheben)
	Why   string     // Grund fuer das Log bei Off
	Cats  []Category // jetzt gesperrte Kategorien
}

// State liefert den Zustand der Gruppe zum Zeitpunkt now.
func (p *Policy) State(now time.Time) State {
	if p.BlockUntil.After(now) {
		return State{Off: true, Until: p.BlockUntil, Why: ReasonOff + "hold"}
	}
	if p.FreeUntil.After(now) {
		return State{Free: true, Until: p.FreeUntil}
	}
	loc := p.Loc
	if loc == nil {
		loc = time.Local
	}
	t := now.In(loc)
	st := State{Cats: p.Cats}
	extra := false
	for _, r := range p.Rules {
		until, ok := r.active(t)
		if !ok {
			continue
		}
		if r.Off {
			return State{Off: true, Until: until, Why: ReasonOff + "schedule:" + r.Label}
		}
		if !extra { // nicht in p.Cats hineinschreiben
			st.Cats, extra = append([]Category(nil), st.Cats...), true
		}
		st.Cats = append(st.Cats, r.Cats...)
	}
	return st
}

func isoWeekday(t time.Time) int {
	if d := int(t.Weekday()); d != 0 {
		return d
	}
	return 7
}

// active: der Zeitplan gilt jetzt; until ist sein Ende.
func (r TimeRule) active(t time.Time) (time.Time, bool) {
	has := func(d int) bool { return r.Days&(1<<uint(d-1)) != 0 }
	day, now := isoWeekday(t), t.Hour()*60+t.Minute()
	midnight := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
	at := func(dayOffset, minutes int) time.Time {
		return midnight.AddDate(0, 0, dayOffset).Add(time.Duration(minutes) * time.Minute)
	}
	switch {
	case r.Start == r.End:
		if has(day) {
			return at(1, 0), true
		}
	case r.Start < r.End:
		if has(day) && now >= r.Start && now < r.End {
			return at(0, r.End), true
		}
	default: // ueber Mitternacht
		if has(day) && now >= r.Start {
			return at(1, r.End), true
		}
		prev := day - 1
		if prev == 0 {
			prev = 7
		}
		if has(prev) && now < r.End {
			return at(0, r.End), true
		}
	}
	return time.Time{}, false
}

// offMsg beantwortet eine Anfrage bei "Internet aus" mit der Adresse der Node (ohne bekannte Adresse wie
// eine Sperre).
func (s *Server) offMsg(r *dns.Msg) *dns.Msg {
	q := r.Question[0]
	if s.HintV4 == nil && s.HintV6 == nil {
		return s.blockedMsg(r)
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: offTTL}
	switch {
	case q.Qtype == dns.TypeA && s.HintV4 != nil:
		m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: s.HintV4}}
	case q.Qtype == dns.TypeAAAA && s.HintV6 != nil:
		m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: s.HintV6}}
	}
	copyEdns(r, m)
	return m
}
