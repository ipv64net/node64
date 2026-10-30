package dns64

import (
	"html"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/dns64/dnsserver"
	"github.com/ipv64net/node64/internal/dns64/groups"
)

// Hinweisseite bei "Internet aus" (Phase G4): Geraete einer gesperrten Gruppe bekommen fuer fremde Namen die
// Adresse der Node; ruft der Browser http://<name> auf, antwortet der gemeinsame Eingang auf Port 80 mit dieser
// Seite (Ersatz-Route nur fuer gesperrte Geraete, alle anderen bekommen die Standardseite). Bei https:// zeigt der
// Browser nur einen Zertifikatsfehler, das laesst sich ohne Zertifikat fuer die fremde Domain nicht aendern.
// Angemeldet wird die Route nur, solange eine Gruppe gesperrt sein kann (Knopf oder Zeitplan "Internet aus").

// offPossible: eine Gruppe hat einen aktiven Sperr-Knopf oder einen eingeschalteten Zeitplan "Internet aus".
func offPossible(list []groups.Group) bool {
	for _, g := range list {
		if g.Hold == groups.HoldBlock && holdUntil(g.HoldUntil).After(time.Now()) {
			return true
		}
		for _, s := range g.Schedules {
			if s.Enabled && s.Action == groups.ScheduleOff {
				return true
			}
		}
	}
	return false
}

// syncHintRoute meldet die Hinweisseite beim Eingang an bzw. ab (running = DNS-Dienst laeuft).
func (m *Module) syncHintRoute(list []groups.Group, running bool) {
	if m.ingress == nil {
		return
	}
	m.edgeMu.Lock()
	m.edgeHint = running && offPossible(list)
	m.edgeMu.Unlock()
	if err := m.pushEdge(); err != nil {
		m.log.Warn("dns64 hint page not registered at the edge", "err", err)
	}
}

// offNow: das Geraet gehoert zu einer Gruppe, die gerade "Internet aus" hat.
func (m *Module) offNow(ip netip.Addr) bool {
	p := m.policy(ip)
	return p != nil && p.State(time.Now()).Off
}

// hintPage zeigt, fuer welche Gruppe das Internet aus ist und bis wann.
func (m *Module) hintPage(w http.ResponseWriter, r *http.Request) {
	ip, _ := netip.ParseAddrPort(r.RemoteAddr)
	p := m.policy(ip.Addr().Unmap().WithZone(""))
	if p == nil {
		http.NotFound(w, r)
		return
	}
	st := p.State(time.Now())
	t := func(key string, args ...any) string {
		if m.g.T == nil { // ohne Kern (Tests)
			return key
		}
		return m.g.T(r, key, args...)
	}
	lang := "de"
	if m.g.Lang != nil {
		lang = m.g.Lang(r)
	}
	until := t("dns64.hint.until_forever")
	if st.Until.Before(dnsserver.Forever) {
		at := st.Until.In(m.location())
		if at.YearDay() == time.Now().In(m.location()).YearDay() {
			until = t("dns64.hint.until", "time", at.Format("15:04"))
		} else {
			until = t("dns64.hint.until_day", "time", at.Format("02.01. 15:04"))
		}
	}
	why := t("dns64.hint.hold")
	if label, ok := strings.CutPrefix(st.Why, dnsserver.ReasonOff+"schedule:"); ok {
		why = t("dns64.hint.schedule", "name", label)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	e := html.EscapeString
	_, _ = w.Write([]byte(`<!doctype html><html lang="` + e(lang) + `"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>` + e(t("dns64.hint.title")) + `</title><style>body{font-family:system-ui,sans-serif;background:#f4f6f8;color:#1f2933;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}` +
		`main{background:#fff;border-radius:12px;padding:2rem 2.5rem;max-width:30rem;box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center}h1{font-size:1.4rem;margin:.2rem 0 1rem}` +
		`.big{font-size:2.6rem}.muted{color:#6b7785;font-size:.9rem}@media(prefers-color-scheme:dark){body{background:#111418;color:#e4e7eb}main{background:#1c2128}}</style></head>` +
		`<body><main><div class="big">&#9208;</div><h1>` + e(t("dns64.hint.title")) + `</h1><p><b>` + e(p.Group) + `</b> · ` + e(why) + `</p><p>` + e(until) + `</p>` +
		`<p class="muted">` + e(t("dns64.hint.note", "host", r.Host)) + `</p></main></body></html>`))
}

// groupStateView ist der Zustand einer Gruppe fuer die Seite.
type groupStateView struct {
	Off      bool      `json:"internet_off"`
	Free     bool      `json:"free"`
	Hold     bool      `json:"by_button"` // per Knopf (sonst Zeitplan)
	Forever  bool      `json:"until_released"`
	Until    time.Time `json:"until,omitzero"`     // Ende
	Schedule string    `json:"schedule,omitempty"` // aktiver Zeitplan
}

// groupStates liefert den Zustand jeder Gruppe (Seite Gruppen).
func (m *Module) groupStates() map[int64]groupStateView {
	out := map[int64]groupStateView{}
	pol := m.pol.Load()
	if pol == nil {
		return out
	}
	now := time.Now()
	for id, p := range *pol {
		st := p.State(now)
		v := groupStateView{Off: st.Off, Free: st.Free, Until: st.Until, Forever: (st.Off || st.Free) && !st.Until.Before(dnsserver.Forever)}
		if v.Forever || !(st.Off || st.Free) {
			v.Until = time.Time{}
		}
		v.Hold = st.Free || st.Why == dnsserver.ReasonOff+"hold"
		if label, ok := strings.CutPrefix(st.Why, dnsserver.ReasonOff+"schedule:"); ok {
			v.Schedule = label
		}
		out[id] = v
	}
	return out
}

// nextMorning: der naechste Zeitpunkt 07:00 in der Zeitzone der Node (Knopf "bis morgen frueh").
func (m *Module) nextMorning(now time.Time) time.Time {
	t := now.In(m.location())
	at := time.Date(t.Year(), t.Month(), t.Day(), 7, 0, 0, 0, t.Location())
	if !at.After(t) {
		at = at.AddDate(0, 0, 1)
	}
	return at
}
