package cdn64

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// CDN64 Statistik (Reiter /cdn64/protection): was srv07/srv08 fuer die Namen des Kontos abgewehrt haben - Daten von
// ipv64 (GET /cdn64o/protection), kurz zwischengespeichert. Dazu der Schalter WAF/JA4 je Host in der Liste.
// Plan: docs/PLAN-CDN64-SCHUTZ.md (Abschnitte 6 und 8).

// protectionTTL: so lange gilt ein Abruf je Zeitraum.
const protectionTTL = 60 * time.Second

// protectionDays: waehlbare Zeitraeume (1 = heute).
var protectionDays = []int{1, 7, 30}

type protectionCache struct {
	mu   sync.Mutex
	at   map[int]time.Time
	data map[int]*ipv64api.CDN64Protection
}

func (m *Module) protectionRoutes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /cdn64/protection", page(m.pageProtection))
	mux.Handle("POST /cdn64/hosts/{id}/protection", page(m.pageProtectionSet))
}

// protectionOn: CDN64 online angebunden und das Konto hat CDN64-Namen (letzter Abgleich) - dann gibt es den Reiter.
func (m *Module) protectionOn() bool {
	if m.online.api == nil || m.edge == nil {
		return false
	}
	rm := m.online.remote.Load()
	return rm != nil && rm.Data != nil && len(rm.Data.Hosts) > 0
}

// protection holt die Statistik (aus dem Zwischenspeicher, wenn juenger als protectionTTL).
func (m *Module) protection(ctx context.Context, days int) (*ipv64api.CDN64Protection, error) {
	a := m.online.api
	if a == nil || !a.Ready(ctx) {
		return nil, errOnline("no_api_key")
	}
	c := &m.online.prot
	c.mu.Lock()
	if p := c.data[days]; p != nil && time.Since(c.at[days]) < protectionTTL {
		c.mu.Unlock()
		return p, nil
	}
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p, err := a.Protection(ctx, days)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.data == nil {
		c.data, c.at = map[int]*ipv64api.CDN64Protection{}, map[int]time.Time{}
	}
	c.data[days], c.at[days] = p, time.Now()
	c.mu.Unlock()
	return p, nil
}

// protectionRow: Zeile der Tabelle je Name.
type protectionRow struct {
	ipv64api.CDN64ProtectionHost
	Blocked, Overload int64
	Link              string // Host dieser Node bzw. Modus 3 auf ipv64.net ("" = kein Ziel)
	Ext               bool   // Link geht nach ipv64.net
	WAF               bool
	JA4               string // off, count, block ("" = unbekannt)
}

type protectionData struct {
	Tabs     []tab
	Days     int
	Ranges   []int
	Error    string // Text, wenn ipv64 nicht antwortet
	P        *ipv64api.CDN64Protection
	Blocked  int64 // Summe aller Gruende
	Overload int64
	Rows     []protectionRow
	Modes    []int  // Modi der Namen (je ein Satz im Kasten "Ohne CDN64")
	Chart    string // JSON fuer cdn64-protection.js
	Counting bool   // Startphase: JA4 wird nur gezaehlt
}

func (m *Module) pageProtection(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if !slices.Contains(protectionDays, days) {
		days = 7
	}
	d := protectionData{Tabs: m.tabs("/cdn64/protection"), Days: days, Ranges: protectionDays}
	p, err := m.protection(r.Context(), days)
	if err != nil {
		code := onlineCode(err)
		d.Error = m.onlineText(r, code, m.tr(r, "cdn64.online.e.error"))
		m.log.Warn("cdn64 protection: ipv64 not available", "err", err)
		m.g.Render(w, r, http.StatusOK, Name+"/protection", "cdn64.protection.title", d)
		return
	}
	d.P, d.Blocked, d.Overload, d.Counting = p, p.Totals.Blocked(), p.Totals.Overload(), p.JA4Global == "count"
	d.Rows = m.protectionRows(r.Context(), p.Hosts)
	for _, x := range d.Rows {
		if !slices.Contains(d.Modes, x.Mode) && x.Mode >= 1 && x.Mode <= 3 {
			d.Modes = append(d.Modes, x.Mode)
		}
	}
	slices.Sort(d.Modes)
	if len(d.Modes) == 0 {
		d.Modes = []int{1, 2, 3}
	}
	d.Chart = m.protectionChart(r, p, days, time.Now())
	m.g.Render(w, r, http.StatusOK, Name+"/protection", "cdn64.protection.title", d)
}

// tr: Text mit Schluessel als Ersatz (Tests ohne Uebersetzung).
func (m *Module) tr(r *http.Request, key string) string {
	if m.g.T == nil {
		return key
	}
	return m.g.T(r, key)
}

// protectionRows: Namen mit Summen, Schalter aus dem letzten Abgleich und Link zum Host (meist abgewehrt zuerst).
func (m *Module) protectionRows(ctx context.Context, hosts []ipv64api.CDN64ProtectionHost) []protectionRow {
	local := map[string]int64{}
	if hl, err := m.hosts(ctx); err == nil {
		for _, h := range hl {
			for _, n := range h.Names {
				local[strings.ToLower(n)] = h.ID
			}
		}
	}
	remote := map[int64]ipv64api.CDN64Host{}
	if rm := m.online.remote.Load(); rm != nil && rm.Data != nil {
		for _, h := range rm.Data.Hosts {
			remote[h.ID] = h
		}
	}
	out := make([]protectionRow, 0, len(hosts))
	for _, h := range hosts {
		x := protectionRow{CDN64ProtectionHost: h, Blocked: h.Blocked(), Overload: h.Overload()}
		if id := local[strings.ToLower(h.FQDN)]; id > 0 {
			x.Link = "/cdn64/hosts/" + strconv.FormatInt(id, 10)
		} else if h.Mode == 3 {
			x.Link, x.Ext = "https://ipv64.net/cdn64?edit="+strconv.FormatInt(h.ID, 10), true
		}
		if rh, ok := remote[h.ID]; ok {
			x.WAF, x.JA4 = rh.WAF, rh.JA4
		}
		out = append(out, x)
	}
	slices.SortStableFunc(out, func(a, b protectionRow) int {
		if a.Blocked != b.Blocked {
			if a.Blocked > b.Blocked {
				return -1
			}
			return 1
		}
		return strings.Compare(a.FQDN, b.FQDN)
	})
	return out
}

// protectionChart: Abgewehrtes je Tag, gestapelt nach Grund (JSON fuer cdn64-protection.js). Tage ohne Werte werden
// aufgefuellt; der letzte Tag ist heute bzw. der juengste Tag von ipv64 (andere Zeitzone).
func (m *Module) protectionChart(r *http.Request, p *ipv64api.CDN64Protection, days int, now time.Time) string {
	by := map[string]ipv64api.CDN64ProtectionCounts{}
	last := now.Format(time.DateOnly)
	for _, x := range p.Daily {
		by[x.Day] = x.CDN64ProtectionCounts
		if x.Day > last {
			last = x.Day
		}
	}
	end, err := time.Parse(time.DateOnly, last)
	if err != nil {
		end, _ = time.Parse(time.DateOnly, now.Format(time.DateOnly))
	}
	type set struct {
		Label string  `json:"label"`
		Color string  `json:"color"` // Bootstrap-Farbe (CSS-Variable --bs-<color>)
		Data  []int64 `json:"data"`
	}
	sets := []*set{{Label: m.tr(r, "cdn64.protection.r_list"), Color: "danger"}, {Label: m.tr(r, "cdn64.protection.r_acl"), Color: "secondary"},
		{Label: m.tr(r, "cdn64.protection.r_overload"), Color: "warning"}, {Label: m.tr(r, "cdn64.protection.r_waf"), Color: "info"},
		{Label: m.tr(r, "cdn64.protection.r_ja4"), Color: "purple"}}
	var labels []string
	for i := days - 1; i >= 0; i-- {
		day := end.AddDate(0, 0, -i).Format(time.DateOnly)
		c := by[day]
		labels = append(labels, day)
		for j, v := range []int64{c.BlockedList, c.BlockedACL, c.Overload(), c.BlockedWAF, c.BlockedJA4} {
			sets[j].Data = append(sets[j].Data, v)
		}
	}
	b, _ := json.Marshal(map[string]any{"labels": labels, "sets": sets})
	return string(b)
}

// POST /cdn64/hosts/{id}/protection (waf=1, ja4=off|count|block): Schutz der Server fuer alle Namen des Hosts.
func (m *Module) pageProtectionSet(w http.ResponseWriter, r *http.Request) {
	h, ok := m.hostFromPath(w, r)
	if !ok {
		return
	}
	waf, ja4 := r.PostFormValue("waf") == "1", r.PostFormValue("ja4")
	if ja4 != "off" && ja4 != "count" && ja4 != "block" {
		http.Error(w, "invalid ja4", http.StatusBadRequest)
		return
	}
	back := "/cdn64"
	err := m.onlineProtect(r.Context(), h, waf, ja4)
	if err != nil {
		m.g.Flash(w, r, "danger", m.onlineText(r, onlineCode(err), err.Error()))
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	state := "waf=off"
	if waf {
		state = "waf=on"
	}
	m.g.Audit(r, "cdn64.online.protection", h.Names[0], state+" ja4="+ja4)
	m.g.Flash(w, r, "success", m.g.T(r, "cdn64.protection.saved", "name", h.Names[0]))
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// onlineProtect setzt WAF und JA4 bei ipv64 fuer alle Namen des Hosts und holt danach den Stand.
func (m *Module) onlineProtect(ctx context.Context, h *Host, waf bool, ja4 string) error {
	a := m.online.api
	if a == nil || !a.Ready(ctx) {
		return errOnline("no_api_key")
	}
	ids, err := m.onlineHostIDs(ctx, h)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := a.SetProtection(ctx, id, &waf, ja4); err != nil {
			return err
		}
	}
	ov, err := a.Overview(ctx)
	m.onlineSetRemote(ov, err)
	return nil
}
