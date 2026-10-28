package dyndns

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"net/netip"

	"github.com/ipv64net/node64/internal/ipv64api"
)

func (m *Module) targetRoutes(mux interface {
	Handle(string, http.Handler)
}, page func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /dyndns/targets/new", page(m.pageTargetNew))
	mux.Handle("POST /dyndns/targets/new", page(m.pageTargetPick))
	mux.Handle("POST /dyndns/targets/manual", page(m.pageTargetManual))
	mux.Handle("GET /dyndns/targets/{id}", page(m.pageTargetEdit))
	mux.Handle("POST /dyndns/targets/{id}", page(m.pageTargetSave))
	mux.Handle("POST /dyndns/targets/{id}/token", page(m.pageTargetToken))
	mux.Handle("POST /dyndns/targets/{id}/delete", page(m.pageTargetDelete))
	mux.Handle("POST /dyndns/targets/{id}/update", page(m.pageTargetUpdate))
}

func (m *Module) back(w http.ResponseWriter, r *http.Request, kind, text, to string) {
	if text != "" {
		m.g.Flash(w, r, kind, text)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// ---------------------------------------------------------------- Auswahl aus dem Account

// pickName ist ein Name im Account mit seinen A/AAAA-Records.
type pickName struct {
	Key      string // domain|host
	Domain   string
	Host     string
	FQDN     string
	A        []string
	AAAA     []string
	Suffix   bool   // AAAA mit Interface-ID (::...), wird ueber das Praefix aktualisiert
	Blocked  string // Grund, warum der Name nicht waehlbar ist (Failover)
	CDN      bool   // ueber das ipv64-CDN (Reverse-Proxy) geleitet: Updater pflegt die Ursprungsadresse
	Exists   bool   // schon als Ziel eingerichtet
	Kind     string // dyndns, own
	Ignore   string // ipv4/ipv6: bei ipv64 fuer Updater ignoriert
	recordID int64
	token    string
	aID      int64 // erster A-Record (sein Token wirkt bei ipv64 fuer A und AAAA des Namens)
	aToken   string
	First    bool   // erster Name einer Domain (Kopfzeile in der Liste)
	Def4     string // Vorbelegung der Modi in der Liste
	Def6     string
	SuffixOf string // Interface-ID aus dem vorhandenen AAAA (fuer "Praefix + Interface-ID"), leer = keine
}

// Modi, die sich direkt in der Auswahlliste waehlen lassen (alles weitere in der Bearbeitung)
var (
	pickModes4 = []string{Mode4Auto, Mode4Off}
	pickModes6 = []string{Mode6Host, Mode6Prefix, Mode6Suffix, Mode6Off}
)

// suffixOf liefert die unteren 64 Bit einer vollen IPv6 als Interface-ID ("::x:x:x:x"), sonst leer.
func suffixOf(content string) string {
	a, err := netip.ParseAddr(content)
	if err != nil || !a.Is6() || strings.HasPrefix(content, "::") {
		return ""
	}
	b := a.As16()
	for i := 0; i < 8; i++ {
		b[i] = 0
	}
	s := netip.AddrFrom16(b)
	if s.IsUnspecified() {
		return ""
	}
	return s.String()
}

// accountNames laedt Domains und Records und fasst sie je Name zusammen (Tokens nur intern).
func (m *Module) accountNames(ctx context.Context, key string) ([]*pickName, error) {
	doms, err := m.key.Client().Domains(ctx, key)
	if err != nil {
		return nil, err
	}
	existing := map[string]bool{}
	if ts, err := m.Targets(ctx); err == nil {
		for _, t := range ts {
			existing[t.Domain+"|"+t.Host] = true
		}
	}
	var out []*pickName
	for _, d := range doms {
		if !d.Active {
			continue
		}
		recs, err := m.key.Client().Records(ctx, key, d.Name)
		if err != nil {
			return nil, err
		}
		byHost := map[string]*pickName{}
		for _, rec := range recs {
			if rec.Type != "A" && rec.Type != "AAAA" || rec.State == "cdn_record" { // Adressen des CDN selbst: nie anfassen
				continue
			}
			p := byHost[rec.Prefix]
			if p == nil {
				p = &pickName{Key: d.Name + "|" + rec.Prefix, Domain: d.Name, Host: rec.Prefix, FQDN: rec.FQDN, Kind: d.Kind, Ignore: d.Ignore, Exists: existing[d.Name+"|"+rec.Prefix]}
				byHost[rec.Prefix] = p
			}
			switch rec.State {
			case "active", "inactive":
			case "cdn_proxied", "cdn_partial":
				p.CDN = true
			default:
				p.Blocked = rec.State
			}
			if rec.Type == "A" {
				p.A = append(p.A, rec.Content)
			} else {
				p.AAAA = append(p.AAAA, rec.Content)
				p.Suffix = p.Suffix || strings.HasPrefix(rec.Content, "::")
			}
			if p.token == "" {
				p.token, p.recordID = rec.Token, int64(rec.ID)
			}
			if rec.Type == "A" && p.aToken == "" {
				p.aToken, p.aID = rec.Token, int64(rec.ID)
			}
		}
		for _, p := range byHost {
			if p.aToken != "" { // Record-Token: A bevorzugt
				p.token, p.recordID = p.aToken, p.aID
			}
			for _, c := range p.AAAA {
				if s := suffixOf(c); s != "" && p.SuffixOf == "" {
					p.SuffixOf = s
				}
			}
			d := m.defaultsFor(p)
			p.Def4, p.Def6 = d.Mode4, d.Mode6
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		return out[i].Host < out[j].Host
	})
	for i, p := range out {
		p.First = i == 0 || out[i-1].Domain != p.Domain
	}
	return out, nil
}

// defaultsFor waehlt die Modi fuer einen neu gewaehlten Namen.
func (m *Module) defaultsFor(p *pickName) *Target {
	t := &Target{Domain: p.Domain, Host: p.Host, RecordID: p.recordID, TokenKind: "record", Token: p.token, Mode4: Mode4Off, Mode6: Mode6Off, Enabled: true}
	if len(p.A) > 0 && p.Ignore != "ipv4" {
		t.Mode4 = Mode4Auto
	}
	if len(p.AAAA) > 0 && p.Ignore != "ipv6" {
		t.Mode6 = Mode6Host
		if p.Suffix {
			t.Mode6 = Mode6Prefix
		}
	}
	return t
}

type newData struct {
	Modes4P []string // in der Liste waehlbar
	Modes6P []string
	HasKey  bool
	Account ipv64api.AccountInfo
	Names   []*pickName
	Err     string
	Modes4  []string
	Modes6  []string
}

func (m *Module) pageTargetNew(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := newData{Modes4: Modes4, Modes6: Modes6, Modes4P: pickModes4, Modes6P: pickModes6}
	if m.key != nil {
		d.Account = m.key.Info(ctx)
	}
	if key := m.keyOf(ctx); key != "" {
		d.HasKey = true
		lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		names, err := m.accountNames(lctx, key)
		cancel()
		if err != nil {
			d.Err = err.Error()
		}
		d.Names = names
	}
	m.g.Render(w, r, http.StatusOK, Name+"/target_new", "dyn.targets.add", d)
}

func (m *Module) pageTargetPick(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key := m.keyOf(ctx)
	_ = r.ParseForm()
	if key == "" || len(r.PostForm["pick"]) == 0 {
		m.back(w, r, "warning", m.g.T(r, "dyn.targets.none_picked"), "/dyndns/targets/new")
		return
	}
	picks := map[string]pickChoice{}
	n := 0 // Namen, die wirklich angelegt wuerden (IPv4 und IPv6 "aus" legt addPicked nicht an)
	for _, k := range r.PostForm["pick"] {
		c := pickChoice{Mode4: r.PostFormValue("m4:" + k), Mode6: r.PostFormValue("m6:" + k)}
		picks[k] = c
		if c.Mode4 != Mode4Off || c.Mode6 != Mode6Off {
			n++
		}
	}
	// Mehrere Namen auf einmal ueberschreiben deren A/AAAA: nur mit bestaetigter Rueckfrage (Fenster in dyndns.js)
	if n > 1 && r.PostFormValue("confirm_many") != "1" {
		m.back(w, r, "warning", m.g.T(r, "dyn.pick.confirm_needed"), "/dyndns/targets/new")
		return
	}
	lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	added, failed, err := m.addPicked(lctx, key, picks)
	cancel()
	if err != nil {
		m.back(w, r, "danger", m.g.T(r, "dyn.api.failed", "error", err.Error()), "/dyndns/targets/new")
		return
	}
	for _, t := range added {
		m.audit(r, "dyndns.target_add", t.FQDN(), "")
	}
	if len(failed) > 0 {
		m.g.Flash(w, r, "warning", m.g.T(r, "dyn.targets.add_failed", "names", strings.Join(failed, ", ")))
	}
	m.back(w, r, "success", m.g.T(r, "dyn.targets.added", "count", len(added)), "/dyndns")
}

// pageTargetManual legt ein Ziel ohne API-Key an (Token von Hand).
func (m *Module) pageTargetManual(w http.ResponseWriter, r *http.Request) {
	t := &Target{Domain: r.PostFormValue("domain"), Host: r.PostFormValue("host"), TokenKind: r.PostFormValue("token_kind"), Token: r.PostFormValue("token"),
		Mode4: r.PostFormValue("mode4"), Mode6: r.PostFormValue("mode6"), Enabled: true}
	// hier nur die einfachen Modi; Feinheiten (fest, Interface-ID, Interface) danach in der Bearbeitung
	if t.Mode4 != Mode4Auto {
		t.Mode4 = Mode4Off
	}
	if t.Mode6 != Mode6Host && t.Mode6 != Mode6Prefix {
		t.Mode6 = Mode6Off
	}
	if err := m.InsertTarget(r.Context(), t); err != nil {
		m.back(w, r, "danger", m.fieldErr(r, err), "/dyndns/targets/new#manual")
		return
	}
	m.audit(r, "dyndns.target_add", t.FQDN(), "manual")
	m.back(w, r, "success", m.g.T(r, "dyn.targets.added", "count", 1), "/dyndns/targets/"+strconv.FormatInt(t.ID, 10))
}

func (m *Module) fieldErr(r *http.Request, err error) string {
	if errors.Is(err, ErrExists) {
		return m.g.T(r, "dyn.targets.exists")
	}
	return m.g.T(r, "dyn.targets.invalid", "field", m.g.T(r, "dyn.field."+err.Error()))
}

// ---------------------------------------------------------------- Bearbeiten

type editData struct {
	T      *Target
	HasKey bool
	Modes4 []string
	Modes6 []string
	Local  []ifAddr
}

func (m *Module) loadTarget(w http.ResponseWriter, r *http.Request) *Target {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	t, err := m.Target(r.Context(), id)
	if err != nil || t == nil {
		m.back(w, r, "warning", m.g.T(r, "dyn.targets.missing"), "/dyndns")
		return nil
	}
	return t
}

func (m *Module) pageTargetEdit(w http.ResponseWriter, r *http.Request) {
	t := m.loadTarget(w, r)
	if t == nil {
		return
	}
	m.g.Render(w, r, http.StatusOK, Name+"/target_edit", "dyn.targets.edit", editData{T: t, HasKey: m.keyOf(r.Context()) != "", Modes4: Modes4, Modes6: Modes6, Local: localIPv6()})
}

func (m *Module) pageTargetSave(w http.ResponseWriter, r *http.Request) {
	t := m.loadTarget(w, r)
	if t == nil {
		return
	}
	t.Mode4, t.Fixed4 = r.PostFormValue("mode4"), r.PostFormValue("fixed4")
	t.Mode6, t.Fixed6, t.Suffix6, t.Iface = r.PostFormValue("mode6"), r.PostFormValue("fixed6"), r.PostFormValue("suffix6"), r.PostFormValue("iface")
	t.Enabled = r.PostFormValue("enabled") == "on"
	if t.Enabled {
		t.Paused = "" // wieder einschalten hebt eine automatische Pause auf
	}
	if tok := strings.TrimSpace(r.PostFormValue("token")); tok != "" {
		t.Token, t.TokenKind = tok, r.PostFormValue("token_kind")
	}
	if err := m.UpdateTarget(r.Context(), t); err != nil {
		m.back(w, r, "danger", m.fieldErr(r, err), "/dyndns/targets/"+r.PathValue("id"))
		return
	}
	m.audit(r, "dyndns.target_edit", t.FQDN(), "")
	m.back(w, r, "success", m.g.T(r, "common.saved"), "/dyndns")
}

// pageTargetToken holt den Record-Token ueber die API neu (z. B. nach Token-Wechsel bei ipv64).
// errNoRecord: bei ipv64 gibt es fuer den Namen keinen A/AAAA-Record mehr.
var errNoRecord = errors.New("no A or AAAA record for this name at ipv64")

// refreshToken holt den Record-Token ueber die API neu und speichert ihn (badauth-Pause wird aufgehoben).
func (m *Module) refreshToken(ctx context.Context, t *Target) error {
	key := m.keyOf(ctx)
	if key == "" {
		return ipv64api.ErrNoKey
	}
	recs, err := m.key.Client().Records(ctx, key, t.Domain)
	if err != nil {
		return err
	}
	// gespeicherter Record zuerst, sonst A vor AAAA (wie bei der Auswahl)
	var best *ipv64api.Record
	score := func(rec *ipv64api.Record) int {
		switch {
		case int64(rec.ID) == t.RecordID:
			return 3
		case rec.Type == "A":
			return 2
		}
		return 1
	}
	for i := range recs {
		rec := &recs[i]
		if rec.Prefix == t.Host && (rec.Type == "A" || rec.Type == "AAAA") && rec.State != "cdn_record" && (best == nil || score(rec) > score(best)) {
			best = rec
		}
	}
	if best == nil {
		return errNoRecord
	}
	t.Token, t.TokenKind, t.RecordID = best.Token, "record", int64(best.ID)
	if t.Paused == PauseBadAuth {
		t.Paused = ""
	}
	return m.UpdateTarget(ctx, t)
}

func (m *Module) pageTargetToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := m.loadTarget(w, r)
	if t == nil {
		return
	}
	back := "/dyndns/targets/" + r.PathValue("id")
	switch err := m.refreshToken(ctx, t); {
	case errors.Is(err, ipv64api.ErrNoKey):
		m.back(w, r, "warning", m.g.T(r, "dyn.api.needed"), back)
	case errors.Is(err, errNoRecord):
		m.back(w, r, "warning", m.g.T(r, "dyn.targets.no_record"), back)
	case err != nil:
		m.back(w, r, "danger", m.g.T(r, "dyn.api.failed", "error", err.Error()), back)
	default:
		m.audit(r, "dyndns.token_refresh", t.FQDN(), "")
		m.back(w, r, "success", m.g.T(r, "dyn.targets.token_refreshed"), back)
	}
}

// pageTargetUpdate meldet das Ziel sofort (auch ohne Abweichung; kostet Update-Limit).
func (m *Module) pageTargetUpdate(w http.ResponseWriter, r *http.Request) {
	t := m.loadTarget(w, r)
	if t == nil {
		return
	}
	back := "/dyndns/targets/" + r.PathValue("id")
	if r.PostFormValue("back") == "list" {
		back = "/dyndns"
	}
	res, err := m.UpdateNow(r.Context(), t)
	switch {
	case errors.Is(err, ErrBusy):
		m.back(w, r, "warning", m.g.T(r, "dyn.update.busy"), back)
		return
	case res == NowNothing:
		m.back(w, r, "warning", m.g.T(r, "dyn.update.nothing", "name", t.FQDN()), back)
		return
	}
	m.audit(r, "dyndns.update_now", t.FQDN(), "")
	if got, _ := m.Target(r.Context(), t.ID); got != nil && got.Status() == "error" {
		m.back(w, r, "danger", m.g.T(r, "dyn.update.failed", "name", t.FQDN(), "error", got.LastError), back)
		return
	} else if got != nil && got.Paused != "" {
		m.back(w, r, "warning", m.g.T(r, "dyn.update.paused", "name", t.FQDN(), "reason", m.g.T(r, "dyn.pause."+got.Paused)), back)
		return
	}
	m.back(w, r, "success", m.g.T(r, "dyn.update.done", "name", t.FQDN()), back)
}

func (m *Module) pageTargetDelete(w http.ResponseWriter, r *http.Request) {
	t := m.loadTarget(w, r)
	if t == nil {
		return
	}
	if err := m.DeleteTarget(r.Context(), t.ID); err != nil {
		m.back(w, r, "danger", err.Error(), "/dyndns")
		return
	}
	m.audit(r, "dyndns.target_delete", t.FQDN(), "")
	m.back(w, r, "success", m.g.T(r, "dyn.targets.deleted", "name", t.FQDN()), "/dyndns")
}
