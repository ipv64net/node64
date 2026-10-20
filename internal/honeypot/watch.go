package honeypot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/notify"
)

// Fruehwarnung fuer eigene Netze (Plan Abschnitt 11, Phase H5): Netze werden bei ipv64 gespeichert und dort nach
// jeder Bewertung geprueft (GET/POST/DELETE /api/v2/threat/watch, GET /api/v2/threat/watch/alerts). Die Node
// verwaltet sie in der Oberflaeche (watch_ui.go) und holt die Treffer alle 30 Minuten ab: jeder Abruf mit neuen
// Treffern ergibt eine gebuendelte Benachrichtigung (notify.KindHoneypotWatch). Die letzten Treffer und der Stand
// des Abrufs liegen als JSON in den Einstellungen des Kerns (keine eigene Tabelle). Ein eigener Sensor ist nicht
// noetig: der Abruf laeuft auch, wenn die Meldung an ipv64 aus ist.

const (
	setWatch       = Name + ".watch" // Zustand der Fruehwarnung (JSON watchState), Einstellung honeypot.watch
	watchKeep      = 200             // so viele Treffer bleiben lokal
	watchMaxPages  = 10              // hoechstens so viele Seiten Treffer je Abruf (je 100)
	watchNotifyMax = 10              // so viele Treffer nennt eine Benachrichtigung
)

// KindNotifyWatch ist die Art der Benachrichtigung der Fruehwarnung (gebuendelt je Abruf).
const KindNotifyWatch = notify.KindHoneypotWatch

// watchTimingT sind die Abstaende des Abrufs.
type watchTimingT struct {
	First, FirstJitter time.Duration // erster Abruf nach dem Start (+ Zufall bis FirstJitter)
	Every, Jitter      time.Duration // regulaerer Abstand (+ Zufall bis Jitter)
	AuthBackoff        time.Duration // nach 401/403: so lange kein neuer Versuch mit demselben Key
	MinRetry           time.Duration // kuerzeste Wartezeit nach 429
}

var (
	watchTimingMu sync.Mutex
	watchTiming   = watchTimingT{First: 2 * time.Minute, FirstJitter: 3 * time.Minute, Every: 30 * time.Minute, Jitter: 5 * time.Minute,
		AuthBackoff: 6 * time.Hour, MinRetry: time.Minute}

	// watchRunMu serialisiert Abrufe (Schleife und „Jetzt abrufen“), damit next und die Treffer nicht doppelt
	// verarbeitet werden.
	watchRunMu sync.Mutex
)

// watchTimes liefert die Abstaende (Tests setzen mit setWatchTiming kurze Werte).
func watchTimes() watchTimingT {
	watchTimingMu.Lock()
	defer watchTimingMu.Unlock()
	return watchTiming
}

func setWatchTiming(t watchTimingT) {
	watchTimingMu.Lock()
	defer watchTimingMu.Unlock()
	watchTiming = t
}

// watchJitter liefert eine zufaellige Dauer in [0, d).
func watchJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(d)))
}

// watchHit ist ein lokal gespeicherter Treffer.
type watchHit struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	CIDR      string    `json:"cidr,omitempty"`
	Label     string    `json:"label,omitempty"` // Bezeichnung des Netzes bzw. Domain der DynDNS-IP
	Source    string    `json:"source"`          // network oder dyndns
	Listed    bool      `json:"listed"`
	Score     int       `json:"score"`
	Kinds     []string  `json:"kinds,omitempty"`
	FirstSeen string    `json:"first_seen,omitempty"`
	LastSeen  string    `json:"last_seen,omitempty"`
	Created   string    `json:"created_at,omitempty"` // Zeitpunkt bei ipv64 (Text wie geliefert)
	Fetched   time.Time `json:"fetched"`              // abgeholt
}

// watchState ist der Zustand der Fruehwarnung (Einstellung honeypot.watch).
type watchState struct {
	Next        string     `json:"next,omitempty"` // Stand fuer den naechsten Abruf (since)
	Hits        []watchHit `json:"hits,omitempty"` // neueste zuerst, hoechstens watchKeep
	Total       int64      `json:"total"`          // alle je abgeholten Treffer
	Networks    int        `json:"networks"`       // Stand des letzten Abrufs
	DynDNS      int        `json:"dyndns"`
	LastCheck   time.Time  `json:"last_check,omitzero"`
	LastSuccess time.Time  `json:"last_success,omitzero"`
	NextAttempt time.Time  `json:"next_attempt,omitzero"`
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt time.Time  `json:"last_error_at,omitzero"`
	ErrorStatus int        `json:"error_status,omitempty"` // HTTP-Status des letzten Fehlers
	KeyFP       string     `json:"key_fp,omitempty"`       // Kennung des Keys beim letzten 401/403 (gekuerzter Hash)
}

// AuthFailed: der Key wurde zuletzt abgelehnt (401/403).
func (s watchState) AuthFailed() bool {
	return s.ErrorStatus == http.StatusUnauthorized || s.ErrorStatus == http.StatusForbidden
}

// keyFP: kurze Kennung des Keys, um einen neuen Key nach 401/403 zu erkennen (verraet den Key nicht).
func keyFP(key string) string {
	h := sha256.Sum256([]byte("honeypot-watch:" + key))
	return hex.EncodeToString(h[:6])
}

func (m *Module) watchLoad(ctx context.Context) watchState {
	var s watchState
	if raw := m.core.SettingOr(ctx, setWatch, ""); raw != "" {
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			m.log.Warn("honeypot watch: state unreadable, starting fresh", "err", err)
			s = watchState{}
		}
	}
	return s
}

// watchSave speichert den Zustand (auch wenn ctx gerade endet, damit next und abgeholte Treffer nicht verloren gehen).
func (m *Module) watchSave(ctx context.Context, s watchState) {
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	raw, err := json.Marshal(s)
	if err == nil {
		err = m.core.SetSetting(sctx, setWatch, string(raw))
	}
	if err != nil {
		m.log.Warn("honeypot watch: state not saved", "err", err)
	}
}

// errWatchNoKey: kein zentraler API-Key eingetragen.
var errWatchNoKey = errors.New("no ipv64 API key")

// watchRoutes haengt die Seite der Fruehwarnung ein (aus Routes); die Seite steht in watch_ui.go.

// watchLoop holt Treffer der Fruehwarnung ab (aus Start, laeuft bis ctx endet): erster Abruf ein paar Minuten nach
// dem Start, danach alle 30 Minuten mit Zufallsversatz; 429 wartet Retry-After ab, nach 401/403 wird mit
// demselben Key erst nach AuthBackoff wieder gefragt.
func (m *Module) watchLoop(ctx context.Context) {
	tm := watchTimes()
	wait := tm.First + watchJitter(tm.FirstJitter)
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		_, wait, _ = m.watchCheck(ctx, false)
		if wait <= 0 {
			wait = watchTimes().Every
		}
	}
}

// watchCheck fuehrt einen Abruf aus: Liste (Netze, DynDNS-IPs), dann Treffer seit next (seitenweise), Meldung,
// Zustand speichern. Liefert die Zahl neuer Treffer und die Wartezeit bis zum naechsten Abruf. force (Knopf in der
// Oberflaeche) fragt auch nach einem 401/403 sofort wieder und laesst den geplanten Zeitpunkt stehen.
func (m *Module) watchCheck(ctx context.Context, force bool) (int, time.Duration, error) {
	watchRunMu.Lock()
	defer watchRunMu.Unlock()
	tm := watchTimes()
	every := tm.Every + watchJitter(tm.Jitter)
	c, key := m.api(ctx)
	if c == nil || key == "" {
		return 0, every, errWatchNoKey
	}
	st := m.watchLoad(ctx)
	now := time.Now()
	fp := keyFP(key)
	if !force && st.AuthFailed() && st.KeyFP == fp && now.Sub(st.LastErrorAt) < tm.AuthBackoff {
		return 0, tm.Every, nil // Key abgelehnt und unveraendert: seltener versuchen
	}
	st.LastCheck = now
	list, err := c.ThreatWatchList(ctx, key)
	if err != nil {
		return 0, m.watchFail(ctx, &st, fp, err, force, tm, every), err
	}
	st.Networks, st.DynDNS = len(list.Networks), len(list.DynDNS)
	var fresh []watchHit
	if st.Networks+st.DynDNS > 0 { // ohne Netz und DynDNS-IP gibt es nichts abzuholen
		fresh, err = m.watchFetch(ctx, c, key, &st, list, now)
	}
	if len(fresh) > 0 {
		st.Hits = mergeHits(st.Hits, fresh)
		st.Total += int64(len(fresh))
		m.watchNotify(fresh, now)
	}
	if err != nil {
		return len(fresh), m.watchFail(ctx, &st, fp, err, force, tm, every), err
	}
	st.LastSuccess, st.LastError, st.LastErrorAt, st.ErrorStatus, st.KeyFP = now, "", time.Time{}, 0, ""
	if !force {
		st.NextAttempt = now.Add(every)
	}
	m.watchSave(ctx, st)
	return len(fresh), every, nil
}

// watchFetch holt die Treffer seit st.Next (aelteste zuerst) und schiebt next weiter. Schon bekannte IDs (z. B.
// wenn since den letzten Treffer einschliesst) fallen weg. Bei einem Fehler mitten im Abruf kommen die bis dahin
// geholten Treffer trotzdem zurueck (next steht passend dazu).
func (m *Module) watchFetch(ctx context.Context, c *ipv64api.Client, key string, st *watchState, list *ipv64api.ThreatWatch, now time.Time) ([]watchHit, error) {
	known := make(map[int64]bool, len(st.Hits))
	for _, h := range st.Hits {
		known[h.ID] = true
	}
	labels := map[int64]string{}
	for _, n := range list.Networks {
		labels[n.ID] = n.Label
	}
	domains := map[string]string{}
	for _, d := range list.DynDNS {
		domains[d.IP] = d.Domain
	}
	var fresh []watchHit
	for page := 0; page < watchMaxPages; page++ {
		res, err := c.ThreatWatchAlerts(ctx, key, st.Next)
		if err != nil {
			return fresh, err
		}
		for _, a := range res.Alerts {
			if known[a.ID] {
				continue
			}
			known[a.ID] = true
			h := watchHit{ID: a.ID, IP: a.IP, CIDR: a.CIDR, Source: a.Source, Listed: a.Listed, Score: a.Score, Kinds: a.Kinds,
				FirstSeen: a.FirstSeen, LastSeen: a.LastSeen, Created: a.CreatedAt, Fetched: now.UTC()}
			if a.NetworkID != nil {
				h.Label = labels[*a.NetworkID]
			}
			if h.Label == "" && a.Source == "dyndns" {
				h.Label = domains[a.IP]
			}
			fresh = append(fresh, h)
		}
		more := len(res.Alerts) >= ipv64api.ThreatWatchPage && res.Next != "" && res.Next != st.Next
		if res.Next != "" {
			st.Next = res.Next
		}
		if !more {
			break
		}
	}
	return fresh, nil
}

// mergeHits stellt neue Treffer (aelteste zuerst) vor die gespeicherten (neueste zuerst) und kuerzt auf watchKeep.
func mergeHits(old, fresh []watchHit) []watchHit {
	out := make([]watchHit, 0, min(len(old)+len(fresh), watchKeep))
	for i := len(fresh) - 1; i >= 0 && len(out) < watchKeep; i-- {
		out = append(out, fresh[i])
	}
	for _, h := range old {
		if len(out) >= watchKeep {
			break
		}
		out = append(out, h)
	}
	return out
}

// watchFail haelt einen Fehler fest und liefert die Wartezeit: 429 nach Retry-After (mindestens MinRetry),
// 401/403 normaler Takt, aber ohne Anfrage bis AuthBackoff vorbei oder der Key neu ist; sonst normaler Takt.
func (m *Module) watchFail(ctx context.Context, st *watchState, fp string, err error, force bool, tm watchTimingT, every time.Duration) time.Duration {
	if ctx.Err() != nil { // Ende des Moduls: kein Fehler, aber schon abgeholte Treffer und next sichern
		m.watchSave(ctx, *st)
		return every
	}
	now := time.Now()
	wait, next := every, now.Add(every)
	st.LastError, st.LastErrorAt, st.ErrorStatus, st.KeyFP = err.Error(), now, 0, ""
	var ae *ipv64api.APIError
	if errors.As(err, &ae) {
		st.ErrorStatus = ae.Status
		switch {
		case st.AuthFailed():
			st.KeyFP = fp
			wait, next = tm.Every, now.Add(tm.AuthBackoff)
		case ae.Status == http.StatusTooManyRequests && ae.RetryAfter > 0:
			wait = max(ae.RetryAfter, tm.MinRetry)
			next = now.Add(wait)
		}
	}
	if !force {
		st.NextAttempt = next
	}
	m.log.Warn("honeypot watch: fetch failed", "err", err, "status", st.ErrorStatus, "retry_in", wait.Round(time.Second))
	m.watchSave(ctx, *st)
	return wait
}

// watchNotify schickt eine gebuendelte Benachrichtigung fuer die neuen Treffer eines Abrufs.
func (m *Module) watchNotify(fresh []watchHit, now time.Time) {
	m.log.Info("notification", "kind", KindNotifyWatch, "hits", len(fresh))
	if m.notifier == nil || len(fresh) == 0 {
		return
	}
	lines := make([]string, 0, watchNotifyMax+1)
	for i, h := range fresh {
		if i == watchNotifyMax {
			lines = append(lines, "+ "+strconv.Itoa(len(fresh)-watchNotifyMax)+" …")
			break
		}
		lines = append(lines, hitLine(h))
	}
	name := fresh[0].IP
	if len(fresh) > 1 {
		name += " +" + strconv.Itoa(len(fresh)-1)
	}
	m.notifier(notify.Alert{EventID: "honeypot-watch-" + strconv.FormatInt(fresh[0].ID, 10) + "-" + strconv.FormatInt(fresh[len(fresh)-1].ID, 10),
		Kind: KindNotifyWatch, Time: now.UTC(), Check: notify.CheckInfo{Name: name, NotifyDown: true, NotifyUp: true, Local: true},
		Message: strings.Join(lines, "\n")})
}

// hitLine: ein Treffer als Zeile der Benachrichtigung (ohne Uebersetzung, Begriffe in beiden Sprachen lesbar).
func hitLine(h watchHit) string {
	parts := []string{h.IP}
	switch {
	case h.Source == "dyndns" && h.Label != "":
		parts = append(parts, h.Label+" (DynDNS)")
	case h.Source == "dyndns":
		parts = append(parts, "DynDNS")
	case h.Label != "" && h.CIDR != "":
		parts = append(parts, h.Label+" ("+h.CIDR+")")
	case h.CIDR != "":
		parts = append(parts, h.CIDR)
	}
	score := "Score " + strconv.Itoa(h.Score)
	if h.Listed {
		score += ", v64 Blocklist"
	}
	parts = append(parts, score)
	if len(h.Kinds) > 0 {
		parts = append(parts, strings.Join(h.Kinds, ", "))
	}
	if h.FirstSeen != "" || h.LastSeen != "" {
		parts = append(parts, strings.Trim(h.FirstSeen+" – "+h.LastSeen, " –"))
	}
	return strings.Join(parts, " · ")
}
