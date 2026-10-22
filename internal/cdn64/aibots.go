package cdn64

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// KI-Bots je Host: Anfragen, deren User-Agent eine Kennung aus der Liste "v64 KI-Bots (User-Agent)" von ipv64.net
// enthaelt (Spiegel von ai.robots.txt, kein Abruf bei GitHub), bekommen 403. Gross/klein egal; die Kennung muss als
// eigenes Wort im User-Agent stehen ("Spider" trifft nicht "Baiduspider"). Abrufe auf Anfrage eines Nutzers
// (ChatGPT-User, Perplexity-User, Assistenten, Agenten) sind je Host abschaltbar. /robots.txt wird nie gesperrt, damit
// Bots die Sperre lesen koennen; auf Wunsch liefert PROXY64 eine robots.txt mit KI-Sperre, wenn das Ziel keine hat (404).
// Laden wie die Blocklisten (alle 30 Minuten nur bei Aenderung, Zwischenspeicher), nur solange ein Host es nutzt.

const (
	aiUAFile    = "ipv64_ai_useragents.json"
	aiCacheFile = "ai_useragents.json"
	aiUAMax     = 4 << 20
	aiTokMin    = 3
	aiTokMax    = 80
	aiMinBots   = 10   // weniger = Unsinn, alte Liste behalten
	aiMaxBots   = 5000 // hoechstens so viele Kennungen
	rejAIBot    = "ai_bot"
	aiRobotsTxt = "/robots.txt"
)

// aiList: geladene Kennungen (kleingeschrieben fuer den Abgleich) und die fertigen robots.txt.
type aiList struct {
	all, crawl             []string // mit bzw. ohne Nutzer-Abrufe
	robotsAll, robotsCrawl string
	count, users           int
}

// AIBotsState ist der Stand der User-Agent-Liste (Seite und API).
type AIBotsState struct {
	Needed  bool      `json:"needed"`  // mindestens ein eingeschalteter Host nutzt sie
	Entries int64     `json:"entries"` // Kennungen
	Users   int64     `json:"users"`   // davon Nutzer-Abrufe
	Updated time.Time `json:"updated,omitzero"`
	Changed time.Time `json:"changed,omitzero"`
	Error   string    `json:"error,omitempty"`
	Blocked int64     `json:"blocked"` // abgewiesen seit dem Start
}

type aiBots struct {
	cur     atomic.Pointer[aiList]
	need    atomic.Bool
	blocked atomic.Int64
	mu      sync.Mutex
	state   AIBotsState
}

// aiTokValid: druckbares ASCII, ohne Leerzeichen am Rand, 3..80 Zeichen.
func aiTokValid(t string) bool {
	if len(t) < aiTokMin || len(t) > aiTokMax || t[0] == ' ' || t[len(t)-1] == ' ' {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < 0x20 || t[i] > 0x7e {
			return false
		}
	}
	return true
}

// parseAIBots liest ipv64_ai_useragents.json ({"bots":[{"name":..,"user":..}]}).
func parseAIBots(raw []byte) (*aiList, error) {
	var in struct {
		Bots []struct {
			Name string `json:"name"`
			User bool   `json:"user"`
		} `json:"bots"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	if len(in.Bots) > aiMaxBots {
		return nil, errors.New("too many user agents")
	}
	l := &aiList{}
	seen, seenCrawl := map[string]bool{}, map[string]bool{}
	var ra, rc strings.Builder
	for _, b := range in.Bots {
		if !aiTokValid(b.Name) {
			continue
		}
		lo := strings.ToLower(b.Name)
		if !seen[lo] {
			seen[lo] = true
			l.all = append(l.all, lo)
		}
		if !b.User && !seenCrawl[lo] {
			seenCrawl[lo] = true
			l.crawl = append(l.crawl, lo)
		}
		ra.WriteString("User-agent: " + b.Name + "\n")
		if !b.User {
			rc.WriteString("User-agent: " + b.Name + "\n")
		}
		l.count++
		if b.User {
			l.users++
		}
	}
	if l.count < aiMinBots {
		return nil, errors.New("too few user agents")
	}
	const head = "# robots.txt from PROXY64 (Node64): this website has none. AI bots from ai.robots.txt via ipv64.net\n"
	l.robotsAll = head + ra.String() + "Disallow: /\n"
	if rc.Len() > 0 {
		l.robotsCrawl = head + rc.String() + "Disallow: /\n"
	}
	return l, nil
}

// aiWord: Zeichen, das zu einem Wort gehoert (Kennung muss davor und dahinter ein anderes Zeichen haben).
func aiWord(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c >= 0x80
}

// aiMatch: eine Kennung (kleingeschrieben) steht als eigenes Wort im (kleingeschriebenen) User-Agent.
func aiMatch(ua string, toks []string) bool {
	for _, t := range toks {
		for i := 0; i+len(t) <= len(ua); {
			j := strings.Index(ua[i:], t)
			if j < 0 {
				break
			}
			j += i
			end := j + len(t)
			if (j == 0 || !aiWord(ua[j-1])) && (end == len(ua) || !aiWord(ua[end])) {
				return true
			}
			i = j + 1
		}
	}
	return false
}

// match: User-Agent ist ein KI-Bot; user = Nutzer-Abrufe auch sperren.
func (a *aiBots) match(ua string, user bool) bool {
	l := a.cur.Load()
	if l == nil || ua == "" {
		return false
	}
	toks := l.crawl
	if user {
		toks = l.all
	}
	return aiMatch(strings.ToLower(ua), toks)
}

// robots: robots.txt mit KI-Sperre ("" = Liste noch nicht geladen).
func (a *aiBots) robots(user bool) string {
	l := a.cur.Load()
	if l == nil {
		return ""
	}
	if user {
		return l.robotsAll
	}
	return l.robotsCrawl
}

func (a *aiBots) put(l *aiList, changed time.Time) {
	a.cur.Store(l)
	a.mu.Lock()
	a.state.Entries, a.state.Users, a.state.Changed, a.state.Error = int64(l.count), int64(l.users), changed, ""
	a.mu.Unlock()
}

// aiBlocked: Anfrage an einen Host mit KI-Sperre kommt von einem KI-Bot (zaehlt mit). /robots.txt bleibt erreichbar.
func (m *Module) aiBlocked(a *Advanced, r *http.Request) bool {
	if !a.AIBots || r.URL.Path == aiRobotsTxt {
		return false
	}
	if m.bl.ai.match(r.UserAgent(), !a.AIBotsAllowUser) {
		m.bl.ai.blocked.Add(1)
		return true
	}
	return false
}

// aiRobots ersetzt die 404 des Ziels auf /robots.txt durch eine robots.txt mit KI-Sperre (Host mit ai_robots).
func (m *Module) aiRobots(a *Advanced, resp *http.Response) {
	if !a.AIRobots || resp.StatusCode != http.StatusNotFound || resp.Request == nil || resp.Request.URL.Path != aiRobotsTxt ||
		(resp.Request.Method != http.MethodGet && resp.Request.Method != http.MethodHead) {
		return
	}
	body := m.bl.ai.robots(!a.AIBotsAllowUser)
	if body == "" {
		return
	}
	_ = resp.Body.Close()
	resp.StatusCode, resp.Status = http.StatusOK, "200 OK"
	resp.Header = http.Header{"Content-Type": {"text/plain; charset=utf-8"}, "Cache-Control": {"max-age=3600"}, "Content-Length": {strconv.Itoa(len(body))}}
	resp.ContentLength, resp.TransferEncoding = int64(len(body)), nil
	resp.Body = io.NopCloser(strings.NewReader(body))
}

// normalizeAI: KI-Sperre nur fuer HTTP-Hosts, robots.txt nur fuer Proxy-Hosts.
func (a *Advanced) normalizeAI(kind string) {
	if kind != KindProxy && kind != KindRedirect && kind != KindStatus {
		a.AIBots = false
	}
	if !a.AIBots {
		a.AIBotsAllowUser = false
	}
	if kind != KindProxy {
		a.AIRobots = false
	}
}

// aiNeed: ein eingeschalteter Host nutzt die Liste (bei jedem apply); fehlt sie noch, wird geladen.
func (m *Module) aiNeed(active []*Host) {
	need := slices.ContainsFunc(active, func(h *Host) bool { return h.Advanced.AIBots || h.Advanced.AIRobots })
	m.bl.ai.need.Store(need)
	if need && m.bl.ai.cur.Load() == nil {
		select {
		case m.bl.kick <- struct{}{}:
		default:
		}
	}
}

// aiLoadCache: zwischengespeicherte Liste (beim Start: Sperre sofort, ohne auf ipv64 zu warten).
func (m *Module) aiLoadCache() {
	dir := m.blCacheDir()
	if dir == "" {
		return
	}
	p := filepath.Join(dir, aiCacheFile)
	raw, err := os.ReadFile(p)
	if err != nil {
		return
	}
	if l, err := parseAIBots(raw); err == nil {
		changed := time.Time{}
		if fi, err := os.Stat(p); err == nil {
			changed = fi.ModTime()
		}
		m.bl.ai.put(l, changed)
	}
}

// aiRefresh laedt die Liste (nur bei Aenderung), solange ein Host sie nutzt; bei Fehler bleibt die bisherige.
func (m *Module) aiRefresh(ctx context.Context) {
	a := &m.bl.ai
	if !a.need.Load() {
		return
	}
	have := a.cur.Load() != nil
	raw, same, err := m.blGet(ctx, aiUAFile, "ai:ua", have, aiUAMax)
	var l *aiList
	if err == nil && !same {
		if l, err = parseAIBots(bytes.TrimSpace(raw)); err == nil {
			m.blCacheWrite(aiCacheFile, raw)
			a.put(l, time.Now())
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		if ctx.Err() == nil {
			m.log.Warn("cdn64 ai user agent list not loaded", "err", err)
			a.state.Error = err.Error()
		}
		return
	}
	a.state.Updated, a.state.Error = time.Now(), ""
}

// aiState: Stand fuer Seite und API.
func (m *Module) aiState() AIBotsState {
	a := &m.bl.ai
	a.mu.Lock()
	st := a.state
	a.mu.Unlock()
	st.Needed, st.Blocked = a.need.Load(), a.blocked.Load()
	return st
}
