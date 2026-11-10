package monitor64

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/agentdist"
	"github.com/ipv64net/node64/internal/monitor64/transport"
	"github.com/ipv64net/node64/internal/update"
)

// Agent-Verteilung (Plan "Monitor64-Agent", docs/MONITOR64-AGENT-RELEASE.md): Die Node holt das signierte Verzeichnis
// der Agent-Dateien (agents.json) von ipv64.net bzw. node64.de, laedt Programme und Skripte beim ersten Bedarf nach
// <data>/monitor64/agent/, prueft sie (SHA-256, signierte Kopfzeile) und bietet sie Hosts ohne Anmeldung unter
// /monitor64/agent/<datei> an. Dieselben Dateien schiebt sie als automatisches Update ueber die bestehende
// Verbindung auf die Agents (agentdist_update.go). Ohne Agent-Host und ohne Aufruf der Seite bzw. der Downloads
// geschieht nichts (kein Abruf).

const (
	// EnvAgentURL: andere Quelle(n) der Agent-Dateien, durch Komma getrennt - fuer Tests, wie NODE64_UPDATE_URL beim
	// Selbst-Update (dann ist auch http erlaubt). Geprueft wird mit den Schluesseln der Selbst-Updates
	// (selfupdate.PublicKeys; fuer Tests beim Bauen per -ldflags ergaenzbar).
	EnvAgentURL = "NODE64_MONITOR64_AGENT_URL"

	agentBase         = "https://ipv64.net/node64/agent" // Standard-Quelle (Ordner "node64" wie die Selbst-Updates)
	agentBaseFallback = "https://node64.de/agent"        // Ausweichquelle

	agentIndexEvery   = 6 * time.Hour    // Verzeichnis so oft neu holen
	agentIndexRetry   = 30 * time.Minute // nach einem Fehlschlag
	agentRefreshWait  = 20 * time.Second // ein Download wartet hoechstens so lange auf das Verzeichnis ...
	agentServeWait    = 35 * time.Second // ... und danach so lange auf das Nachladen der Datei (zusammen unter dem Zeitlimit der Antwort)
	agentMaxDownloads = 8                // gleichzeitige Downloads von Programmen durch Hosts
	agentEventKind    = "agent_update"   // Ereignis im Verlauf des Hosts ("Agent 0.3 -> 0.4")
	agentEventsShown  = 20
)

// agentRT ist der Laufzeitstand der Agent-Verteilung.
type agentRT struct {
	once  sync.Once
	dist  *agentdist.Store
	slots chan struct{} // gleichzeitige Updates (agentMaxUpdates)
	serve chan struct{} // gleichzeitige Downloads

	// nur Tests (vor dem ersten Gebrauch setzen): andere Quelle und Schluessel
	bases []string
	keys  func() []ed25519.PublicKey

	mu     sync.Mutex
	life   context.Context        // laeuft, solange das Modul laeuft (nil = gestoppt)
	hosts  map[string]*agentState // je Zugang (UID), gespeichert in hosts.json
	events time.Time              // alte Ereignisse zuletzt aufgeraeumt
}

// agentBases liefert die Quellen und ob http erlaubt ist (nur bei eigener Quelle aus der Umgebung).
func agentBases() ([]string, bool) {
	var out []string
	for _, b := range strings.Split(os.Getenv(EnvAgentURL), ",") {
		if b = strings.TrimRight(strings.TrimSpace(b), "/"); b != "" {
			out = append(out, b)
		}
	}
	if len(out) > 0 {
		return out, true
	}
	return []string{agentBase, agentBaseFallback}, false
}

// agents legt den Zwischenspeicher beim ersten Gebrauch an (liest ein abgelegtes Verzeichnis, ohne Netz).
func (m *Module) agents() *agentRT {
	ad := &m.ad
	ad.once.Do(func() {
		bases, insecure := agentBases()
		if ad.bases != nil {
			bases, insecure = ad.bases, true
		}
		dir := filepath.Join(m.dir(), "agent")
		ad.dist = agentdist.New(agentdist.Options{Dir: dir, Bases: bases, AllowHTTP: insecure, Keys: ad.keys, UserAgent: "node64/" + m.nodeVersion, Logger: m.log})
		ad.slots = make(chan struct{}, agentMaxUpdates)
		ad.serve = make(chan struct{}, agentMaxDownloads)
		ad.mu.Lock()
		ad.hosts = loadAgentStates(filepath.Join(dir, agentStateFile))
		ad.mu.Unlock()
	})
	return ad
}

// ---------------------------------------------------------------------------------------------------------
// Downloads fuer Hosts (ohne Anmeldung)

// agentUnavailable antwortet mit 503 als Text (curl -f bricht damit ab, statt eine Fehlerseite auszufuehren).
func agentUnavailable(w http.ResponseWriter, msg string) {
	w.Header().Set("Retry-After", "30")
	http.Error(w, "monitor64-agent: "+msg, http.StatusServiceUnavailable)
}

// serveAgentFile: GET /monitor64/agent/{file} - install.sh, install.ps1, SHA256SUMS und
// monitor64-agent-<os>-<arch>[.exe]. Ohne Anmeldung, weil Hosts die Dateien per curl bzw. irm holen; ausgeliefert
// wird nur, was im signierten Verzeichnis steht und geprueft ist (feste Namen, kein Pfad). So funktionieren
// "install.sh --base http(s)://<node>/monitor64/agent/" und "install.ps1 -Base ...".
func (m *Module) serveAgentFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if m.scheduler() == nil {
		agentUnavailable(w, "Monitor64 is not running on this node")
		return
	}
	ad := m.agents()
	if ad.dist.Due(agentIndexEvery, agentIndexRetry) { // erster Bedarf bzw. Stand aelter als 6 h: Verzeichnis holen
		rctx, cancel := context.WithTimeout(r.Context(), agentRefreshWait)
		if err := ad.dist.Refresh(rctx); err != nil {
			m.log.Warn("monitor64: agent index", "err", err) // ein gespeichertes Verzeichnis gilt weiter
		}
		cancel()
	}
	ctx, cancel := context.WithTimeout(r.Context(), agentServeWait)
	defer cancel()
	ix := ad.dist.Index()
	if ix == nil {
		agentUnavailable(w, "agent files are not available yet (the node could not load the signed index, see Monitor64 > Agent)")
		return
	}
	h := w.Header()
	h.Set("Cache-Control", "no-cache")
	if name == agentdist.SumsFile {
		h.Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(ix.Sums())
		return
	}
	f, program, ok := ix.Lookup(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !program {
		b, err := ad.dist.Script(ctx, name)
		if err != nil {
			m.log.Warn("monitor64: agent script", "file", name, "err", err)
			agentUnavailable(w, name+" could not be loaded by the node, try again later")
			return
		}
		h.Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(b)
		return
	}
	select {
	case ad.serve <- struct{}{}:
		defer func() { <-ad.serve }()
	default:
		agentUnavailable(w, "too many downloads at once, try again")
		return
	}
	path, _, err := ad.dist.Program(ctx, name)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) { // die Node laedt im Hintergrund weiter
			agentUnavailable(w, name+" is still being loaded by the node, try again in a minute")
			return
		}
		m.log.Warn("monitor64: agent file", "file", name, "err", err)
		agentUnavailable(w, name+" could not be loaded by the node, try again later")
		return
	}
	in, err := os.Open(path)
	if err != nil {
		agentUnavailable(w, name+" is not available")
		return
	}
	defer in.Close()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="`+f.Name+`"`)
	http.ServeContent(w, r, "", time.Time{}, in)
}

// ---------------------------------------------------------------------------------------------------------
// Seite und API "Agent"

// agentFileOut ist ein Programm der aktuellen Version (Download-Link von der Node).
type agentFileOut struct {
	agentdist.File
	Key    string `json:"key"`    // linux-amd64 ...
	Cached bool   `json:"cached"` // liegt geprueft auf der Node
}

// agentHostOut ist ein Host mit Agent-Zugang.
type agentHostOut struct {
	UID      string    `json:"uid"` // Host
	Name     string    `json:"name"`
	Access   string    `json:"access"` // Zugang
	Push     bool      `json:"push,omitempty"`
	Version  string    `json:"version,omitempty"`
	Platform string    `json:"platform,omitempty"` // linux-amd64 ...
	Auto     bool      `json:"auto"`
	State    string    `json:"state"`              // current, pending, unknown, nofile, elsewhere, off
	Busy     bool      `json:"busy,omitempty"`     // Update laeuft bzw. wartet auf einen freien Platz
	Error    string    `json:"error,omitempty"`    // Fehler des letzten Versuchs
	Tried    time.Time `json:"tried,omitzero"`     // letzter Versuch
	Next     time.Time `json:"next,omitzero"`      // naechster automatischer Versuch
	Node     string    `json:"node,omitempty"`     // elsewhere: zustaendige Node
	Latest   string    `json:"latest,omitempty"`   // verfuegbare Version
	Disabled bool      `json:"disabled,omitempty"` // Zugang ausgeschaltet
}

// agentEventOut ist ein Eintrag "Agent a -> b" mit dem Namen des Hosts.
type agentEventOut struct {
	eventRow
	Host string `json:"host"`
}

// agentCmdInfo: was das Skript fuer die Installationsbefehle braucht (Seite Agent und Assistent).
type agentCmdInfo struct {
	Internet string `json:"internet"`  // Ordner im Internet (mit Schraegstrich am Ende)
	HTTPPort int    `json:"http_port"` // HTTP-Port der Node (0 = aus), fuer den Hinweis bei eigenem Zertifikat
	Port     int    `json:"port"`      // Port des Agents
}

// agentView sind die Daten der Seite Agent.
type agentView struct {
	agentCmdInfo
	Running     bool             `json:"running"`
	Version     string           `json:"version,omitempty"`
	Date        string           `json:"date,omitempty"`
	Source      agentdist.Status `json:"source"`
	Due         bool             `json:"due"` // Verzeichnis sollte neu geholt werden (die Seite stoesst es an)
	Files       []agentFileOut   `json:"files"`
	Scripts     []agentdist.File `json:"scripts"`
	Hosts       []agentHostOut   `json:"hosts"`
	Events      []agentEventOut  `json:"events"`
	PublicKey   string           `json:"public_key,omitempty"`
	Fingerprint string           `json:"fingerprint,omitempty"`
}

// nodeHTTPPort: HTTP-Port der Oberflaeche (NODE64_HTTP_PORT, Standard 8080; 0 = aus).
func nodeHTTPPort() int {
	v := strings.TrimSpace(os.Getenv("NODE64_HTTP_PORT"))
	if v == "" {
		return 8080
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 65535 {
		return 0
	}
	return n
}

func (m *Module) agentCmdInfo() agentCmdInfo {
	bases, _ := agentBases()
	if m.ad.bases != nil {
		bases = m.ad.bases
	}
	return agentCmdInfo{Internet: bases[0] + "/", HTTPPort: nodeHTTPPort(), Port: m64proto.DefaultPort}
}

// agentAccesses: alle Agent-Zugaenge (auch ausgeschaltete).
func (m *Module) agentAccesses(ctx context.Context) ([]*Access, error) {
	all, err := m.store.Accesses(ctx, "")
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, a := range all {
		if a.Type == "agent" {
			out = append(out, a)
		}
	}
	return out, nil
}

// agentHostOf baut den Stand eines Agent-Zugangs fuer Oberflaeche und API.
func (m *Module) agentHostOf(h *Host, a *Access, ix *agentdist.Index) agentHostOut {
	var cfg accessConfig
	_ = json.Unmarshal(a.Config, &cfg)
	o := agentHostOut{UID: h.UID, Name: h.Name, Access: a.UID, Push: cfg.Mode == "push", Auto: h.AgentAutoUpd, State: "unknown", Disabled: !a.Enabled}
	if ix != nil {
		o.Latest = ix.Version
	}
	st, ok := m.agents().state(a.UID)
	if ok {
		o.Version, o.Busy, o.Error, o.Tried = st.Version, st.busy, st.Err, st.TryAt
		if st.OS != "" {
			o.Platform = agentdist.Key(st.OS, st.Arch)
		}
	}
	role, owner := m.roleOf(h)
	switch {
	case !a.Enabled:
		o.State = "off"
	case role == roleIdle:
		o.State, o.Node = "elsewhere", m.clusterSnapshot().name(owner)
	case o.Version == "" || ix == nil:
	case !update.Newer(ix.Version, o.Version):
		o.State = "current"
	default:
		o.State = "pending"
		if _, has := ix.Files[o.Platform]; !has {
			o.State = "nofile"
		} else if h.AgentAutoUpd && !o.Busy && st.TryVer == ix.Version && !st.TryAt.IsZero() {
			o.Next = st.TryAt.Add(agentRetryAfter)
		}
	}
	return o
}

// agentOfAccess: Stand des Agents fuer die Host-Seite (Hinweis am Zugang); nil = kein Agent-Zugang.
func (m *Module) agentOfAccess(h *Host, a *Access) *agentHostOut {
	if a == nil || a.Type != "agent" || m.scheduler() == nil {
		return nil
	}
	o := m.agentHostOf(h, a, m.agents().dist.Index())
	return &o
}

// agentView baut die Daten der Seite Agent (ohne Netz).
func (m *Module) agentView(ctx context.Context) agentView {
	v := agentView{agentCmdInfo: m.agentCmdInfo(), Running: m.scheduler() != nil, Files: []agentFileOut{}, Scripts: []agentdist.File{}, Hosts: []agentHostOut{},
		Events: []agentEventOut{}}
	if !v.Running {
		return v
	}
	ad := m.agents()
	ix := ad.dist.Index()
	v.Source, v.Due = ad.dist.Status(), ad.dist.Due(agentIndexEvery, agentIndexRetry)
	if ix != nil {
		v.Version, v.Date = ix.Version, ix.Date
		progs, scripts := ix.Names()
		for _, name := range progs {
			f, _, _ := ix.Lookup(name)
			v.Files = append(v.Files, agentFileOut{File: f, Key: agentdist.Key(f.OS, f.Arch), Cached: ad.dist.Cached(name)})
		}
		for _, name := range scripts {
			v.Scripts = append(v.Scripts, ix.Scripts[name])
		}
	}
	if signer, err := m.nodeSigner(ctx); err == nil {
		v.Fingerprint = transport.Fingerprint(signer.PublicKey())
		v.PublicKey, _ = m.PublicKeyLine(ctx)
	}
	names := map[string]string{}
	hosts, _ := m.store.Hosts(ctx)
	byUID := map[string]*Host{}
	for _, h := range hosts {
		byUID[h.UID], names[h.UID] = h, h.Name
	}
	accs, _ := m.agentAccesses(ctx)
	for _, a := range accs {
		if h := byUID[a.HostUID]; h != nil {
			v.Hosts = append(v.Hosts, m.agentHostOf(h, a, ix))
		}
	}
	sort.SliceStable(v.Hosts, func(i, j int) bool { return strings.ToLower(v.Hosts[i].Name) < strings.ToLower(v.Hosts[j].Name) })
	evs, err := m.store.queryEvents(ctx, `SELECT ts, kind, text, actor, host_uid, service_key, problem_uid FROM m64_events
		WHERE kind = ? AND problem_uid = '' ORDER BY ts DESC, id DESC LIMIT ?`, agentEventKind, agentEventsShown)
	if err == nil {
		for _, e := range evs {
			v.Events = append(v.Events, agentEventOut{eventRow: e, Host: names[e.HostUID]})
		}
	}
	return v
}

// pageAgent: Seite "Agent" - verfuegbare Version, Downloads, Installationsbefehle, Hosts mit ihrer Agent-Version.
func (m *Module) pageAgent(w http.ResponseWriter, r *http.Request) {
	d := m.basePage(r, "agent", "/monitor64/agent")
	v := m.agentView(r.Context())
	d.PublicKey = v.PublicKey
	d.JS["agent"] = v
	m.render(w, r, "agent", "monitor64.tab.agent", d)
}

// apiAgent: GET Stand der Agent-Verteilung.
func (m *Module) apiAgent(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.agentView(r.Context()))
}

// apiAgentRefresh: POST Verzeichnis jetzt neu holen ("jetzt pruefen"); der Fehler steht im Stand der Quelle.
func (m *Module) apiAgentRefresh(w http.ResponseWriter, r *http.Request) {
	if m.scheduler() == nil {
		m.fail(w, r, errNotRunning)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), agentRefreshWait+agentServeWait)
	defer cancel()
	if err := m.agents().dist.Refresh(ctx); err != nil {
		m.log.Warn("monitor64: agent index", "err", err)
	}
	writeJSON(w, http.StatusOK, m.agentView(r.Context()))
}

// agentAutoIn: automatische Updates eines Hosts ein- bzw. ausschalten (Seite Agent).
type agentAutoIn struct {
	Auto *bool `json:"autoupdate"`
}

// apiAgentAuto: PUT automatische Updates des Agents fuer einen Host.
func (m *Module) apiAgentAuto(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h, err := m.store.Host(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	var in agentAutoIn
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	if in.Auto == nil {
		m.fail(w, r, errBad("json", "error", "autoupdate missing"))
		return
	}
	if h.AgentAutoUpd != *in.Auto {
		h.AgentAutoUpd = *in.Auto
		if err := m.store.SaveHost(ctx, h, m.actor(r)); err != nil {
			m.fail(w, r, err)
			return
		}
		m.audit(r, "host.update", h.Name, "uid="+h.UID+" agent_autoupdate="+strconv.FormatBool(h.AgentAutoUpd))
		m.ReloadHost(ctx, h.UID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"uid": h.UID, "autoupdate": h.AgentAutoUpd})
}
