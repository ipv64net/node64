package monitor64

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64agent"
	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/monitor64/agentdist"
	"github.com/ipv64net/node64/internal/selfupdate"
)

// Kein Test des Pakets soll je die echten Quellen (ipv64.net, node64.de) ansprechen: ohne eigene Test-Quelle zeigt die
// Agent-Verteilung auf einen geschlossenen lokalen Port.
func init() { _ = os.Setenv(EnvAgentURL, "http://127.0.0.1:9/agent") }

// agentRel ist eine Test-Quelle der Agent-Dateien: Ordner im Aufbau der Ablage, signiert mit einem Test-Schluessel
// und per HTTP angeboten.
type agentRel struct {
	t    *testing.T
	root string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	srv  *httptest.Server
}

func newAgentRel(t *testing.T) *agentRel {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := &agentRel{t: t, root: t.TempDir(), pub: pub, priv: priv}
	r.srv = httptest.NewServer(http.FileServer(http.Dir(r.root)))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *agentRel) keys() []ed25519.PublicKey { return []ed25519.PublicKey{r.pub} }

// use haengt die Test-Quelle an ein Modul (vor dem ersten Gebrauch der Agent-Verteilung).
func (r *agentRel) use(m *Module) { m.ad.bases, m.ad.keys = []string{r.srv.URL}, r.keys }

// ownFile ist der Dateiname fuer die Plattform, auf der der Test laeuft (der Agent im Prozess nimmt nur die an).
func ownFile() string { return agentdist.FileName(runtime.GOOS, runtime.GOARCH) }

func (r *agentRel) bin(version, name string) []byte {
	return []byte("agent-binary " + name + " " + version)
}

// publish legt eine Version ab (eigene Plattform und linux/arm64, Skripte, Kopfzeilen, signiertes Verzeichnis).
func (r *agentRel) publish(version string) *agentdist.Index {
	r.t.Helper()
	dir := filepath.Join(r.root, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		r.t.Fatal(err)
	}
	files := map[string][]byte{"install.sh": []byte("#!/bin/sh\n# install " + version + "\n"), "install.ps1": []byte("# install " + version + "\n")}
	for _, name := range []string{ownFile(), agentdist.FileName("linux", "arm64"), agentdist.FileName("freebsd", "amd64")} {
		files[name] = r.bin(version, name)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
	ix, err := agentdist.Build(version, dir)
	if err != nil {
		r.t.Fatal(err)
	}
	for _, f := range ix.Files {
		h := m64proto.UpdateHeader{Version: version, OS: f.OS, Arch: f.Arch, Size: f.Size, SHA256: f.SHA256}
		h.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(r.priv, m64proto.SignedMessage(h.Version, h.OS, h.Arch, h.SHA256)))
		b, _ := json.Marshal(h)
		if err := os.WriteFile(filepath.Join(dir, f.Name+agentdist.HeaderSuffix), b, 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
	raw, _ := json.Marshal(ix)
	if err := os.WriteFile(filepath.Join(r.root, agentdist.IndexFile+".sig"), selfupdate.Sign(raw, r.priv), 0o644); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.root, agentdist.IndexFile), raw, 0o644); err != nil {
		r.t.Fatal(err)
	}
	return ix
}

// testAgent ist ein Monitor64-Agent im Prozess. Nach einem angenommenen Update startet er wie der echte neu - mit
// der neuen Version auf demselben Port (stay = die alte Version laeuft weiter, wie nach einem Rueckfall).
type testAgent struct {
	t       *testing.T
	exe     string
	cfg     m64agent.Config
	stay    bool
	mu      sync.Mutex
	srv     *m64agent.Server
	addr    string
	version string
}

func newTestAgent(t *testing.T, m *Module, version string, relKeys []ed25519.PublicKey, probe func(exe, version string) error) *testAgent {
	t.Helper()
	line, err := m.PublicKeyLine(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	if err := os.WriteFile(keys, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hk, err := m64agent.LoadOrCreateHostKey(filepath.Join(dir, "hostkey"))
	if err != nil {
		t.Fatal(err)
	}
	a := &testAgent{t: t, exe: filepath.Join(dir, "monitor64-agent")}
	if err := os.WriteFile(a.exe, []byte("agent "+version), 0o755); err != nil {
		t.Fatal(err)
	}
	a.cfg = m64agent.Config{HostKey: hk, KeysFile: keys, Collector: &fakeHost{fsUsed: 50}, ReleaseKeys: relKeys, ExePath: a.exe, Probe: probe}
	a.cfg.OnUpdated = func(v string) {
		if !a.stay {
			a.restart(v)
		}
	}
	if !a.start(version) {
		t.Fatal("agent does not start")
	}
	t.Cleanup(func() {
		a.mu.Lock()
		srv := a.srv
		a.mu.Unlock()
		_ = srv.Close()
	})
	return a
}

func (a *testAgent) start(version string) bool {
	cfg := a.cfg
	cfg.Version = version
	srv, err := m64agent.New(cfg)
	if err != nil {
		a.t.Error(err)
		return false
	}
	a.mu.Lock()
	addr := a.addr
	a.mu.Unlock()
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	var ln net.Listener
	for i := 0; ; i++ {
		if ln, err = net.Listen("tcp", addr); err == nil {
			break
		}
		if i > 100 {
			a.t.Error(err)
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
	a.mu.Lock()
	a.srv, a.addr, a.version = srv, ln.Addr().String(), version
	a.mu.Unlock()
	go func() { _ = srv.Serve(ln) }()
	return true
}

func (a *testAgent) restart(version string) {
	a.mu.Lock()
	old := a.srv
	a.mu.Unlock()
	_ = old.Close()
	a.start(version)
}

func (a *testAgent) port() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, port, _ := net.SplitHostPort(a.addr)
	return port
}

func (a *testAgent) file() string {
	b, _ := os.ReadFile(a.exe)
	return string(b)
}

// addUpdHost legt einen Host mit Agent-Zugang an und laesst die erste Runde laufen (Hostschluessel, Ansicht).
func addUpdHost(t *testing.T, m *Module, name string, a *testAgent, auto bool) (*Host, *Access, *hostRT) {
	t.Helper()
	ctx := context.Background()
	by := Actor{Kind: "user", Name: "dennis", Method: "local"}
	h := &Host{Name: name, Address: "127.0.0.1", Kind: "linux-agent", IntervalSec: 60, AgentAutoUpd: auto}
	if err := m.store.SaveHost(ctx, h, by); err != nil {
		t.Fatal(err)
	}
	acc := &Access{HostUID: h.UID, Type: "agent", Config: []byte(`{"port":` + a.port() + `}`), Enabled: true}
	if err := m.store.SaveAccess(ctx, acc, false, by); err != nil {
		t.Fatal(err)
	}
	m.ReloadHost(ctx, h.UID)
	rt := m.rtOf(h.UID)
	if rt == nil {
		t.Fatal("host not scheduled")
	}
	m.poll(ctx, rt)
	if v := rt.getView(); v == nil || len(v.Accesses) != 1 || !v.Accesses[0].OK {
		t.Fatalf("first round: %+v", v)
	}
	return h, acc, rt
}

func waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout: %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// fastAgentTimes kuerzt die Wartezeiten auf den Neustart des Agents.
func fastAgentTimes(t *testing.T) {
	t.Helper()
	w, p := agentRestartWait, agentRestartPoll
	agentRestartWait, agentRestartPoll = 5*time.Second, 20*time.Millisecond
	t.Cleanup(func() { agentRestartWait, agentRestartPoll = w, p })
}

func agentEvents(t *testing.T, m *Module, host string) []eventRow {
	t.Helper()
	evs, err := m.store.queryEvents(context.Background(), `SELECT ts, kind, text, actor, host_uid, service_key, problem_uid FROM m64_events WHERE kind = ? AND host_uid = ? ORDER BY id`, agentEventKind, host)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func agentStateOf(m *Module, acc string) agentState {
	st, _ := m.agents().state(acc)
	return st
}

// Automatisches Update: neue Version im Verzeichnis -> die Node merkt die Version des Agents ("info"), schiebt die
// signierte Datei, der Agent startet neu, im Verlauf steht "Agent 0.3.0 -> 0.4.0" (System). Danach geschieht nichts mehr.
func TestAgentAutoUpdate(t *testing.T) {
	fastAgentTimes(t)
	ctx := context.Background()
	rel := newAgentRel(t)
	rel.publish("0.4.0")
	m, _, _ := newTestModule(t)
	rel.use(m)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	a := newTestAgent(t, m, "0.3.0", rel.keys(), nil)
	h, acc, _ := addUpdHost(t, m, "auto01", a, true)

	if m.agents().dist.Index() != nil {
		t.Fatal("index loaded before it was needed")
	}
	m.agentRound(ctx)
	waitFor(t, "update to 0.4.0", func() bool {
		st := agentStateOf(m, acc.UID)
		return st.Version == "0.4.0" && !st.busy && st.Pending == nil
	})
	st := agentStateOf(m, acc.UID)
	if st.Err != "" || st.OS != runtime.GOOS || st.Arch != runtime.GOARCH || st.TryVer != "0.4.0" {
		t.Fatalf("state: %+v", st)
	}
	if got := a.file(); got != string(rel.bin("0.4.0", ownFile())) {
		t.Fatalf("agent file: %q", got)
	}
	evs := agentEvents(t, m, h.UID)
	if len(evs) != 1 || evs[0].Actor.Kind != "system" || !strings.Contains(evs[0].Text, "monitor64.detail.agent_updated") || !strings.Contains(evs[0].Text, "from=0.3.0") || !strings.Contains(evs[0].Text, "to=0.4.0") {
		t.Fatalf("events: %+v", evs)
	}
	// Stand ueberlebt den Neustart der Node (Datei), die Ansicht zeigt "aktuell" und das Ereignis
	if saved := loadAgentStates(filepath.Join(m.dir(), "agent", agentStateFile)); saved[acc.UID] == nil || saved[acc.UID].Version != "0.4.0" || saved[acc.UID].Host != h.UID {
		t.Fatalf("saved state: %+v", saved[acc.UID])
	}
	v := m.agentView(ctx)
	if v.Version != "0.4.0" || len(v.Hosts) != 1 || v.Hosts[0].State != "current" || v.Hosts[0].Version != "0.4.0" || !v.Hosts[0].Auto || len(v.Events) != 1 || v.Events[0].Host != "auto01" {
		t.Fatalf("view: %+v", v)
	}
	hd, err := m.hostDetail(ctx, h.UID)
	if err != nil || len(hd.Accesses) != 1 || hd.Accesses[0].Agent == nil || hd.Accesses[0].Agent.Version != "0.4.0" || hd.Accesses[0].Agent.State != "current" {
		t.Fatalf("host detail: %v %+v", err, hd.Accesses)
	}
	// weiterer Durchgang: nichts zu tun (kein zweites Ereignis), Runden laufen weiter
	m.agentRound(ctx)
	m.poll(ctx, m.rtOf(h.UID))
	time.Sleep(100 * time.Millisecond)
	if n := len(agentEvents(t, m, h.UID)); n != 1 {
		t.Fatalf("events after a second round: %d", n)
	}
	if v := m.rtOf(h.UID).getView(); v == nil || !v.Accesses[0].OK {
		t.Fatalf("round after the update: %+v", v)
	}
	// neue Version erscheint: beim naechsten Abruf des Verzeichnisses geht es weiter
	rel.publish("0.5.0")
	if err := m.agents().dist.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	m.agentRound(ctx)
	waitFor(t, "update to 0.5.0", func() bool { st := agentStateOf(m, acc.UID); return st.Version == "0.5.0" && !st.busy })
	if n := len(agentEvents(t, m, h.UID)); n != 2 {
		t.Fatalf("events: %d", n)
	}
	if _, err := os.Stat(filepath.Join(m.dir(), "agent", "0.4.0")); !os.IsNotExist(err) {
		t.Fatal("old version still stored")
	}
}

// Automatik aus: kein Update, die Seite zeigt "steht aus"; "jetzt aktualisieren" (API) schiebt es mit dem Akteur.
func TestAgentManualUpdate(t *testing.T) {
	fastAgentTimes(t)
	ctx := context.Background()
	rel := newAgentRel(t)
	rel.publish("0.4.0")
	e := newEnvWith(t, rel.use)
	m := e.m
	a := newTestAgent(t, m, "0.3.0", rel.keys(), nil)
	h, acc, _ := addUpdHost(t, m, "manual01", a, false)

	m.agentRound(ctx)
	waitFor(t, "info", func() bool { return agentStateOf(m, acc.UID).Version == "0.3.0" })
	time.Sleep(100 * time.Millisecond)
	if st := agentStateOf(m, acc.UID); st.busy || !st.TryAt.IsZero() || a.file() != "agent 0.3.0" {
		t.Fatalf("updated although automatic updates are off: %+v", st)
	}
	var view agentView
	decodeBody(t, e.do("GET", "/api/monitor64/agent", nil).Body.Bytes(), &view)
	if len(view.Hosts) != 1 || view.Hosts[0].State != "pending" || view.Hosts[0].Auto || view.Hosts[0].Latest != "0.4.0" || view.Hosts[0].Platform != agentdist.Key(runtime.GOOS, runtime.GOARCH) {
		t.Fatalf("view: %+v", view.Hosts)
	}
	rec := e.do("POST", "/api/monitor64/hosts/"+h.UID+"/agent/update", nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("update now: %d %s", rec.Code, rec.Body)
	}
	waitFor(t, "manual update", func() bool { st := agentStateOf(m, acc.UID); return st.Version == "0.4.0" && !st.busy })
	evs := agentEvents(t, m, h.UID)
	if len(evs) != 1 || evs[0].Actor.Kind != "user" || evs[0].Actor.Name != "dennis" {
		t.Fatalf("events: %+v", evs)
	}
	if !e.audited("monitor64.agent.update|manual01|") {
		t.Fatalf("audit: %v", e.audits)
	}
	// schon aktuell: klare Antwort statt eines weiteren Versuchs
	if rec := e.do("POST", "/api/monitor64/hosts/"+h.UID+"/agent/update", nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "agent_current") {
		t.Fatalf("second update: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/api/monitor64/hosts/nope/agent/update", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host: %d", rec.Code)
	}
	// Automatik je Host umschalten (Seite Agent)
	if rec := e.do("PUT", "/api/monitor64/hosts/"+h.UID+"/agent", map[string]any{"autoupdate": true}); rec.Code != http.StatusOK {
		t.Fatalf("auto on: %d %s", rec.Code, rec.Body)
	}
	if got, _ := m.store.Host(ctx, h.UID); !got.AgentAutoUpd || !m.rtOf(h.UID).host.AgentAutoUpd {
		t.Fatal("automatic updates not switched on")
	}
	if rec := e.do("PUT", "/api/monitor64/hosts/"+h.UID+"/agent", map[string]any{}); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body: %d", rec.Code)
	}
	// Host ohne Agent-Zugang
	h2 := &Host{Name: "ssh01", Address: "192.0.2.9", Kind: "ssh", IntervalSec: 60}
	if err := m.store.SaveHost(ctx, h2, Actor{Kind: "user", Name: "dennis"}); err != nil {
		t.Fatal(err)
	}
	m.ReloadHost(ctx, h2.UID)
	if rec := e.do("POST", "/api/monitor64/hosts/"+h2.UID+"/agent/update", nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "agent_none") {
		t.Fatalf("host without agent: %d %s", rec.Code, rec.Body)
	}
}

// Der Agent lehnt eine Datei ab, die nicht mit seinem Release-Schluessel signiert ist: Hinweis am Zugang, alte Datei
// bleibt, neuer Versuch erst nach agentRetryAfter. Ein Downgrade lehnt er ebenso ab.
func TestAgentUpdateRefused(t *testing.T) {
	fastAgentTimes(t)
	ctx := context.Background()
	rel := newAgentRel(t)
	rel.publish("0.4.0")
	m, _, _ := newTestModule(t)
	rel.use(m)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	other, _, _ := ed25519.GenerateKey(rand.Reader) // der Agent vertraut einem anderen Schluessel
	a := newTestAgent(t, m, "0.3.0", []ed25519.PublicKey{other}, nil)
	h, acc, rt := addUpdHost(t, m, "refuse01", a, true)

	m.agentRound(ctx)
	waitFor(t, "refused update", func() bool { st := agentStateOf(m, acc.UID); return st.Err != "" && !st.busy })
	st := agentStateOf(m, acc.UID)
	if !strings.Contains(st.Err, "signature does not match a release key") || st.Version != "0.3.0" || st.TryVer != "0.4.0" || st.TryAt.IsZero() || st.Pending != nil {
		t.Fatalf("state: %+v", st)
	}
	if a.file() != "agent 0.3.0" || len(agentEvents(t, m, h.UID)) != 0 {
		t.Fatal("refused update changed the agent or wrote an event")
	}
	// kein neuer Versuch vor Ablauf der Wartezeit
	tried := st.TryAt
	m.agentRound(ctx)
	time.Sleep(150 * time.Millisecond)
	if st := agentStateOf(m, acc.UID); !st.TryAt.Equal(tried) || st.busy {
		t.Fatalf("retried too early: %+v", st)
	}
	// Hinweis am Zugang (Host-Seite) und auf der Seite Agent, mit Zeitpunkt des naechsten Versuchs
	hd, err := m.hostDetail(ctx, h.UID)
	if err != nil || hd.Accesses[0].Agent == nil || !strings.Contains(hd.Accesses[0].Agent.Error, "signature") || hd.Accesses[0].Agent.State != "pending" {
		t.Fatalf("host detail: %v %+v", err, hd.Accesses[0].Agent)
	}
	if v := m.agentView(ctx); len(v.Hosts) != 1 || v.Hosts[0].Error == "" || !v.Hosts[0].Next.Equal(tried.Add(agentRetryAfter)) {
		t.Fatalf("view: %+v", v.Hosts)
	}
	// nach der Wartezeit versucht es die Node erneut
	m.agentSet(acc.UID, h.UID, func(s *agentState) bool { s.TryAt = time.Now().Add(-agentRetryAfter - time.Minute); return false })
	m.agentRound(ctx)
	waitFor(t, "second attempt", func() bool { st := agentStateOf(m, acc.UID); return st.TryAt.After(tried) && !st.busy })

	// Downgrade: der Agent laeuft schon mit 0.9.0 - die Node bietet 0.4.0 nicht an, und der Agent nimmt sie nicht
	b := newTestAgent(t, m, "0.9.0", rel.keys(), nil)
	h2, acc2, rt2 := addUpdHost(t, m, "newer01", b, true)
	m.agentRound(ctx)
	waitFor(t, "info of the newer agent", func() bool { return agentStateOf(m, acc2.UID).Version == "0.9.0" })
	time.Sleep(100 * time.Millisecond)
	if st := agentStateOf(m, acc2.UID); st.busy || !st.TryAt.IsZero() || st.Err != "" {
		t.Fatalf("downgrade attempted: %+v", st)
	}
	if v := m.agentHostOf(h2, acc2, m.agents().dist.Index()); v.State != "current" {
		t.Fatalf("state of the newer agent: %+v", v)
	}
	path, hdr, err := m.agents().dist.Program(ctx, ownFile())
	if err != nil {
		t.Fatal(err)
	}
	rt2.mu.Lock()
	c, err := rt2.agentCol(acc2.UID).ref.agent(rt2.agentCol(acc2.UID).cfg)
	rt2.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	in, _ := os.Open(path)
	_, err = c.Update(ctx, hdr, in)
	_ = in.Close()
	if err == nil || !strings.Contains(err.Error(), "not newer") || b.file() != "agent 0.9.0" {
		t.Fatalf("downgrade: %v, file %q", err, b.file())
	}
	_ = rt
}

// Die neue Version meldet sich nicht (Rueckfall des Agents auf die alte Datei): nach agentConfirmWait steht der
// Fehler am Zugang, kein Ereignis.
func TestAgentUpdateFallback(t *testing.T) {
	fastAgentTimes(t)
	agentRestartWait = 200 * time.Millisecond
	ctx := context.Background()
	rel := newAgentRel(t)
	rel.publish("0.4.0")
	m, _, _ := newTestModule(t)
	rel.use(m)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	a := newTestAgent(t, m, "0.3.0", rel.keys(), nil)
	a.stay = true // die alte Version laeuft weiter
	h, acc, _ := addUpdHost(t, m, "fallback01", a, true)

	m.agentRound(ctx)
	waitFor(t, "pending update", func() bool { st := agentStateOf(m, acc.UID); return st.Pending != nil && !st.busy })
	if st := agentStateOf(m, acc.UID); st.Pending.From != "0.3.0" || st.Pending.To != "0.4.0" || st.Err != "" {
		t.Fatalf("pending: %+v", st.Pending)
	}
	m.agentRound(ctx) // noch innerhalb der Wartezeit: weiter warten, kein zweiter Versuch
	if st := agentStateOf(m, acc.UID); st.Pending == nil || st.busy {
		t.Fatalf("state: %+v", st)
	}
	m.agentSet(acc.UID, h.UID, func(s *agentState) bool { s.Pending.At = time.Now().Add(-agentConfirmWait - time.Second); return false })
	m.agentRound(ctx)
	st := agentStateOf(m, acc.UID)
	if st.Pending != nil || !strings.Contains(st.Err, "monitor64.agent.err_fallback") || st.Version != "0.3.0" || st.busy {
		t.Fatalf("state after the fallback: %+v", st)
	}
	if len(agentEvents(t, m, h.UID)) != 0 {
		t.Fatal("event without an update")
	}
}

// Hoechstens agentMaxUpdates Hosts gleichzeitig: vier Agents brauchen ein Update, zwei laufen, zwei warten auf den
// naechsten Durchgang.
func TestAgentUpdateLimit(t *testing.T) {
	fastAgentTimes(t)
	ctx := context.Background()
	rel := newAgentRel(t)
	rel.publish("0.4.0")
	m, _, _ := newTestModule(t)
	rel.use(m)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	var running, peak atomic.Int32
	release := make(chan struct{})
	probe := func(string, string) error { // der Agent prueft die neue Datei: hier haelt der Test das Update an
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		running.Add(-1)
		return nil
	}
	var accs []*Access
	for i := range 4 {
		a := newTestAgent(t, m, "0.3.0", rel.keys(), probe)
		_, acc, _ := addUpdHost(t, m, "limit0"+strconv.Itoa(i), a, true)
		accs = append(accs, acc)
	}
	busy := func() int {
		n := 0
		for _, a := range accs {
			if agentStateOf(m, a.UID).busy {
				n++
			}
		}
		return n
	}
	m.agentRound(ctx)
	waitFor(t, "two updates running", func() bool { return running.Load() == agentMaxUpdates })
	m.agentRound(ctx) // weiterer Durchgang, solange beide Plaetze belegt sind: es bleibt bei zweien
	time.Sleep(200 * time.Millisecond)
	if busy() != agentMaxUpdates || running.Load() != agentMaxUpdates || peak.Load() != agentMaxUpdates {
		t.Fatalf("busy %d running %d peak %d", busy(), running.Load(), peak.Load())
	}
	close(release)
	updated := func() int {
		n := 0
		for _, a := range accs {
			if st := agentStateOf(m, a.UID); st.Version == "0.4.0" && !st.busy {
				n++
			}
		}
		return n
	}
	waitFor(t, "first two updated", func() bool { return updated() == agentMaxUpdates && busy() == 0 })
	m.agentRound(ctx)
	waitFor(t, "all updated", func() bool { return updated() == 4 })
	if peak.Load() != agentMaxUpdates {
		t.Fatalf("peak %d", peak.Load())
	}
}

// Download-Routen fuer Hosts: ohne Anmeldung, nur feste Namen aus dem signierten Verzeichnis, kein Pfad.
func TestAgentDownloadRoutes(t *testing.T) {
	ctx := context.Background()
	rel := newAgentRel(t)
	ix := rel.publish("0.4.0")
	m, _, _ := newTestModule(t)
	rel.use(m)
	mux := http.NewServeMux()
	pass := func(h http.Handler) http.Handler { return h }
	deny := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	}
	m.Routes(mux, module.Guards{Enabled: pass, Auth: deny}) // Anmeldung schlaegt immer fehl: nur oeffentliche Routen antworten
	get := func(path string, hdr ...string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	// Modul laeuft nicht: nichts ausliefern, nichts laden
	if rec := get("/monitor64/agent/install.sh"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("not running: %d", rec.Code)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })

	rec := get("/monitor64/agent/install.sh")
	if rec.Code != 200 || rec.Body.String() != "#!/bin/sh\n# install 0.4.0\n" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("install.sh: %d %q", rec.Code, rec.Body)
	}
	if rec := get("/monitor64/agent/install.ps1"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "install 0.4.0") {
		t.Fatalf("install.ps1: %d", rec.Code)
	}
	rec = get("/monitor64/agent/SHA256SUMS")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), ix.Files[agentdist.Key(runtime.GOOS, runtime.GOARCH)].SHA256+"  "+ownFile()+"\n") || strings.Count(rec.Body.String(), "\n") != 3 {
		t.Fatalf("SHA256SUMS: %d %q", rec.Code, rec.Body)
	}
	if m.agents().dist.Cached(ownFile()) {
		t.Fatal("program loaded before it was requested")
	}
	rec = get("/monitor64/agent/" + ownFile())
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), rel.bin("0.4.0", ownFile())) || rec.Header().Get("Content-Type") != "application/octet-stream" ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), ownFile()) {
		t.Fatalf("program: %d %q %v", rec.Code, rec.Body, rec.Header())
	}
	if !m.agents().dist.Cached(ownFile()) {
		t.Fatal("program not stored")
	}
	if rec := get("/monitor64/agent/"+ownFile(), "Range", "bytes=0-4"); rec.Code != http.StatusPartialContent || rec.Body.String() != "agent" {
		t.Fatalf("range: %d %q", rec.Code, rec.Body)
	}
	// nichts ausser den Dateien des Verzeichnisses: kein Pfad, keine Ablage, keine Kopfzeilen, keine fremden Namen
	for _, p := range []string{"/monitor64/agent/hosts.json", "/monitor64/agent/agents.json", "/monitor64/agent/agents.json.sig", "/monitor64/agent/0.4.0",
		"/monitor64/agent/" + ownFile() + ".update.json", "/monitor64/agent/monitor64-agent-plan9-amd64", "/monitor64/agent/install.sh%00", "/monitor64/agent/INSTALL.SH",
		"/monitor64/agent/0.4.0/" + ownFile(), "/monitor64/agent/a/b/c", "/monitor64/agent/..%5chosts.json", "/monitor64/agent/0.4.0%2F" + ownFile()} {
		if rec := get(p); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d %q", p, rec.Code, rec.Body)
		}
	}
	// ".." im Pfad: der ServeMux leitet auf den bereinigten Pfad um bzw. die Datei steht nicht im Verzeichnis - nie Inhalt
	for _, p := range []string{"/monitor64/agent/..%2Fhosts.json", "/monitor64/agent/..%2F..%2Fnode64.db", "/monitor64/agent/%2e%2e%2fmonitor64.db", "/monitor64/agent/../agent/hosts.json"} {
		if rec := get(p); rec.Code < 300 || rec.Body.Len() > 200 {
			t.Errorf("%s: %d %q", p, rec.Code, rec.Body)
		}
	}
	// Seite und API bleiben hinter der Anmeldung
	for _, p := range []string{"/monitor64/agent", "/api/monitor64/agent"} {
		if rec := get(p); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without login: %d", p, rec.Code)
		}
	}
	// nur lesen
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		req := httptest.NewRequest(method, "/monitor64/agent/install.sh", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d", method, rec.Code)
		}
	}
}

// Quelle nicht erreichbar bzw. falsch signiert: die Node liefert nichts aus und nennt den Fehler auf der Seite.
func TestAgentSourceErrors(t *testing.T) {
	ctx := context.Background()
	rel := newAgentRel(t)
	rel.publish("0.4.0")
	e := newEnvWith(t, func(m *Module) {
		rel.use(m)
		other, _, _ := ed25519.GenerateKey(rand.Reader)
		m.ad.keys = func() []ed25519.PublicKey { return []ed25519.PublicKey{other} } // die Node vertraut einem anderen Schluessel
	})
	if rec := e.do("GET", "/monitor64/agent/install.sh", nil); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "monitor64-agent:") {
		t.Fatalf("wrong signature: %d %q", rec.Code, rec.Body)
	}
	if rec := e.do("GET", "/monitor64/agent/"+ownFile(), nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("program with a wrong signature: %d", rec.Code)
	}
	var v agentView
	decodeBody(t, e.do("POST", "/api/monitor64/agent/refresh", nil).Body.Bytes(), &v)
	if v.Version != "" || !strings.Contains(v.Source.Error, "signature") || len(v.Files) != 0 || v.Source.Checked.IsZero() {
		t.Fatalf("view: %+v", v)
	}
	if ents, _ := os.ReadDir(filepath.Join(e.m.dir(), "agent")); len(ents) != 0 {
		t.Fatalf("files stored although the signature is wrong: %v", ents)
	}
	_ = ctx
}

// Seite Agent und ihre Daten; der Assistent bekommt dieselbe Quelle fuer den Installationsbefehl.
func TestAgentPage(t *testing.T) {
	rel := newAgentRel(t)
	rel.publish("0.4.0")
	e := newEnvWith(t, rel.use)
	ctx := context.Background()
	by := Actor{Kind: "user", Name: "dennis"}
	h := &Host{Name: "srv<1>", Address: "192.0.2.30", Kind: "linux-agent", IntervalSec: 60, AgentAutoUpd: true}
	if err := e.m.store.SaveHost(ctx, h, by); err != nil {
		t.Fatal(err)
	}
	if err := e.m.store.SaveAccess(ctx, &Access{HostUID: h.UID, Type: "agent", Config: json.RawMessage(`{"mode":"push","token":"abcdefghijklmnop1234"}`), Enabled: true}, false, by); err != nil {
		t.Fatal(err)
	}
	e.m.ReloadHost(ctx, h.UID)

	rec := e.do("GET", "/monitor64/agent", nil)
	if rec.Code != 200 {
		t.Fatalf("page: %d", rec.Code)
	}
	body := rec.Body.String()
	mustContain(t, "agent", body, `href="/monitor64/agent"><i class="bi bi-download"></i>`, `nav-link active" href="/monitor64/agent"`, `data-m64-page="agent"`, `id="m64-ag-os"`, `id="m64-ag-cmd"`,
		`id="m64-ag-src"`, `id="m64-ag-source"`, `id="m64-ag-files"`, `id="m64-ag-hosts"`, `id="m64-ag-events"`, `id="m64-ag-refresh"`, `id="m64-ag-pubkey">ssh-ed25519 `, `id="m64-data"`,
		`"internet":"`+rel.srv.URL+`/"`, `"due":true`, `"public_key":"ssh-ed25519 `, `"fingerprint":"SHA256:`, `"push":true`, `"state":"unknown"`, "monitor64.agent.intro")
	if strings.Contains(body, "abcdefghijklmnop1234") {
		t.Fatal("page leaks the push token")
	}
	if strings.Contains(body, "srv<1>") || !strings.Contains(body, "003c1") { // Name des Hosts nur escaped in den Startdaten
		t.Fatal("host name not escaped")
	}
	// "jetzt pruefen" holt das Verzeichnis
	var v agentView
	decodeBody(t, e.do("POST", "/api/monitor64/agent/refresh", nil).Body.Bytes(), &v)
	if v.Version != "0.4.0" || v.Due || v.Source.Error != "" || v.Source.Source != rel.srv.URL || len(v.Files) != 3 || len(v.Scripts) != 2 || v.Port != m64proto.DefaultPort || !v.Running {
		t.Fatalf("view: %+v", v)
	}
	for _, f := range v.Files {
		if f.Cached || f.Name != agentdist.FileName(f.OS, f.Arch) || f.Key != agentdist.Key(f.OS, f.Arch) || len(f.SHA256) != 64 {
			t.Errorf("file: %+v", f)
		}
	}
	// der Assistent kennt die Quelle (Befehl mit --base) und der Reiter steht auf jeder Seite
	nw := e.do("GET", "/monitor64/new", nil).Body.String()
	mustContain(t, "new", nw, `"agent":{"internet":"`+rel.srv.URL+`/"`, `href="/monitor64/agent"`)
	js := string(bundleJS)
	mustContain(t, "script", js, "function agentCmd(", "'install.sh | sudo sh -s --'", "--base ", "-Base \"", "agent: pageAgent", "agentSrcHTML(src)", "/agent/update'")
	if strings.Contains(js, "https://node64.de/agent/install") {
		t.Error("script still has a fixed install address")
	}
}
