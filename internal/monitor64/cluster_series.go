package monitor64

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/tsdb"
)

// Anfragen zwischen den Nodes (peer: POST /peer/v2/call/monitor64/<name>):
//   - series: Verlauf eines Hosts live abfragen (der Verlauf wird nicht kopiert). Das Diagramm fragt die Nodes, die
//     den Host im Zeitraum ueberwacht haben koennen (zustaendig, bevorzugt, Ersatz, Uebernahmen im Zeitraum), und setzt
//     die Stuecke zusammen; bei Ueberschneidung gelten die Daten der bevorzugten Node. Ist eine davon offline, bleibt
//     dort eine Luecke mit Hinweis ("Daten auf node01 (nicht erreichbar)").
//   - repoll: Anstoss (Trap an eine nicht zustaendige Node): die zustaendige fragt den Host sofort ab.
//   - reach: Zugaenge eines Hosts von dieser Node aus testen ("von node02 auch erreichbar") fuer die Wahl der
//     Ersatz-Nodes.
//   - smart: alle zuletzt gelesenen SMART-Werte einer Platte (liegen nur im Speicher der zustaendigen Node).
//   - sparks: Mini-Verlaeufe (24 Std.) fuer Uebersicht und Host-Seite einer anderen Node, gebuendelt je Node
//     (cluster_sparks.go).

const (
	callSeries = "series"
	callRepoll = "repoll"
	callReach  = "reach"

	seriesCallLimit = 15 * time.Second
	maxSeriesKeys   = 16
	reachParallel   = 8 // Zugaenge eines Hosts, die eine Node zugleich testet
)

// reachLimit: hoechstens so lange dauert "von allen Nodes testen" (eigene Pruefung und Anfragen nebeneinander, je
// Zugang testTimeout); deutlich unter dem Schreib-Zeitlimit des Webservers (60 s).
var reachLimit = testTimeout + 10*time.Second

// reachTest testet einen Zugang (Variable fuer Tests).
var reachTest = func(m *Module, ctx context.Context, h *Host, a Access) testResult { return m.testAccess(ctx, h, a) }

type seriesReq struct {
	Host   string   `json:"host"`
	Keys   []string `json:"keys"` // "dienst|messgroesse"
	From   int64    `json:"from"`
	To     int64    `json:"to"`
	Points int      `json:"points"`
}

type seriesResp struct {
	Series []tsdb.Series `json:"series"`
}

type hostReq struct {
	Host string `json:"host"`
}

// reachResult ist der Test eines Zugangs von einer Node aus.
type reachResult struct {
	Access string `json:"access"`
	Type   string `json:"type"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Ms     int64  `json:"ms"`
	Skip   bool   `json:"skip,omitempty"` // Push-Betrieb: nur die eigene Node des Agents
}

// HandleClusterCall beantwortet eine Anfrage einer anderen Node.
func (m *Module) HandleClusterCall(ctx context.Context, from, name string, body []byte) (any, error) {
	if m.scheduler() == nil {
		return nil, errNotRunning
	}
	switch name {
	case callSeries:
		var in seriesReq
		if err := json.Unmarshal(body, &in); err != nil || !reUID.MatchString(in.Host) || len(in.Keys) == 0 || len(in.Keys) > maxSeriesKeys ||
			in.To <= in.From || in.Points <= 0 || in.Points > 700 {
			return nil, errBad("series")
		}
		hs := m.history()
		if hs == nil {
			return nil, errNotRunning
		}
		keys := make([]string, len(in.Keys))
		for i, k := range in.Keys {
			svc, metric, ok := strings.Cut(k, "|")
			if !ok || svc == "" || metric == "" || len(k) > 512 {
				return nil, errBad("series")
			}
			keys[i] = seriesKey(in.Host, svc, metric)
		}
		res, err := hs.QueryMulti(ctx, keys, time.Unix(in.From, 0), time.Unix(in.To, 0), in.Points)
		if err != nil {
			return nil, err
		}
		return seriesResp{Series: res}, nil
	case callRepoll:
		var in hostReq
		if err := json.Unmarshal(body, &in); err != nil || !reUID.MatchString(in.Host) {
			return nil, errBad("host")
		}
		if h, err := m.store.Host(ctx, in.Host); err == nil {
			if role, _ := m.roleOf(h); role != roleIdle {
				if s := m.scheduler(); s != nil {
					s.RunNow("host:" + in.Host)
				}
			}
		}
		return map[string]bool{"ok": true}, nil
	case callTrap: // Trap an eine nicht zustaendige Node (traps_cluster.go)
		return m.handleTrapCall(ctx, from, body)
	case callSmart: // alle SMART-Werte einer Platte fuer den Dialog einer anderen Node (smartdetail.go)
		return m.handleSmartCall(body)
	case callSparks: // Mini-Verlaeufe fuer die Uebersicht einer anderen Node (cluster_sparks.go)
		return m.handleSparksCall(ctx, body)
	case callReach:
		var in hostReq
		if err := json.Unmarshal(body, &in); err != nil || !reUID.MatchString(in.Host) {
			return nil, errBad("host")
		}
		cctx, cancel := context.WithTimeout(ctx, testTimeout+2*time.Second) // Antwort vor dem Zeitlimit der fragenden Node
		defer cancel()
		return m.reachHere(cctx, in.Host)
	}
	return nil, errBad("call")
}

// reachHere testet die Zugaenge eines Hosts von dieser Node aus (nebeneinander, je Zugang testTimeout).
func (m *Module) reachHere(ctx context.Context, hostUID string) ([]reachResult, error) {
	h, err := m.store.Host(ctx, hostUID)
	if err != nil {
		return nil, err
	}
	accs, err := m.store.Accesses(ctx, hostUID)
	if err != nil {
		return nil, err
	}
	out := []reachResult{}
	var todo []int
	var rows []*Access
	for _, a := range accs {
		if !a.Enabled {
			continue
		}
		r := reachResult{Access: a.UID, Type: a.Type}
		var cfg accessConfig
		_ = json.Unmarshal(a.Config, &cfg)
		r.Skip = a.Type == "agent" && cfg.Mode == "push"
		if !r.Skip {
			todo, rows = append(todo, len(out)), append(rows, a)
		}
		out = append(out, r)
	}
	sem := make(chan struct{}, reachParallel)
	var wg sync.WaitGroup
	for k, i := range todo {
		a := rows[k]
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				out[i].Error = ctx.Err().Error()
				return
			}
			defer func() { <-sem }()
			res := reachTest(m, ctx, h, *a)
			out[i].OK, out[i].Error, out[i].Ms = res.OK, res.Error, res.Ms
		})
	}
	wg.Wait()
	return out, nil
}

// forwardRepoll: Anstoss fuer einen Host, den eine andere Node ueberwacht (true = weitergereicht bzw. erledigt).
func (m *Module) forwardRepoll(uid string) bool {
	if m.hooks().Call == nil {
		return false
	}
	m.rtMu.Lock()
	rt := m.rts[uid]
	m.rtMu.Unlock()
	if rt == nil {
		return false
	}
	role, owner := m.roleOf(rt.host)
	if role != roleIdle {
		return false
	}
	if s := m.clusterSnapshot(); !s.online(owner) {
		return true // zustaendige Node nicht erreichbar: die naechste Runde dort faengt es auf
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := m.hooks().Call(ctx, owner, callRepoll, hostReq{Host: uid}, nil); err != nil {
			m.log.Debug("monitor64: forward trigger", "host", rt.host.Name, "err", err)
		}
	}()
	return true
}

// seriesSource ist eine Node mit Daten fuer ein Diagramm.
type seriesSource struct {
	Node    string `json:"node"`
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Missing bool   `json:"missing,omitempty"` // nicht erreichbar: Luecke mit Hinweis
}

// clusterSeriesNodes: Nodes, die den Host im Zeitraum ueberwacht haben koennen (ohne diese Node), bevorzugte zuerst.
func (m *Module) clusterSeriesNodes(ctx context.Context, h *Host, from, to time.Time) []string {
	s := m.clusterSnapshot()
	if !s.Active {
		return nil
	}
	nodes := candidatesOf(h, s.Self)
	if o := ownerOf(h, s.Self); !slices.Contains(nodes, o) {
		nodes = append(nodes, o)
	}
	for _, e := range m.eventsWhere(ctx, `host_uid = ? AND problem_uid = '' AND kind IN ('takeover', 'handover') AND ts >= ? AND ts <= ?`,
		h.UID, ts(from.Add(-30*24*time.Hour)), ts(to)) {
		if !slices.Contains(nodes, e.Node) {
			nodes = append(nodes, e.Node)
		}
	}
	return slices.DeleteFunc(nodes, func(n string) bool { return n == "" || n == s.Self })
}

// clusterSeries ergaenzt den lokalen Verlauf um die Stuecke der anderen Nodes.
func (m *Module) clusterSeries(ctx context.Context, h *Host, ss []string, local []tsdb.Series, from, to time.Time, pts int) ([]tsdb.Series, []seriesSource) {
	nodes := m.clusterSeriesNodes(ctx, h, from, to)
	if len(nodes) == 0 || m.hooks().Call == nil {
		return local, nil
	}
	s := m.clusterSnapshot()
	pref := preferredOf(h, s.Self)
	type got struct {
		node string
		res  []tsdb.Series
		ok   bool
	}
	results := make([]got, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		results[i].node = n
		if !s.online(n) {
			continue
		}
		wg.Go(func() {
			cctx, cancel := context.WithTimeout(ctx, seriesCallLimit)
			defer cancel()
			var out seriesResp
			err := m.hooks().Call(cctx, n, callSeries, seriesReq{Host: h.UID, Keys: ss, From: from.Unix(), To: to.Unix(), Points: pts}, &out)
			if err == nil && len(out.Series) == len(ss) {
				results[i].res, results[i].ok = out.Series, true
			}
		})
	}
	wg.Wait()
	var sources []seriesSource
	type part struct {
		node string
		ser  []tsdb.Series
	}
	parts := []part{{node: s.Self, ser: local}}
	for _, r := range results {
		sources = append(sources, seriesSource{Node: r.node, Name: s.name(r.node), OK: r.ok, Missing: !r.ok})
		if r.ok {
			parts = append(parts, part{node: r.node, ser: r.res})
		}
	}
	// bevorzugte Node zuerst: ihre Punkte gelten bei Ueberschneidung
	sort.SliceStable(parts, func(i, j int) bool { return parts[i].node == pref && parts[j].node != pref })
	out := make([]tsdb.Series, len(local))
	for k := range local {
		lists := make([][]tsdb.Point, 0, len(parts))
		base := local[k]
		for _, p := range parts {
			if k < len(p.ser) {
				lists = append(lists, p.ser[k].Points)
				if base.Res == "" && p.ser[k].Res != "" {
					base.Res, base.Step = p.ser[k].Res, p.ser[k].Step
				}
			}
		}
		base.Points = mergePoints(lists, base.Step)
		out[k] = base
	}
	return out, sources
}

// mergePoints legt Punktlisten zusammen: eine spaetere Liste fuellt nur Stellen, an denen keine fruehere Liste einen
// Punkt hat (Abstand kleiner als ein halber Schritt, mindestens 30 s).
func mergePoints(lists [][]tsdb.Point, step int64) []tsdb.Point {
	tol := step / 2
	if tol < 30 {
		tol = 30
	}
	var out []tsdb.Point
	for i, l := range lists {
		if i == 0 {
			out = append(out, l...)
			continue
		}
		sort.Slice(out, func(a, b int) bool { return out[a].T < out[b].T })
		have := out
		for _, p := range l {
			j := sort.Search(len(have), func(x int) bool { return have[x].T >= p.T-tol })
			if j < len(have) && have[j].T <= p.T+tol {
				continue
			}
			out = append(out, p)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].T < out[b].T })
	if out == nil {
		out = []tsdb.Point{}
	}
	return out
}
