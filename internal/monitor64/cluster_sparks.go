package monitor64

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Mini-Verlaeufe (Sparks) im Cluster: der Verlauf liegt nur bei der Node, die den Host ueberwacht. Fuer Hosts einer
// anderen Node fragt die Uebersicht bzw. die Host-Seite deshalb live bei der zustaendigen Node (Anfrage "sparks") -
// gebuendelt (eine Anfrage je Node, nicht je Host), mit kurzem Zeitlimit und fuer sparksCacheFor gemerkt. Ist die Node
// nicht erreichbar oder kennt die Anfrage nicht (aeltere Version), bleiben die Mini-Verlaeufe leer (kein Fehler).

const (
	callSparks     = "sparks"
	sparkPoints    = 48
	sparkRange     = 24 * time.Hour
	maxSparkItems  = 2000 // Reihen je Anfrage (mehr: weitere Anfragen an dieselbe Node)
	maxSparkChunks = 5    // hoechstens so viele Anfragen je Node und Abruf
)

var (
	sparksCallLimit = 4 * time.Second  // die Seite wartet nicht laenger auf eine andere Node
	sparksCacheFor  = 60 * time.Second // so lange gilt die Antwort einer Node (auch "nicht erreichbar")
)

// sparkItem ist eine Reihe eines Mini-Verlaufs (ID: Schluessel in der Antwort der API, geht nicht an die andere Node).
type sparkItem struct {
	ID     string `json:"-"`
	Host   string `json:"h"`
	Svc    string `json:"s"`
	Metric string `json:"m"`
}

type sparksReq struct {
	Items []sparkItem `json:"items"`
}

// sparksResp: Werte je Reihe in der Reihenfolge der Anfrage (Mittelwerte, 24 Std., 48 Punkte).
type sparksResp struct {
	Sparks [][]float64 `json:"sparks"`
}

// sparkCache ist die gemerkte Antwort einer Node fuer einen Abruf (Uebersicht bzw. ein Host).
type sparkCache struct {
	at   time.Time
	sig  string // gefragte Reihen (andere Reihen: neu fragen)
	vals [][]float64
}

// sparkValues liest die Mini-Verlaeufe aus dem eigenen Verlauf.
func sparkValues(ctx context.Context, hs historyStore, items []sparkItem, now time.Time) ([][]float64, error) {
	keys := make([]string, len(items))
	for i, it := range items {
		keys[i] = seriesKey(it.Host, it.Svc, it.Metric)
	}
	res, err := hs.QueryMulti(ctx, keys, now.Add(-sparkRange), now, sparkPoints)
	if err != nil {
		return nil, err
	}
	out := make([][]float64, len(items))
	for i := range out {
		out[i] = []float64{}
		if i < len(res) {
			for _, p := range res[i].Points {
				out[i] = append(out[i], p.Avg)
			}
		}
	}
	return out, nil
}

// handleSparksCall beantwortet die Anfrage "sparks" einer anderen Node (Werte auf vier Stellen gekuerzt: die Antwort
// bleibt klein, fuer die Mini-Verlaeufe reicht es).
func (m *Module) handleSparksCall(ctx context.Context, body []byte) (any, error) {
	var in sparksReq
	if err := json.Unmarshal(body, &in); err != nil || len(in.Items) == 0 || len(in.Items) > maxSparkItems {
		return nil, errBad("sparks")
	}
	for _, it := range in.Items {
		if !reUID.MatchString(it.Host) || it.Svc == "" || it.Metric == "" || len(it.Svc)+len(it.Metric) > 512 {
			return nil, errBad("sparks")
		}
	}
	hs := m.history()
	if hs == nil {
		return nil, errNotRunning
	}
	vals, err := sparkValues(ctx, hs, in.Items, time.Now())
	if err != nil {
		return nil, err
	}
	for _, l := range vals {
		for i, v := range l {
			if r, err := strconv.ParseFloat(strconv.FormatFloat(v, 'g', 4, 64), 64); err == nil {
				l[i] = r
			}
		}
	}
	return sparksResp{Sparks: vals}, nil
}

// sparkNode: andere Node, die den Host ueberwacht ("" = diese Node bzw. ohne Cluster).
func (m *Module) sparkNode(host string) string {
	if m.hooks().Call == nil {
		return ""
	}
	m.rtMu.Lock()
	rt := m.rts[host]
	m.rtMu.Unlock()
	if rt == nil {
		return ""
	}
	if role, owner := m.roleOf(rt.host); role == roleIdle && owner != "" && owner != m.clusterSelf() {
		return owner
	}
	return ""
}

// sparks liefert die Mini-Verlaeufe je ID: eigene Hosts aus dem Verlauf hier, Hosts anderer Nodes von der zustaendigen
// Node (scope: Abruf fuer den Zwischenspeicher, "" = Uebersicht, sonst der Host).
func (m *Module) sparks(ctx context.Context, scope string, items []sparkItem) (map[string][]float64, error) {
	out := map[string][]float64{}
	var local []sparkItem
	remote := map[string][]sparkItem{}
	nodes := map[string]string{} // Host -> Node
	for _, it := range items {
		node, ok := nodes[it.Host]
		if !ok {
			node = m.sparkNode(it.Host)
			nodes[it.Host] = node
		}
		if node == "" {
			local = append(local, it)
		} else {
			remote[node] = append(remote[node], it)
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for node, list := range remote {
		wg.Go(func() {
			vals := m.remoteSparks(ctx, node, scope, list)
			mu.Lock()
			defer mu.Unlock()
			for i, it := range list {
				if i < len(vals) && len(vals[i]) > 0 {
					out[it.ID] = vals[i]
				}
			}
		})
	}
	var err error
	if hs := m.history(); hs != nil && len(local) > 0 {
		var vals [][]float64
		if vals, err = sparkValues(ctx, hs, local, time.Now()); err == nil {
			mu.Lock()
			for i, it := range local {
				out[it.ID] = vals[i]
			}
			mu.Unlock()
		}
	}
	wg.Wait()
	return out, err
}

// remoteSparks fragt die Mini-Verlaeufe bei einer anderen Node (nil = nicht erreichbar bzw. Anfrage gescheitert). Die
// Antwort gilt sparksCacheFor, auch die leere: eine Node, die nicht antwortet, haelt die Seite nur einmal auf.
func (m *Module) remoteSparks(ctx context.Context, node, scope string, items []sparkItem) [][]float64 {
	var sb strings.Builder
	for _, it := range items {
		sb.WriteString(seriesKey(it.Host, it.Svc, it.Metric))
		sb.WriteByte('\n')
	}
	sig, key, now := sb.String(), node+"|"+scope, m.cl.clock()
	m.cl.mu.Lock()
	c := m.cl.sparks[key]
	m.cl.mu.Unlock()
	if c != nil && c.sig == sig && now.Sub(c.at) < sparksCacheFor && !now.Before(c.at) {
		return c.vals
	}
	var vals [][]float64
	if m.clusterSnapshot().online(node) {
		cctx, cancel := context.WithTimeout(ctx, sparksCallLimit)
		defer cancel()
		for i := 0; i < len(items) && i < maxSparkItems*maxSparkChunks; i += maxSparkItems {
			part := items[i:min(i+maxSparkItems, len(items))]
			var res sparksResp
			if err := m.hooks().Call(cctx, node, callSparks, sparksReq{Items: part}, &res); err != nil || len(res.Sparks) != len(part) {
				m.log.Debug("monitor64: sparks of another node", "node", node, "err", err)
				vals = nil
				break
			}
			vals = append(vals, res.Sparks...)
		}
	}
	m.cl.mu.Lock()
	if m.cl.sparks == nil {
		m.cl.sparks = map[string]*sparkCache{}
	}
	for k, old := range m.cl.sparks { // abgelaufene Antworten vergessen (Abrufe je Host sammeln sich sonst)
		if now.Sub(old.at) >= sparksCacheFor || now.Before(old.at) {
			delete(m.cl.sparks, k)
		}
	}
	m.cl.sparks[key] = &sparkCache{at: now, sig: sig, vals: vals}
	m.cl.mu.Unlock()
	return vals
}
