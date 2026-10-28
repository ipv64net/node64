package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/ipv64net/node64/internal/hub/store"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/wire"
)

const (
	pingEvery  = 30 * time.Second
	writeWait  = 15 * time.Second
	maxMsgSize = 1 << 20
	// maxConfigChunk: Obergrenze je config-Nachricht. Unter 1 MB, damit auch Nodes mit altem Leselimit (1 MB)
	// grosse Accounts bekommen; ein einzelner Eintrag darueber geht allein in eine Nachricht.
	maxConfigChunk = 768 << 10
)

// conn ist eine Node-Verbindung.
type conn struct {
	g       *Gateway
	ws      *websocket.Conn
	node    *store.Node
	ctx     context.Context
	cancel  context.CancelFunc
	sendQ   chan wire.Msg
	mu      sync.Mutex
	lastRev int64 // unter mu: Leser, Worker und fanoutLoop greifen zu
	closed  bool
	pendMu  sync.Mutex     // deliverPending (hello und fanoutLoop)
	sentCmd map[int64]bool // auf dieser Verbindung zugestellte, noch offene Kommandos (unter pendMu)
	nextID  int64
	work    chan wire.Msg // Nachrichten mit DB-Arbeit (Messpunkte usw.), eigener Worker je Verbindung
	testing atomic.Bool   // laeuft gerade ein Kanal-Test dieser Node
}

func (c *conn) send(m wire.Msg) {
	select {
	case c.sendQ <- m:
	default:
		c.g.log.Warn("send queue full, closing", "node", c.node.ID)
		c.close(websocket.StatusPolicyViolation, "slow consumer")
	}
}

// rev liefert den Konfigurationsstand, den die Node ueber diese Verbindung hat.
func (c *conn) rev() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastRev
}

// bumpRev hebt den Stand an (nie zurueck) und liefert den neuen Stand.
func (c *conn) bumpRev(r int64) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r > c.lastRev {
		c.lastRev = r
	}
	return c.lastRev
}

func (c *conn) close(code websocket.StatusCode, reason string) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	_ = c.ws.Close(code, reason)
	c.cancel()
}

// ws nimmt eine Node-Verbindung an.
func (g *Gateway) ws(w http.ResponseWriter, r *http.Request) {
	n := nodeOf(r)
	if g.Connections() >= g.maxConns {
		w.Header().Set("Retry-After", "30")
		writeErr(w, http.StatusServiceUnavailable, "hub full")
		return
	}
	if !g.limiter.allow("ws:"+n.ID, 10, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "too many connections")
		return
	}
	var since int64
	if v := r.URL.Query().Get("since"); v != "" {
		_, _ = fmtSscan(v, &since)
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	ws.SetReadLimit(maxMsgSize)
	ctx, cancel := context.WithCancel(g.ctx)
	c := &conn{g: g, ws: ws, node: n, ctx: ctx, cancel: cancel, sendQ: make(chan wire.Msg, 256), lastRev: since}
	g.add(c)
	defer g.remove(c)
	_ = g.st.NodeSeen(ctx, n.ID, n.Token.ID)
	g.log.Info("node connected", "node", n.Name, "user", n.UserID, "ip", g.clientIP(r), "since", since)

	c.work = make(chan wire.Msg, 64)
	go c.writer()
	go c.pinger()
	go c.worker()
	c.hello(ctx)
	c.reader()
}

func (c *conn) hello(ctx context.Context) {
	g := c.g
	n := c.node
	acc, _ := g.st.Account(ctx, n.UserID)
	eps, _ := g.st.Endpoints(ctx)
	rev := g.st.CurrentRevision(ctx, n.UserID)
	c.send(wire.Msg{T: "hello", Data: raw(wire.Hello{ServerTime: time.Now().UTC(), Revision: rev, Account: acc, RemoteMgmt: n.RemoteMgmt, NodeName: n.Name, Location: n.Location, Endpoints: eps, Hub: g.location,
		Features: []string{"proxy", wire.NotifyDirect}})})
	// Aenderungen seit dem Stand der Node
	changes, gap, err := g.st.ConfigSince(ctx, n.UserID, n.ID, c.rev())
	if err != nil {
		g.log.Error("config since failed", "node", n.ID, "err", err)
		return
	}
	if gap {
		c.send(wire.Msg{T: "revision_gap"})
		return
	}
	// immer eine config schicken (auch leer): die Node wartet darauf, bevor sie ihre Outbox abspielt
	c.sendConfig(changes, rev)
	c.deliverPending(ctx)
	// aktueller Stand der Checks, die die Node nicht selbst misst
	if items, err := g.st.RemoteStatesOf(ctx, n.UserID); err == nil {
		c.sendRemote(items)
	}
}

// sendConfig schickt Aenderungen in Teilen unter maxConfigChunk (die Node wendet jede config-Nachricht
// fuer sich an). Teile vor dem letzten tragen "more" und den hoechsten Stand ihres Teils.
func (c *conn) sendConfig(changes []wire.Change, rev int64) {
	parts := chunkChanges(changes, maxConfigChunk)
	for i, part := range parts {
		var top int64
		for _, ch := range part {
			top = max(top, ch.Revision)
		}
		if i < len(parts)-1 {
			c.bumpRev(top)
			c.send(wire.Msg{T: "config", Data: raw(map[string]any{"revision": top, "changes": part, "more": true})})
			continue
		}
		c.send(wire.Msg{T: "config", Data: raw(map[string]any{"revision": c.bumpRev(max(top, rev)), "changes": part})})
	}
}

// chunkChanges teilt Aenderungen nach ihrer JSON-Groesse; liefert immer mindestens einen Teil.
func chunkChanges(changes []wire.Change, limit int) [][]wire.Change {
	var out [][]wire.Change
	start, size := 0, 0
	for i, ch := range changes {
		n := len(ch.Data) + 256
		if b, err := json.Marshal(ch); err == nil {
			n = len(b) + 1
		}
		if i > start && size+n > limit {
			out = append(out, changes[start:i])
			start, size = i, 0
		}
		size += n
	}
	return append(out, changes[start:])
}

// deliverPending schickt offene Kommandos und Sendeauftraege. Kommandos merkt sich jede Verbindung
// selbst: nach dem Neuverbinden kommt alles Offene erneut, erledigte fallen aus der Liste.
func (c *conn) deliverPending(ctx context.Context) {
	c.pendMu.Lock()
	defer c.pendMu.Unlock()
	if cmds, err := c.g.st.PendingCommands(ctx, c.node.ID); err == nil {
		open := make(map[int64]bool, len(cmds))
		for _, cmd := range cmds {
			if !c.sentCmd[cmd.ID] {
				c.send(wire.Msg{T: "command", Data: raw(cmd)})
			}
			open[cmd.ID] = true
		}
		c.sentCmd = open
	}
	orders, _ := c.g.st.PendingSendOrders(ctx, c.node.ID)
	for _, o := range orders {
		c.send(wire.Msg{T: "send_order", Data: raw(o)})
	}
}

func (c *conn) writer() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case m := <-c.sendQ:
			b, err := json.Marshal(m)
			if err != nil {
				continue
			}
			wctx, cancel := context.WithTimeout(c.ctx, writeWait)
			err = c.ws.Write(wctx, websocket.MessageText, b)
			cancel()
			if err != nil {
				c.close(websocket.StatusAbnormalClosure, "write failed")
				return
			}
		}
	}
}

func (c *conn) pinger() {
	t := time.NewTicker(pingEvery)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(c.ctx, 20*time.Second)
			err := c.ws.Ping(pctx)
			cancel()
			if err != nil {
				c.g.log.Info("node ping failed", "node", c.node.Name, "err", err)
				c.close(websocket.StatusAbnormalClosure, "ping timeout")
				return
			}
			c.g.markSeen(c.node.ID)
		}
	}
}

func (c *conn) reader() {
	for {
		_, data, err := c.ws.Read(c.ctx)
		if err != nil {
			status := websocket.CloseStatus(err)
			if status == -1 && !errors.Is(err, context.Canceled) {
				c.g.log.Info("node read ended", "node", c.node.Name, "err", err)
			}
			c.close(websocket.StatusNormalClosure, "")
			return
		}
		var m wire.Msg
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		switch m.T {
		case "measurements", "events", "states", "deliveries", "status", "push", "proxies", "proxy_data":
			// DB-lastig: im Worker, damit der Leser weiter liest (Pongs!) und eine langsame DB keine Verbindungen trennt
			select {
			case c.work <- m:
			case <-c.ctx.Done():
				return
			}
		case "channel_test":
			// Versand ueber Mail/SMS-Bruecke kann dauern: weder Leser noch Worker blockieren
			go c.handle(m)
		default:
			c.handle(m)
		}
	}
}

// worker arbeitet DB-lastige Nachrichten der Verbindung der Reihe nach ab.
func (c *conn) worker() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case m := <-c.work:
			c.handle(m)
		}
	}
}

func (c *conn) ack(id int64, a any) {
	c.send(wire.Msg{T: "ack", ID: id, Data: raw(a)})
}

func (c *conn) handle(m wire.Msg) {
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()
	g := c.g
	n := c.node
	switch m.T {
	case "pong":
		g.markSeen(n.ID)
	case "measurements":
		var in struct {
			Batch []wire.Measurement `json:"batch"`
		}
		if err := json.Unmarshal(m.Data, &in); err != nil || len(in.Batch) > 500 {
			c.ack(m.ID, wire.Ack{Error: "invalid batch (max 500)"})
			return
		}
		ack, err := g.st.IngestMeasurements(ctx, n, in.Batch)
		if err != nil {
			g.log.Error("node data failed", "node", n.ID, "type", m.T, "err", err) // sonst nur "database error" bei der Node
			c.ack(m.ID, wire.Ack{Error: "database error"})
			return
		}
		c.ack(m.ID, ack)
	case "states":
		var in struct {
			Items []wire.State `json:"items"`
		}
		if err := json.Unmarshal(m.Data, &in); err != nil {
			c.ack(m.ID, wire.Ack{Error: "invalid states"})
			return
		}
		if err := g.st.IngestStates(ctx, n, in.Items); err != nil {
			g.log.Error("node data failed", "node", n.ID, "type", m.T, "err", err) // sonst nur "database error" bei der Node
			c.ack(m.ID, wire.Ack{Error: "database error"})
			return
		}
		c.ack(m.ID, wire.Ack{})
	case "proxies":
		// weiterreichende Node meldet die nicht verknuepften Mitglieder ihrer lokalen Gruppe (proxy.go)
		var in struct {
			Items []wire.ProxyNode `json:"items"`
		}
		if err := json.Unmarshal(m.Data, &in); err != nil || len(in.Items) > store.MaxProxies {
			c.ack(m.ID, wire.Ack{Error: "invalid proxies"})
			return
		}
		acks, err := g.st.RegisterProxies(ctx, n, in.Items)
		if err != nil {
			g.log.Error("register proxies failed", "node", n.ID, "err", err)
			c.ack(m.ID, wire.Ack{Error: "database error"})
			return
		}
		c.ack(m.ID, map[string]any{"acks": acks})
	case "proxy_data":
		// Zustaende und Messpunkte einer Stellvertreter-Node, ueber die weiterreichende Node
		var in wire.ProxyData
		if err := json.Unmarshal(m.Data, &in); err != nil || len(in.Batch) > 500 {
			c.ack(m.ID, wire.Ack{Error: "invalid batch (max 500)"})
			return
		}
		p, err := g.st.ProxyOf(ctx, n, in.Node)
		if err != nil {
			g.log.Error("node data failed", "node", n.ID, "type", m.T, "err", err) // sonst nur "database error" bei der Node
			c.ack(m.ID, wire.Ack{Error: "database error"})
			return
		}
		if p == nil {
			c.ack(m.ID, wire.Ack{Error: "not a proxy of this node"})
			return
		}
		if err := g.st.IngestStates(ctx, p, in.States); err != nil {
			g.log.Error("node data failed", "node", n.ID, "type", m.T, "err", err) // sonst nur "database error" bei der Node
			c.ack(m.ID, wire.Ack{Error: "database error"})
			return
		}
		ack, err := g.st.IngestMeasurements(ctx, p, in.Batch)
		if err != nil {
			g.log.Error("node data failed", "node", n.ID, "type", m.T, "err", err) // sonst nur "database error" bei der Node
			c.ack(m.ID, wire.Ack{Error: "database error"})
			return
		}
		c.ack(m.ID, ack)
	case "events":
		var in struct {
			Batch []wire.Event `json:"batch"`
		}
		if err := json.Unmarshal(m.Data, &in); err != nil || len(in.Batch) > 500 {
			c.ack(m.ID, wire.Ack{Error: "invalid batch"})
			return
		}
		ack, err := g.st.IngestEvents(ctx, n, in.Batch)
		if err != nil {
			g.log.Error("node data failed", "node", n.ID, "type", m.T, "err", err) // sonst nur "database error" bei der Node
			c.ack(m.ID, wire.Ack{Error: "database error"})
			return
		}
		c.ack(m.ID, ack)
	case "deliveries":
		var in struct {
			Batch []wire.Delivery `json:"batch"`
		}
		if err := json.Unmarshal(m.Data, &in); err == nil {
			_ = g.st.IngestDeliveries(ctx, n, in.Batch)
		}
		c.ack(m.ID, wire.Ack{})
	case "push":
		// Push, den die Node lokal empfangen hat: Messpunkt am hub, Weitergabe an die anderen messenden Nodes
		var in struct {
			Token string `json:"token"`
			Down  bool   `json:"down"`
			Msg   string `json:"msg"`
			From  string `json:"from"`
			Time  string `json:"time"`
		}
		if json.Unmarshal(m.Data, &in) == nil && in.Token != "" && g.limiter.allow("push:"+in.Token, 60, time.Minute) {
			if t, err := time.Parse(time.RFC3339Nano, in.Time); err == nil && time.Since(t) > 2*time.Minute {
				break // lag zu lange in der Warteschlange der Node: wuerde einen Ausfall verdecken
			}
			if _, err := g.st.PushInFrom(ctx, in.Token, in.Down, in.Msg, "node "+n.Name+" ("+in.From+")", n.ID, n.UserID); err != nil {
				g.log.Warn("push from node failed", "node", n.ID, "err", err)
			}
		}
	case "channel_test":
		// Test eines Kanals, den nur ipv64 zustellen kann (Mail, SMS, App), angefordert von der Node
		var in struct {
			ChannelID int64  `json:"channel_id"`
			Lang      string `json:"lang"`
		}
		res := map[string]any{"ok": false}
		if !c.testing.CompareAndSwap(false, true) {
			c.ack(m.ID, map[string]any{"ok": false, "test_error": "another test is still running"})
			return
		}
		defer c.testing.Store(false)
		if json.Unmarshal(m.Data, &in) == nil && in.ChannelID > 0 {
			var ch *notify.Channel
			if list, err := g.nf.ChannelsFor(ctx, n.UserID); err == nil {
				for _, x := range list {
					if x.ID == in.ChannelID {
						ch = x
					}
				}
			}
			if ch == nil {
				res["test_error"] = "channel not found"
			} else {
				errText, _, _ := g.sendChannelTest(ctx, ch, n.UserID, "test", "", in.Lang)
				res["ok"], res["test_error"] = errText == "", errText
			}
		}
		c.ack(m.ID, res) // Fehler des Tests nicht als "error": der Versandweg zum hub ist in Ordnung
	case "propose":
		var p wire.Propose
		if err := json.Unmarshal(m.Data, &p); err != nil {
			c.ack(m.ID, wire.ProposeResult{Error: "invalid propose"})
			return
		}
		res, err := g.st.Propose(ctx, n.UserID, n.ID, p, "node")
		if err != nil {
			g.log.Error("propose failed", "node", n.ID, "err", err)
			c.ack(m.ID, wire.ProposeResult{Error: "database error"})
			return
		}
		if res.Conflict {
			c.send(wire.Msg{T: "conflict", ID: m.ID, Data: raw(res)})
			return
		}
		c.bumpRev(res.Revision)
		c.ack(m.ID, res)
	case "run_check":
		// "Jetzt pruefen" an einer Node: die anderen messenden Nodes beauftragen
		var in struct {
			Token string `json:"token"`
		}
		if json.Unmarshal(m.Data, &in) == nil && in.Token != "" && g.limiter.allow("run:"+in.Token, 10, time.Minute) {
			if err := g.st.RunCheckOn(ctx, n.UserID, in.Token, n.ID); err != nil {
				g.log.Warn("run check failed", "node", n.ID, "err", err)
			}
		}
	case "settings":
		// Ruhezeiten/Grenzen an einer Node geaendert: gelten fuer den Account (Portal und alle Nodes)
		var in map[string]string
		if json.Unmarshal(m.Data, &in) != nil {
			c.ack(m.ID, map[string]any{"ok": false, "error": "invalid settings"})
			return
		}
		clean := map[string]string{}
		for _, k := range notify.SyncedSettings {
			if v, ok := in[k]; ok {
				nv, err := notify.NormalizeSetting(k, v)
				if err != nil {
					c.ack(m.ID, map[string]any{"ok": false, "error": err.Error()})
					return
				}
				clean[k] = nv
			}
		}
		rev, err := g.st.SetAccountSettings(ctx, n.UserID, clean)
		if err != nil {
			g.log.Error("settings from node failed", "node", n.ID, "err", err)
			c.ack(m.ID, map[string]any{"ok": false, "error": "database error"})
			return
		}
		c.bumpRev(rev)
		c.ack(m.ID, map[string]any{"ok": true})
	case "node_info":
		// Name/Standort an der Node geaendert: Portal und andere Nodes (ueber config "node") sehen es sofort
		var in struct {
			Name     string `json:"name"`
			Location string `json:"location"`
		}
		if json.Unmarshal(m.Data, &in) != nil || strings.TrimSpace(in.Name) == "" {
			c.ack(m.ID, map[string]any{"ok": false, "error": "name required"})
			return
		}
		rev, err := g.st.RenameNode(ctx, n.UserID, n.ID, strings.TrimSpace(in.Name), strings.TrimSpace(in.Location))
		if err != nil {
			g.log.Error("node rename failed", "node", n.ID, "err", err)
			c.ack(m.ID, map[string]any{"ok": false, "error": "database error"})
			return
		}
		c.bumpRev(rev)
		c.ack(m.ID, map[string]any{"ok": true})
	case "status":
		var st wire.Status
		if err := json.Unmarshal(m.Data, &st); err == nil {
			_ = g.st.NodeStatus(ctx, n.ID, st)
		}
	case "order_done":
		var r struct {
			ID    int64  `json:"id"`
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(m.Data, &r); err == nil {
			_ = g.st.SendOrderDone(ctx, n.ID, r.ID, r.OK, r.Error)
		}
	case "command_result":
		var r wire.CommandResult
		if err := json.Unmarshal(m.Data, &r); err == nil {
			_ = g.st.CommandDone(ctx, n.ID, r)
		}
	case "notify":
		c.handleNotify(ctx, m)
	case "ack":
		// Bestaetigungen fuer config u. ae.: nichts zu tun
	default:
		g.log.Debug("unknown message", "t", m.T, "node", n.ID)
	}
}

// handleNotify: die Node bittet um Versand ueber einen ipv64-Kanal (ipv64_mail/ipv64_sms).
func (c *conn) handleNotify(ctx context.Context, m wire.Msg) {
	var in struct {
		ChannelID int64            `json:"channel_id"`
		Kind      string           `json:"kind"`
		Title     string           `json:"title"`
		Text      string           `json:"text"`
		URL       string           `json:"url"`
		EventID   string           `json:"event_id"`
		Check     notify.CheckInfo `json:"check"`
	}
	if err := json.Unmarshal(m.Data, &in); err != nil {
		c.ack(m.ID, wire.Ack{Error: "invalid notify"})
		return
	}
	chans, err := c.g.nf.ChannelsFor(ctx, c.node.UserID)
	if err != nil {
		c.g.log.Error("channels for node failed", "node", c.node.ID, "err", err)
		c.ack(m.ID, wire.Ack{Error: "database error"})
		return
	}
	var ch *notify.Channel
	for _, x := range chans {
		if x.ID == in.ChannelID && (x.Type == notify.TypeIPv64Mail || x.Type == notify.TypeIPv64SMS) {
			ch = x
		}
	}
	if ch == nil || !ch.Enabled {
		c.ack(m.ID, wire.Ack{Error: "channel not available"})
		return
	}
	snd, ok := c.g.senders[ch.Type]
	if !ok {
		c.ack(m.ID, wire.Ack{Error: "no sender"})
		return
	}
	in.Check.UserID = c.node.UserID
	msg := notify.Message{Kind: notify.Kind(in.Kind), Title: in.Title, Text: in.Text, URL: in.URL, Time: time.Now(), Check: in.Check, EventID: in.EventID, Language: ch.Lang}
	err = snd.Send(ctx, ch, msg)
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	_ = c.g.nf.AddDelivery(ctx, notify.Delivery{EventID: in.EventID, ChannelID: ch.ID, Channel: ch.Name, Kind: in.Kind, CheckToken: in.Check.Token, Subject: in.Title, OK: err == nil, Error: errText})
	_ = c.g.nf.Touch(ctx, ch.ID, errText)
	c.ack(m.ID, wire.Ack{Error: errText})
}

// ---------------------------------------------------------------- Registry und Schleifen

func (g *Gateway) add(c *conn) {
	g.mu.Lock()
	if old, ok := g.conns[c.node.ID]; ok && old != c {
		old.close(websocket.StatusPolicyViolation, "replaced by new connection")
	}
	g.conns[c.node.ID] = c
	if g.byUser[c.node.UserID] == nil {
		g.byUser[c.node.UserID] = map[*conn]bool{}
	}
	g.byUser[c.node.UserID][c] = true
	g.mu.Unlock()
}

func (g *Gateway) remove(c *conn) {
	g.mu.Lock()
	if g.conns[c.node.ID] == c {
		delete(g.conns, c.node.ID)
	}
	if m := g.byUser[c.node.UserID]; m != nil {
		delete(m, c)
		if len(m) == 0 {
			delete(g.byUser, c.node.UserID)
		}
	}
	g.mu.Unlock()
	c.close(websocket.StatusNormalClosure, "")
	g.log.Info("node disconnected", "node", c.node.Name)
	// Karenz: verbindet sich die Node binnen 60 s neu (auch an einem anderen hub), bleibt sie online
	go func(id string) {
		select {
		case <-g.ctx.Done():
			return
		case <-time.After(60 * time.Second):
		}
		if g.get(id) != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = g.st.NodeGone(ctx, id)
	}(c.node.ID)
}

func (g *Gateway) get(nodeID string) *conn {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.conns[nodeID]
}

func (g *Gateway) markSeen(nodeID string) {
	g.mu.Lock()
	g.seen[nodeID] = true
	g.mu.Unlock()
}

// sendUsage schickt den Nodes eines Accounts den Stand des Tageskontingents der Online-Checks.
func (g *Gateway) sendUsage(userID int64) {
	today, limit, known := g.st.DailyUsage(userID)
	if !known {
		return
	}
	m := wire.Msg{T: "usage", Data: raw(map[string]any{"checks_today": today, "checks_per_day": limit, "blocked": g.st.DailyBlocked(userID)})}
	g.mu.RLock()
	conns := make([]*conn, 0, len(g.byUser[userID]))
	for c := range g.byUser[userID] {
		conns = append(conns, c)
	}
	g.mu.RUnlock()
	for _, c := range conns {
		c.send(m)
	}
}

// seenLoop schreibt last_seen gebuendelt und erkennt veraltete Nodes (Housekeeper).
func (g *Gateway) seenLoop() {
	defer g.wg.Done()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	g.st.OnUsageFlip = func(userID int64, _ bool) { g.sendUsage(userID) } // gesperrt/frei: sofort melden
	tick := 0
	for {
		select {
		case <-g.ctx.Done():
			return
		case <-t.C:
			// Tageskontingent: Accounts der verbundenen Nodes abgleichen, alle 2 min den Stand schicken
			g.mu.RLock()
			uids := make([]int64, 0, len(g.byUser))
			for id := range g.byUser {
				uids = append(uids, id)
			}
			g.mu.RUnlock()
			g.st.TrackUsage(uids)
			if tick++; tick%4 == 0 {
				for _, id := range uids {
					g.sendUsage(id)
				}
			}
			g.mu.Lock()
			ids := make([]string, 0, len(g.seen))
			for id := range g.seen {
				ids = append(ids, id)
			}
			g.seen = map[string]bool{}
			g.mu.Unlock()
			ctx, cancel := context.WithTimeout(g.ctx, 20*time.Second)
			if len(ids) > 0 {
				if err := g.st.NodesSeen(ctx, ids); err != nil {
					g.log.Warn("nodes seen update failed", "err", err)
				}
			}
			// im Portal getrennte oder entfernte Nodes: Verbindung beenden
			g.mu.Lock()
			connected := make([]string, 0, len(g.conns))
			for id := range g.conns {
				connected = append(connected, id)
			}
			g.mu.Unlock()
			if gone, err := g.st.GoneNodes(ctx, connected); err == nil {
				for _, id := range gone {
					if c := g.get(id); c != nil {
						g.log.Info("node unlinked elsewhere, closing", "node", c.node.Name)
						c.close(websocket.StatusPolicyViolation, "token revoked")
					}
				}
			}
			if nodes, err := g.st.LiveNodes(ctx); err == nil && g.st.IsHousekeeper(nodes) {
				if stale, _ := g.st.StaleNodes(ctx); len(stale) > 0 {
					g.log.Info("nodes marked offline", "count", len(stale))
				}
			}
			cancel()
		}
	}
}

// remoteLoop schickt den Nodes alle 15 s die Zustaende der Checks, die sie nicht selbst messen
// (Online-Checks, Checks anderer Nodes des Accounts), damit ihre Oberflaeche aktuell ist.
func (g *Gateway) remoteLoop() {
	defer g.wg.Done()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	last := time.Now().UTC().Add(-time.Minute)
	for {
		select {
		case <-g.ctx.Done():
			return
		case <-t.C:
			if g.Connections() == 0 {
				last = time.Now().UTC().Add(-time.Minute)
				continue
			}
			ctx, cancel := context.WithTimeout(g.ctx, 10*time.Second)
			now := time.Now().UTC()
			list, err := g.st.RemoteStatesSince(ctx, last.Add(-2*time.Second))
			cancel()
			if err != nil {
				g.log.Warn("remote states query failed", "err", err)
				continue
			}
			last = now
			byUser := map[int64][]store.RemoteState{}
			for _, r := range list {
				byUser[r.UserID] = append(byUser[r.UserID], r)
			}
			for uid, items := range byUser {
				g.mu.RLock()
				conns := make([]*conn, 0, len(g.byUser[uid]))
				for c := range g.byUser[uid] {
					conns = append(conns, c)
				}
				g.mu.RUnlock()
				for _, c := range conns {
					c.sendRemote(items)
				}
			}
		}
	}
}

// sendRemote filtert die Zustaende fuer diese Node und schickt sie (Nachricht remote_states).
func (c *conn) sendRemote(items []store.RemoteState) {
	out := make([]store.RemoteState, 0, len(items))
	for _, r := range items {
		if r.ForNode(c.node.ID) {
			out = append(out, r)
		}
	}
	if len(out) > 0 {
		c.send(wire.Msg{T: "remote_states", Data: raw(map[string]any{"items": out})})
	}
}

// fanoutLoop verteilt Konfigurationsaenderungen, Kommandos und Sendeauftraege
// an verbundene Nodes (Log-Polling jede Sekunde; Redis spaeter als Beschleuniger).
func (g *Gateway) fanoutLoop() {
	defer g.wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-g.ctx.Done():
			return
		case <-t.C:
			if g.Connections() == 0 {
				continue
			}
			ctx, cancel := context.WithTimeout(g.ctx, 20*time.Second)
			changes, err := g.st.ConfigChanges(ctx, g.lastLog, 1000)
			if err == nil {
				users := map[int64]bool{}
				for _, ch := range changes {
					g.lastLog = ch.ID
					users[ch.UserID] = true
				}
				for uid := range users {
					g.mu.RLock()
					list := make([]*conn, 0, len(g.byUser[uid]))
					for c := range g.byUser[uid] {
						list = append(list, c)
					}
					g.mu.RUnlock()
					for _, c := range list {
						ch, gap, err := g.st.ConfigSince(ctx, uid, c.node.ID, c.rev())
						if err != nil {
							continue
						}
						if gap {
							c.send(wire.Msg{T: "revision_gap"})
							continue
						}
						if len(ch) > 0 {
							c.sendConfig(ch, 0)
						}
					}
				}
			}
			// Kommandos und Sendeauftraege fuer verbundene Nodes
			g.mu.RLock()
			list := make([]*conn, 0, len(g.conns))
			for _, c := range g.conns {
				list = append(list, c)
			}
			g.mu.RUnlock()
			for _, c := range list {
				c.deliverPending(ctx)
			}
			cancel()
		}
	}
}

func fmtSscan(s string, v *int64) (int, error) {
	var n int64
	for _, ch := range strings.TrimSpace(s) {
		if ch < '0' || ch > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int64(ch-'0')
	}
	*v = n
	return 1, nil
}
