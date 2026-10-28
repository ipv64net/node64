package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/wire"
)

// session ist eine WebSocket-Verbindung zum hub.
type session struct {
	c      *Live
	ws     *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc
	hub    string

	mu      sync.Mutex
	nextID  int64
	waiters map[int64]chan wire.Msg
	ready   chan struct{} // nach hello + erster config
	readyOk bool
	sendMu  sync.Mutex

	returnHome bool // Sitzung endet, weil der Stamm-hub wieder erreichbar ist

	proxy  atomic.Bool // der hub nimmt Stellvertreter-Nodes an (hello)
	direct atomic.Bool // der hub kann wire.NotifyDirect (hello)
}

// loop haelt die Verbindung mit Backoff und Jitter (1 s .. 60 s, +-30 %).
func (c *Live) loop(ctx context.Context) {
	defer c.wg.Done()
	backoff := time.Second
	failed := ""
	for {
		if ctx.Err() != nil {
			return
		}
		if !c.Linked() {
			return
		}
		hub := c.pickEndpoint(failed)
		err := c.runSession(ctx, hub)
		c.mu.Lock()
		c.connected, c.hub = false, ""
		stable := c.sessionReady
		c.sessionReady = false
		c.mu.Unlock()
		if stable {
			backoff = time.Second // echte Sitzung gehabt (hello empfangen): Wartezeit zuruecksetzen
		}
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errRevoked) {
			c.log.Warn("ipv64 link revoked by server; staying standalone")
			if cerr := c.clearLink(context.Background()); cerr != nil {
				c.log.Error("cleanup after revoke failed", "err", cerr)
			}
			c.mu.Lock()
			c.running = false // erneutes Verknuepfen startet die Schleife wieder
			c.mu.Unlock()
			c.setErr(errors.New("the link was removed on ipv64.net, the node runs standalone"))
			return
		}
		if errors.Is(err, errHome) {
			backoff, failed = time.Second, ""
			continue // direkt zum Stamm-hub
		}
		if errors.Is(err, errBye) {
			backoff = time.Second
			failed = hub // sofort neu verbinden, bevorzugt beim anderen hub
			continue
		}
		if err != nil {
			c.setErr(err)
			c.log.Info("hub connection ended", "hub", hub, "err", err, "retry_in", backoff)
			failed = hub
		}
		jitter := time.Duration(float64(backoff) * (0.7 + rand.Float64()*0.6))
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter):
		}
		backoff *= 2
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
	}
}

var (
	errRevoked = errors.New("token revoked")
	errBye     = errors.New("hub said bye")
	errHome    = errors.New("returning to home hub")
	errGap     = errors.New("revision gap")
)

func (c *Live) runSession(ctx context.Context, hub string) error {
	c.mu.Lock()
	c.revHeld = false // die neue Sitzung liefert ab der gespeicherten Revision
	c.mu.Unlock()
	wsURL := strings.Replace(strings.Replace(hub, "https://", "wss://", 1), "http://", "ws://", 1) + "/v1/ws?since=" + strconv.FormatInt(c.getInt(SetRevision), 10)
	dctx, dcancel := context.WithTimeout(ctx, 30*time.Second)
	ws, resp, err := websocket.Dial(dctx, wsURL, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + c.token()}, "User-Agent": {"node64/" + c.d.Version}}, CompressionMode: websocket.CompressionDisabled})
	dcancel()
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return errRevoked
		}
		return err
	}
	ws.SetReadLimit(maxReadBytes) // config grosser Accounts
	sctx, cancel := context.WithCancel(ctx)
	s := &session{c: c, ws: ws, ctx: sctx, cancel: cancel, hub: hub, waiters: map[int64]chan wire.Msg{}, ready: make(chan struct{})}
	defer func() {
		cancel()
		_ = ws.Close(websocket.StatusNormalClosure, "")
		c.mu.Lock()
		c.ws = nil
		c.mu.Unlock()
	}()
	c.mu.Lock()
	c.ws = s
	c.connected, c.hub = true, hub
	c.connAt = time.Now()
	c.lastErr = ""
	c.mu.Unlock()
	c.set(SetHub, hub)
	c.log.Info("connected to hub", "hub", hub)

	errc := make(chan error, 1)
	go func() { errc <- s.reader() }()

	// Nach hello+config: Outbox abspielen, Nachlieferung, dann Dauerbetrieb
	select {
	case <-sctx.Done():
		return <-errc
	case err := <-errc:
		return err
	case <-s.ready:
	}
	c.mu.Lock()
	c.sessionReady = true // nur eine Sitzung mit hello zaehlt als stabil (nicht ein 30-s-Dial-Timeout)
	c.mu.Unlock()
	s.afterConnect()
	go s.worker()

	err = <-errc
	if s.returnHome {
		return errHome
	}
	return err
}

// reader verarbeitet Nachrichten des hubs.
func (s *session) reader() error {
	for {
		_, data, err := s.ws.Read(s.ctx)
		s.c.rxBytes.Add(int64(len(data)))
		if err != nil {
			if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
				return errBye
			}
			return err
		}
		var m wire.Msg
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		if err := s.handle(m); err != nil {
			return err
		}
	}
}

func (s *session) handle(m wire.Msg) error {
	c := s.c
	ctx := s.ctx
	switch m.T {
	case "hello":
		var h wire.Hello
		if err := json.Unmarshal(m.Data, &h); err == nil {
			if len(h.Endpoints) > 0 {
				eps, _ := json.Marshal(h.Endpoints)
				c.set(SetEndpoints, string(eps))
			}
			acc, _ := json.Marshal(h.Account)
			c.set(SetAccount, string(acc))
			// Name/Standort uebernimmt refreshMe nach afterConnect (lokale Aenderungen gehen vor)
			c.set(SetRemoteMgmt, h.RemoteMgmt)
			for _, f := range h.Features {
				if f == "proxy" {
					s.proxy.Store(true)
				}
				if f == wire.NotifyDirect {
					s.direct.Store(true)
				}
			}
			if !s.direct.Load() {
				c.hubDirect.Store(false) // aelterer hub: er sendet alles selbst
			}
			if h.Hub != "" {
				c.mu.Lock()
				c.hub = s.hub + " (" + h.Hub + ")"
				c.mu.Unlock()
			}
			c.startBackfill(ctx) // Luecken im Verlauf fremder Messstellen nachladen
		}
	case "usage":
		// Tageskontingent der Online-Checks (bei Sperre/Freigabe sofort, sonst alle 2 min)
		var in struct {
			Today int `json:"checks_today"`
			Limit int `json:"checks_per_day"`
		}
		var acc wire.Account
		if json.Unmarshal(m.Data, &in) == nil && json.Unmarshal([]byte(c.setting(SetAccount, "{}")), &acc) == nil {
			if acc.Usage == nil {
				acc.Usage = map[string]int{}
			}
			if acc.Limits == nil {
				acc.Limits = map[string]int{}
			}
			acc.Usage["checks_today"], acc.Limits["checks_per_day"] = in.Today, in.Limit
			b, _ := json.Marshal(acc)
			c.set(SetAccount, string(b))
		}
	case "remote_states":
		var in struct {
			Items []healthchecks.RemoteState `json:"items"`
		}
		if err := json.Unmarshal(m.Data, &in); err == nil {
			for _, it := range in.Items {
				c.d.HC.ApplyRemoteState(ctx, it)
			}
		}
	case "config":
		var in struct {
			Revision int64         `json:"revision"`
			Changes  []wire.Change `json:"changes"`
			More     bool          `json:"more"` // grosse Konfiguration in Teilen: weitere folgen
		}
		err := json.Unmarshal(m.Data, &in)
		if err == nil {
			c.applyChanges(ctx, in.Changes, in.Revision)
		}
		if err != nil || !in.More { // bereit erst mit dem letzten Teil (sonst liefe der Postausgang zu frueh)
			s.markReady()
		}
		s.send(wire.Msg{T: "ack", ID: m.ID})
	case "revision_gap":
		c.log.Info("revision gap, full sync")
		if err := c.fullSync(ctx); err != nil {
			return fmt.Errorf("full sync: %w", err)
		}
		s.markReady()
	case "ack", "conflict":
		s.mu.Lock()
		ch := s.waiters[m.ID]
		delete(s.waiters, m.ID)
		s.mu.Unlock()
		if ch != nil {
			ch <- m
		}
	case "command":
		var cmd wire.Command
		if err := json.Unmarshal(m.Data, &cmd); err == nil {
			go s.runCommand(cmd)
		}
	case "send_order":
		var o wire.SendOrder
		if err := json.Unmarshal(m.Data, &o); err == nil {
			go s.runSendOrder(o)
		}
	case "bye":
		return errBye
	}
	return nil
}

func (s *session) markReady() {
	s.mu.Lock()
	if !s.readyOk {
		s.readyOk = true
		close(s.ready)
	}
	s.mu.Unlock()
}

func (s *session) send(m wire.Msg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	s.c.txBytes.Add(int64(len(b)))
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	wctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	defer cancel()
	return s.ws.Write(wctx, websocket.MessageText, b)
}

// request schickt eine Nachricht und wartet auf ack/conflict.
func (s *session) request(t string, data any) (wire.Msg, error) {
	s.mu.Lock()
	s.nextID++
	id := s.nextID
	ch := make(chan wire.Msg, 1)
	s.waiters[id] = ch
	s.mu.Unlock()
	if err := s.send(wire.Msg{T: t, ID: id, Data: mustJSON(data)}); err != nil {
		return wire.Msg{}, err
	}
	select {
	case m := <-ch:
		var a struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(m.Data, &a)
		// nur ein Datenbankfehler zaehlt als "hub bestaetigt nicht"; eine inhaltliche Ablehnung (z. B. unbekannte
		// Node) zeigt, dass der hub arbeitet
		s.c.noteAck(!(m.T == "ack" && a.Error == "database error"))
		return m, nil
	case <-time.After(30 * time.Second):
		s.mu.Lock()
		delete(s.waiters, id)
		s.mu.Unlock()
		s.c.noteAck(false)
		// Ohne Antwort ist die Verbindung mit hoher Wahrscheinlichkeit tot (z. B. harte Netztrennung):
		// Sitzung beenden, die Schleife verbindet neu und spielt den Postausgang nach.
		s.c.log.Warn("no ack from hub, reconnecting", "type", t)
		s.cancel()
		return wire.Msg{}, errors.New("timeout waiting for ack")
	case <-s.ctx.Done():
		return wire.Msg{}, s.ctx.Err()
	}
}

// afterConnect: Outbox, Nachlieferung, Zustands-Schnappschuss, Status.
func (s *session) afterConnect() {
	s.pushNodeInfo() // lokal geaenderter Name/Standort zuerst, sonst holt refreshMe den alten
	s.pushNotifySettings()
	if s.c.setting("sync.channel_config_v1", "") == "" {
		// einmalig: Portal-Kanaele bringen jetzt ihre nicht geheimen Werte mit (Felder zum Bearbeiten)
		if err := s.c.fullSync(s.ctx); err == nil {
			s.c.set("sync.channel_config_v1", "1")
		}
	}
	go s.c.refreshMe(context.Background()) // Name, Standort und Nodes des Accounts aktualisieren
	s.replayOutbox()
	s.uploadMeasurements()
	s.uploadEvents()
	s.sendSnapshot()
	s.sendStatus()
}

// worker: regelmaessige Uploads und Zustandsmeldungen.
func (s *session) worker() {
	c := s.c
	meas := time.NewTicker(30 * time.Second)
	defer meas.Stop()
	status := time.NewTicker(5 * time.Minute)
	defer status.Stop()
	states := time.NewTicker(2 * time.Second)
	defer states.Stop()
	// Eigener Ping: nur so faellt eine stille Netztrennung (Pakete werden verworfen) zeitnah auf.
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	// Nicht beim Stamm-hub (nach einem Ausfall): nach 10-20 min pruefen, ob er wieder da ist, und zurueckwechseln.
	home := time.NewTimer(time.Duration(10+rand.IntN(10)) * time.Minute)
	defer home.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-home.C:
			if h := c.homeHub(); s.hub != h && c.hubHealthy(s.ctx, h) {
				c.log.Info("home hub is back, switching", "from", s.hub, "to", h)
				s.returnHome = true
				s.cancel()
				return
			}
			home.Reset(time.Duration(10+rand.IntN(10)) * time.Minute)
		case <-ping.C:
			pctx, pcancel := context.WithTimeout(s.ctx, 10*time.Second)
			err := s.ws.Ping(pctx)
			pcancel()
			if err != nil && s.ctx.Err() == nil {
				c.log.Warn("hub not answering ping, reconnecting", "err", err)
				s.cancel()
				return
			}
		case <-c.wake:
			s.pushNodeInfo()
			s.pushNotifySettings()
			s.replayOutbox()
			s.flushStates()
		case <-states.C:
			s.flushStates()
		case <-meas.C:
			s.uploadMeasurements()
			s.uploadEvents()
		case <-status.C:
			s.sendStatus()
			go s.c.refreshMe(context.Background()) // Nodes des Accounts (Online-Status) aktuell halten
		}
	}
}

func (s *session) replayOutbox() {
	c := s.c
	ctx := s.ctx
	list, err := c.d.HC.OutboxPending(ctx)
	if err != nil {
		return
	}
	for _, o := range list {
		p := wire.Propose{Entity: o.Entity, Op: o.Op, ID: o.EntityID, BaseRevision: o.BaseRevision, ChangedAt: o.CreatedAt}
		if o.Payload != "" {
			p.Data = json.RawMessage(o.Payload)
		}
		if o.Entity == "check" && o.Op == "upsert" {
			// Kanalzuordnung erst beim Senden abbilden: ein gerade neu angelegter Kanal hat seine
			// Server-ID moeglicherweise erst nach dem Anlegen des Check-Eintrags im Postausgang bekommen.
			if ck, _ := c.d.HC.CheckByToken(ctx, o.EntityID); ck != nil {
				p.Data = mustJSON(c.d.HC.WireCheck(ck, c.localToRemote(ctx)))
			}
		}
		if o.Entity != "check" {
			// Server-ID statt lokaler ID
			var lid int64
			fmt.Sscan(o.EntityID, &lid)
			p.ID = "0"
			switch o.Entity {
			case "maintenance":
				if mw, _ := c.d.HC.MaintenanceByID(ctx, lid); mw != nil && mw.RemoteID > 0 {
					p.ID = strconv.FormatInt(mw.RemoteID, 10)
				}
			case "channel":
				if ch, _ := c.d.NF.Channel(ctx, lid); ch != nil && ch.RemoteID > 0 {
					p.ID = strconv.FormatInt(ch.RemoteID, 10)
				}
			}
			if p.ID == "0" && o.Op == "delete" {
				// lokal schon geloescht: die Server-ID steht im Postausgang
				var x struct {
					ID int64 `json:"id"`
				}
				if json.Unmarshal([]byte(o.Payload), &x) == nil && x.ID > 0 {
					p.ID = strconv.FormatInt(x.ID, 10)
				} else {
					c.logErr("OutboxDelete", c.d.HC.OutboxDelete(ctx, o.ID)) // nie auf dem Server gewesen
					continue
				}
			}
		}
		m, err := s.request("propose", p)
		if err != nil {
			c.log.Warn("propose failed", "entity", o.Entity, "id", checks.TokenHint(o.EntityID), "err", err)
			return
		}
		var res wire.ProposeResult
		_ = json.Unmarshal(m.Data, &res)
		switch {
		case m.T == "conflict" || res.Conflict:
			// der hub hat eine juengere Fassung (oder hat geloescht): die zuletzt gemachte Aenderung gewinnt,
			// also die Server-Fassung uebernehmen und die lokale verwerfen
			c.logErr("OutboxDelete", c.d.HC.OutboxDelete(ctx, o.ID))
			c.adoptServer(ctx, o.Entity, p.ID, res)
			c.log.Info("sync: newer server version adopted", "entity", o.Entity, "id", checks.TokenHint(o.EntityID))
		case res.Error != "":
			c.logErr("OutboxSetError", c.d.HC.OutboxSetError(ctx, o.ID, "pending", res.Error))
			c.log.Warn("server rejected change", "entity", o.Entity, "id", checks.TokenHint(o.EntityID), "err", res.Error)
			// Ablehnung (z. B. Limit): Eintrag bleibt mit Fehler stehen, blockiert aber nichts anderes
			c.logErr("OutboxSetError", c.d.HC.OutboxSetError(ctx, o.ID, "conflict", res.Error))
			server := ""
			if len(res.Server) > 0 && string(res.Server) != "null" {
				server = string(res.Server)
			}
			c.logErr("ConflictAdd", c.d.HC.ConflictAdd(ctx, healthchecks.Conflict{Entity: o.Entity, EntityID: o.EntityID, LocalOp: o.Op, LocalPayload: o.Payload,
				ServerPayload: server, ServerRevision: res.Revision, Error: res.Error}))
		default:
			s.applyAck(ctx, o, res)
			c.logErr("OutboxDelete", c.d.HC.OutboxDelete(ctx, o.ID))
		}
	}
}

// applyAck uebernimmt Server-Revision und -ID nach einem bestaetigten Vorschlag.
func (s *session) applyAck(ctx context.Context, o healthchecks.Outbox, res wire.ProposeResult) {
	c := s.c
	var lid int64
	fmt.Sscan(o.EntityID, &lid)
	switch o.Entity {
	case "check":
		if o.Op != "delete" {
			c.logErr("SetCheckRevision", c.d.HC.SetCheckRevision(ctx, o.EntityID, res.Revision))
			// Zustand erneut melden: die erste Messung eines neuen Checks kommt oft an, bevor der hub ihn kennt,
			// und ginge sonst bis zur naechsten Messung verloren (Zertifikat: Stunden)
			if ck, _ := c.d.HC.CheckByToken(ctx, o.EntityID); ck != nil && ck.MeasuredHere() {
				c.d.HC.PushState(o.EntityID)
			}
			var w wire.Check
			if json.Unmarshal(res.Data, &w) == nil && len(w.Locations) > 0 {
				// Server kann Standorte gekuerzt haben: lokal uebernehmen, ohne neuen Vorschlag
				c.logErr("apply trimmed locations", c.d.HC.ApplyWireCheck(ctx, w, func(remote int64) int64 {
					if ch, _ := c.d.NF.ByRemote(ctx, remote); ch != nil {
						return ch.ID
					}
					return 0
				}))
			}
		}
	case "maintenance":
		if o.Op != "delete" {
			var w wire.Maintenance
			if json.Unmarshal(res.Data, &w) == nil {
				c.logErr("SetMaintenanceRemote", c.d.HC.SetMaintenanceRemote(ctx, lid, w.ID, res.Revision))
			}
		}
	case "channel":
		if o.Op != "delete" {
			var w wire.Channel
			if json.Unmarshal(res.Data, &w) == nil {
				c.logErr("SetRemote", c.d.NF.SetRemote(ctx, lid, w.ID, res.Revision))
			}
		}
	}
	if res.Revision > c.getInt(SetRevision) {
		c.setInt(SetRevision, res.Revision)
	}
}

func (s *session) uploadMeasurements() {
	c := s.c
	for i := 0; i < 20; i++ { // hoechstens 10.000 je Runde
		ack := c.getInt(SetAckSeq)
		batch, err := c.d.HC.MeasurementsAfter(s.ctx, ack, 500)
		if err != nil || len(batch) == 0 {
			return
		}
		fetched := len(batch)
		batch = chunks(shrinkMeasurements(batch))[0] // unter der Leselimite des hubs, der Rest in der naechsten Runde
		m, err := s.request("measurements", map[string]any{"batch": batch})
		if err != nil {
			return
		}
		var a wire.Ack
		_ = json.Unmarshal(m.Data, &a)
		if a.Error != "" {
			c.log.Warn("measurement upload rejected", "err", a.Error)
			return
		}
		if a.AckSeq > ack {
			c.setInt(SetAckSeq, a.AckSeq)
		} else {
			return
		}
		c.mu.Lock()
		c.lastSync = time.Now()
		c.mu.Unlock()
		if fetched < 500 && len(batch) == fetched {
			return
		}
	}
}

func (s *session) uploadEvents() {
	c := s.c
	for i := 0; i < 20; i++ {
		last := c.getInt(SetEventID)
		batch, newLast, err := c.d.HC.EventsAfter(s.ctx, last, 500)
		if err != nil || len(batch) == 0 {
			return
		}
		for _, part := range chunks(shrinkEvents(batch)) { // unter der Leselimite des hubs
			m, err := s.request("events", map[string]any{"batch": part})
			if err != nil {
				return
			}
			var a wire.Ack
			_ = json.Unmarshal(m.Data, &a)
			if a.Error != "" {
				return
			}
		}
		c.setInt(SetEventID, newLast)
		if len(batch) < 500 {
			return
		}
	}
}

func (s *session) sendSnapshot() {
	items := s.c.d.HC.Snapshot(s.ctx)
	if len(items) == 0 {
		return
	}
	for _, part := range chunks(shrinkStates(items)) {
		if _, err := s.request("states", map[string]any{"items": part}); err != nil {
			return
		}
	}
}

func (s *session) flushStates() {
	c := s.c
	c.mu.Lock()
	if len(c.states) == 0 {
		c.mu.Unlock()
		return
	}
	items := make([]wire.State, 0, len(c.states))
	for _, st := range c.states {
		items = append(items, st)
	}
	c.states = map[string]wire.State{}
	c.mu.Unlock()
	var err error
	for _, part := range chunks(shrinkStates(items)) {
		if _, err = s.request("states", map[string]any{"items": part}); err != nil {
			break
		}
	}
	if err != nil {
		// zurueck in die Warteschlange
		c.mu.Lock()
		for _, st := range items {
			if _, ok := c.states[st.Token]; !ok {
				c.states[st.Token] = st
			}
		}
		c.mu.Unlock()
	}
}

// pushNodeInfo meldet lokal geaenderten Namen/Standort an den hub (Portal, andere Nodes).
func (s *session) pushNodeInfo() {
	c := s.c
	if !c.nodeInfoPending() {
		return
	}
	gen := c.infoGen.Load()
	name, loc := c.setting("node.name", ""), c.setting("node.location", "")
	m, err := s.request("node_info", map[string]string{"name": name, "location": loc})
	if err != nil {
		return
	}
	var res struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(m.Data, &res)
	if !res.OK {
		c.log.Warn("hub rejected node name", "err", res.Error)
	}
	c.set(SetNodeName, name) // abgeglichener Stand (auch bei Ablehnung, sonst endlose Wiederholung)
	c.set(SetLocation, loc)
	if c.infoGen.Load() == gen {
		c.set(SetNodeInfoDirty, "")
	}
}

// pushNotifySettings meldet lokal geaenderte Benachrichtigungs-Einstellungen (Ruhezeiten, Grenzen) an den hub.
func (s *session) pushNotifySettings() {
	c := s.c
	if c.setting(SetNotifyDirty, "") != "1" {
		return
	}
	gen := c.notifyGen.Load()
	m, err := s.request("settings", c.notifySettings(s.ctx))
	if err != nil {
		return
	}
	var res struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(m.Data, &res)
	if !res.OK {
		c.log.Warn("hub rejected notification settings", "err", res.Error)
	}
	if c.notifyGen.Load() == gen {
		c.set(SetNotifyDirty, "")
	}
}

func (s *session) sendStatus() {
	c := s.c
	ctx := s.ctx
	st := wire.Status{Version: c.d.Version, Modules: []string{"healthchecks"}, Timezone: c.d.Core.SettingOr(ctx, "node.timezone", "UTC"),
		OutboxSize: c.d.HC.OutboxCount(ctx), Conflicts: c.d.HC.ConflictCount(ctx), LocalTime: time.Now(),
		Name: c.d.Core.SettingOr(ctx, "node.name", ""), Location: c.d.Core.SettingOr(ctx, "node.location", "")}
	// Meldungen der nur hier gemessenen Checks selbst senden: nur mit einem hub, der es kann, und mit API-Key
	direct := s.direct.Load() && c.d.DirectNotify != nil && c.d.DirectNotify()
	if direct {
		st.Modules = append(st.Modules, wire.NotifyDirect)
	}
	err := s.send(wire.Msg{T: "status", Data: mustJSON(st)})
	switch {
	case !direct:
		c.hubDirect.Store(false) // nicht (mehr) angekuendigt: der hub sendet wieder alles
	case err == nil:
		c.hubDirect.Store(true) // erst nach der Ankuendigung selbst senden (sonst sendet der hub noch alles: doppelt)
	}
}

// ---------------------------------------------------------------- Kommandos und Sendeauftraege

func (s *session) runCommand(cmd wire.Command) {
	c := s.c
	ctx := s.ctx
	res := wire.CommandResult{ID: cmd.ID}
	mode := c.setting(SetRemoteMgmt, "full")
	var args map[string]any
	_ = json.Unmarshal(cmd.Args, &args)
	token, _ := args["token"].(string)
	// push und "Jetzt pruefen" kommen von anderen Nodes desselben Accounts: immer erlaubt
	allowed := mode == "full" || (mode == "read" && (cmd.Name == "repair" || cmd.Name == "test_check")) || cmd.Name == "push" || cmd.Name == "run_check"
	switch {
	case !allowed:
		res.Error = "not allowed by remote management setting (" + mode + ")"
	case cmd.Name == "push":
		// Heartbeat ueber ipv64 (health.php) fuer einen lokalen Push-Check
		down, _ := args["down"].(bool)
		msg, _ := args["msg"].(string)
		from, _ := args["from"].(string)
		var at time.Time
		if v, _ := args["time"].(string); v != "" {
			at, _ = time.Parse(time.RFC3339Nano, v)
		}
		res.OK = c.d.HC.PushRemote(ctx, token, down, msg, from, at)
		if !res.OK {
			res.Error = "push not accepted (unknown check or too old)"
		}
	case cmd.Name == "run_check":
		res.OK = c.d.HC.RunNow(token)
		if !res.OK {
			res.Error = "unknown check"
		}
	case cmd.Name == "pause" || cmd.Name == "resume":
		if err := c.d.HC.SetPausedRemote(ctx, token, cmd.Name == "pause"); err != nil {
			res.Error = err.Error()
		} else {
			res.OK = true
		}
	case cmd.Name == "test_check":
		var def wire.Check
		if b, err := json.Marshal(args["definition"]); err == nil {
			_ = json.Unmarshal(b, &def)
		}
		results := c.d.HC.TestDefinition(ctx, def)
		res.OK = true
		out := make([]map[string]any, 0, len(results))
		for _, r := range results {
			if r.Status != "up" {
				res.OK = false
			}
			// Portal-freundliche Form (snake_case, Latenz in ms)
			out = append(out, map[string]any{"status": r.Status, "latency_ms": r.LatencyMS(), "reason": r.Reason, "message": r.Message, "time": r.Time, "family": r.Family, "details": r.Details})
		}
		res.Output = mustJSON(out)
	case cmd.Name == "repair":
		if err := c.fullSync(ctx); err != nil {
			res.Error = err.Error()
		} else {
			res.OK = true
		}
	case cmd.Name == "resolve_conflict":
		var id int64
		if v, ok := args["id"].(float64); ok {
			id = int64(v)
		}
		keep, _ := args["keep"].(string)
		if err := c.Resolve(ctx, id, keep); err != nil {
			res.Error = err.Error()
		} else {
			res.OK = true
		}
	default:
		res.Error = "unknown command " + cmd.Name
	}
	_ = s.send(wire.Msg{T: "command_result", Data: mustJSON(res)})
}

func (s *session) runSendOrder(o wire.SendOrder) {
	c := s.c
	ctx := s.ctx
	done := func(ok bool, errText string) {
		_ = s.send(wire.Msg{T: "order_done", Data: mustJSON(map[string]any{"id": o.ID, "ok": ok, "error": errText})})
	}
	ch, err := c.d.NF.ByRemote(ctx, o.ChannelID)
	if err != nil || ch == nil {
		done(false, "channel not found on node")
		return
	}
	snd, ok := c.d.Senders[ch.Type]
	if !ok {
		done(false, "no sender for "+string(ch.Type))
		return
	}
	m := notify.Message{Kind: notify.Kind(o.Kind), EventID: o.EventID, Time: time.Now(), Language: ch.Lang}
	if v, ok := o.Payload["title"].(string); ok {
		m.Title = v
	}
	if v, ok := o.Payload["text"].(string); ok {
		m.Text = v
	}
	if v, ok := o.Payload["url"].(string); ok {
		m.URL = v
	}
	if v, ok := o.Payload["priority"].(float64); ok {
		m.Priority = int(v)
	}
	if v, ok := o.Payload["payload"].(map[string]any); ok {
		m.Payload = v
	}
	if b, err := json.Marshal(o.Payload["check"]); err == nil {
		_ = json.Unmarshal(b, &m.Check)
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err = snd.Send(sctx, ch, m)
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	c.logErr("AddDelivery", c.d.NF.AddDelivery(ctx, notify.Delivery{EventID: o.EventID, ChannelID: ch.ID, Channel: ch.Name, Kind: o.Kind, CheckToken: m.Check.Token, Subject: m.Title, OK: err == nil, Error: errText}))
	c.logErr("Touch", c.d.NF.Touch(ctx, ch.ID, errText))
	done(err == nil, errText)
}
