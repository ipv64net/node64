// Package gateway ist die Rolle "gateway" des hub: Verbindung der Nodes
// (WebSocket), Erstverknuepfung per Code, HTTPS-Abgleich und Push-Eingang.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/ipv64net/node64/internal/checks"
	hubnotify "github.com/ipv64net/node64/internal/hub/notify"
	"github.com/ipv64net/node64/internal/hub/store"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/wire"
)

// Gateway haelt die Verbindungen einer Instanz.
type Gateway struct {
	st           *store.Store
	nf           *hubnotify.Store
	senders      map[notify.Type]notify.Sender
	log          *slog.Logger
	version      string
	location     string
	maxConns     int
	portalSecret []byte
	trusted      map[string]bool // IPs ohne Ratenlimit (Lasttest) // Portal -> hub (portal.go), gleiches Geheimnis wie die Bruecke
	realIPFrom   []netip.Prefix  // Absender, deren X-Real-IP gilt (Reverse Proxy)

	mu      sync.RWMutex
	conns   map[string]*conn         // node_id -> Verbindung
	byUser  map[int64]map[*conn]bool // userid -> Verbindungen
	seen    map[string]bool          // Nodes mit Pong seit dem letzten Flush
	lastLog int64
	limiter *ipLimiter
	wg      sync.WaitGroup
	cancel  context.CancelFunc
	ctx     context.Context
}

// New erzeugt das Gateway.
func New(st *store.Store, nf *hubnotify.Store, senders map[notify.Type]notify.Sender, log *slog.Logger, version, location string, maxConns int) *Gateway {
	return &Gateway{st: st, nf: nf, senders: senders, log: log.With("module", "gateway"), version: version, location: location, maxConns: maxConns,
		conns: map[string]*conn{}, byUser: map[int64]map[*conn]bool{}, seen: map[string]bool{}, limiter: newIPLimiter(),
		realIPFrom: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}}
}

// Register haengt die Routen an den Multiplexer.
func (g *Gateway) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/nodes/link/start", g.linkStart)
	mux.HandleFunc("POST /v1/nodes/link/poll", g.linkPoll)
	mux.Handle("GET /v1/nodes/me", g.auth(g.me))
	mux.Handle("PATCH /v1/nodes/me", g.auth(g.patchMe))
	mux.Handle("POST /v1/nodes/me/bootstrap", g.auth(g.bootstrap))
	mux.Handle("GET /v1/nodes/me/config", g.auth(g.config))
	mux.Handle("GET /v1/nodes/me/results", g.auth(g.results))
	mux.Handle("GET /v1/nodes/me/history", g.auth(g.history))
	mux.Handle("POST /v1/nodes/me/unlink", g.auth(g.unlink))
	mux.Handle("POST /v1/nodes/me/measurements", g.auth(g.httpMeasurements))
	mux.Handle("POST /v1/nodes/me/events", g.auth(g.httpEvents))
	mux.Handle("GET /v1/nodes/me/events", g.auth(g.hubEvents))
	mux.Handle("POST /v1/nodes/me/testruns", g.auth(g.createTestrun))
	mux.Handle("GET /v1/nodes/me/testruns/{id}", g.auth(g.getTestrun))
	mux.Handle("PUT /v1/nodes/me/checks/{token}", g.auth(g.httpProposeCheck))
	mux.Handle("DELETE /v1/nodes/me/checks/{token}", g.auth(g.httpProposeCheck))
	mux.Handle("GET /v1/ws", g.auth(g.ws))
	mux.HandleFunc("GET /v1/push/{token}", g.push)
	mux.HandleFunc("POST /v1/push/{token}", g.push)
}

// Start startet Fan-out und Pflege-Schleifen.
func (g *Gateway) Start(ctx context.Context) error {
	g.ctx, g.cancel = context.WithCancel(ctx)
	if id, err := g.st.MaxConfigLogID(ctx); err == nil {
		g.lastLog = id
	}
	g.wg.Add(3)
	go g.remoteLoop()
	go g.fanoutLoop()
	go g.seenLoop()
	return nil
}

// Stop schliesst alle Verbindungen (bye) und wartet.
func (g *Gateway) Stop() {
	if g.cancel == nil {
		return
	}
	g.mu.RLock()
	list := make([]*conn, 0, len(g.conns))
	for _, c := range g.conns {
		list = append(list, c)
	}
	g.mu.RUnlock()
	for _, c := range list {
		c.send(wire.Msg{T: "bye", Data: raw(map[string]string{"reason": "shutdown"})})
	}
	time.Sleep(500 * time.Millisecond)
	for _, c := range list {
		c.close(websocket.StatusGoingAway, "shutdown")
	}
	g.cancel()
	g.wg.Wait()
}

// Connections liefert die Anzahl verbundener Nodes.
func (g *Gateway) Connections() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.conns)
}

// ---------------------------------------------------------------- Hilfen

func raw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func readJSON(r *http.Request, v any, limit int64) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, limit))
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return errors.New("empty body")
	}
	return json.Unmarshal(b, v)
}

// SetRealIPFrom setzt die Absender, deren X-Real-IP gilt (config real_ip_from).
func (g *Gateway) SetRealIPFrom(p []netip.Prefix) { g.realIPFrom = p }

// clientIP: vom Reverse Proxy (real_ip_from) dessen X-Real-IP, sonst RemoteAddr.
func (g *Gateway) clientIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if a, err := netip.ParseAddr(host); err == nil && g.fromProxy(a.Unmap()) {
		// nur eine gueltige IP uebernehmen (landet in Ratenlimits, Log und Push-Messpunkten)
		if x, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
			return x.Unmap().String()
		}
	}
	return host
}

func (g *Gateway) fromProxy(a netip.Addr) bool {
	for _, p := range g.realIPFrom {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

type ctxKey int

const ctxNode ctxKey = 1

func nodeOf(r *http.Request) *store.Node {
	n, _ := r.Context().Value(ctxNode).(*store.Node)
	return n
}

// auth prueft den Node-Token (Authorization: Bearer node64t_...).
func (g *Gateway) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
		if tok == "" {
			tok = r.URL.Query().Get("token") // WebSocket aus Browsern o. ae.
		}
		if !g.trusted[g.clientIP(r)] && !g.limiter.allow("auth:"+g.clientIP(r), 60, time.Minute) {
			writeErr(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		n, err := g.st.NodeByToken(r.Context(), tok)
		if err != nil {
			if errors.Is(err, store.ErrInvalidToken) {
				g.limiter.allow("bad:"+g.clientIP(r), 20, time.Minute)
				writeErr(w, http.StatusUnauthorized, "token_revoked")
				return
			}
			writeErr(w, http.StatusInternalServerError, "database error")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxNode, n)))
	})
}

// ---------------------------------------------------------------- Erstverknuepfung

func (g *Gateway) linkStart(w http.ResponseWriter, r *http.Request) {
	if !g.limiter.allow("link:"+g.clientIP(r), 5, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	var in wire.LinkStart
	if err := readJSON(r, &in, 4096); err != nil || len(in.NodeID) != 32 || in.Name == "" {
		writeErr(w, http.StatusBadRequest, "node_id (32 chars) and name required")
		return
	}
	out, err := g.st.LinkStart(r.Context(), in)
	if err != nil {
		g.log.Error("handler failed", "path", r.URL.Path, "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (g *Gateway) linkPoll(w http.ResponseWriter, r *http.Request) {
	var in wire.LinkPoll
	if err := readJSON(r, &in, 4096); err != nil || in.Code == "" || in.PollSecret == "" {
		writeErr(w, http.StatusBadRequest, "code and poll_secret required")
		return
	}
	if !g.limiter.allow("poll:"+in.Code, 20, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	out, err := g.st.LinkPoll(r.Context(), in)
	if errors.Is(err, store.ErrInvalidToken) {
		writeErr(w, http.StatusNotFound, "code unknown, expired or already used")
		return
	}
	if errors.Is(err, store.ErrNodeOwned) {
		g.log.Warn("link refused, node owned by another account", "ip", g.clientIP(r))
		writeErr(w, http.StatusConflict, "node is linked to another account; unlink it there first")
		return
	}
	if err != nil {
		g.log.Error("handler failed", "path", r.URL.Path, "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	if out == nil {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "pending"})
		return
	}
	g.log.Info("node linked", "node", out.Name, "user", out.Account.ID)
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------- HTTPS-Endpunkte

func (g *Gateway) me(w http.ResponseWriter, r *http.Request) {
	n := nodeOf(r)
	acc, _ := g.st.Account(r.Context(), n.UserID)
	eps, _ := g.st.Endpoints(r.Context())
	peers, _ := g.st.AccountNodes(r.Context(), n.UserID)
	settings, _ := g.st.AccountSettings(r.Context(), n.UserID)
	writeJSON(w, http.StatusOK, map[string]any{"node_id": n.ID, "name": n.Name, "location": n.Location, "remote_mgmt": n.RemoteMgmt, "account": acc,
		"nodes": peers, "settings": settings, "endpoints": eps, "revision": g.st.CurrentRevision(r.Context(), n.UserID), "ack_seq": n.LastAckSeq, "server_time": time.Now().UTC(), "hub": g.location})
}

func (g *Gateway) patchMe(w http.ResponseWriter, r *http.Request) {
	n := nodeOf(r)
	var st wire.Status
	if err := readJSON(r, &st, 64<<10); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := g.st.NodeStatus(r.Context(), n.ID, st); err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (g *Gateway) bootstrap(w http.ResponseWriter, r *http.Request) {
	n := nodeOf(r)
	var in wire.Bootstrap
	if err := readJSON(r, &in, 8<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	out, err := g.st.Bootstrap(r.Context(), n.UserID, n.ID, in)
	if err != nil {
		g.log.Error("bootstrap failed", "node", n.ID, "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	g.log.Info("bootstrap", "node", n.Name, "checks", len(out.Checks), "channels", len(out.Channels), "renamed", len(out.Renamed))
	writeJSON(w, http.StatusOK, out)
}

func (g *Gateway) config(w http.ResponseWriter, r *http.Request) {
	n := nodeOf(r)
	cfg, err := g.st.FullConfig(r.Context(), n.UserID, n.ID)
	if err != nil {
		g.log.Error("handler failed", "path", r.URL.Path, "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (g *Gateway) results(w http.ResponseWriter, r *http.Request) {
	n := nodeOf(r)
	states, err := g.st.Results(r.Context(), n.UserID)
	if err != nil {
		g.log.Error("handler failed", "path", r.URL.Path, "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	overall, _ := g.st.OverallStates(r.Context(), n.UserID)
	writeJSON(w, http.StatusOK, map[string]any{"states": states, "overall": overall, "server_time": time.Now().UTC()})
}

// history liefert Verlauf eines Checks zum Nachladen in die Node (?token, since, until, kind=raw|hourly, limit).
func (g *Gateway) history(w http.ResponseWriter, r *http.Request) {
	n, q := nodeOf(r), r.URL.Query()
	since, err := time.Parse(time.RFC3339Nano, q.Get("since"))
	if err != nil || q.Get("token") == "" {
		writeErr(w, http.StatusBadRequest, "token and since (RFC 3339) required")
		return
	}
	until := time.Now().UTC()
	if u := q.Get("until"); u != "" {
		if until, err = time.Parse(time.RFC3339Nano, u); err != nil {
			writeErr(w, http.StatusBadRequest, "until must be RFC 3339")
			return
		}
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 10000 {
		limit = 5000
	}
	if !g.limiter.allow("hist:"+n.ID, 600, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	pts, err := g.st.History(r.Context(), n.UserID, q.Get("token"), "node:"+n.ID, q.Get("kind") == "hourly", since, until, limit)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "check not found")
		return
	}
	if err != nil {
		g.log.Error("handler failed", "path", r.URL.Path, "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"points": pts})
}

// hubEvents: Ereignisse, die der hub selbst bewertet hat (z. B. nicht ueberwacht), fuer die Detailseite der Node.
//
//	GET /v1/nodes/me/events?token=&limit= -> {"events": [...]}
func (g *Gateway) hubEvents(w http.ResponseWriter, r *http.Request) {
	n, q := nodeOf(r), r.URL.Query()
	if q.Get("token") == "" {
		writeErr(w, http.StatusBadRequest, "token required")
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if !g.limiter.allow("hev:"+n.ID, 120, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	evs, err := g.st.HubEvents(r.Context(), n.UserID, q.Get("token"), limit)
	if err != nil {
		g.log.Error("handler failed", "path", r.URL.Path, "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": evs})
}

// createTestrun: Online-Testlauf vor dem Umhaengen (Node). Die Standorte messen einmal; Ergebnis per getTestrun.
//
//	POST /v1/nodes/me/testruns {"definition": wire.Check, "locations": ["nbg","fsn"]} -> {"id": 1, "locations": [...]}
func (g *Gateway) createTestrun(w http.ResponseWriter, r *http.Request) {
	n := nodeOf(r)
	var in struct {
		Definition wire.Check `json:"definition"`
		Locations  []string   `json:"locations"`
	}
	if err := readJSON(r, &in, 256<<10); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !g.limiter.allow("trun:"+n.ID, 20, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	in.Definition.Execution = "online"
	if err := checks.Validate(checks.Definition{Type: checks.Type(in.Definition.Type), Target: in.Definition.Target, Params: in.Definition.Params,
		IPMode: checks.IPMode(in.Definition.IPMode)}); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	id, locs, err := g.st.CreateNodeTestrun(r.Context(), n.UserID, in.Definition, in.Locations)
	if errors.Is(err, store.ErrTestrunPrivate) || errors.Is(err, store.ErrTestrunType) {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err != nil {
		g.log.Error("handler failed", "path", r.URL.Path, "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "locations": locs})
}

// getTestrun: Stand eines Testlaufs des Accounts.
//
//	GET /v1/nodes/me/testruns/{id} -> {"id", "status", "results": {"nbg": {ok, error, results, time}, ...}}
func (g *Gateway) getTestrun(w http.ResponseWriter, r *http.Request) {
	n := nodeOf(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if !g.limiter.allow("trget:"+n.ID, 300, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	tr, err := g.st.NodeTestrun(r.Context(), n.UserID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "testrun not found")
		return
	}
	if err != nil {
		g.log.Error("handler failed", "path", r.URL.Path, "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, tr)
}

func (g *Gateway) unlink(w http.ResponseWriter, r *http.Request) {
	n := nodeOf(r)
	var in struct {
		KeepChecks bool `json:"keep_checks"`
	}
	_ = readJSON(r, &in, 4096)
	if err := g.st.Unlink(r.Context(), n, in.KeepChecks); err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	if c := g.get(n.ID); c != nil {
		c.send(wire.Msg{T: "bye", Data: raw(map[string]string{"reason": "unlinked"})})
		c.close(websocket.StatusNormalClosure, "unlinked")
	}
	g.log.Info("node unlinked", "node", n.Name, "keep_checks", in.KeepChecks)
	writeJSON(w, http.StatusOK, map[string]string{"status": "unlinked"})
}

func (g *Gateway) httpMeasurements(w http.ResponseWriter, r *http.Request) {
	n := nodeOf(r)
	var batch []wire.Measurement
	if err := readJSON(r, &batch, 8<<20); err != nil || len(batch) > 5000 {
		writeErr(w, http.StatusBadRequest, "invalid batch (max 5000)")
		return
	}
	ack, err := g.st.IngestMeasurements(r.Context(), n, batch)
	if err != nil {
		g.log.Error("handler failed", "path", r.URL.Path, "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, ack)
}

func (g *Gateway) httpEvents(w http.ResponseWriter, r *http.Request) {
	n := nodeOf(r)
	var batch []wire.Event
	if err := readJSON(r, &batch, 8<<20); err != nil || len(batch) > 5000 {
		writeErr(w, http.StatusBadRequest, "invalid batch (max 5000)")
		return
	}
	ack, err := g.st.IngestEvents(r.Context(), n, batch)
	if err != nil {
		g.log.Error("handler failed", "path", r.URL.Path, "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, ack)
}

func (g *Gateway) httpProposeCheck(w http.ResponseWriter, r *http.Request) {
	n := nodeOf(r)
	p := wire.Propose{Entity: "check", ID: r.PathValue("token"), Op: "upsert", BaseRevision: 0}
	if r.Method == http.MethodDelete {
		p.Op = "delete"
		fmt.Sscan(r.URL.Query().Get("base_revision"), &p.BaseRevision)
	} else {
		var body struct {
			BaseRevision int64           `json:"base_revision"`
			Data         json.RawMessage `json:"data"`
		}
		if err := readJSON(r, &body, 1<<20); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		p.BaseRevision, p.Data = body.BaseRevision, body.Data
		if len(p.Data) == 0 {
			writeErr(w, http.StatusBadRequest, "data required")
			return
		}
	}
	res, err := g.st.Propose(r.Context(), n.UserID, n.ID, p, "node")
	if err != nil {
		g.log.Error("handler failed", "path", r.URL.Path, "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	switch {
	case res.Conflict:
		writeJSON(w, http.StatusConflict, res)
	case res.Error != "":
		writeJSON(w, http.StatusUnprocessableEntity, res)
	default:
		writeJSON(w, http.StatusOK, res)
	}
}

// push nimmt Heartbeats direkt am hub an (gleichwertig zu health.php).
func (g *Gateway) push(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	w.Header().Set("Content-Type", "text/plain")
	if len(token) < 20 || len(token) > 50 || !g.limiter.allow("push:"+token, 60, time.Minute) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, "Max. 60 per minute")
		return
	}
	down := strings.EqualFold(r.URL.Query().Get("status"), "down") || r.URL.Query().Has("fail")
	msg := r.URL.Query().Get("msg")
	if msg == "" {
		msg = r.URL.Query().Get("message")
	}
	ok, err := g.st.PushIn(r.Context(), token, down, msg, g.clientIP(r))
	if errors.Is(err, store.ErrDailyLimit) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, "Daily limit reached")
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Error")
		return
	}
	if !ok {
		w.WriteHeader(http.StatusOK) // nichts verraten
	}
	fmt.Fprint(w, "OK")
}

// ---------------------------------------------------------------- Ratenbegrenzung

type ipLimiter struct {
	mu sync.Mutex
	m  map[string]*bucket
}

type bucket struct {
	count int
	reset time.Time
}

func newIPLimiter() *ipLimiter { return &ipLimiter{m: map[string]*bucket{}} }

// allow zaehlt einen Zugriff; false, wenn limit im Fenster erreicht.
func (l *ipLimiter) allow(key string, limit int, window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.m[key]
	if !ok || now.After(b.reset) {
		b = &bucket{reset: now.Add(window)}
		l.m[key] = b
		if len(l.m) > 100000 {
			for k, x := range l.m {
				if now.After(x.reset) {
					delete(l.m, k)
				}
			}
		}
	}
	b.count++
	return b.count <= limit
}
