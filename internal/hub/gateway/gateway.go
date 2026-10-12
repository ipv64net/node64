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
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

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

	mu      sync.RWMutex
	conns   map[string]*conn         // node_id -> Verbindung
	byUser  map[int64]map[*conn]bool // userid -> Verbindungen
	seen    map[string]bool          // Nodes mit Pong seit dem letzten Flush
	sentCmd map[int64]bool           // bereits zugestellte Kommandos
	lastLog int64
	limiter *ipLimiter
	wg      sync.WaitGroup
	cancel  context.CancelFunc
	ctx     context.Context
}

// New erzeugt das Gateway.
func New(st *store.Store, nf *hubnotify.Store, senders map[notify.Type]notify.Sender, log *slog.Logger, version, location string, maxConns int) *Gateway {
	return &Gateway{st: st, nf: nf, senders: senders, log: log.With("module", "gateway"), version: version, location: location, maxConns: maxConns,
		conns: map[string]*conn{}, byUser: map[int64]map[*conn]bool{}, seen: map[string]bool{}, sentCmd: map[int64]bool{}, limiter: newIPLimiter()}
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
	mux.Handle("POST /v1/nodes/me/unlink", g.auth(g.unlink))
	mux.Handle("POST /v1/nodes/me/measurements", g.auth(g.httpMeasurements))
	mux.Handle("POST /v1/nodes/me/events", g.auth(g.httpEvents))
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

// clientIP: hinter nginx auf localhost X-Real-IP, sonst RemoteAddr.
func clientIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if x := strings.TrimSpace(r.Header.Get("X-Real-IP")); x != "" {
			return x
		}
	}
	return host
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
		if !g.trusted[clientIP(r)] && !g.limiter.allow("auth:"+clientIP(r), 60, time.Minute) {
			writeErr(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		n, err := g.st.NodeByToken(r.Context(), tok)
		if err != nil {
			if errors.Is(err, store.ErrInvalidToken) {
				g.limiter.allow("bad:"+clientIP(r), 20, time.Minute)
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
	if !g.limiter.allow("link:"+clientIP(r), 5, time.Minute) {
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
	ok, err := g.st.PushIn(r.Context(), token, down, msg, clientIP(r))
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
