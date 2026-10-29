package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Signierte Anfragen zwischen den Nodes des Clusters: Kopfzeilen mit Absenderin, Zeit, Account und Nonce,
// Signatur ueber Methode, Pfad, Zeit, Account, Nonce, Bindung an die TLS-Verbindung und SHA-256 des Bodys
// (transport.go). Die Antworten sind ebenso signiert.
const (
	hdrNode = "X-Node64-Peer"
	hdrTime = "X-Node64-Time"
	hdrAcc  = "X-Node64-Account"
	hdrSig  = "X-Node64-Sig"
	maxBody = 8 << 20
)

// errSuspendedThere: die andere Node hat diese ausgesetzt (dort wieder aufnehmen).
var errSuspendedThere = errors.New("suspended by the other node")

// call schickt eine signierte Anfrage an eine Node des Clusters (nur HTTPS, an die Kopplung gebunden).
// Ausgesetzte Mitglieder bekommen nichts (ErrSuspended).
func (m *Manager) call(ctx context.Context, x Member, method, path string, in, out any) error {
	return m.callAny(ctx, x, method, path, in, out, false)
}

// callAny: anyState = auch an ausgesetzte Mitglieder (Pruefung beim Wiederaufnehmen, Abmeldung).
func (m *Manager) callAny(ctx context.Context, x Member, method, path string, in, out any, anyState bool) error {
	if !anyState && (x.Suspended() || m.accountChanged(ctx, x)) {
		return ErrSuspended
	}
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
	}
	status, b, err := m.exchange(ctx, x, method, path, body)
	if err != nil {
		var se *suspendErr
		if errors.As(err, &se) {
			m.suspend(ctx, x, se.reason, se.msg)
		}
		return err
	}
	if status != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		switch {
		case status == http.StatusForbidden && e.Error == ErrAccountMismatch.Error():
			m.suspend(ctx, x, ReasonAccountMismatch, "account of the other node does not match")
			return ErrAccountMismatch
		case status == http.StatusForbidden && e.Error == ErrTLSBinding.Error():
			m.suspend(ctx, x, ReasonTLSBinding, e.Error) // die Anfrage kam dort ueber eine andere Verbindung an
			return ErrTLSBinding
		case status == http.StatusForbidden && e.Error == errSuspendedThere.Error():
			return errSuspendedThere
		case status == http.StatusServiceUnavailable && e.Error == "healthchecks not running":
			return errPeerHCOff
		}
		return fmt.Errorf("HTTP %d %s", status, e.Error)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// verify prueft eine eingehende signierte Anfrage (bind = Exporter der eigenen TLS-Verbindung) und liefert die
// Absenderin. Passt ihr Account nicht zum Cluster (anderer als dessen Account, 0 passt immer), wird sie ausgesetzt;
// ausgesetzte Mitglieder duerfen nur noch pingen (fuer das Wiederaufnehmen) und sich bzw. diese Node abmelden.
func (m *Manager) verify(r *http.Request, body, bind []byte) (*Member, int, error) {
	ctx := r.Context()
	x, err := m.member(ctx, r.Header.Get(hdrNode))
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if x == nil {
		return nil, http.StatusUnauthorized, errors.New("unknown node")
	}
	ts := r.Header.Get(hdrTime)
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || time.Since(time.Unix(sec, 0)).Abs() > timeSkew {
		return nil, http.StatusUnauthorized, errors.New("time skew")
	}
	nonce, accS := r.Header.Get(hdrNonce), r.Header.Get(hdrAcc)
	pub, err := base64.StdEncoding.DecodeString(x.PubKey)
	sig, err2 := base64.StdEncoding.DecodeString(r.Header.Get(hdrSig))
	if err != nil || err2 != nil || len(pub) != ed25519.PublicKeySize || len(nonce) < 16 || len(nonce) > 64 {
		return nil, http.StatusUnauthorized, errors.New("bad signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), reqMsg(r.Method, r.URL.RequestURI(), ts, accS, nonce, bind, body), sig) {
		// von der Absenderin signiert, aber fuer eine andere Verbindung: Mittelsmann, der TLS terminiert
		if cb, err := hex.DecodeString(r.Header.Get(hdrBind)); err == nil && len(cb) == bindLen && !bytes.Equal(cb, bind) &&
			ed25519.Verify(ed25519.PublicKey(pub), reqMsg(r.Method, r.URL.RequestURI(), ts, accS, nonce, cb, body), sig) {
			return nil, http.StatusForbidden, ErrTLSBinding
		}
		return nil, http.StatusUnauthorized, errors.New("bad signature")
	}
	if !m.nonceFresh(nonce) {
		return nil, http.StatusUnauthorized, errors.New("replayed request")
	}
	acc, _ := strconv.ParseInt(accS, 10, 64)
	mismatch := false
	if m.accountChanged(ctx, *x) {
		x.State, mismatch = stateSuspended, true
	} else if !compatible(acc, m.ClusterAccount(ctx)) { // der signierte Account: gleich oder 0, nie ein anderer
		m.suspend(ctx, *x, ReasonAccountMismatch, "account of the other node does not match")
		x.State, mismatch = stateSuspended, true
	} else if acc != x.AccountID && !x.Suspended() { // passend geaendert (z. B. 0→X): vermerken
		_, _ = m.db.ExecContext(ctx, `UPDATE peer_members SET account_id = ? WHERE node_id = ?`, acc, x.NodeID)
		x.AccountID = acc
	}
	if x.Suspended() && !suspendedMay(r, body, m.d.NodeID(), x.NodeID) {
		if mismatch {
			return nil, http.StatusForbidden, ErrAccountMismatch
		}
		return nil, http.StatusForbidden, errSuspendedThere
	}
	return x, 0, nil
}

// suspendedMay: was ein ausgesetztes Mitglied noch darf (Ping fuer das Wiederaufnehmen, Abmelden).
func suspendedMay(r *http.Request, body []byte, self, from string) bool {
	switch r.URL.Path {
	case "/peer/v1/ping":
		return true
	case "/peer/v1/members":
		var op memberOp
		return json.Unmarshal(body, &op) == nil && op.Op == "remove" && (op.Member.NodeID == self || op.Member.NodeID == from)
	}
	return false
}

// Handle prueft TLS, Bindung und Signatur und ruft h mit der Absenderin und dem Body auf. Die Antwort wird
// signiert (gilt fuer alle /peer/v1/* und /peer/v2/*).
func (m *Manager) Handle(h func(w http.ResponseWriter, r *http.Request, from *Member, body []byte)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			rejectPlain(w)
			return
		}
		bind, err := tlsBind(r.TLS)
		sw := &sigWriter{hdr: http.Header{}}
		defer m.sendSigned(w, sw, r, bind)
		if err != nil {
			writeJSON(sw, http.StatusForbidden, map[string]string{"error": ErrTLSBinding.Error()})
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, maxBody))
		from, code, err := m.verify(r, body, bind)
		if err != nil {
			m.d.Log.Warn("peer request rejected", "node", r.Header.Get(hdrNode), "path", r.URL.Path, "err", err)
			writeJSON(sw, code, map[string]string{"error": err.Error()})
			return
		}
		// jede gueltige Anfrage ist ein Lebenszeichen (eine zurueckgekehrte Node gilt sofort wieder als erreichbar)
		_, _ = m.db.ExecContext(r.Context(), `UPDATE peer_members SET last_seen = ?, last_error = '' WHERE node_id = ? AND state != ?`, fmtTime(time.Now()), from.NodeID, stateSuspended)
		h(sw, r, from, body)
	})
}

// Register haengt die Endpunkte der Gruppe an (ohne Sitzung und CSRF; Signatur bzw. Kopplungscode).
func (m *Manager) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /peer/v1/pair", m.handlePair)
	mux.Handle("GET /peer/v1/ping", m.Handle(func(w http.ResponseWriter, r *http.Request, _ *Member, _ []byte) {
		writeJSON(w, http.StatusOK, pingInfo{NodeID: m.d.NodeID(), Name: m.d.NodeName(), Version: m.d.Version, AccountID: m.d.AccountID(), Linked: m.linkedSelf(), Sync: m.syncCaps(r.Context())})
	}))
	mux.Handle("POST /peer/v1/members", m.Handle(m.handleMembers))
	mux.Handle("GET /peer/v1/changes", m.Handle(m.handleChanges))
	mux.Handle("POST /peer/v1/poke", m.Handle(m.handlePoke))
	mux.Handle("GET /peer/v1/measurements", m.Handle(m.handleMeasurements))
	mux.Handle("GET /peer/v1/relay", m.Handle(m.handleRelay))
	m.registerSync2(mux) // allgemeiner Abgleich der Module (sync2.go)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------- Kopplung

// pairMsg ist Anfrage und Antwort der Kopplung; MAC = HMAC-SHA256(Code, JSON ohne MAC und Bindung an die
// TLS-Verbindung), Nonce der Anfrage auch in der Antwort (bindet beide aneinander).
type pairMsg struct {
	NodeID    string   `json:"node_id"`
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	PubKey    string   `json:"pubkey"`
	AccountID int64    `json:"account_id"`
	Version   string   `json:"version"`
	HTTPSPort int      `json:"https_port,omitempty"` // Rueckfall fuer die Adresse, wenn URL leer ist
	Members   []Member `json:"members,omitempty"`
	Nonce     string   `json:"nonce"`
	MAC       string   `json:"mac"`
}

func (p pairMsg) mac(code string, bind []byte) string {
	p.MAC = ""
	b, _ := json.Marshal(p)
	h := hmac.New(sha256.New, []byte(normCode(code)))
	h.Write(b)
	h.Write([]byte{0})
	h.Write(bind)
	return hex.EncodeToString(h.Sum(nil))
}

func normCode(c string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
}

const codeChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// StartPairing erzeugt einen Code (10 Minuten, einmal gueltig), mit dem eine weitere Node beitreten kann.
func (m *Manager) StartPairing() (string, time.Time, error) {
	if m.httpsPort() <= 0 {
		return "", time.Time{}, ErrNoHTTPS
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	for i := range b {
		b[i] = codeChars[int(b[i])%len(codeChars)]
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.code, m.exp, m.tries = string(b), time.Now().Add(codeTTL), 0
	return m.code, m.exp, nil
}

// PairingCode liefert den offenen Code (leer = keiner).
func (m *Manager) PairingCode() (string, time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.code == "" || time.Now().After(m.exp) {
		return "", time.Time{}
	}
	return m.code, m.exp
}

// CancelPairing verwirft den offenen Code.
func (m *Manager) CancelPairing() {
	m.mu.Lock()
	m.code = ""
	m.mu.Unlock()
}

// Join tritt ueber eine Node des Clusters bei (addr = deren Adresse, selfURL = Adresse dieser Node; beide werden
// https, die eigene mit dem HTTPS-Port). Die Accounts beider Cluster muessen passen: gleich oder eine Seite ohne (0).
// Gesendet wird der Account des Clusters (eigener, sonst der der Mitglieder), damit eine Node ohne Account keine
// zwei Accounts verbindet.
func (m *Manager) Join(ctx context.Context, addr, code, selfURL string) error {
	port := m.httpsPort()
	if port <= 0 {
		return ErrNoHTTPS
	}
	acc := m.ClusterAccount(ctx)
	addr = httpsURL(addr)
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	req := pairMsg{NodeID: m.d.NodeID(), Name: m.d.NodeName(), URL: selfAddr(selfURL, port), PubKey: m.PublicKey(), AccountID: acc,
		Version: m.d.Version, HTTPSPort: port, Nonce: hex.EncodeToString(nonce)}
	p, err := dialPeer(ctx, addr)
	if err != nil {
		var se *suspendErr
		if errors.As(err, &se) {
			return ErrTLSBinding
		}
		return err
	}
	defer p.Close()
	req.MAC = req.mac(code, p.bind)
	body, _ := json.Marshal(req)
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	hdr.Set("User-Agent", "node64/"+m.d.Version)
	hdr.Set(hdrBind, hex.EncodeToString(p.bind))
	status, _, b, err := p.do(ctx, http.MethodPost, "/peer/v1/pair", body, hdr)
	if err != nil {
		return err
	}
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(b, &e)
	var out pairMsg
	switch {
	case status == http.StatusForbidden && e.Error == ErrTLSBinding.Error():
		return ErrTLSBinding
	case status == http.StatusForbidden:
		return ErrAccountMismatch
	case status == http.StatusUnauthorized:
		return ErrCode
	case status == http.StatusConflict && e.Error == ErrNoHTTPS.Error():
		return ErrNoHTTPS
	case status != http.StatusOK:
		return fmt.Errorf("HTTP %d %s", status, e.Error)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return err
	}
	if out.Nonce != req.Nonce || subtle.ConstantTimeCompare([]byte(out.mac(code, p.bind)), []byte(out.MAC)) != 1 {
		return ErrCode // Antwort nicht von einer Node, die den Code kennt (oder nicht ueber diese Verbindung)
	}
	if !compatible(out.AccountID, acc) {
		return ErrAccountMismatch
	}
	if acc == 0 {
		acc = out.AccountID
	}
	if out.NodeID == m.d.NodeID() {
		return ErrSelf
	}
	if err := m.upsert(ctx, Member{NodeID: out.NodeID, Name: out.Name, URL: addr, PubKey: out.PubKey, AccountID: out.AccountID}, m.d.NodeID()); err != nil {
		return err
	}
	m.activate(ctx, out.NodeID, out.AccountID) // neu gekoppelt: auch ein vorher ausgesetztes Mitglied ist wieder aktiv
	for _, x := range out.Members {
		if compatible(x.AccountID, acc) {
			if acc == 0 {
				acc = x.AccountID
			}
			_ = m.upsert(ctx, x, out.NodeID)
		}
	}
	m.joined(ctx)
	m.d.Log.Info("joined cluster", "via", out.Name, "members", len(out.Members)+1)
	go func() {
		m.pingAll(context.Background())
		m.pullAll(context.Background(), "")
		m.pokeSoon() // die anderen holen den Bestand dieser Node
	}()
	return nil
}

func (m *Manager) handlePair(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		rejectPlain(w)
		return
	}
	bind, err := tlsBind(r.TLS)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": ErrTLSBinding.Error()})
		return
	}
	var in pairMsg
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	m.mu.Lock()
	code, valid := m.code, m.code != "" && time.Now().Before(m.exp)
	ok := valid && subtle.ConstantTimeCompare([]byte(in.mac(code, bind)), []byte(in.MAC)) == 1
	// Code stimmt, aber fuer eine andere Verbindung: Mittelsmann (zaehlt nicht als Fehlversuch)
	cb, _ := hex.DecodeString(r.Header.Get(hdrBind))
	relayed := valid && !ok && len(cb) == bindLen && !bytes.Equal(cb, bind) && subtle.ConstantTimeCompare([]byte(in.mac(code, cb)), []byte(in.MAC)) == 1
	if valid && !ok && !relayed {
		if m.tries++; m.tries >= 5 {
			m.code = "" // zu viele Fehlversuche: Code verworfen
		}
	}
	m.mu.Unlock()
	if relayed {
		m.d.Log.Warn("peer pairing rejected (tls binding)", "ip", r.RemoteAddr)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": ErrTLSBinding.Error()})
		return
	}
	if !ok {
		m.d.Log.Warn("peer pairing rejected (code)", "ip", r.RemoteAddr)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "code wrong or expired"})
		return
	}
	own, port := m.ClusterAccount(r.Context()), m.httpsPort()
	switch {
	case port <= 0:
		writeJSON(w, http.StatusConflict, map[string]string{"error": ErrNoHTTPS.Error()})
		return
	case !compatible(in.AccountID, own): // gleicher Account oder eine Seite ohne (0); nie zwei verschiedene
		m.d.Log.Warn("peer pairing rejected (account)", "node", in.Name, "account", in.AccountID)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "account mismatch"})
		return
	case in.NodeID == m.d.NodeID() || in.NodeID == "":
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot pair with itself"})
		return
	}
	m.mu.Lock()
	if m.code != code {
		m.mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "code wrong or expired"})
		return
	}
	m.code = "" // einmal gueltig, erst nach allen Pruefungen verbraucht
	m.mu.Unlock()
	existing, _ := m.Members(r.Context())
	url := httpsURL(in.URL)
	if url == "" { // Rueckfall: Absender-Adresse mit ihrem HTTPS-Port
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		url = "https://" + net.JoinHostPort(ip, strconv.Itoa(in.HTTPSPort))
	}
	newcomer := Member{NodeID: in.NodeID, Name: in.Name, URL: url, PubKey: in.PubKey, AccountID: in.AccountID}
	if err := m.upsert(r.Context(), newcomer, m.d.NodeID()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	m.activate(r.Context(), in.NodeID, in.AccountID)
	// eigene Adresse: so, wie die neue Node diese gerade per TLS erreicht hat
	out := pairMsg{NodeID: m.d.NodeID(), Name: m.d.NodeName(), URL: httpsURL(r.Host), PubKey: m.PublicKey(), AccountID: own,
		Version: m.d.Version, HTTPSPort: port, Nonce: in.Nonce}
	for _, x := range existing {
		if x.NodeID != in.NodeID && !x.Suspended() {
			out.Members = append(out.Members, Member{NodeID: x.NodeID, Name: x.Name, URL: x.URL, PubKey: x.PubKey, AccountID: x.AccountID})
		}
	}
	out.MAC = out.mac(code, bind)
	m.d.Log.Info("node joined cluster", "node", in.Name, "url", url)
	m.auditPeer(r.Context(), in.Name, "peer.joined", in.Name, url)
	go m.gossip(context.Background(), memberOp{Op: "add", Member: newcomer}, in.NodeID) // die anderen lernen die neue Node kennen
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------- Mitglieder verteilen

type memberOp struct {
	Op     string `json:"op"` // add, remove
	Member Member `json:"member"`
}

// gossip schickt eine Aenderung der Mitglieder an alle (ausser skip). Ausgesetzte Mitglieder erfahren nur, dass
// sie bzw. diese Node den Cluster verlassen.
func (m *Manager) gossip(ctx context.Context, op memberOp, skip string) {
	list, err := m.Members(ctx)
	if err != nil {
		return
	}
	self := m.d.NodeID()
	for _, x := range list {
		bye := op.Op == "remove" && (op.Member.NodeID == x.NodeID || op.Member.NodeID == self)
		if x.NodeID == skip || x.Suspended() && !bye {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := m.callAny(cctx, x, http.MethodPost, "/peer/v1/members", op, nil, bye); err != nil {
			m.d.Log.Warn("peer member update not delivered", "to", x.Name, "op", op.Op, "err", err)
		}
		cancel()
	}
}

func (m *Manager) handleMembers(w http.ResponseWriter, r *http.Request, from *Member, body []byte) {
	var op memberOp
	if json.Unmarshal(body, &op) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	ctx := r.Context()
	switch op.Op {
	case "add":
		if !compatible(op.Member.AccountID, m.ClusterAccount(ctx)) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "account mismatch"})
			return
		}
		if known, _ := m.member(ctx, op.Member.NodeID); known == nil && op.Member.NodeID != m.d.NodeID() {
			m.auditPeer(ctx, from.Name, "peer.member_added", op.Member.Name, op.Member.URL)
		}
		_ = m.upsert(ctx, op.Member, from.NodeID)
	case "remove":
		if op.Member.NodeID == m.d.NodeID() { // diese Node wurde entfernt: Gruppe verlassen
			_, _ = m.db.ExecContext(ctx, `DELETE FROM peer_members`)
			m.d.Log.Warn("removed from local group", "by", from.Name)
			m.auditPeer(r.Context(), from.Name, "peer.removed_by", from.Name, "")
		} else {
			if known, _ := m.member(ctx, op.Member.NodeID); known != nil {
				m.auditPeer(ctx, from.Name, "peer.member_removed", known.Name, "")
			}
			_ = m.remove(ctx, op.Member.NodeID)
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown op"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Remove nimmt eine Node aus der Gruppe (alle anderen und die Node selbst erfahren es).
func (m *Manager) Remove(ctx context.Context, nodeID string) error {
	x, err := m.member(ctx, nodeID)
	if err != nil || x == nil {
		return err
	}
	m.gossip(ctx, memberOp{Op: "remove", Member: Member{NodeID: nodeID}}, "")
	return m.remove(ctx, nodeID)
}

// Leave verlaesst die Gruppe.
func (m *Manager) Leave(ctx context.Context) error {
	m.gossip(ctx, memberOp{Op: "remove", Member: Member{NodeID: m.d.NodeID()}}, "")
	_, err := m.db.ExecContext(ctx, `DELETE FROM peer_members`)
	return err
}

// auditPeer schreibt eine Aenderung, die eine andere Node der Gruppe ausgeloest hat, ins Audit-Log.
func (m *Manager) auditPeer(ctx context.Context, by, action, target, details string) {
	if err := m.d.Core.Audit(context.WithoutCancel(ctx), store.AuditEntry{Actor: "node:" + by, Action: action, Target: target, Details: details, Origin: "peer"}); err != nil {
		m.d.Log.Error("audit write failed", "err", err)
	}
}
