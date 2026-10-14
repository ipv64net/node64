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
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Signierte Anfragen zwischen den Nodes der Gruppe: Kopfzeilen mit Absenderin, Zeit und Account, Signatur
// ueber Methode, Pfad, Zeit, Account und SHA-256 des Bodys.
const (
	hdrNode = "X-Node64-Peer"
	hdrTime = "X-Node64-Time"
	hdrAcc  = "X-Node64-Account"
	hdrSig  = "X-Node64-Sig"
	maxBody = 8 << 20
)

func sigMsg(method, path, ts, acc string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte(method + "\n" + path + "\n" + ts + "\n" + acc + "\n" + hex.EncodeToString(h[:]))
}

// call schickt eine signierte Anfrage an eine Node der Gruppe.
func (m *Manager) call(ctx context.Context, x Member, method, path string, in, out any) error {
	acc := m.d.AccountID()
	if acc <= 0 {
		return ErrNoAccount
	}
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(x.URL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ts, accS := strconv.FormatInt(time.Now().Unix(), 10), strconv.FormatInt(acc, 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "node64/"+m.d.Version)
	req.Header.Set(hdrNode, m.d.NodeID())
	req.Header.Set(hdrTime, ts)
	req.Header.Set(hdrAcc, accS)
	req.Header.Set(hdrSig, base64.StdEncoding.EncodeToString(ed25519.Sign(m.priv, sigMsg(method, path, ts, accS, body))))
	resp, err := m.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		if resp.StatusCode == http.StatusForbidden && e.Error == "account mismatch" {
			return ErrAccountMismatch
		}
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, e.Error)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// verify prueft eine eingehende signierte Anfrage und liefert die Absenderin.
func (m *Manager) verify(r *http.Request, body []byte) (*Member, int, error) {
	x, err := m.member(r.Context(), r.Header.Get(hdrNode))
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
	accS := r.Header.Get(hdrAcc)
	acc, _ := strconv.ParseInt(accS, 10, 64)
	if own := m.d.AccountID(); own <= 0 || acc != own || x.AccountID != own {
		return nil, http.StatusForbidden, ErrAccountMismatch
	}
	pub, err := base64.StdEncoding.DecodeString(x.PubKey)
	sig, err2 := base64.StdEncoding.DecodeString(r.Header.Get(hdrSig))
	if err != nil || err2 != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(pub), sigMsg(r.Method, r.URL.RequestURI(), ts, accS, body), sig) {
		return nil, http.StatusUnauthorized, errors.New("bad signature")
	}
	return x, 0, nil
}

// Handle prueft die Signatur und ruft h mit der Absenderin und dem Body auf.
func (m *Manager) Handle(h func(w http.ResponseWriter, r *http.Request, from *Member, body []byte)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, maxBody))
		from, code, err := m.verify(r, body)
		if err != nil {
			m.d.Log.Warn("peer request rejected", "node", r.Header.Get(hdrNode), "path", r.URL.Path, "err", err)
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		h(w, r, from, body)
	})
}

// Register haengt die Endpunkte der Gruppe an (ohne Sitzung und CSRF; Signatur bzw. Kopplungscode).
func (m *Manager) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /peer/v1/pair", m.handlePair)
	mux.Handle("GET /peer/v1/ping", m.Handle(func(w http.ResponseWriter, r *http.Request, _ *Member, _ []byte) {
		writeJSON(w, http.StatusOK, pingInfo{NodeID: m.d.NodeID(), Name: m.d.NodeName(), Version: m.d.Version, AccountID: m.d.AccountID(), Linked: m.linkedSelf()})
	}))
	mux.Handle("POST /peer/v1/members", m.Handle(m.handleMembers))
	mux.Handle("GET /peer/v1/changes", m.Handle(m.handleChanges))
	mux.Handle("POST /peer/v1/poke", m.Handle(m.handlePoke))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------- Kopplung

// pairMsg ist Anfrage und Antwort der Kopplung; MAC = HMAC-SHA256(Code, JSON ohne MAC), Nonce der Anfrage
// auch in der Antwort (bindet beide aneinander).
type pairMsg struct {
	NodeID    string   `json:"node_id"`
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	PubKey    string   `json:"pubkey"`
	AccountID int64    `json:"account_id"`
	Version   string   `json:"version"`
	Members   []Member `json:"members,omitempty"`
	Nonce     string   `json:"nonce"`
	MAC       string   `json:"mac"`
}

func (p pairMsg) mac(code string) string {
	p.MAC = ""
	b, _ := json.Marshal(p)
	h := hmac.New(sha256.New, []byte(normCode(code)))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func normCode(c string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
}

const codeChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// StartPairing erzeugt einen Code (10 Minuten, einmal gueltig), mit dem eine weitere Node beitreten kann.
func (m *Manager) StartPairing() (string, time.Time, error) {
	if m.d.AccountID() <= 0 {
		return "", time.Time{}, ErrNoAccount
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

// Join tritt ueber eine Node der Gruppe bei (addr = deren Adresse, selfURL = Adresse dieser Node).
func (m *Manager) Join(ctx context.Context, addr, code, selfURL string) error {
	acc := m.d.AccountID()
	if acc <= 0 {
		return ErrNoAccount
	}
	addr = strings.TrimRight(strings.TrimSpace(addr), "/")
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	req := pairMsg{NodeID: m.d.NodeID(), Name: m.d.NodeName(), URL: strings.TrimRight(strings.TrimSpace(selfURL), "/"), PubKey: m.PublicKey(), AccountID: acc,
		Version: m.d.Version, Nonce: hex.EncodeToString(nonce)}
	req.MAC = req.mac(code)
	body, _ := json.Marshal(req)
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, addr+"/peer/v1/pair", bytes.NewReader(body))
	if err != nil {
		return err
	}
	hr.Header.Set("Content-Type", "application/json")
	resp, err := m.hc.Do(hr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	var out pairMsg
	switch {
	case resp.StatusCode == http.StatusForbidden:
		return ErrAccountMismatch
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrCode
	case resp.StatusCode != http.StatusOK:
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, e.Error)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return err
	}
	if out.Nonce != req.Nonce || subtle.ConstantTimeCompare([]byte(out.mac(code)), []byte(out.MAC)) != 1 {
		return ErrCode // Antwort nicht von einer Node, die den Code kennt
	}
	if out.AccountID != acc {
		return ErrAccountMismatch
	}
	if out.NodeID == m.d.NodeID() {
		return ErrSelf
	}
	if out.URL == "" {
		out.URL = addr
	}
	if err := m.upsert(ctx, Member{NodeID: out.NodeID, Name: out.Name, URL: addr, PubKey: out.PubKey, AccountID: out.AccountID}, m.d.NodeID()); err != nil {
		return err
	}
	for _, x := range out.Members {
		if x.AccountID == acc {
			_ = m.upsert(ctx, x, out.NodeID)
		}
	}
	m.d.Log.Info("joined local group", "via", out.Name, "members", len(out.Members)+1)
	go func() {
		m.pingAll(context.Background())
		m.pullAll(context.Background(), "")
		m.pokeSoon() // die anderen holen den Bestand dieser Node
	}()
	return nil
}

func (m *Manager) handlePair(w http.ResponseWriter, r *http.Request) {
	var in pairMsg
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	m.mu.Lock()
	code, valid := m.code, m.code != "" && time.Now().Before(m.exp)
	ok := valid && subtle.ConstantTimeCompare([]byte(in.mac(code)), []byte(in.MAC)) == 1
	if valid && !ok {
		if m.tries++; m.tries >= 5 {
			m.code = "" // zu viele Fehlversuche: Code verworfen
		}
	}
	m.mu.Unlock()
	if !ok {
		m.d.Log.Warn("peer pairing rejected (code)", "ip", r.RemoteAddr)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "code wrong or expired"})
		return
	}
	own := m.d.AccountID()
	switch {
	case own <= 0:
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no ipv64 account on this node"})
		return
	case in.AccountID != own:
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
	url := in.URL
	if url == "" {
		url = "http://" + strings.Split(r.RemoteAddr, ":")[0]
	}
	newcomer := Member{NodeID: in.NodeID, Name: in.Name, URL: url, PubKey: in.PubKey, AccountID: in.AccountID}
	if err := m.upsert(r.Context(), newcomer, m.d.NodeID()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	out := pairMsg{NodeID: m.d.NodeID(), Name: m.d.NodeName(), URL: scheme + "://" + r.Host, PubKey: m.PublicKey(), AccountID: own, Version: m.d.Version, Nonce: in.Nonce}
	for _, x := range existing {
		if x.NodeID != in.NodeID {
			out.Members = append(out.Members, Member{NodeID: x.NodeID, Name: x.Name, URL: x.URL, PubKey: x.PubKey, AccountID: x.AccountID})
		}
	}
	out.MAC = out.mac(code)
	m.d.Log.Info("node joined local group", "node", in.Name, "url", url)
	go m.gossip(context.Background(), memberOp{Op: "add", Member: newcomer}, in.NodeID) // die anderen lernen die neue Node kennen
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------- Mitglieder verteilen

type memberOp struct {
	Op     string `json:"op"` // add, remove
	Member Member `json:"member"`
}

// gossip schickt eine Aenderung der Mitglieder an alle (ausser skip).
func (m *Manager) gossip(ctx context.Context, op memberOp, skip string) {
	list, err := m.Members(ctx)
	if err != nil {
		return
	}
	for _, x := range list {
		if x.NodeID == skip {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := m.call(cctx, x, http.MethodPost, "/peer/v1/members", op, nil); err != nil {
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
		if op.Member.AccountID != m.d.AccountID() {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "account mismatch"})
			return
		}
		_ = m.upsert(ctx, op.Member, from.NodeID)
	case "remove":
		if op.Member.NodeID == m.d.NodeID() { // diese Node wurde entfernt: Gruppe verlassen
			_, _ = m.db.ExecContext(ctx, `DELETE FROM peer_members`)
			m.d.Log.Warn("removed from local group", "by", from.Name)
		} else {
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
