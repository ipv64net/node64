package environment

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/store"
)

// Gebundene Endpunkte fuer hinzugefuegte Nodes (ohne Sitzung, wie /peer/*): POST /peer/v2/env/status (Name, Version,
// Update) und POST /peer/v2/env/ticket (Anmelde-Ticket fuer den Benutzer des Zugangs). Die oeffnende Node A signiert
// mit dem aus dem Geheimnis abgeleiteten Schluessel ueber Pfad, Zeit, Nonce, Kennung von B, Bindung an die
// TLS-Verbindung und SHA-256 des Bodys; B signiert die Antwort mit seinem Node-Schluessel (peer.HandleBound), A
// prueft sie gegen den oeffentlichen Schluessel aus dem Zugangsschluessel. Fehlversuche begrenzt die Web-Schicht wie
// die Anmeldung (AuthFailed).

const (
	PathStatus = "/peer/v2/env/status"
	PathTicket = "/peer/v2/env/ticket"

	hdrKey  = "X-Node64-Env-Key"
	hdrTime = "X-Node64-Env-Time"
	hdrSig  = "X-Node64-Env-Sig"

	timeSkew      = 5 * time.Minute
	statusTimeout = 3 * time.Second
)

var nodeIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

func envMsg(path, ts, nonce, target string, bind, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte("node64-env-req\n" + path + "\n" + ts + "\n" + nonce + "\n" + target + "\n" + hex.EncodeToString(bind) + "\n" + hex.EncodeToString(h[:]))
}

// RemoteStatus ist die Antwort auf /peer/v2/env/status.
type RemoteStatus struct {
	NodeID  string `json:"node_id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Update  string `json:"update,omitempty"` // neuere Version verfuegbar
	User    string `json:"user,omitempty"`   // Benutzer des Zugangs
}

// remoteTicketReq schickt A an /peer/v2/env/ticket.
type remoteTicketReq struct {
	Role     string `json:"role"`
	Back     string `json:"back,omitempty"`
	FromNode string `json:"from_node,omitempty"`
	FromName string `json:"from_name,omitempty"`
}

// RemoteError: die andere Node hat die Anfrage abgelehnt (Status und Text aus ihrer signierten Antwort).
type RemoteError struct {
	Status int
	Msg    string
}

func (e *RemoteError) Error() string { return fmt.Sprintf("HTTP %d %s", e.Status, e.Msg) }

// remotePost schickt eine gebundene, mit dem Zugangsschluessel signierte Anfrage an eine hinzugefuegte Node.
func (s *Service) remotePost(ctx context.Context, n *AddedNode, path string, in, out any) error {
	k, err := s.key(n)
	if err != nil {
		return err
	}
	if k == nil {
		return ErrInvalidKey
	}
	c, err := peer.DialBound(ctx, n.URL, k.NodeID, k.PubKey)
	if err != nil {
		return err
	}
	defer c.Close()
	body, _ := json.Marshal(in)
	priv := accessPair(k.Secret)
	pub := accessPub(k.Secret)
	st, b, err := c.Post(ctx, path, body, func(nonce string) http.Header {
		ts := strconv.FormatInt(s.d.Now().Unix(), 10)
		h := http.Header{}
		h.Set(hdrKey, pub)
		h.Set(hdrTime, ts)
		h.Set(hdrSig, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, envMsg(path, ts, nonce, k.NodeID, c.Bind(), body))))
		return h
	})
	if err != nil {
		return err
	}
	if st != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		return &RemoteError{Status: st, Msg: e.Error}
	}
	return json.Unmarshal(b, out)
}

// AddedStatus ist der Status einer hinzugefuegten Node fuer die Liste.
type AddedStatus struct {
	Online  bool
	Name    string // Name, den die Node meldet (nur mit Schluessel)
	Version string
	Update  string
	KeyOK   bool   // Schluessel gilt (Zugang vorhanden, Benutzer nicht gesperrt)
	KeyErr  string // warum nicht ("" = kein Schluessel oder gilt)
	Denied  bool   // die andere Node hat den Schluessel abgelehnt (status.go fragt dann eine Weile nicht neu)
}

// Status fragt eine hinzugefuegte Node ab (Zeitlimit 3 s): mit Schluessel ueber /peer/v2/env/status, sonst
// /api/health ohne Zertifikatspruefung (nur Erreichbarkeit und Version, nicht vertrauenswuerdig).
func (s *Service) Status(ctx context.Context, n *AddedNode) AddedStatus {
	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	var st AddedStatus
	if n.HasKey {
		var rs RemoteStatus
		err := s.remotePost(ctx, n, PathStatus, struct{}{}, &rs)
		var re *RemoteError
		switch {
		case err == nil:
			return AddedStatus{Online: true, Name: rs.Name, Version: rs.Version, Update: rs.Update, KeyOK: true}
		case errors.As(err, &re):
			st.Online, st.KeyErr = true, re.Msg // erreichbar und echt, aber Zugang abgelehnt
			st.Denied = re.Status == http.StatusForbidden || re.Status == http.StatusUnauthorized
		default:
			st.KeyErr = err.Error()
		}
	}
	if v, ok := health(ctx, n.URL); ok {
		st.Online = true
		if st.Version == "" {
			st.Version = v
		}
	}
	return st
}

// healthClient fragt /api/health ab (selbst signierte Zertifikate sind bei Nodes ueblich; die Antwort zaehlt nur fuer
// die Anzeige).
var healthClient = &http.Client{
	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // nur Anzeige
		Proxy: nil, ResponseHeaderTimeout: statusTimeout},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func health(ctx context.Context, base string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/health", nil)
	if err != nil {
		return "", false
	}
	resp, err := healthClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	var h struct {
		Version string `json:"version"`
		Status  string `json:"status"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&h) != nil || h.Status == "" {
		return "", false
	}
	return cleanText(h.Version, 40), true
}

// RequestRemoteTicket fragt auf der oeffnenden Node ein Ticket bei einer hinzugefuegten Node an. Nur der Benutzer,
// der den Schluessel eingetragen hat (uid), meldet sich damit an.
func (s *Service) RequestRemoteTicket(ctx context.Context, n *AddedNode, uid, role, back string) (string, error) {
	if !n.HasKey || uid == "" || uid != n.OwnerUID {
		return "", ErrAccessDenied
	}
	req := remoteTicketReq{Role: role, Back: back}
	if s.d.NodeID != nil {
		req.FromNode = s.d.NodeID()
	}
	if s.d.NodeName != nil {
		req.FromName = s.d.NodeName()
	}
	var out TicketResponse
	if err := s.remotePost(ctx, n, PathTicket, req, &out); err != nil {
		var re *RemoteError
		if errors.As(err, &re) && (re.Status == http.StatusForbidden || re.Status == http.StatusUnauthorized) {
			s.markDenied(n, re.Msg)
		}
		return "", err
	}
	if len(out.Ticket) < 40 {
		return "", errors.New("environment: invalid ticket")
	}
	return out.Ticket, nil
}

// RemoteResult ist die Antwort auf eine gebundene Anfrage (AuthFailed: Fehlversuch fuer die Drosselung).
type RemoteResult struct {
	Status     int
	Body       any
	AuthFailed bool
}

func deny(status int, msg string, authFailed bool) RemoteResult {
	return RemoteResult{Status: status, Body: map[string]string{"error": msg}, AuthFailed: authFailed}
}

// KeyID ist der Pruefwert, mit dem sich eine gebundene Anfrage ausweist (fuer die Drosselung je Schluessel).
func KeyID(h http.Header) string {
	k := h.Get(hdrKey)
	if len(k) > 64 {
		k = k[:64]
	}
	return k
}

// HandleRemote beantwortet eine gebundene Anfrage einer hinzugefuegten Node (path: PathStatus oder PathTicket, bind:
// Exporter der eigenen TLS-Verbindung, ip fuer Audit-Log; quiet: abgelehnte Schluessel nicht mehr protokollieren,
// weil von dieser IP schon viele kamen).
func (s *Service) HandleRemote(ctx context.Context, path string, h http.Header, nonce string, bind, body []byte, ip string, quiet bool) RemoteResult {
	a, err := s.verifyRemote(ctx, path, h, nonce, bind, body)
	if err != nil {
		if errors.Is(err, ErrAccessDenied) {
			if quiet {
				return deny(http.StatusForbidden, ErrAccessDenied.Error(), true)
			}
			s.d.Log.Warn("environment access denied", "path", path, "ip", ip)
			s.auditRemote(ctx, "-", "environment.ticket_denied", "", "access key unknown, revoked or signature invalid", ip)
			return deny(http.StatusForbidden, ErrAccessDenied.Error(), true)
		}
		return deny(http.StatusInternalServerError, "internal error", false)
	}
	u, err := s.d.Store.UserByUID(ctx, a.UserUID)
	if err != nil {
		return deny(http.StatusInternalServerError, "internal error", false)
	}
	var req remoteTicketReq
	if path == PathTicket && json.Unmarshal(body, &req) != nil {
		return deny(http.StatusBadRequest, "invalid request", false)
	}
	fromNode, fromName := "", cleanName(req.FromName)
	if nodeIDRe.MatchString(req.FromNode) {
		fromNode = req.FromNode
	}
	if fromName == "" {
		fromName = a.Name
	}
	if u == nil || u.Disabled {
		why := ErrUnknownUser
		if u != nil {
			why = ErrLocked
		}
		s.d.Log.Warn("environment access denied", "access", a.Name, "err", why, "ip", ip)
		s.auditRemote(ctx, "access:"+a.Name, "environment.ticket_denied", fromName, why.Error(), ip)
		return deny(http.StatusForbidden, why.Error(), false)
	}
	switch path {
	case PathStatus:
		st := RemoteStatus{Name: "Node64", User: u.Username}
		if s.d.NodeID != nil {
			st.NodeID = s.d.NodeID()
		}
		if s.d.NodeName != nil {
			st.Name = s.d.NodeName()
		}
		st.Version = s.d.Version
		var l struct {
			Version string `json:"version"`
			Newer   bool   `json:"newer"`
		}
		if json.Unmarshal([]byte(s.d.Store.SettingOr(ctx, "updates.latest", "")), &l) == nil && l.Newer {
			st.Update = l.Version
		}
		return RemoteResult{Status: http.StatusOK, Body: st}
	case PathTicket:
		tok, err := s.addTicket(&Ticket{UID: u.UID, Role: MinRole(req.Role, s.d.Store.EffectiveRole(ctx, u)), FromNode: fromNode, FromName: fromName,
			Back: cleanBack(req.Back), AccessID: a.ID})
		if err != nil {
			return deny(http.StatusServiceUnavailable, err.Error(), false)
		}
		s.touchAccess(ctx, a.ID, fromNode, fromName)
		return RemoteResult{Status: http.StatusOK, Body: TicketResponse{Ticket: tok}}
	}
	return deny(http.StatusNotFound, "not found", false)
}

// verifyRemote prueft Zugang, Zeit, Nonce und Signatur (ErrAccessDenied fuer alles, was der Aufrufer falsch macht).
func (s *Service) verifyRemote(ctx context.Context, path string, h http.Header, nonce string, bind, body []byte) (*Access, error) {
	pubS := h.Get(hdrKey)
	pub, err := base64.RawURLEncoding.DecodeString(pubS)
	sig, err2 := base64.StdEncoding.DecodeString(h.Get(hdrSig))
	ts := h.Get(hdrTime)
	sec, err3 := strconv.ParseInt(ts, 10, 64)
	if err != nil || err2 != nil || err3 != nil || len(pub) != ed25519.PublicKeySize || len(bind) == 0 ||
		s.d.Now().Sub(time.Unix(sec, 0)).Abs() > timeSkew || s.d.NodeID == nil {
		return nil, ErrAccessDenied
	}
	a, err := s.accessByPub(ctx, pubS)
	if err != nil {
		return nil, err
	}
	if a == nil || !ed25519.Verify(ed25519.PublicKey(pub), envMsg(path, ts, nonce, s.d.NodeID(), bind, body), sig) || !s.nonceFresh(nonce) {
		return nil, ErrAccessDenied
	}
	return a, nil
}

// nonceFresh: Nonce noch nicht gesehen (gemeinsamer, hart begrenzter Speicher aus peer).
func (s *Service) nonceFresh(n string) bool { return s.nc.Fresh(n, s.d.Now()) }

func (s *Service) auditRemote(ctx context.Context, actor, action, target, details, ip string) {
	if err := s.d.Store.Audit(context.WithoutCancel(ctx), store.AuditEntry{Actor: actor, Action: action, Target: target, Details: details, IP: ip, Origin: "peer"}); err != nil {
		s.d.Log.Error("audit write failed", "err", err)
	}
}

// cleanBack: Rueckweg nur als Ursprung der oeffnenden Node plus /environment (http(s), ohne Zugangsdaten, Abfrage
// oder anderen Pfad; "" sonst).
func cleanBack(raw string) string {
	if len(raw) > 512 || !strings.HasSuffix(raw, "/environment") {
		return ""
	}
	o, err := NormURL(strings.TrimSuffix(raw, "/environment"))
	if err != nil || !strings.Contains(raw, "://") || o+"/environment" != raw {
		return ""
	}
	return raw
}

// SameHost: gleicher Host samt Port (das Schema zaehlt nicht: hinter einem Proxy mit TLS bildet die oeffnende Node
// ihre Adresse mit http://, der Browser schickt https://).
func SameHost(a, b string) bool {
	pa, err1 := url.Parse(a)
	pb, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && pa.Host != "" && strings.EqualFold(pa.Host, pb.Host)
}
