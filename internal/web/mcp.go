package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/mcp"
	"github.com/ipv64net/node64/internal/store"
)

// MCP-Schnittstelle (KI-Anwendungen, docs/MCP.md): /mcp auf dem Web-Port, Schalter in den Einstellungen
// (Standard aus = 404), nur aus privaten Netzen (sonst 403), eigene Schluessel mit Rechten je Bereich,
// Rate-Limit je Schluessel. Die Werkzeuge (internal/mcp) rufen die vorhandenen API-Handler in-process auf.

const (
	setMCPEnabled = "mcp.enabled"
	mcpRate       = 60 // Aufrufe je Minute und Schluessel
	ctxMCPKey     = ctxKey(100)
)

func (s *Server) mcpRoutes() {
	s.mcpCounter = mcp.NewCounter()
	s.mcpLimit = newIPLimiter(mcpRate, mcpRate)
	s.mcpHandler = mcp.NewHandler(mcp.Options{Backend: mcpBackend{s}, Version: s.Version, Counter: s.mcpCounter, Logger: s.log.With("module", "mcp")})
	s.mux.HandleFunc("/mcp", s.mcpServe)
	s.mux.Handle("GET /settings/mcp", s.auth(s.mcpSettings))
	s.mux.Handle("POST /settings/mcp", s.auth(s.mcpSettingsSave))
	s.mux.Handle("POST /settings/mcp/keys", s.auth(s.mcpKeyCreate))
	s.mux.Handle("POST /settings/mcp/keys/{id}/delete", s.auth(s.mcpKeyDelete))
}

func (s *Server) mcpEnabled(ctx context.Context) bool {
	return s.Store.SettingOr(ctx, setMCPEnabled, "0") == "1"
}

// mcpPrivateSource: Absender und alle Weiterleitungs-Koepfe muessen aus privaten Netzen kommen. Koepfe von aussen
// koennen den Zugang nie oeffnen, nur sperren (z. B. PROXY64 bzw. ein Reverse-Proxy reicht eine oeffentliche
// Adresse in X-Forwarded-For weiter). Kam die Anfrage ueber PROXY64 (fester Kopf X-Node64-Proxy), muss eine
// weitergereichte Client-Adresse da sein: die erweiterten Einstellungen eines Proxy-Hosts koennen
// X-Forwarded-For/X-Real-IP entfernen, dann saehe ein Besucher aus dem Internet sonst privat aus.
func mcpPrivateSource(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !lanOnly(ip.Unmap()) {
		return false
	}
	var fwd []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		fwd = append(fwd, strings.Split(h, ",")...)
	}
	fwd = append(fwd, r.Header.Values("X-Real-Ip")...)
	for _, h := range r.Header.Values("Forwarded") {
		for _, part := range strings.FieldsFunc(h, func(c rune) bool { return c == ',' || c == ';' }) {
			if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && strings.EqualFold(k, "for") {
				v = strings.Trim(v, `"`)
				if strings.HasPrefix(v, "[") {
					v = strings.TrimPrefix(v[:max(strings.Index(v, "]"), 1)], "[")
				} else if h, _, err := net.SplitHostPort(v); err == nil {
					v = h
				}
				fwd = append(fwd, v)
			}
		}
	}
	n := 0
	for _, f := range fwd {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			if h, _, err2 := net.SplitHostPort(f); err2 == nil {
				a, err = netip.ParseAddr(h)
			}
		}
		if err != nil || !lanOnly(a.Unmap()) {
			return false
		}
		n++
	}
	return n > 0 || r.Header.Get(mcpProxyHeader) == ""
}

// mcpProxyHeader setzt PROXY64 bei jeder weitergeleiteten Anfrage (internal/cdn64, nicht ueberschreibbar).
const mcpProxyHeader = "X-Node64-Proxy"

// mcpBatch: Rumpf ist ein JSON-RPC-Batch (Array). Das SDK nimmt Batches bei alten Protokoll-Versionen noch an;
// sie wuerden das Rate-Limit je Anfrage umgehen (MCP 2025-06-18 hat Batches abgeschafft). Der Rumpf bleibt lesbar.
func mcpBatch(r *http.Request) bool {
	if r.Method != http.MethodPost || r.Body == nil {
		return false
	}
	br := bufio.NewReader(r.Body)
	r.Body = struct {
		io.Reader
		io.Closer
	}{br, r.Body}
	for {
		b, err := br.Peek(1)
		if err != nil {
			return false
		}
		switch b[0] {
		case ' ', '\t', '\r', '\n':
			_, _ = br.ReadByte()
		default:
			return b[0] == '['
		}
	}
}

func mcpErr(w http.ResponseWriter, status int, msg string) {
	writeErr(w, status, msg)
}

// mcpServe prueft Schalter, Quelle, Schluessel und Rate-Limit und gibt an den MCP-Handler weiter.
func (s *Server) mcpServe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.mcpEnabled(ctx) {
		mcpErr(w, http.StatusNotFound, "not found")
		return
	}
	ip := s.clientIP(r)
	if !mcpPrivateSource(r) {
		s.log.Warn("mcp request from public address rejected", "ip", ip, "remote", r.RemoteAddr)
		mcpErr(w, http.StatusForbidden, "the MCP interface is only available from private networks")
		return
	}
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	tok = strings.TrimSpace(tok)
	if !ok || tok == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="node64-mcp"`)
		mcpErr(w, http.StatusUnauthorized, "MCP key required (Authorization: Bearer mcp64_...)")
		return
	}
	lk := "mcpkey:" + ipKey(ip)
	if wait := s.limiter.retryAfter(lk); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		mcpErr(w, http.StatusTooManyRequests, "too many invalid MCP keys, try again later")
		return
	}
	key, err := s.Store.MCPKeyByValue(ctx, tok)
	var u *store.User
	if err == nil && key != nil {
		u, err = s.Store.UserByID(ctx, key.UserID)
	}
	if err != nil || key == nil || u == nil {
		s.limiter.fail(lk)
		s.log.Warn("invalid mcp key", "ip", ip)
		w.Header().Set("WWW-Authenticate", `Bearer realm="node64-mcp", error="invalid_token"`)
		mcpErr(w, http.StatusUnauthorized, "invalid MCP key")
		return
	}
	if !s.mcpLimit.allow("key:" + strconv.FormatInt(key.ID, 10)) {
		w.Header().Set("Retry-After", "5")
		mcpErr(w, http.StatusTooManyRequests, fmt.Sprintf("rate limit: %d requests per minute per MCP key", mcpRate))
		return
	}
	if mcpBatch(r) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"jsonrpc": "2.0", "id": nil,
			"error": map[string]any{"code": -32600, "message": "JSON-RPC batch requests are not supported, send one request per HTTP call"}})
		return
	}
	if time.Since(key.LastUsedAt) > 30*time.Second || key.LastIP != ip {
		_ = s.Store.TouchMCPKey(ctx, key.ID, ip)
	}
	id := mcp.Identity{KeyID: key.ID, KeyName: key.Name, KeyHint: key.Hint, UserID: u.ID, IP: ip, Read: key.ReadAreas()}
	s.mcpHandler.ServeHTTP(w, r.WithContext(mcp.WithIdentity(ctx, id)))
}

// ---------------------------------------------------------------- Backend fuer die Werkzeuge

type mcpBackend struct{ s *Server }

// respRecorder nimmt die Antwort eines API-Handlers im Speicher auf (hoechstens 16 MB).
type respRecorder struct {
	h      http.Header
	status int
	buf    bytes.Buffer
}

func (r *respRecorder) Header() http.Header { return r.h }
func (r *respRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}
func (r *respRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	if r.buf.Len()+len(b) > 16<<20 {
		return 0, errors.New("response too large")
	}
	return r.buf.Write(b)
}

// Get ruft einen GET-Pfad der lokalen API in-process auf: gleicher Router, gleiche Handler und Pruefungen,
// angemeldet als Inhaber des Schluessels (wie ein API-Key).
func (b mcpBackend) Get(ctx context.Context, id mcp.Identity, path string, q url.Values) (status int, body []byte, err error) {
	s := b.s
	if !strings.HasPrefix(path, "/api/") {
		return 0, nil, errors.New("only /api/ paths")
	}
	u, err := s.Store.UserByID(ctx, id.UserID)
	if err != nil || u == nil {
		return 0, nil, errors.New("key owner not found")
	}
	target := path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	ctx = context.WithValue(ctx, ctxUser, u)
	ctx = context.WithValue(ctx, ctxMCPKey, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, err
	}
	req.RemoteAddr = net.JoinHostPort(id.IP, "0")
	req.Host = "localhost"
	req.Header.Set("Accept", "application/json")
	rec := &respRecorder{h: http.Header{}}
	func() {
		defer func() {
			if p := recover(); p != nil {
				s.log.Error("panic in api handler (mcp)", "path", path, "err", p)
				rec.status, err = http.StatusInternalServerError, errors.New("internal error")
			}
		}()
		s.mux.ServeHTTP(rec, req)
	}()
	if err != nil {
		return 0, nil, err
	}
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	return rec.status, rec.buf.Bytes(), nil
}

// Available: laeuft das Modul des Bereichs bzw. gibt es den Teil des Kerns.
func (b mcpBackend) Available(area string) bool {
	s := b.s
	switch area {
	case mcp.AreaNode, mcp.AreaAudit:
		return true
	case mcp.AreaCerts:
		return s.Certs != nil
	case mcp.AreaNotifications:
		return s.Notify != nil
	}
	if m := mcp.ModuleOf[area]; m != "" {
		return s.Modules.IsRunning(m)
	}
	return false
}

// Audit: jeder Werkzeugaufruf (Bereich mcp im Audit-Log).
func (b mcpBackend) Audit(ctx context.Context, id mcp.Identity, tool, params string, callErr error) {
	actor := "-"
	if u, err := b.s.Store.UserByID(ctx, id.UserID); err == nil && u != nil {
		actor = u.Username
	}
	details := "ok"
	if callErr != nil {
		details = "error: " + truncate(callErr.Error(), 150)
	}
	if params != "" {
		details += " " + params
	}
	b.s.auditEntry(context.WithoutCancel(ctx), store.AuditEntry{Actor: actor, Action: "mcp.call", Target: tool, Details: truncate(details, 300), IP: id.IP,
		Origin: mcpOrigin(id.KeyName, id.KeyHint)})
}

func mcpOrigin(name, hint string) string {
	o := "mcp:" + name
	if hint != "" {
		o += " (" + hint + ")"
	}
	return o
}

// ---------------------------------------------------------------- Einstellungen › KI-Schnittstelle (MCP)

type mcpArea struct {
	Name      string
	Available bool
}

type mcpData struct {
	Enabled  bool
	URL      string
	Keys     []store.MCPKey
	Areas    []mcpArea
	NewKey   string
	Snippets map[string]string
	ClientIP string
	Private  bool // diese Anfrage kommt aus einem privaten Netz
}

func (s *Server) mcpView(r *http.Request, newKey string) *View {
	v := s.view(r, "mcp.title")
	d := mcpData{Enabled: s.mcpEnabled(r.Context()), URL: v.Scheme + "://" + v.Host + "/mcp", NewKey: newKey, ClientIP: s.clientIP(r), Private: mcpPrivateSource(r)}
	d.Keys, _ = s.Store.MCPKeys(r.Context(), v.User.ID)
	b := mcpBackend{s}
	for _, a := range mcp.Areas {
		d.Areas = append(d.Areas, mcpArea{Name: a, Available: b.Available(a)})
	}
	key := newKey
	if key == "" {
		key = "<MCP-KEY>"
	}
	d.Snippets = mcpSnippets(d.URL, key)
	v.Data = d
	return v
}

// mcpSnippets: fertige Konfiguration je Anwendung (docs/MCP.md).
func mcpSnippets(u, key string) map[string]string {
	auth := "Bearer " + key
	js := func(v any) string {
		b, _ := json.MarshalIndent(v, "", "  ")
		return string(b)
	}
	return map[string]string{
		"claude_code": fmt.Sprintf("claude mcp add --transport http node64 %s --header \"Authorization: %s\"", u, auth),
		"cursor":      js(map[string]any{"mcpServers": map[string]any{"node64": map[string]any{"url": u, "headers": map[string]string{"Authorization": auth}}}}),
		"vscode":      js(map[string]any{"servers": map[string]any{"node64": map[string]any{"type": "http", "url": u, "headers": map[string]string{"Authorization": auth}}}}),
		"claude_desktop": js(map[string]any{"mcpServers": map[string]any{"node64": map[string]any{"command": "npx",
			"args": []string{"-y", "mcp-remote", u, "--header", "Authorization:${NODE64_AUTH}"}, "env": map[string]string{"NODE64_AUTH": auth}}}}),
	}
}

func (s *Server) mcpSettings(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "mcp", s.mcpView(r, ""))
}

func (s *Server) mcpSettingsSave(w http.ResponseWriter, r *http.Request) {
	on := r.PostFormValue("enabled") == "1"
	if err := s.Store.SetSetting(r.Context(), setMCPEnabled, map[bool]string{true: "1", false: "0"}[on]); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "mcp.settings", "", fmt.Sprintf("enabled=%v", on))
	v := s.view(r, "mcp.title")
	s.flash(w, r, "success", v.T("common.saved"))
	http.Redirect(w, r, "/settings/mcp", http.StatusSeeOther)
}

func (s *Server) mcpKeyCreate(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	name := strings.TrimSpace(r.PostFormValue("name"))
	var scopes []string
	for _, a := range r.PostForm["area"] {
		if mcp.ValidArea(a) {
			scopes = append(scopes, a+":read")
		}
	}
	if name == "" || len(name) > 100 || len(scopes) == 0 {
		v := s.view(r, "mcp.title")
		s.flash(w, r, "danger", v.T("mcp.key_invalid"))
		http.Redirect(w, r, "/settings/mcp#keys", http.StatusSeeOther)
		return
	}
	key, k, err := s.Store.NewMCPKey(r.Context(), u.ID, name, scopes)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "mcp.key_create", name, k.Hint+" "+strings.Join(k.ReadAreas(), ","))
	v := s.mcpView(r, key) // nur in dieser Antwort sichtbar
	v.Flash = &Flash{Kind: "success", Text: v.T("mcp.key_created")}
	s.render(w, r, http.StatusOK, "mcp", v)
}

func (s *Server) mcpKeyDelete(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var name string
	if keys, err := s.Store.MCPKeys(r.Context(), u.ID); err == nil {
		for _, k := range keys {
			if k.ID == id {
				name = k.Name + " (" + k.Hint + ")"
			}
		}
	}
	deleted, err := s.Store.DeleteMCPKey(r.Context(), u.ID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v := s.view(r, "mcp.title")
	if !deleted {
		s.flash(w, r, "warning", v.T("apikey.not_found"))
		http.Redirect(w, r, "/settings/mcp#keys", http.StatusSeeOther)
		return
	}
	s.audit(r, "mcp.key_revoke", name, "")
	s.flash(w, r, "success", v.T("mcp.key_revoked"))
	http.Redirect(w, r, "/settings/mcp#keys", http.StatusSeeOther)
}
