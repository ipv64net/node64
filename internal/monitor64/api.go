package monitor64

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/monitor64/promscrape"
	"github.com/ipv64net/node64/internal/monitor64/snmp"
	"github.com/ipv64net/node64/internal/monitor64/transport"
	"github.com/ipv64net/node64/internal/monitor64/tsdb"
)

// Lokale JSON-API von Monitor64 unter /api/monitor64/... (Sitzung mit X-CSRF-Token bei Aenderungen – prueft der
// Kern – oder API-Key). Ist das Modul aus: 404 (g.Enabled). Geheimnisse der Zugaenge werden nur geschrieben, nie
// zurueckgegeben ("secret_set"). Jede Aenderung speichert den Akteur in der Tabelle und im Audit-Log.

const maxBody = 1 << 20

// apiError ist eine Fehlerantwort: Code (stabil) und Text in der Sprache des Aufrufers.
type apiError struct {
	status int
	code   string
	args   []any
}

func (e *apiError) Error() string { return e.code }

func errBad(code string, args ...any) *apiError {
	return &apiError{status: http.StatusBadRequest, code: code, args: args}
}

var errNotRunning = &apiError{status: http.StatusServiceUnavailable, code: "not_running"}

// writeJSON kodiert erst in einen Puffer: schlaegt das fehl (z. B. NaN von einem Host), gibt es 500 mit Fehlercode
// statt 200 mit leerem bzw. abgebrochenem Koerper (die Oberflaeche zeigt dann "Interner Fehler").
func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		buf.Reset()
		buf.WriteString(`{"error":"internal","message":""}` + "\n")
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// fail schreibt einen Fehler als JSON {"error": code, "message": text}.
func (m *Module) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
	case errors.Is(err, ErrNotFound):
		ae = &apiError{status: http.StatusNotFound, code: "not_found"}
	default:
		m.log.Warn("monitor64: api", "path", r.URL.Path, "err", err)
		ae = &apiError{status: http.StatusInternalServerError, code: "internal"}
	}
	msg := ae.code
	if m.g.T != nil {
		msg = m.g.T(r, "monitor64.err."+ae.code, ae.args...)
	}
	writeJSON(w, ae.status, map[string]string{"error": ae.code, "message": msg})
}

// decode liest einen JSON-Koerper streng (unbekannte Felder sind ein Fehler).
func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errBad("json", "error", err.Error())
	}
	return nil
}

// actor ermittelt, wer die Anfrage stellt: Benutzer (UID clusterweit, Name, Anmeldeart) oder API-Key (Name).
// Die Anmeldeart (SSO, LDAP) gibt der Kern den Modulen noch nicht weiter; bis dahin "local".
func (m *Module) actor(r *http.Request) Actor {
	a := Actor{Kind: "user", Method: "local"}
	if m.g.Actor != nil {
		a.Name = m.g.Actor(r)
	}
	if m.g.ClientIP != nil {
		a.IP = m.g.ClientIP(r)
	}
	ctx := r.Context()
	if a.Name != "" && a.Name != "-" {
		if u, err := m.st.UserByName(ctx, a.Name); err == nil && u != nil {
			a.UID = u.UID
		}
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer node64_") {
		a.Kind, a.Method = "api", ""
		if k, err := m.st.APIKeyByValue(ctx, strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))); err == nil && k != nil {
			a.Name = k.Name
		}
	}
	return a
}

func (m *Module) audit(r *http.Request, action, target, details string) {
	if m.g.Audit != nil {
		m.g.Audit(r, "monitor64."+action, target, details)
	}
}

// ---------------------------------------------------------------------------------------------------------
// Hosts

// hostIn sind die Felder eines Hosts aus Formular bzw. API.
type hostIn struct {
	Name         string   `json:"name"`
	Address      string   `json:"address"`
	Kind         string   `json:"kind"`
	Group        string   `json:"group"`
	Tags         []string `json:"tags"`
	IntervalSec  int      `json:"interval_sec"`
	Notes        string   `json:"notes"`
	Paused       bool     `json:"paused"`
	AgentAutoUpd *bool    `json:"agent_autoupdate"`
}

var reAddress = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]%]{1,253}$`)

// cleanAddress prueft die Adresse eines Hosts: Hostname, IPv4 oder IPv6 (auch Link-Local mit Zone), wahlweise mit
// Port ("nas:2222", "[2001:db8::1]:2222"). IPv6 ohne Port steht ohne Klammern ("[2001:db8::1]" -> "2001:db8::1");
// mehrere Doppelpunkte ohne Klammern sind immer eine IPv6-Adresse.
func cleanAddress(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if !reAddress.MatchString(s) {
		return "", false
	}
	port := func(p string) bool {
		n, err := strconv.Atoi(p)
		return err == nil && n >= 1 && n <= 65535
	}
	if strings.HasPrefix(s, "[") {
		i := strings.Index(s, "]")
		if i < 0 {
			return "", false
		}
		if a, err := netip.ParseAddr(s[1:i]); err != nil || !a.Is6() {
			return "", false
		}
		if s[i+1:] == "" {
			return s[1:i], true
		}
		return s, strings.HasPrefix(s[i+1:], ":") && port(s[i+2:])
	}
	if strings.ContainsAny(s, "[]") {
		return "", false
	}
	switch strings.Count(s, ":") {
	case 0:
		return s, !strings.Contains(s, "%")
	case 1:
		h, p, _ := strings.Cut(s, ":")
		return s, h != "" && port(p) && !strings.Contains(s, "%")
	}
	a, err := netip.ParseAddr(s)
	return s, err == nil && a.Is6()
}

func cleanText(s string, max int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s))
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max])
	}
	return s
}

func (in *hostIn) apply(h *Host, defInterval int) error {
	h.Name = cleanText(in.Name, 100)
	if h.Name == "" {
		return errBad("name")
	}
	addr, ok := cleanAddress(in.Address)
	if !ok {
		return errBad("address")
	}
	h.Address = addr
	if _, ok := hostKindOf(in.Kind); !ok && in.Kind != "" {
		return errBad("kind")
	}
	if in.Kind != "" { // leer = unveraendert (Aenderung ueber die API ohne Art)
		h.Kind = in.Kind
	}
	h.Group = cleanText(in.Group, 64)
	if len(in.Tags) > 32 {
		return errBad("tags")
	}
	h.Tags = in.Tags
	h.IntervalSec = in.IntervalSec
	if h.IntervalSec == 0 {
		h.IntervalSec = defInterval
	}
	h.Notes = cleanText(in.Notes, 1000)
	h.Paused = in.Paused
	if in.AgentAutoUpd != nil {
		h.AgentAutoUpd = *in.AgentAutoUpd
	}
	return nil
}

// accessIn ist ein Zugang aus Formular bzw. API. Secret leer = unveraendert (bei Aenderung).
type accessIn struct {
	Type        string          `json:"type"`
	Config      json.RawMessage `json:"config"`
	Secret      string          `json:"secret"`
	ClearSecret bool            `json:"clear_secret"`
	NewToken    bool            `json:"new_token"` // Push: neuen Token erzeugen
	HostKey     string          `json:"hostkey"`
	Enabled     *bool           `json:"enabled"`
}

var (
	// reUser: Konto fuer SSH ohne Agent (Linux-Name; steht im angezeigten Befehl fuer authorized_keys und sudoers,
	// dort waeren "\" und "@" Sonderzeichen). reLogin: Konten von Geraeten und APIs (Redfish, TrueNAS, NUT,
	// Prometheus, SNMPv3), auch Verzeichnis-Konten wie user@domain und DOMAIN\user; ":" (Basic-Auth), Leer- und
	// Steuerzeichen bleiben verboten.
	reUser  = regexp.MustCompile(`^[A-Za-z0-9._-]{0,32}$`)
	reLogin = regexp.MustCompile(`^[A-Za-z0-9._@\\-]{0,128}$`)
	reToken = regexp.MustCompile(`^[A-Za-z0-9@!._:-]{0,128}$`)
	reNode  = regexp.MustCompile(`^[A-Za-z0-9._-]{0,64}$`)
	rePin   = regexp.MustCompile(`^([A-Fa-f0-9:]{0,128}|SHA256:[A-Za-z0-9+/]{43}=?)$`) // Zertifikat (hex) bzw. SSH-Host-Key (Docker ssh://)
	reFP    = regexp.MustCompile(`^(SHA256:[A-Za-z0-9+/=]{20,64})?$`)
)

// Grenzen fuer Geheimnisse: Token/Passwort; Docker-Zugangsdaten (TLS-Schluessel, Zertifikat und CA als PEM bzw.
// privater SSH-Schluessel) sind laenger.
const (
	maxSecret       = 4096
	maxSecretDocker = 64 << 10
)

// cleanAccessConfig prueft die Konfiguration eines Zugangs (streng, ohne Geheimnisse) und gibt sie normiert zurueck.
func cleanAccessConfig(typ string, raw json.RawMessage) (json.RawMessage, error) {
	var c accessConfig
	if len(raw) > 0 && string(raw) != "null" {
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return nil, errBad("config", "error", err.Error())
		}
	}
	c.User, c.URL, c.TokenID, c.Node, c.Pin = strings.TrimSpace(c.User), strings.TrimSpace(c.URL), strings.TrimSpace(c.TokenID), strings.TrimSpace(c.Node), strings.TrimSpace(c.Pin)
	switch {
	case c.Port < 0 || c.Port > 65535:
		return nil, errBad("port")
	case !validUser(typ, c.User):
		return nil, errBad("user")
	case !reToken.MatchString(c.TokenID):
		return nil, errBad("token_id")
	case !reNode.MatchString(c.Node):
		return nil, errBad("node")
	case !rePin.MatchString(c.Pin):
		return nil, errBad("pin")
	case len(c.URL) > 512:
		return nil, errBad("url")
	}
	if typ == "prom" {
		if err := promscrape.ValidateCustom(c.Metrics); err != nil {
			return nil, errBad("metrics", "error", err.Error())
		}
		if c.URL != "" {
			if _, err := promscrape.NormalizeURL(c.URL, promscrape.DefaultPort); err != nil {
				return nil, errBad("url")
			}
		}
	} else if len(c.Metrics) > 0 {
		return nil, errBad("metrics", "error", "nur fuer Prometheus")
	}
	c.UPS, c.TLS, c.API = strings.TrimSpace(c.UPS), strings.TrimSpace(c.TLS), strings.TrimSpace(c.API)
	switch {
	case len(c.UPS) > 512 || (typ != "nut" && c.UPS != ""):
		return nil, errBad("ups")
	case c.TLS != "" && (typ != "nut" || (c.TLS != "off" && c.TLS != "require")):
		return nil, errBad("tls")
	case c.API != "" && (typ != "truenas" || (c.API != "jsonrpc" && c.API != "rest")):
		return nil, errBad("api")
	case c.Session && typ != "redfish":
		return nil, errBad("session")
	}
	c.Mode, c.Token = strings.TrimSpace(c.Mode), strings.TrimSpace(c.Token)
	switch {
	case c.Mode != "" && (typ != "agent" || c.Mode != "push"):
		return nil, errBad("mode")
	case c.Token != "" && (c.Mode != "push" || len(c.Token) > 64):
		return nil, errBad("token")
	}
	if err := cleanSNMPConfig(typ, &c); err != nil {
		return nil, err
	}
	if c.URL != "" && typ != "prom" {
		ok := strings.HasPrefix(c.URL, "https://") || strings.HasPrefix(c.URL, "http://")
		switch typ {
		case "nut": // host[:3493] oder nut://
			ok = !strings.Contains(c.URL, "/") || strings.HasPrefix(c.URL, "nut://")
		case "truenas", "redfish": // TrueNAS widerruft ueber http benutzte API-Keys; BMC nur https
			ok = strings.HasPrefix(c.URL, "https://")
		case "snmp": // Adresse des Hosts, Port im Zugang
			ok = false
		}
		if typ == "docker" {
			ok = ok || strings.HasPrefix(c.URL, "unix://") || strings.HasPrefix(c.URL, "tcp://") || strings.HasPrefix(c.URL, "ssh://")
		}
		if !ok {
			return nil, errBad("url")
		}
	}
	b, _ := json.Marshal(c)
	return b, nil
}

// validUser prueft den Benutzernamen je Zugangsart (SNMPv3: hoechstens 32 Byte, RFC 3414).
func validUser(typ, u string) bool {
	switch typ {
	case "ssh", "agent":
		return reUser.MatchString(u)
	case "snmp":
		return len(u) <= 32 && reLogin.MatchString(u)
	}
	return reLogin.MatchString(u)
}

// accessOut ist ein Zugang in API-Antworten: nie das Geheimnis, nur ob eines gesetzt ist.
type accessOut struct {
	UID       string          `json:"uid"`
	Type      string          `json:"type"`
	Config    json.RawMessage `json:"config"`
	HostKey   string          `json:"hostkey,omitempty"`
	Enabled   bool            `json:"enabled"`
	SecretSet bool            `json:"secret_set"`
}

func accessOuts(list []*Access) []accessOut {
	out := make([]accessOut, 0, len(list))
	for _, a := range list {
		out = append(out, accessOut{UID: a.UID, Type: a.Type, Config: a.Config, HostKey: a.HostKey, Enabled: a.Enabled, SecretSet: a.Secret != ""})
	}
	return out
}

// buildAccess setzt die Felder eines Zugangs aus der Eingabe (Geheimnis verschluesselt).
func (m *Module) buildAccess(a *Access, in accessIn, isNew bool) (keepSecret bool, err error) {
	if isNew || in.Type != "" {
		if !validAccessType(in.Type) {
			return false, errBad("access_type")
		}
		a.Type = in.Type
	}
	raw := in.Config
	if !isNew && (len(raw) == 0 || string(raw) == "null") {
		raw = a.Config // Aenderung ohne config: vorhandene Felder bleiben (werden nur neu geprueft)
	}
	cfg, err := cleanAccessConfig(a.Type, raw)
	if err != nil {
		return false, err
	}
	if a.Type == "agent" { // Token des Push-Betriebs: nur gueltige uebernehmen, sonst behalten bzw. neu
		var nc, oc accessConfig
		_ = json.Unmarshal(cfg, &nc)
		_ = json.Unmarshal(a.Config, &oc)
		nc.Token = pushToken(nc.Mode, nc.Token, oc.Token, in.NewToken)
		cfg, _ = json.Marshal(nc)
	}
	a.Config = cfg
	hadSecret := a.Secret != ""
	hk := strings.TrimSpace(in.HostKey)
	switch {
	case hk == "reset" && !isNew:
		a.HostKey = "" // naechster Kontakt merkt den neuen Schluessel (wie hostkey-reset; mit Passwort erst nach Bestaetigung)
	case !reFP.MatchString(hk):
		return false, errBad("hostkey")
	case isNew:
		a.HostKey = hk
	case a.HostKey == "" && hk != "":
		a.HostKey = hk // noch keiner gemerkt: der in der Oberflaeche bestaetigte Fingerabdruck (SSH mit Passwort)
	}
	if in.Enabled != nil {
		a.Enabled = *in.Enabled
	} else if isNew {
		a.Enabled = true
	}
	limit := maxSecret
	if a.Type == "docker" {
		limit = maxSecretDocker
	}
	if len(in.Secret) > limit {
		return false, errBad("secret")
	}
	if a.Type == "snmp" {
		if err := m.snmpSecretIn(a, &in, isNew); err != nil {
			return false, err
		}
	}
	switch {
	case in.Secret != "":
		a.Secret = m.box.Encrypt(in.Secret)
	case in.ClearSecret:
		a.Secret = ""
	default:
		keepSecret = !isNew
	}
	// SSH: bekommt ein Zugang erstmals ein Passwort, gilt ein bisher nur gelernter Hostschluessel (Anmeldung mit dem
	// Schluessel der Node, nie von jemandem verglichen) nicht als bestaetigt - ohne Fingerabdruck in der Eingabe wird
	// er verworfen, das Passwort geht dann erst nach der Bestaetigung raus.
	if a.Type == "ssh" && !isNew && !hadSecret && in.Secret != "" && hk == "" {
		a.HostKey = ""
	}
	return keepSecret, nil
}

// serviceIn ist ein erkannter Dienst aus "Verbindung testen", den der Assistent uebernimmt.
type serviceIn struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Default bool   `json:"default"`
}

type createIn struct {
	hostIn
	Accesses []accessIn  `json:"accesses"`
	Services []serviceIn `json:"services"`
	Adopt    []string    `json:"adopt"`
}

func (m *Module) defaultInterval(ctx context.Context) int {
	var n int
	if _, err := fmt.Sscanf(m.st.SettingOr(ctx, setInterval, "60"), "%d", &n); err != nil || n < 30 || n > 900 {
		return 60
	}
	return n
}

// apiHosts: GET Liste der Hosts mit aktuellem Zustand.
func (m *Module) apiHosts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.overview(r.Context()).Hosts)
}

// apiHostCreate: POST Host mit Zugaengen anlegen; erkannte Dienste (aus "Verbindung testen") werden eingetragen,
// die bestaetigten uebernommen (Plan "Dienste erkennen": beim Anlegen im Assistenten bestaetigen).
func (m *Module) apiHostCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in createIn
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	h := &Host{AgentAutoUpd: true}
	if err := in.apply(h, m.defaultInterval(ctx)); err != nil {
		m.fail(w, r, err)
		return
	}
	if len(in.Accesses) > 8 || len(in.Services) > 5000 {
		m.fail(w, r, errBad("too_many"))
		return
	}
	accs := make([]*Access, 0, len(in.Accesses))
	for _, ai := range in.Accesses {
		a := &Access{}
		if _, err := m.buildAccess(a, ai, true); err != nil {
			m.fail(w, r, err)
			return
		}
		accs = append(accs, a)
	}
	found := make([]model.Service, 0, len(in.Services))
	for _, s := range in.Services {
		key, name, kind := cleanText(s.Key, 200), cleanText(s.Name, 200), cleanText(s.Kind, 32)
		if key == "" {
			continue
		}
		found = append(found, model.Service{Key: key, Name: name, Kind: kind, Default: s.Default})
	}
	by := m.actor(r)
	if err := m.store.SaveHost(ctx, h, by); err != nil {
		m.fail(w, r, err)
		return
	}
	for _, a := range accs {
		a.HostUID = h.UID
		if err := m.store.SaveAccess(ctx, a, false, by); err != nil {
			m.fail(w, r, err)
			return
		}
	}
	if len(found) > 0 {
		adopt := map[string]bool{}
		for _, k := range in.Adopt {
			adopt[k] = true
		}
		if _, err := m.store.UpsertDiscovered(ctx, h.UID, found, adopt, by); err != nil {
			m.fail(w, r, err)
			return
		}
	}
	m.audit(r, "host.create", h.Name, fmt.Sprintf("uid=%s address=%s accesses=%d adopted=%d", h.UID, h.Address, len(accs), len(in.Adopt)))
	m.ReloadHost(ctx, h.UID)
	m.repoll(h.UID) // erste Werte sofort, nicht erst zum naechsten Takt
	writeJSON(w, http.StatusCreated, map[string]any{"uid": h.UID})
}

// apiHostUpdate: PUT Host aendern.
func (m *Module) apiHostUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h, err := m.store.Host(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	var in hostIn
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	wasPaused := h.Paused
	if err := in.apply(h, h.IntervalSec); err != nil {
		m.fail(w, r, err)
		return
	}
	if err := m.store.SaveHost(ctx, h, m.actor(r)); err != nil {
		m.fail(w, r, err)
		return
	}
	if h.Paused != wasPaused { // Pause im Verlauf (Statusseiten zaehlen pausierte Zeit nicht)
		kind := "resume"
		if h.Paused {
			kind = "pause"
		}
		m.event(ctx, "", h.UID, "", kind, "", m.actor(r), time.Now())
	}
	m.audit(r, "host.update", h.Name, "uid="+h.UID)
	m.ReloadHost(ctx, h.UID)
	m.reloadConfig(ctx) // Gruppe/Tags aendern Abweichungen und Wartung
	writeJSON(w, http.StatusOK, map[string]any{"uid": h.UID})
}

// historyStore ist, was die API vom Verlauf ausser Schreiben braucht (Paket tsdb).
type historyStore interface {
	QueryMulti(ctx context.Context, keys []string, from, to time.Time, maxPoints int) ([]tsdb.Series, error)
	DeleteSeriesPrefix(ctx context.Context, prefix string) (int, error)
}

func (m *Module) history() historyStore {
	h, _ := m.seriesStore().(historyStore)
	return h
}

// apiHostDelete: DELETE Host entfernen; ?history=delete loescht auch den Verlauf (Problem-Historie bleibt).
func (m *Module) apiHostDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h, err := m.store.Host(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	by := m.actor(r)
	if err := m.store.DeleteHost(ctx, h.UID, by); err != nil {
		m.fail(w, r, err)
		return
	}
	m.ReloadHost(ctx, h.UID)
	// offene Probleme schliessen (sonst blieben sie ohne Host offen und zaehlten weiter am Reiter Probleme)
	if err := m.CloseHostProblems(ctx, h.UID, by); err != nil {
		m.log.Warn("monitor64: close problems of removed host", "host", h.Name, "err", err)
	}
	m.notifyMu.Lock()
	if m.notifier != nil {
		m.notifier.Forget(h.UID)
	}
	m.notifyMu.Unlock()
	deleted := 0
	hist := r.URL.Query().Get("history") == "delete"
	if hist {
		if hs := m.history(); hs != nil {
			if deleted, err = hs.DeleteSeriesPrefix(ctx, h.UID+"|"); err != nil {
				m.log.Warn("monitor64: delete history", "host", h.Name, "err", err)
			}
		}
	}
	m.audit(r, "host.delete", h.Name, fmt.Sprintf("uid=%s history_deleted=%t series=%d", h.UID, hist, deleted))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "series_deleted": deleted})
}

// ---------------------------------------------------------------------------------------------------------
// Zugaenge

func (m *Module) accessByUID(ctx context.Context, uid string) (*Access, error) {
	list, err := m.store.Accesses(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, a := range list {
		if a.UID == uid {
			return a, nil
		}
	}
	return nil, ErrNotFound
}

// apiAccessCreate: POST Zugang an einem Host anlegen.
func (m *Module) apiAccessCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h, err := m.store.Host(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	var in accessIn
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	a := &Access{HostUID: h.UID}
	if _, err := m.buildAccess(a, in, true); err != nil {
		m.fail(w, r, err)
		return
	}
	if err := m.store.SaveAccess(ctx, a, false, m.actor(r)); err != nil {
		m.fail(w, r, err)
		return
	}
	m.audit(r, "access.create", h.Name, "type="+a.Type+" uid="+a.UID)
	m.ReloadHost(ctx, h.UID)
	m.repoll(h.UID) // neuer Zugang: gleich abfragen
	writeJSON(w, http.StatusCreated, accessOuts([]*Access{a})[0])
}

// apiAccessUpdate: PUT Zugang aendern (Geheimnis leer = unveraendert, clear_secret = entfernen).
func (m *Module) apiAccessUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a, err := m.accessByUID(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	var in accessIn
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	oldType, oldCfg, hadSecret := a.Type, a.Config, a.Secret != ""
	keep, err := m.buildAccess(a, in, false)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	// Ziel (Art, URL, Pin) geaendert und kein neues Geheimnis: das gespeicherte ginge sonst bei der naechsten Abfrage
	// an das neue Ziel (wie beim Test: "das gespeicherte geht nur an das gespeicherte Ziel")
	if keep && hadSecret && a.Type != "snmp" && (a.Type != oldType || targetChanged(oldCfg, a.Config)) {
		m.fail(w, r, errBad("secret_again"))
		return
	}
	if err := m.store.SaveAccess(ctx, a, keep, m.actor(r)); err != nil {
		m.fail(w, r, err)
		return
	}
	m.audit(r, "access.update", a.HostUID, fmt.Sprintf("type=%s uid=%s secret_changed=%t hostkey_reset=%t", a.Type, a.UID, !keep, strings.TrimSpace(in.HostKey) == "reset"))
	m.ReloadHost(ctx, a.HostUID)
	m.repoll(a.HostUID) // geaenderter Zugang: gleich abfragen
	writeJSON(w, http.StatusOK, accessOuts([]*Access{a})[0])
}

// apiAccessHostKey: POST gemerkten Hostschluessel verwerfen; der naechste Kontakt merkt den neuen (Knopf
// "neuen uebernehmen" nach "Schluessel geaendert").
func (m *Module) apiAccessHostKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a, err := m.accessByUID(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	old := a.HostKey
	a.HostKey = ""
	if err := m.store.SaveAccess(ctx, a, true, m.actor(r)); err != nil {
		m.fail(w, r, err)
		return
	}
	m.audit(r, "access.hostkey_reset", a.HostUID, "uid="+a.UID+" old="+old)
	m.ReloadHost(ctx, a.HostUID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// apiAccessDelete: DELETE Zugang entfernen.
func (m *Module) apiAccessDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a, err := m.accessByUID(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	if err := m.store.DeleteAccess(ctx, a.UID, m.actor(r)); err != nil {
		m.fail(w, r, err)
		return
	}
	m.audit(r, "access.delete", a.HostUID, "type="+a.Type+" uid="+a.UID)
	m.ReloadHost(ctx, a.HostUID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// testResult ist das Ergebnis von "Verbindung testen" (eine Abfrage, nichts gespeichert).
type testResult struct {
	OK          bool        `json:"ok"`
	Error       string      `json:"error,omitempty"`
	Ms          int64       `json:"ms"`
	Fingerprint string      `json:"fingerprint,omitempty"`
	Services    []serviceIn `json:"services"`
	// nur API-Zugaenge (Proxmox VE, PBS, Docker)
	NeedConfirm bool               `json:"need_confirm,omitempty"` // Fingerabdruck bestaetigen (als Pin speichern), dann erneut testen
	Trusted     bool               `json:"trusted,omitempty"`      // Zertifikat von einer bekannten CA bzw. Pin passt
	CertSubject string             `json:"cert_subject,omitempty"`
	Version     string             `json:"version,omitempty"`
	Node        string             `json:"node,omitempty"`
	Cluster     string             `json:"cluster,omitempty"`
	Nodes       []apis.ClusterNode `json:"nodes,omitempty"`
	Summary     string             `json:"summary,omitempty"`
	Warning     string             `json:"warning,omitempty"`
	// nur SNMP
	Device   string             `json:"device,omitempty"`   // nas, ups, printer, switch, router, ap, server, device
	Profiles []snmp.ProfileInfo `json:"profiles,omitempty"` // erkannte Profile (verified = an echtem Geraet geprueft)
	Queries  []string           `json:"queries,omitempty"`  // "Was wird abgefragt?"
}

const testTimeout = 20 * time.Second

// testAccess fragt einen Zugang einmal ab, ohne etwas zu speichern (eigener Eintrag im Verbindungs-Pool, danach
// verworfen; der Hostschluessel wird nur gemeldet).
func (m *Module) testAccess(ctx context.Context, h *Host, a Access) testResult {
	res := testResult{Services: []serviceIn{}}
	if m.scheduler() == nil || m.pool == nil {
		res.Error = i18nText("monitor64.err.not_running")
		return res
	}
	if a.Type == "agent" {
		var cfg accessConfig
		_ = json.Unmarshal(a.Config, &cfg)
		if cfg.Mode == "push" {
			ctx, cancel := context.WithTimeout(ctx, testTimeout)
			defer cancel()
			start := time.Now()
			m.testPush(ctx, a, cfg, &res)
			res.Ms = time.Since(start).Milliseconds()
			return res
		}
	}
	a.UID = "test:" + newUID()
	defer m.pool.Remove(a.UID)
	ctx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()
	start := time.Now()
	if isAPIAccess(a.Type) {
		m.testAPIAccess(ctx, h, a, &res)
		res.Ms = time.Since(start).Milliseconds()
		return res
	}
	col, err := m.newCollector(ctx, h, &a)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer col.close()
	svcs, err := col.collect(ctx)
	res.Ms = time.Since(start).Milliseconds()
	res.Fingerprint = a.HostKey
	var uk *transport.UnconfirmedKeyError
	if errors.As(err, &uk) { // SSH mit Passwort: erst den Fingerabdruck bestaetigen lassen, dann anmelden
		res.Fingerprint, res.NeedConfirm = uk.Got, true
		return res
	}
	if err != nil {
		res.Error = err.Error()
	}
	res.OK = len(svcs) > 0 || err == nil
	for _, s := range svcs {
		res.Services = append(res.Services, serviceIn{Key: s.Key, Name: s.Name, Kind: s.Kind, Default: s.Default})
	}
	slices.SortStableFunc(res.Services, func(x, y serviceIn) int { return kindOrder(x.Kind) - kindOrder(y.Kind) })
	return res
}

// testPush testet einen Push-Zugang ueber den laufenden Client des gespeicherten Zugangs (kein eigener Test-Client:
// der Agent hat seine Verbindungen beim Token, ein zweiter Client konkurrierte mit dem echten um sie). Ungespeichert
// bzw. mit geaendertem Token: erst speichern; Zugang aus oder noch nicht eingeplant: kein Test.
func (m *Module) testPush(ctx context.Context, a Access, cfg accessConfig, res *testResult) {
	if a.UID == "" {
		res.Error = i18nText("monitor64.err.push_test_saved")
		return
	}
	c := m.pool.Existing(a.UID)
	switch {
	case c == nil:
		res.Error = i18nText("monitor64.err.push_inactive")
		return
	case c.PushToken() != cfg.Token:
		res.Error = i18nText("monitor64.err.push_test_saved")
		return
	}
	rep, err := c.Collect(ctx)
	res.Fingerprint = c.HostKey()
	if err != nil {
		res.Error = transport.CleanError(err).Error()
		return
	}
	res.OK = true
	for _, s := range MapReport(nil, rep) {
		res.Services = append(res.Services, serviceIn{Key: s.Key, Name: s.Name, Kind: s.Kind, Default: s.Default})
	}
	if perr := sectionErrors(rep); perr != nil {
		res.Error = perr.Error()
	}
	slices.SortStableFunc(res.Services, func(x, y serviceIn) int { return kindOrder(x.Kind) - kindOrder(y.Kind) })
}

// testAPIAccess testet einen API-Zugang (apis.*.Test: Fingerabdruck, Bestaetigung, Cluster-Nodes). Nur wenn die
// Verbindung steht und bestaetigt ist, folgt eine Abfragerunde fuer die Dienste (sonst wuerde das Token an ein
// unbestaetigtes Zertifikat gesendet).
func (m *Module) testAPIAccess(ctx context.Context, h *Host, a Access, res *testResult) {
	var cfg accessConfig
	_ = json.Unmarshal(a.Config, &cfg)
	secret := ""
	if a.Secret != "" {
		s, err := m.box.Decrypt(a.Secret)
		if err != nil {
			res.Error = i18nText("monitor64.detail.secret_unreadable")
			return
		}
		secret = s
	}
	if a.Type == "snmp" {
		m.testSNMP(ctx, h, cfg, secret, res)
		return
	}
	t, done, err := newAPITester(a.Type, h, cfg, secret)
	if err != nil {
		res.Error = err.Error()
		return
	}
	defer done()
	tr := t.Test(ctx)
	res.OK, res.Error, res.Fingerprint, res.NeedConfirm, res.Trusted = tr.OK, tr.Error, tr.Fingerprint, tr.NeedConfirm, tr.Trusted
	res.CertSubject, res.Version, res.Node, res.Cluster, res.Nodes, res.Summary, res.Warning = tr.CertSubject, tr.Version, tr.Node, tr.Cluster, tr.Nodes, tr.Summary, tr.Warning
	if !tr.OK || tr.NeedConfirm {
		res.OK = false
		return
	}
	svcs, err := t.Collect(ctx)
	if err != nil {
		res.Error = err.Error() // Teilfehler: die uebrigen Dienste kommen trotzdem
	}
	for _, s := range svcs {
		res.Services = append(res.Services, serviceIn{Key: s.Key, Name: s.Name, Kind: s.Kind, Default: s.Default})
	}
	slices.SortStableFunc(res.Services, func(x, y serviceIn) int { return kindOrder(x.Kind) - kindOrder(y.Kind) })
}

type testIn struct {
	Address string   `json:"address"`
	Access  accessIn `json:"access"`
	// AccessUID: Formular eines gespeicherten Zugangs (Geheimnis mit dem gespeicherten zusammenfuehren, Push ueber
	// den laufenden Client)
	AccessUID string `json:"access_uid"`
}

// apiTest: POST Verbindung testen, bevor etwas gespeichert ist (Assistent).
func (m *Module) apiTest(w http.ResponseWriter, r *http.Request) {
	var in testIn
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	addr, ok := cleanAddress(in.Address)
	if !ok {
		m.fail(w, r, errBad("address"))
		return
	}
	if in.AccessUID != "" { // gespeicherter Zugang: muss zum Host mit dieser Adresse gehoeren und die Art passen
		ctx := r.Context()
		a, err := m.accessByUID(ctx, in.AccessUID)
		if err != nil {
			m.fail(w, r, err)
			return
		}
		h, err := m.store.Host(ctx, a.HostUID)
		if err != nil {
			m.fail(w, r, err)
			return
		}
		if !strings.EqualFold(strings.Trim(strings.TrimSpace(h.Address), "[]"), strings.Trim(addr, "[]")) {
			m.fail(w, r, errBad("address"))
			return
		}
		res, err := m.testStored(ctx, h, a, in.Access)
		if err != nil {
			m.fail(w, r, err)
			return
		}
		m.audit(r, "access.test", h.Name, fmt.Sprintf("type=%s uid=%s ok=%t", a.Type, a.UID, res.OK))
		writeJSON(w, http.StatusOK, res)
		return
	}
	var a Access
	if _, err := m.buildAccess(&a, in.Access, true); err != nil {
		m.fail(w, r, err)
		return
	}
	res := m.testAccess(r.Context(), &Host{Name: addr, Address: addr}, a)
	m.audit(r, "access.test", addr, fmt.Sprintf("type=%s ok=%t", a.Type, res.OK))
	writeJSON(w, http.StatusOK, res)
}

// apiAccessTest: POST gespeicherten Zugang testen (mit gespeichertem Geheimnis und Hostschluessel). Optional mit den
// Aenderungen aus dem Formular (accessIn wie bei PUT, ohne Typwechsel; nichts wird gespeichert): ein leeres bzw.
// teilweise neues Geheimnis wird wie beim Speichern mit dem gespeicherten zusammengefuehrt (z. B. SNMP v3 nur das
// Auth-Passwort neu). Das gespeicherte Geheimnis geht dabei nur an das gespeicherte Ziel: bei geaenderter URL bzw.
// geaendertem Pin erst speichern oder das Geheimnis neu eingeben.
func (m *Module) apiAccessTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a, err := m.accessByUID(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	h, err := m.store.Host(ctx, a.HostUID)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	var in accessIn
	has, err := decodeOptional(r, &in)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	if !has {
		writeJSON(w, http.StatusOK, m.testAccess(ctx, h, *a))
		return
	}
	res, err := m.testStored(ctx, h, a, in)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// testStored testet einen gespeicherten Zugang mit den Aenderungen aus dem Formular (nichts wird gespeichert):
// Geheimnis wie beim Speichern zusammengefuehrt; das gespeicherte geht nur an das gespeicherte Ziel.
func (m *Module) testStored(ctx context.Context, h *Host, a *Access, in accessIn) (testResult, error) {
	if in.Type != "" && in.Type != a.Type {
		return testResult{}, errBad("access_type")
	}
	in.Type, in.Enabled, in.NewToken = "", nil, false
	t := *a
	keep, err := m.buildAccess(&t, in, false)
	if err != nil {
		return testResult{}, err
	}
	stored := a.Secret != "" && !in.ClearSecret && (keep || a.Type == "snmp") // SNMP: Teil-Geheimnis gemischt
	if stored && t.Secret != "" && targetChanged(a.Config, t.Config) {
		return testResult{Services: []serviceIn{}, Error: i18nText("monitor64.err.test_save_first")}, nil
	}
	return m.testAccess(ctx, h, t), nil
}

// targetChanged: Ziel eines Zugangs (URL, Pin) geaendert - dorthin geht das gespeicherte Geheimnis nicht. Adresse
// und Port des Hosts aendert der Zugang nicht (bei SSH und SNMP bleibt es derselbe Host).
func targetChanged(old, cur json.RawMessage) bool {
	var o, c accessConfig
	_ = json.Unmarshal(old, &o)
	_ = json.Unmarshal(cur, &c)
	return o.URL != c.URL || o.Pin != c.Pin
}

// decodeOptional liest einen JSON-Koerper wie decode; ein leerer Koerper ist erlaubt (has = false).
func decodeOptional(r *http.Request, v any) (has bool, err error) {
	b, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBody))
	if err != nil {
		return false, errBad("json", "error", err.Error())
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return false, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return false, errBad("json", "error", err.Error())
	}
	return true, nil
}

// apiNodeAddr: GET Adresse dieser Node in Richtung eines Hosts (fuer from="..." in authorized_keys). Es wird kein
// Paket gesendet (UDP-"Verbindung" waehlt nur die Quelladresse).
func (m *Module) apiNodeAddr(w http.ResponseWriter, r *http.Request) {
	target := transport.SplitHost(r.URL.Query().Get("target")) // ohne Port und Klammern
	out := map[string]string{"addr": ""}
	if target != "" && reAddress.MatchString(target) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		var d net.Dialer
		if c, err := d.DialContext(ctx, "udp", net.JoinHostPort(target, "22")); err == nil {
			if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
				out["addr"] = ua.IP.String()
			}
			_ = c.Close()
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------------------------------------
// Dienste

type svcKeysIn struct {
	Keys  []string `json:"keys"`
	State int      `json:"state"` // 1 uebernehmen, -1 ignorieren
}

// apiServicesAdopt: POST Dienste uebernehmen (1) oder ignorieren (-1).
func (m *Module) apiServicesAdopt(w http.ResponseWriter, r *http.Request) {
	m.servicesBulk(w, r, false)
}

// apiServicesRemove: POST Dienste entfernen (z. B. nach "verschwunden"; aktiver Klick mit Akteur).
func (m *Module) apiServicesRemove(w http.ResponseWriter, r *http.Request) {
	m.servicesBulk(w, r, true)
}

func (m *Module) servicesBulk(w http.ResponseWriter, r *http.Request, remove bool) {
	ctx := r.Context()
	h, err := m.store.Host(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	var in svcKeysIn
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	if !remove && in.State != 1 && in.State != -1 && in.State != 0 {
		m.fail(w, r, errBad("state"))
		return
	}
	if len(in.Keys) == 0 || len(in.Keys) > 5000 {
		m.fail(w, r, errBad("keys"))
		return
	}
	by := m.actor(r)
	n := 0
	for _, k := range in.Keys {
		var err error
		if remove {
			err = m.store.RemoveService(ctx, h.UID, k, by)
		} else {
			err = m.store.SetAdopted(ctx, h.UID, k, in.State, by)
		}
		if err == nil {
			n++
		} else if !errors.Is(err, ErrNotFound) {
			m.fail(w, r, err)
			return
		}
	}
	action := "services.remove"
	if !remove {
		action = map[int]string{1: "services.adopt", -1: "services.ignore", 0: "services.offer"}[in.State]
	}
	m.audit(r, action, h.Name, fmt.Sprintf("uid=%s keys=%s", h.UID, strings.Join(limitList(in.Keys, 10), ",")))
	m.repoll(h.UID)
	writeJSON(w, http.StatusOK, map[string]any{"changed": n})
}

// svcUpdateIn aendert einen Dienst: Anzeigename, Soll-Zustand, Melden/Nur anzeigen und die Schwellen der Stufe
// "dieser Host" je Regel-Art (eine Messgroesse bzw. Zustandsregel des Dienstes).
type svcUpdateIn struct {
	Key    string                  `json:"key"`
	Name   *string                 `json:"name"`
	Soll   *string                 `json:"soll"`   // "", run, off
	Report *string                 `json:"report"` // "", show
	Rules  map[string]ruleChangeIn `json:"rules"`  // Regel-Art -> Aenderung (fehlende Arten bleiben unveraendert)
	Reset  bool                    `json:"reset"`  // alle Schwellen "dieser Host" der Arten dieses Dienstes entfernen
}

// ruleChangeIn ist die Aenderung der Stufe "dieser Host" fuer eine Regel-Art.
type ruleChangeIn struct {
	Rule  *eval.Rule `json:"rule"`  // null bzw. leer = entfernen
	Scope string     `json:"scope"` // service (nur dieser Dienst, Standard) oder kind (alle Dienste dieses Hosts mit dieser Art)
	Reset bool       `json:"reset"` // beide Einstellungen am Host fuer diese Art entfernen ("auf Standard zurueck")
}

const maxRuleChanges = 32

// apiServiceUpdate: PUT einen Dienst aendern.
func (m *Module) apiServiceUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h, err := m.store.Host(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	var in svcUpdateIn
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	rows, err := m.store.Services(ctx, h.UID)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	var row *ServiceRow
	for _, s := range rows {
		if s.Key == in.Key {
			row = s
		}
	}
	if row == nil {
		m.fail(w, r, ErrNotFound)
		return
	}
	var p svcPatch
	var details []string
	if in.Name != nil {
		n := cleanText(*in.Name, 200)
		p.Name = &n
		details = append(details, "name="+n)
	}
	if in.Soll != nil {
		if *in.Soll != "" && *in.Soll != "run" && *in.Soll != "off" {
			m.fail(w, r, errBad("soll"))
			return
		}
		p.Soll = in.Soll
		details = append(details, "soll="+*in.Soll)
	}
	if in.Report != nil {
		if *in.Report != "" && *in.Report != "show" {
			m.fail(w, r, errBad("report"))
			return
		}
		p.Report = in.Report
		details = append(details, "report="+*in.Report)
	}
	if len(in.Rules) > maxRuleChanges {
		m.fail(w, r, errBad("too_many"))
		return
	}
	cfg := m.config()
	svcRules := parseHostRules(row.HostRule)
	if svcRules == nil {
		svcRules = map[string]eval.Rule{}
	}
	kindRules := map[string]*eval.Rule{} // Regel-Art -> neue Einstellung "alle Dienste dieser Art" (nil = entfernen)
	svcChanged := false
	if in.Reset {
		for _, k := range m.ruleKindsOfService(h.UID, row) {
			if _, ok := svcRules[k]; ok {
				delete(svcRules, k)
				svcChanged = true
			}
			if cfg.hostKind[h.UID+"|"+k] != nil {
				kindRules[k] = nil
			}
		}
	}
	kinds := make([]string, 0, len(in.Rules))
	for k := range in.Rules {
		kinds = append(kinds, k)
	}
	slices.Sort(kinds)
	for _, kind := range kinds {
		ch := in.Rules[kind]
		if _, ok := cfg.std[kind]; !ok {
			m.fail(w, r, errBad("rule_kind", "kind", kind, "error", "unknown"))
			return
		}
		scope := ch.Scope
		if scope == "" {
			scope = "service"
		}
		if scope != "service" && scope != "kind" {
			m.fail(w, r, errBad("scope"))
			return
		}
		var rule *eval.Rule
		if ch.Rule != nil && !ch.Reset {
			if err := ch.Rule.Validate(); err != nil {
				m.fail(w, r, errBad("rule_kind", "kind", kind, "error", err.Error()))
				return
			}
			if !ch.Rule.Empty() {
				rule = ch.Rule
			}
		}
		_, hadSvc := svcRules[kind]
		switch {
		case ch.Reset: // beide Einstellungen am Host fuer diese Art
			delete(svcRules, kind)
			svcChanged = svcChanged || hadSvc
			kindRules[kind] = nil
		case scope == "kind": // gilt fuer alle Dienste der Art; die Einstellung nur dieses Dienstes weicht
			delete(svcRules, kind)
			svcChanged = svcChanged || hadSvc
			kindRules[kind] = rule
		case rule != nil:
			svcRules[kind] = *rule
			svcChanged = true
		default:
			delete(svcRules, kind)
			svcChanged = svcChanged || hadSvc
		}
		if err := m.checkRuleOrder(h, svcRules, kindRules, kind); err != nil {
			m.fail(w, r, err)
			return
		}
	}
	if svcChanged {
		s := encodeHostRules(svcRules)
		p.HostRule = &s
		details = append(details, "rules="+s)
	}
	by := m.actor(r)
	if err := m.store.UpdateService(ctx, h.UID, row.Key, p, by); err != nil {
		m.fail(w, r, err)
		return
	}
	if len(kindRules) > 0 {
		ks := make([]string, 0, len(kindRules))
		for k := range kindRules {
			ks = append(ks, k)
		}
		slices.Sort(ks)
		for _, k := range ks {
			if err := m.store.SaveHostRule(ctx, h.UID, k, kindRules[k], by); err != nil {
				m.fail(w, r, err)
				return
			}
			b, _ := json.Marshal(kindRules[k])
			details = append(details, "kind_rule["+k+"]="+string(b))
		}
		m.reloadConfig(ctx)
	}
	m.audit(r, "service.update", h.Name+" · "+row.Key, strings.Join(details, " "))
	m.repoll(h.UID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// checkRuleOrder prueft die wirksame Schwelle einer Regel-Art mit den geaenderten Einstellungen am Host und den
// geerbten Feldern (Warnung vor Kritisch).
func (m *Module) checkRuleOrder(h *Host, svcRules map[string]eval.Rule, kindRules map[string]*eval.Rule, kind string) error {
	cfg := m.config()
	hl := m.hostLevel(h.UID, svcRules, kind)
	if kr, ok := kindRules[kind]; ok {
		hl.Kind = kr
	}
	if r, ok := svcRules[kind]; ok {
		hl.Service = &r
	} else {
		hl.Service = nil
	}
	e := eval.Resolve(cfg.std, cfg.overrides, hostRef(h), hl, kind)
	if err := e.Validate(); err != nil {
		return errBad("rule_kind", "kind", kind, "error", err.Error())
	}
	return nil
}

// ruleKindsOfService: Regel-Arten eines Dienstes – Messgroessen mit Schwelle aus dem letzten Stand, dazu die
// Zustandsregeln seiner Art; ohne Stand die Arten, fuer die schon etwas am Dienst eingestellt ist.
func (m *Module) ruleKindsOfService(hostUID string, row *ServiceRow) []string {
	var kinds []string
	add := func(k string) {
		if k != "" && !slices.Contains(kinds, k) {
			kinds = append(kinds, k)
		}
	}
	if v := m.viewOf(hostUID); v != nil {
		for _, s := range v.Services {
			if s.Key != row.Key {
				continue
			}
			for _, mt := range s.Metrics {
				add(firstNonEmpty(mt.RuleKind, mt.Metric.Rule))
			}
		}
	}
	for _, k := range factKinds[row.Kind] {
		add(k)
	}
	for k := range parseHostRules(row.HostRule) {
		add(k)
	}
	return kinds
}

// viewOf liefert den aktuellen Stand eines Hosts (nil = nicht eingeplant).
func (m *Module) viewOf(uid string) *HostView {
	m.rtMu.Lock()
	rt := m.rts[uid]
	m.rtMu.Unlock()
	if rt == nil {
		return nil
	}
	if v := rt.getView(); v != nil {
		return v
	}
	return &HostView{Host: rt.host, View: eval.ViewUnknown, State: eval.Unknown}
}

// repoll stoesst eine sofortige Runde an (Neubewertung nach einer Aenderung).
func (m *Module) repoll(uid string) {
	if m.forwardRepoll(uid) { // Cluster: eine andere Node ueberwacht den Host (Anstoss weiterreichen)
		return
	}
	if s := m.scheduler(); s != nil {
		s.RunNow("host:" + uid)
	}
}

// apiDiscover: POST Dienste jetzt erkennen (eine Runde sofort, mit Erkennung) und Ergebnis melden.
func (m *Module) apiDiscover(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h, err := m.store.Host(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	m.rtMu.Lock()
	rt := m.rts[h.UID]
	m.rtMu.Unlock()
	if rt == nil {
		m.fail(w, r, errNotRunning)
		return
	}
	before := map[string]bool{}
	rows, _ := m.store.Services(ctx, h.UID)
	for _, s := range rows {
		before[s.Key] = true
	}
	rt.mu.Lock()
	rt.LastDisc = time.Time{}
	rt.mu.Unlock()
	// eigene Runde wie die geplante (gleiches Zeitlimit, unabhaengig von der Anfrage): bricht der Besucher ab oder
	// braucht ein Zugang laenger als das Test-Zeitlimit, zaehlte das sonst als Ausfall des Zugangs
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), jobTimeout(time.Duration(h.IntervalSec)*time.Second))
	defer cancel()
	m.poll(pctx, rt)
	rows, _ = m.store.Services(ctx, h.UID)
	added, gone := 0, 0
	for _, s := range rows {
		if !before[s.Key] {
			added++
		}
		if !s.VanishedAt.IsZero() {
			gone++
		}
	}
	newCount := 0
	for _, s := range rows {
		if s.Adopted == 0 {
			newCount++
		}
	}
	m.audit(r, "services.discover", h.Name, fmt.Sprintf("uid=%s added=%d", h.UID, added))
	writeJSON(w, http.StatusOK, map[string]any{"added": added, "new": newCount, "vanished": gone})
}
