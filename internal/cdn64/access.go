package cdn64

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ipv64net/node64/internal/store"
)

// Access Lists wie im NPM: Benutzer (Basic Auth, bcrypt) und IP-Regeln (in Reihenfolge, erster Treffer gilt,
// ohne Treffer gesperrt). "Eine Bedingung genuegt" erlaubt IP oder Anmeldung, sonst braucht es beides.
// Anmeldung = API-Key, Benutzer der Liste oder Anmeldedienst (Forward-Auth, forwardauth.go), in dieser Reihenfolge.
// Fehlversuche bei der Anmeldung werden je IP begrenzt.

const (
	authFailMax    = 10
	authFailWindow = 5 * time.Minute
	authBlockFor   = 15 * time.Minute
	authCacheFor   = 5 * time.Minute
)

// AccessUser ist ein Benutzer einer Liste (nur der Hash wird gespeichert).
type AccessUser struct {
	Username string `json:"username"`
	Hash     string `json:"hash,omitempty"`
}

// AccessRule ist eine IP-Regel.
type AccessRule struct {
	Action string `json:"action"` // allow | deny
	CIDR   string `json:"cidr"`   // Adresse oder Netz
	prefix netip.Prefix
}

// AccessList ist eine Zugriffsliste.
type AccessList struct {
	ID         int64        `json:"id"`
	Name       string       `json:"name"`
	SatisfyAny bool         `json:"satisfy_any"`
	PassAuth   bool         `json:"pass_auth"`
	LoginPage  bool         `json:"login_page"` // Anmeldung ueber eine Login-Seite statt des Browser-Dialogs (access_login.go)
	Users      []AccessUser `json:"users"`
	Rules      []AccessRule `json:"rules"`
	Auth       string       `json:"auth"`      // Anmeldedienst (AuthAuthentik …), "" = Benutzer der Liste
	Forward    ForwardAuth  `json:"forward"`   // Einstellung des Anmeldedienstes
	PassUser   bool         `json:"pass_user"` // Remote-User, -Email, -Groups, -Name an das Ziel
	Keys       []AccessKey  `json:"keys"`      // API-Keys
	CreatedAt  time.Time    `json:"created_at"`
	UpdatedAt  time.Time    `json:"updated_at"`
}

// public: ohne Hashes (API/Oberflaeche).
func (a *AccessList) public() *AccessList {
	cp := *a
	cp.Users = make([]AccessUser, len(a.Users))
	for i, u := range a.Users {
		cp.Users[i] = AccessUser{Username: u.Username}
	}
	cp.Keys = make([]AccessKey, len(a.Keys))
	for i, k := range a.Keys {
		cp.Keys[i] = AccessKey{Name: k.Name, Hint: k.Hint, CreatedAt: k.CreatedAt}
	}
	return &cp
}

func (a *AccessList) prepare() {
	for i := range a.Rules {
		a.Rules[i].prefix, _ = parsePrefix(a.Rules[i].CIDR)
	}
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "all" || s == "*" {
		return netip.MustParsePrefix("::/0"), nil
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ipAllowed: erster passender Eintrag entscheidet; "all" passt auf alles.
func (a *AccessList) ipAllowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, r := range a.Rules {
		if r.CIDR == "all" || r.CIDR == "*" || r.prefix.Contains(ip) {
			return r.Action == "allow"
		}
	}
	return false
}

// ---------------------------------------------------------------- Pruefung je Anfrage

// guard prueft Anfragen gegen eine Liste (eine Instanz je Liste, mit Cache fuer erfolgreiche Anmeldungen).
type guard struct {
	list  *AccessList
	fwd   *fwdAuth // Anmeldedienst (nil = keiner)
	mu    sync.Mutex
	cache map[[32]byte]time.Time // sha256(user:pass) -> gueltig bis
}

func newGuard(a *AccessList) *guard {
	a.prepare()
	g := &guard{list: a, cache: map[[32]byte]time.Time{}}
	if a.Auth != AuthUsers {
		g.fwd = newFwdAuth(a.Auth, a.Forward)
	}
	return g
}

// authOK prueft Basic Auth (bcrypt nur einmal je Benutzer/Passwort in 5 Minuten).
func (g *guard) authOK(r *http.Request) (ok, tried bool) {
	user, pass, has := r.BasicAuth()
	if !has {
		return false, false
	}
	key := sha256.Sum256([]byte(user + "\x00" + pass))
	g.mu.Lock()
	until, hit := g.cache[key]
	g.mu.Unlock()
	if hit && time.Now().Before(until) {
		return true, true
	}
	known := false
	for _, u := range g.list.Users {
		if subtle.ConstantTimeCompare([]byte(u.Username), []byte(user)) != 1 {
			continue
		}
		known = true
		if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(pass)) == nil {
			g.mu.Lock()
			if len(g.cache) > 1000 {
				g.cache = map[[32]byte]time.Time{}
			}
			g.cache[key] = time.Now().Add(authCacheFor)
			g.mu.Unlock()
			return true, true
		}
	}
	if !known { // unbekannter Benutzer dauert so lange wie ein falsches Passwort (Benutzernamen nicht erratbar)
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(pass))
	}
	return false, true
}

// dummyHash: bcrypt-Wert ohne Benutzer, nur fuer gleiche Laufzeit bei unbekannten Namen.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("node64-unknown-user"), bcrypt.DefaultCost)

// verdict ist das Ergebnis der Pruefung einer Anfrage.
type verdict struct {
	ok     bool
	status int    // 401 (Anmeldung koennte helfen) oder 403, wenn nicht ok
	failed bool   // falsche Anmeldedaten (zaehlt als Fehlversuch)
	user   string // angemeldet als (Benutzer der Liste oder Name des API-Keys)
	key    bool   // ueber einen API-Key
	fwd    bool   // noch beim Anmeldedienst pruefen
}

// decide: Zugriff erlaubt? key: Schluessel der Sitzungs-Cookies (Login-Seite; nil = ohne).
func (g *guard) decide(r *http.Request, ip netip.Addr, key []byte) verdict {
	a := g.list
	hasRules := len(a.Rules) > 0
	ipOK := !hasRules || a.ipAllowed(ip)
	if len(a.Users) == 0 && len(a.Keys) == 0 && g.fwd == nil { // nur IP-Regeln
		if ipOK {
			return verdict{ok: true}
		}
		return verdict{status: http.StatusForbidden}
	}
	if a.SatisfyAny && hasRules && ipOK {
		return verdict{ok: true}
	}
	if !ipOK && !a.SatisfyAny {
		return verdict{status: http.StatusForbidden}
	}
	name, ok, tried := g.keyOK(r)
	if ok {
		return verdict{ok: true, user: name, key: true}
	}
	if !tried && len(a.Users) > 0 {
		if ok, t := g.authOK(r); ok {
			u, _, _ := r.BasicAuth()
			return verdict{ok: true, user: u}
		} else if t {
			tried = true
		} else if a.LoginPage && g.fwd == nil {
			if u := g.cookieUser(r, key); u != "" {
				return verdict{ok: true, user: u}
			}
		}
	}
	if !tried && g.fwd != nil {
		return verdict{fwd: true}
	}
	return verdict{status: http.StatusUnauthorized, failed: tried}
}

// failLimiter begrenzt Fehlversuche je IP (IPv6 je /64 wie limKey, sonst wechselt ein Angreifer einfach die Adresse).
type failLimiter struct {
	mu   sync.Mutex
	fail map[netip.Addr][]time.Time
	ban  map[netip.Addr]time.Time
}

// authFailKeys: hoechstens so viele Adressen mit Fehlversuchen im Speicher (danach fallen zufaellige heraus).
const authFailKeys = 50000

func newFailLimiter() *failLimiter {
	return &failLimiter{fail: map[netip.Addr][]time.Time{}, ban: map[netip.Addr]time.Time{}}
}

func (l *failLimiter) blocked(ip netip.Addr) bool {
	ip = limKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.ban[ip]
	if ok && time.Now().After(until) {
		delete(l.ban, ip)
		return false
	}
	return ok
}

// failed zaehlt einen Fehlversuch; true = die IP ist jetzt gesperrt (erstmals).
func (l *failLimiter) failed(ip netip.Addr) bool {
	ip = limKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	list := l.fail[ip][:0]
	for _, t := range l.fail[ip] {
		if now.Sub(t) < authFailWindow {
			list = append(list, t)
		}
	}
	list = append(list, now)
	if _, known := l.fail[ip]; !known && len(l.fail) >= authFailKeys { // Speicher begrenzen: erst Abgelaufenes, dann zufaellige
		l.sweepLocked(now)
		for k := range l.fail {
			if len(l.fail) < authFailKeys {
				break
			}
			delete(l.fail, k)
		}
	}
	l.fail[ip] = list
	if len(list) >= authFailMax {
		delete(l.fail, ip)
		l.ban[ip] = now.Add(authBlockFor)
		return true
	}
	return false
}

// sweep entfernt abgelaufene Fehlversuche und Sperren (jede Minute aus limLoop).
func (l *failLimiter) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(time.Now())
}

func (l *failLimiter) sweepLocked(now time.Time) {
	for k, list := range l.fail {
		if len(list) == 0 || now.Sub(list[len(list)-1]) >= authFailWindow {
			delete(l.fail, k)
		}
	}
	for k, until := range l.ban {
		if now.After(until) {
			delete(l.ban, k)
		}
	}
}

// ---------------------------------------------------------------- Datenbank

const aclCols = `id, name, satisfy_any, pass_auth, login_page, users, rules, auth, forward, pass_user, api_keys, created_at, updated_at`

func scanACL(row interface{ Scan(...any) error }) (*AccessList, error) {
	var a AccessList
	var users, rules, fwd, keys, ca, ua string
	if err := row.Scan(&a.ID, &a.Name, &a.SatisfyAny, &a.PassAuth, &a.LoginPage, &users, &rules, &a.Auth, &fwd, &a.PassUser, &keys, &ca, &ua); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(users), &a.Users)
	_ = json.Unmarshal([]byte(rules), &a.Rules)
	_ = json.Unmarshal([]byte(fwd), &a.Forward)
	_ = json.Unmarshal([]byte(keys), &a.Keys)
	if a.Keys == nil {
		a.Keys = []AccessKey{}
	}
	if a.Users == nil {
		a.Users = []AccessUser{}
	}
	if a.Rules == nil {
		a.Rules = []AccessRule{}
	}
	a.CreatedAt, a.UpdatedAt = store.ParseTime(ca), store.ParseTime(ua)
	return &a, nil
}

func (m *Module) accessLists(ctx context.Context) ([]*AccessList, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT `+aclCols+` FROM cdn_access_lists ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AccessList
	for rows.Next() {
		a, err := scanACL(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (m *Module) accessList(ctx context.Context, id int64) (*AccessList, error) {
	a, err := scanACL(m.core.Reader().QueryRowContext(ctx, `SELECT `+aclCols+` FROM cdn_access_lists WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return a, err
}

// UserInput: neue oder geaenderte Benutzer (Passwort im Klartext, wird hier gehasht; leer = unveraendert).
type UserInput struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
}

// saveAccessList legt an oder aendert. users ersetzt die Benutzerliste: Benutzer ohne Passwort behalten ihren
// bisherigen Hash (neue brauchen eins).
func (m *Module) saveAccessList(ctx context.Context, a *AccessList, users []UserInput) error {
	a.Name = strings.TrimSpace(a.Name)
	if a.Name == "" || len(a.Name) > 100 {
		return ferr("name", "cdn64.err.acl_name")
	}
	old := map[string]string{}
	if a.ID > 0 {
		prev, err := m.accessList(ctx, a.ID)
		if err != nil {
			return err
		}
		for _, u := range prev.Users {
			old[u.Username] = u.Hash
		}
	}
	var out []AccessUser
	seen := map[string]bool{}
	for _, u := range users {
		name := strings.TrimSpace(u.Username)
		if name == "" {
			continue
		}
		if len(name) > 64 || strings.ContainsAny(name, ": \t") {
			return &FieldError{Field: "users", Key: "cdn64.err.acl_user", Name: name}
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		hash := old[name]
		if u.Password != "" {
			if len(u.Password) > 72 {
				return &FieldError{Field: "users", Key: "cdn64.err.acl_password", Name: name}
			}
			h, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			hash = string(h)
		}
		if hash == "" {
			return &FieldError{Field: "users", Key: "cdn64.err.acl_password", Name: name}
		}
		out = append(out, AccessUser{Username: name, Hash: hash})
	}
	var rules []AccessRule
	for _, r := range a.Rules {
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		r.CIDR = strings.TrimSpace(r.CIDR)
		if r.CIDR == "" {
			continue
		}
		if r.Action != "allow" && r.Action != "deny" {
			return &FieldError{Field: "rules", Key: "cdn64.err.acl_rule", Name: r.Action + " " + r.CIDR}
		}
		p, err := parsePrefix(r.CIDR)
		if err != nil {
			return &FieldError{Field: "rules", Key: "cdn64.err.acl_rule", Name: r.Action + " " + r.CIDR}
		}
		if r.CIDR != "all" && r.CIDR != "*" {
			r.CIDR = p.String()
		} else {
			r.CIDR = "all"
		}
		rules = append(rules, AccessRule{Action: r.Action, CIDR: r.CIDR})
	}
	a.Auth = strings.TrimSpace(a.Auth)
	if a.Auth == AuthUsers {
		a.Forward = ForwardAuth{}
	} else {
		if err := a.Forward.normalize(a.Auth); err != nil {
			return err
		}
		a.LoginPage = false // die Anmeldeseite stellt der Dienst
	}
	if err := normalizeKeys(a); err != nil {
		return err
	}
	if len(out) == 0 && len(rules) == 0 && a.Auth == AuthUsers && len(a.Keys) == 0 {
		return ferr("rules", "cdn64.err.acl_empty")
	}
	a.Users, a.Rules = out, rules
	ub, _ := json.Marshal(out)
	rb, _ := json.Marshal(rules)
	fb, _ := json.Marshal(a.Forward)
	kb, _ := json.Marshal(a.Keys)
	now := store.Now()
	w := m.core.Writer()
	if a.ID == 0 {
		res, err := w.ExecContext(ctx, `INSERT INTO cdn_access_lists (name, satisfy_any, pass_auth, login_page, users, rules, auth, forward, pass_user, api_keys, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			a.Name, a.SatisfyAny, a.PassAuth, a.LoginPage, string(ub), string(rb), a.Auth, string(fb), a.PassUser, string(kb), now, now)
		if err != nil {
			return err
		}
		a.ID, _ = res.LastInsertId()
	} else if _, err := w.ExecContext(ctx, `UPDATE cdn_access_lists SET name = ?, satisfy_any = ?, pass_auth = ?, login_page = ?, users = ?, rules = ?,
		auth = ?, forward = ?, pass_user = ?, api_keys = ?, updated_at = ? WHERE id = ?`,
		a.Name, a.SatisfyAny, a.PassAuth, a.LoginPage, string(ub), string(rb), a.Auth, string(fb), a.PassUser, string(kb), now, a.ID); err != nil {
		return err
	}
	m.apply(ctx)
	return nil
}

// aclInUse: Hosts, die eine Liste benutzen (direkt oder in einer Location).
func (m *Module) aclInUse(ctx context.Context, id int64) []string {
	list, err := m.hosts(ctx)
	if err != nil {
		return nil
	}
	var out []string
	for _, h := range list {
		use := h.AccessListID == id
		for _, l := range h.Locations {
			use = use || l.AccessListID == id
		}
		if use {
			out = append(out, h.Names[0])
		}
	}
	return out
}

func (m *Module) deleteAccessList(ctx context.Context, id int64) error {
	if used := m.aclInUse(ctx, id); len(used) > 0 {
		return &FieldError{Field: "id", Key: "cdn64.err.acl_in_use", Name: strings.Join(used, ", ")}
	}
	res, err := m.core.Writer().ExecContext(ctx, `DELETE FROM cdn_access_lists WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// guards: je Liste ein Pruefer (beim Aufbau der Routen).
func (m *Module) guards(ctx context.Context) map[int64]*guard {
	out := map[int64]*guard{}
	list, err := m.accessLists(ctx)
	if err != nil {
		return out
	}
	for _, a := range list {
		out[a.ID] = newGuard(a)
	}
	return out
}
