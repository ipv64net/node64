// Package ldapauth meldet Benutzer gegen ein vorhandenes AD/LDAP an (Node64 als LDAP-Client, siehe
// docs/PLAN-NODE64-BENUTZER.md): Verbindung mit TLS (ldaps:// oder StartTLS; Klartext nur mit Schalter), Bind mit dem
// Dienstkonto, Benutzer suchen, Bind als Benutzer, Gruppen lesen. Nur lokal fuer Node64 (kein Bezug zu ipv64.net).
// Passwoerter und das Bind-Passwort stehen nie in Fehlermeldungen.
package ldapauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/ipv64net/node64/internal/authcfg"
)

var (
	// ErrInvalidCredentials: Passwort falsch oder leer, Benutzername ungueltig.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrUnknownUser: der Filter findet keinen Eintrag.
	ErrUnknownUser = errors.New("user not found in directory")
	// ErrAmbiguous: der Filter findet mehr als einen Eintrag.
	ErrAmbiguous = errors.New("user filter matches more than one entry")
	// ErrDisabled: im Verzeichnis deaktiviert, abgelaufen bzw. gesperrt (AD: userAccountControl Bit 2, accountExpires;
	// LDAP: nsAccountLock, dauerhafte Sperre per pwdAccountLockedTime).
	ErrDisabled = errors.New("account disabled in directory")
	// ErrBusy: zu viele gleichzeitige Anmeldungen am Verzeichnis.
	ErrBusy = errors.New("too many concurrent directory requests")
	// ErrConfig: Einrichtung unvollstaendig (Server, Base-DN, Bind-Passwort).
	ErrConfig = errors.New("ldap configuration incomplete")
	// ErrUnreachable: kein Server erreichbar bzw. TLS gescheitert.
	ErrUnreachable = errors.New("no directory server reachable")
)

// Identity ist ein im Verzeichnis angemeldeter Benutzer.
type Identity struct {
	StableKey   string   // AD objectGUID (hex), sonst entryUUID, sonst normalisierter DN
	Username    string   // sAMAccountName bzw. uid, klein geschrieben
	DisplayName string   // displayName, sonst cn
	Email       string   // mail
	DN          string   // Eintrag des Benutzers
	GroupDNs    []string // Gruppen (memberOf, verschachtelt bzw. per Gruppensuche)
	Disabled    bool     // nur Lookup: Konto im Verzeichnis deaktiviert (Authenticate lehnt das schon ab)
}

// TestResult ist das Ergebnis von „Verbindung testen“.
type TestResult struct {
	URL         string   `json:"url"`
	TLS         bool     `json:"tls"`
	Probe       string   `json:"probe,omitempty"`
	Found       bool     `json:"found"`
	DN          string   `json:"dn,omitempty"`
	Username    string   `json:"username,omitempty"`
	DisplayName string   `json:"display_name,omitempty"`
	Email       string   `json:"email,omitempty"`
	StableKey   string   `json:"stable_key,omitempty"`
	Disabled    bool     `json:"disabled,omitempty"`
	Groups      []string `json:"groups"`
}

// Grenzen: gleichzeitige Anfragen ans Verzeichnis, Zeitlimit, Laenge des Benutzernamens, Gruppen je Benutzer.
const (
	maxConcurrent  = 8
	defaultTimeout = 10 * time.Second
	maxTimeout     = 60 * time.Second
	maxNameLen     = 256
	maxGroups      = 1000
	oidInChain     = "1.2.840.113556.1.4.1941" // LDAP_MATCHING_RULE_IN_CHAIN (AD, verschachtelte Gruppen)
	uacDisabled    = 0x2                       // userAccountControl: ACCOUNTDISABLE
	adNever        = 1<<63 - 1                 // accountExpires: laeuft nie ab (wie 0)
	adEpochOffset  = 11644473600               // Sekunden von 1601-01-01 bis 1970-01-01 (accountExpires)
	ppolicyLocked  = "000001010000Z"           // pwdAccountLockedTime: dauerhaft gesperrt (bis ein Admin entsperrt)
)

var sem = make(chan struct{}, maxConcurrent)

// Attribute des Benutzers (beide Profile; was es nicht gibt, fehlt einfach).
var userAttrs = []string{"objectGUID", "entryUUID", "sAMAccountName", "userPrincipalName", "uid", "displayName", "cn", "mail", "memberOf", "userAccountControl",
	"accountExpires", "nsAccountLock", "pwdAccountLockedTime"}

type ctxKey struct{}

// WithRootCAs gibt zusaetzliche vertrauenswuerdige CAs mit (z. B. die eigenen aus der Zertifikatsverwaltung); ohne
// gelten die des Systems.
func WithRootCAs(ctx context.Context, pool *x509.CertPool) context.Context {
	if pool == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, pool)
}

func rootCAs(ctx context.Context) *x509.CertPool {
	p, _ := ctx.Value(ctxKey{}).(*x509.CertPool)
	return p
}

// Timeout: eingestelltes Zeitlimit (0 = 10 s, hoechstens 60 s).
func Timeout(cfg authcfg.LDAPConfig) time.Duration {
	d := time.Duration(cfg.TimeoutSec) * time.Second
	if d <= 0 {
		return defaultTimeout
	}
	return min(d, maxTimeout)
}

func acquire(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return ErrBusy
	}
}

func release() { <-sem }

// ---------------------------------------------------------------- Verbindung

type conn struct {
	*ldap.Conn
	url  string
	tls  bool
	stop func() bool
	ctx  context.Context
	raw  net.Conn      // TCP-Verbindung (Frist)
	to   time.Duration // Zeitlimit je Vorgang
}

// renew setzt die Frist fuer den naechsten Vorgang (Bind, Suche) neu: das Zeitlimit gilt je Vorgang, nicht fuer die
// ganze Verbindung (der Abgleich arbeitet viele Benutzer nacheinander ab); nie ueber die Frist von ctx hinaus.
func (c *conn) renew() {
	if c.raw == nil || c.ctx.Err() != nil {
		return
	}
	deadline := time.Now().Add(c.to)
	if dl, ok := c.ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = c.raw.SetDeadline(deadline)
	if c.ctx.Err() != nil { // gerade abgebrochen: nicht wieder verlaengern
		_ = c.raw.SetDeadline(time.Now())
	}
}

func (c *conn) close() {
	c.stop()
	_ = c.Close()
}

// ErrPlain: ldap:// ohne StartTLS und ohne Schalter fuer Klartext.
var ErrPlain = errors.New("ldap:// needs StartTLS (or allow plain text)")

// CheckURL prueft eine Server-Adresse gegen die Einrichtung (Schema, Host, Klartext).
func CheckURL(cfg authcfg.LDAPConfig, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.User != nil || u.RawQuery != "" {
		return errors.New("invalid server url " + strconv.Quote(raw))
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return errors.New("invalid port in " + strconv.Quote(raw))
		}
	}
	switch strings.ToLower(u.Scheme) {
	case "ldaps":
	case "ldap":
		if !cfg.StartTLS && !cfg.AllowPlain {
			return ErrPlain
		}
	default:
		return errors.New("server url must start with ldaps:// or ldap://")
	}
	return nil
}

// connect verbindet mit dem ersten erreichbaren Server (nacheinander in der eingestellten Reihenfolge).
func connect(ctx context.Context, cfg authcfg.LDAPConfig) (*conn, error) {
	var errs []string
	for _, raw := range cfg.URLs {
		if raw = strings.TrimSpace(raw); raw == "" {
			continue
		}
		c, err := dial(ctx, cfg, raw)
		if err == nil {
			return c, nil
		}
		errs = append(errs, raw+": "+err.Error())
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("%w: no server", ErrConfig)
	}
	return nil, fmt.Errorf("%w: %s", ErrUnreachable, strings.Join(errs, "; "))
}

func dial(ctx context.Context, cfg authcfg.LDAPConfig, raw string) (*conn, error) {
	if err := CheckURL(cfg, raw); err != nil {
		return nil, err
	}
	u, _ := url.Parse(raw)
	scheme, host, port := strings.ToLower(u.Scheme), u.Hostname(), u.Port()
	if port == "" {
		port = map[string]string{"ldaps": "636", "ldap": "389"}[scheme]
	}
	to := Timeout(cfg)
	d := net.Dialer{Timeout: to}
	nc, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	// Zeitlimit fuer den Aufbau (TLS, StartTLS), danach je Vorgang neu (renew); Abbruch ueber ctx beendet sie sofort.
	c := &conn{url: raw, ctx: ctx, raw: nc, to: to}
	c.renew()
	c.stop = context.AfterFunc(ctx, func() { _ = c.raw.SetDeadline(time.Now()) })
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: rootCAs(ctx), InsecureSkipVerify: cfg.SkipVerify} //nolint:gosec // nur mit Schalter (Warnung in der Oberflaeche)
	if scheme == "ldaps" {
		t := tls.Client(nc, tc)
		if err := t.HandshakeContext(ctx); err != nil {
			c.stop()
			_ = nc.Close()
			return nil, err
		}
		nc, c.tls = t, true
	}
	c.Conn = ldap.NewConn(nc, c.tls)
	c.Start()
	c.SetTimeout(to)
	if scheme == "ldap" && cfg.StartTLS {
		if err := c.StartTLS(tc); err != nil {
			c.close()
			return nil, err
		}
		c.tls = true
	}
	return c, nil
}

// bindService meldet das Dienstkonto an (ohne Bind-DN: anonym, z. B. OpenLDAP mit anonymer Suche).
func bindService(c *conn, cfg authcfg.LDAPConfig, bindPassword string) error {
	if strings.TrimSpace(cfg.BindDN) == "" {
		return nil
	}
	if bindPassword == "" {
		return fmt.Errorf("%w: bind password missing", ErrConfig)
	}
	c.renew()
	if err := c.Bind(strings.TrimSpace(cfg.BindDN), bindPassword); err != nil {
		return fmt.Errorf("service account bind failed: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- Suchen

// validName: nicht leer, nicht zu lang, keine Steuerzeichen.
func validName(s string) bool {
	if s == "" || len(s) > maxNameLen {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// UserFilter: Filter fuer einen Benutzernamen (%s wird durch den escapten Namen ersetzt).
func UserFilter(cfg authcfg.LDAPConfig, username string) string {
	return strings.ReplaceAll(cfg.Filter(), "%s", ldap.EscapeFilter(username))
}

func findUser(c *conn, cfg authcfg.LDAPConfig, username string) (*ldap.Entry, error) {
	return findBy(c, cfg, UserFilter(cfg, username))
}

// findBy sucht genau einen Eintrag ueber filter.
func findBy(c *conn, cfg authcfg.LDAPConfig, filter string) (*ldap.Entry, error) {
	req := ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(Timeout(cfg).Seconds()), false,
		filter, userAttrs, nil)
	c.renew()
	res, err := c.Search(req)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			return nil, ErrAmbiguous
		}
		return nil, fmt.Errorf("user search failed: %w", err)
	}
	switch {
	case len(res.Entries) == 0:
		return nil, ErrUnknownUser
	case len(res.Entries) > 1:
		return nil, ErrAmbiguous
	case res.Entries[0].DN == "":
		return nil, ErrUnknownUser
	}
	return res.Entries[0], nil
}

// disabled: Konto im Verzeichnis deaktiviert, abgelaufen oder gesperrt. AD: userAccountControl Bit 2 oder accountExpires
// in der Vergangenheit; LDAP: nsAccountLock (389 DS, FreeIPA) oder dauerhafte Sperre per pwdAccountLockedTime
// (ppolicy; eine zeitweise Sperre nach Fehlversuchen zaehlt nicht, sonst koennte jeder mit falschen Passwoertern
// Rollen nehmen).
func disabled(cfg authcfg.LDAPConfig, e *ldap.Entry) bool {
	attr := func(n string) string { return strings.TrimSpace(e.GetEqualFoldAttributeValue(n)) }
	if cfg.Profile != authcfg.ProfileAD {
		return strings.EqualFold(attr("nsAccountLock"), "true") || attr("pwdAccountLockedTime") == ppolicyLocked
	}
	n, err := strconv.ParseInt(attr("userAccountControl"), 10, 64)
	if err == nil && n&uacDisabled != 0 {
		return true
	}
	return adExpired(attr("accountExpires"), time.Now())
}

// adExpired: accountExpires (100 ns seit 1601-01-01 UTC; 0 und adNever = nie) liegt vor now.
func adExpired(v string, now time.Time) bool {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 || n == adNever {
		return false
	}
	return time.Unix(n/10_000_000-adEpochOffset, 0).Before(now)
}

func identity(cfg authcfg.LDAPConfig, e *ldap.Entry, typed string) *Identity {
	id := &Identity{DN: e.DN, DisplayName: e.GetEqualFoldAttributeValue("displayName"), Email: e.GetEqualFoldAttributeValue("mail")}
	if id.DisplayName == "" {
		id.DisplayName = e.GetEqualFoldAttributeValue("cn")
	}
	if g := e.GetEqualFoldRawAttributeValue("objectGUID"); len(g) > 0 {
		id.StableKey = hex.EncodeToString(g)
	} else if u := strings.TrimSpace(e.GetEqualFoldAttributeValue("entryUUID")); u != "" {
		id.StableKey = strings.ToLower(u)
	} else {
		id.StableKey = NormalizeDN(e.DN)
	}
	names := []string{e.GetEqualFoldAttributeValue("uid"), e.GetEqualFoldAttributeValue("sAMAccountName")}
	if cfg.Profile == authcfg.ProfileAD {
		names[0], names[1] = names[1], names[0]
	}
	for _, n := range append(names, typed) {
		if n = strings.TrimSpace(n); n != "" {
			id.Username = strings.ToLower(n)
			break
		}
	}
	return id
}

// groupSearch liefert die DNs der Gruppen, auf die filter passt (bei mehr als maxGroups die ersten).
func groupSearch(c *conn, cfg authcfg.LDAPConfig, filter string) ([]string, error) {
	req := ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, maxGroups, int(Timeout(cfg).Seconds()), false,
		filter, []string{"1.1"}, nil)
	c.renew()
	res, err := c.Search(req)
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, fmt.Errorf("group search failed: %w", err)
	}
	var out []string
	if res != nil {
		for _, e := range res.Entries {
			out = append(out, e.DN)
		}
	}
	return out, nil
}

// groups: AD memberOf (verschachtelt zusaetzlich per LDAP_MATCHING_RULE_IN_CHAIN); LDAP memberOf, sonst Suche nach
// groupOfNames/groupOfUniqueNames/posixGroup.
func groups(c *conn, cfg authcfg.LDAPConfig, e *ldap.Entry) ([]string, error) {
	list := append([]string{}, e.GetEqualFoldAttributeValues("memberOf")...)
	dn := ldap.EscapeFilter(e.DN)
	var more []string
	var err error
	switch {
	case cfg.Profile == authcfg.ProfileAD && cfg.Nested:
		more, err = groupSearch(c, cfg, "(member:"+oidInChain+":="+dn+")")
	case cfg.Profile != authcfg.ProfileAD && len(list) == 0:
		f := "(|(member=" + dn + ")(uniqueMember=" + dn + ")"
		if uid := e.GetEqualFoldAttributeValue("uid"); uid != "" {
			f += "(memberUid=" + ldap.EscapeFilter(uid) + ")"
		}
		more, err = groupSearch(c, cfg, f+")")
	}
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range append(list, more...) {
		if k := NormalizeDN(g); g != "" && !seen[k] && len(out) < maxGroups {
			seen[k] = true
			out = append(out, g)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- Anmelden und Testen

// Authenticate prueft Benutzername und Passwort am Verzeichnis und liefert den Benutzer mit seinen Gruppen. Ein leeres
// Passwort wird immer abgelehnt (sonst waere es ein „unauthenticated bind“, den viele Server als Erfolg melden).
func Authenticate(ctx context.Context, cfg authcfg.LDAPConfig, bindPassword, username, password string) (*Identity, error) {
	username = strings.TrimSpace(username)
	if password == "" || !validName(username) {
		return nil, ErrInvalidCredentials
	}
	if strings.TrimSpace(cfg.BaseDN) == "" {
		return nil, fmt.Errorf("%w: base dn missing", ErrConfig)
	}
	if err := acquire(ctx, Timeout(cfg)); err != nil {
		return nil, err
	}
	defer release()
	c, err := connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer c.close()
	if err := bindService(c, cfg, bindPassword); err != nil {
		return nil, err
	}
	e, err := findUser(c, cfg, username)
	if err != nil {
		return nil, err
	}
	if disabled(cfg, e) {
		return nil, ErrDisabled
	}
	c.renew()
	if err := c.Bind(e.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("user bind failed: %w", err)
	}
	// Gruppen mit dem Dienstkonto lesen (der Benutzer selbst darf das Verzeichnis oft nicht durchsuchen)
	if err := bindService(c, cfg, bindPassword); err != nil {
		return nil, err
	}
	id := identity(cfg, e, username)
	if id.GroupDNs, err = groups(c, cfg, e); err != nil {
		return nil, err
	}
	return id, nil
}

// nameFilter: Eintrag ueber das Attribut, aus dem identity den Node64-Namen nimmt (sAMAccountName bzw. uid).
func nameFilter(name string) string {
	n := ldap.EscapeFilter(name)
	return "(|(sAMAccountName=" + n + ")(uid=" + n + "))"
}

// Lookup sucht Benutzer (Node64-Namen) mit dem Dienstkonto (ohne deren Passwort) und liefert sie mit Gruppen und
// Sperre: zuerst ueber den Benutzerfilter, findet der nichts, ueber sAMAccountName bzw. uid. Fehlt ein Name in der
// Antwort, gibt es ihn im Verzeichnis nicht (mehr). Fuer den regelmaessigen Abgleich der Gruppen und die
// Nachpruefung bei Passkey-Anmeldungen. Fehler (Verbindung, Dienstkonto, Suche) brechen ab: dann ist nichts geprueft.
func Lookup(ctx context.Context, cfg authcfg.LDAPConfig, bindPassword string, usernames []string) (map[string]*Identity, error) {
	if strings.TrimSpace(cfg.BaseDN) == "" {
		return nil, fmt.Errorf("%w: base dn missing", ErrConfig)
	}
	if err := acquire(ctx, Timeout(cfg)); err != nil {
		return nil, err
	}
	defer release()
	c, err := connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer c.close()
	if err := bindService(c, cfg, bindPassword); err != nil {
		return nil, err
	}
	out := map[string]*Identity{}
	for _, name := range usernames {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !validName(strings.TrimSpace(name)) {
			continue
		}
		e, err := findUser(c, cfg, strings.TrimSpace(name))
		if errors.Is(err, ErrUnknownUser) { // gespeicherter Name: der Benutzerfilter kann ein anderes Attribut meinen (z. B. mail)
			e, err = findBy(c, cfg, nameFilter(strings.TrimSpace(name)))
		}
		if errors.Is(err, ErrUnknownUser) || errors.Is(err, ErrAmbiguous) {
			continue
		}
		if err != nil {
			return nil, err
		}
		id := identity(cfg, e, name)
		id.Disabled = disabled(cfg, e)
		if id.GroupDNs, err = groups(c, cfg, e); err != nil {
			return nil, err
		}
		out[name] = id
	}
	return out, nil
}

// Test verbindet, meldet das Dienstkonto an und sucht optional probeUser (ohne dessen Passwort).
func Test(ctx context.Context, cfg authcfg.LDAPConfig, bindPassword, probeUser string) (TestResult, error) {
	res := TestResult{Probe: strings.TrimSpace(probeUser), Groups: []string{}}
	if strings.TrimSpace(cfg.BaseDN) == "" {
		return res, fmt.Errorf("%w: base dn missing", ErrConfig)
	}
	if err := acquire(ctx, Timeout(cfg)); err != nil {
		return res, err
	}
	defer release()
	c, err := connect(ctx, cfg)
	if err != nil {
		return res, err
	}
	defer c.close()
	res.URL, res.TLS = c.url, c.tls
	if err := bindService(c, cfg, bindPassword); err != nil {
		return res, err
	}
	if res.Probe == "" {
		return res, nil
	}
	if !validName(res.Probe) {
		return res, ErrUnknownUser
	}
	e, err := findUser(c, cfg, res.Probe)
	if errors.Is(err, ErrUnknownUser) {
		return res, nil
	}
	if err != nil {
		return res, err
	}
	id := identity(cfg, e, res.Probe)
	res.Found, res.DN, res.Username, res.DisplayName, res.Email, res.StableKey = true, id.DN, id.Username, id.DisplayName, id.Email, id.StableKey
	res.Disabled = disabled(cfg, e)
	if res.Groups, err = groups(c, cfg, e); err != nil {
		return res, err
	}
	if res.Groups == nil {
		res.Groups = []string{}
	}
	return res, nil
}

// ---------------------------------------------------------------- Gruppen vergleichen

// NormalizeDN: DN ohne Gross/klein und Leerzeichen um die Trenner (Attribute einer RDN sortiert); nicht lesbar = klein
// geschrieben wie eingegeben.
func NormalizeDN(s string) string {
	s = strings.TrimSpace(s)
	d, err := ldap.ParseDN(s)
	if err != nil || d == nil || len(d.RDNs) == 0 {
		return strings.ToLower(s)
	}
	esc := strings.NewReplacer(`\`, `\\`, ",", `\,`, "+", `\+`, "=", `\=`)
	parts := make([]string, 0, len(d.RDNs))
	for _, r := range d.RDNs {
		as := make([]string, 0, len(r.Attributes))
		for _, a := range r.Attributes {
			as = append(as, strings.ToLower(a.Type)+"="+esc.Replace(strings.ToLower(a.Value)))
		}
		sort.Strings(as)
		parts = append(parts, strings.Join(as, "+"))
	}
	return strings.Join(parts, ",")
}

// MatchGroup: passt die Zuordnung einer Node64-Gruppe (DN, oder nur der Name wie cn) zur Gruppe groupDN?
func MatchGroup(mapping, groupDN string) bool {
	m := strings.TrimSpace(mapping)
	if m == "" || strings.TrimSpace(groupDN) == "" {
		return false
	}
	if strings.Contains(m, "=") {
		return NormalizeDN(m) == NormalizeDN(groupDN)
	}
	d, err := ldap.ParseDN(groupDN)
	if err != nil || d == nil || len(d.RDNs) == 0 || len(d.RDNs[0].Attributes) == 0 {
		return strings.EqualFold(m, strings.TrimSpace(groupDN))
	}
	return strings.EqualFold(m, d.RDNs[0].Attributes[0].Value)
}

// GUIDString: objectGUID (16 Byte, hex wie StableKey) in der ueblichen Schreibweise von AD (zur Anzeige).
func GUIDString(key string) string {
	b, err := hex.DecodeString(key)
	if err != nil || len(b) != 16 {
		return key
	}
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]), b[8:10], b[10:16])
}
