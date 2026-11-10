// Package snmp ist der SNMP-Sammler von Monitor64 (Plan docs/PLAN-NODE64-MONITOR64.md, "Zugaenge – SNMP"):
// v1/v2c (Community) und v3 (USM), GETBULK ueber mehrere Spalten gleichzeitig, nur benoetigte Tabellen,
// 64-Bit-Zaehler. Immer abgefragt werden System (Laufzeit, Neustart), IF-MIB (Ports), HOST-RESOURCES, UCD-SNMP,
// IEEE8023-LAG-MIB, ENTITY-SENSOR-MIB, Printer-MIB und UPS-MIB; Geraete-Profile (profiles/*.json, Auswahl ueber
// sysObjectID) und eigene OIDs ergaenzen das.
//
// Wie die API-Sammler (Paket apis): Collect ist eine Abfragerunde (nicht gleichzeitig aufrufen), Zaehler werden im
// Sammler zwischen zwei Runden in Raten umgerechnet, Teilfehler liefern die uebrigen Dienste und einen
// *apis.PartialError. Dienst-Schluessel, Arten und Regeln entsprechen dem Mapper (if:, fs:, mem, cpu, temp: ...),
// damit Standard-Schwellen gleich wirken. Alles vom Geraet ist nicht vertrauenswuerdig: Groessen und Zeilen sind
// begrenzt, Texte bereinigt, NaN/Inf verworfen.
//
// Texte (Service.Name, Service.Text) vorerst deutsch wie im Mapper. Community und v3-Passwoerter stehen nie in
// Fehlertexten.
package snmp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Standardwerte.
const (
	DefaultPort         = 161
	DefaultTimeout      = 3 * time.Second  // je Anfrage
	DefaultRetries      = 1                // Wiederholungen je Anfrage
	DefaultMaxRep       = 20               // GETBULK max-repetitions (wird auf die Spaltenzahl verteilt)
	DefaultRoundTimeout = 30 * time.Second // ganze Runde (Plan: hoechstens 80 % des Intervalls, max. 30 s)
	DefaultRestartHold  = 15 * time.Minute // so lange steht nach einem Neustart der Fact "restarted"
	staticEvery         = 10 * time.Minute // Portnamen, Sensornamen neu lesen
	absentRetry         = 60 * time.Minute // fehlende MIB so lange nicht neu fragen
	profileEvery        = 60 * time.Minute // Profile neu waehlen
	counterTTL          = 60 * time.Minute // Zaehlerstaende ohne Aktualisierung vergessen
	maxPartErrors       = 5
	maxCustom           = 100  // eigene OIDs je Zugang
	maxSeenUp           = 8192 // gemerkte Ports, die schon verbunden waren
)

// Secret enthaelt die Geheimnisse eines SNMP-Zugangs (im Kern verschluesselt als ein Text, siehe String/ParseSecret).
type Secret struct {
	Community string `json:"community,omitempty"` // v1/v2c
	AuthPass  string `json:"auth,omitempty"`      // v3 Authentifizierung
	PrivPass  string `json:"priv,omitempty"`      // v3 Verschluesselung
}

// String liefert den Text fuer das verschluesselte Secret des Zugangs (JSON).
func (s Secret) String() string {
	b, _ := json.Marshal(s)
	return string(b)
}

// ParseSecret liest das entschluesselte Secret; ein Text ohne JSON gilt als Community.
func ParseSecret(raw string) Secret {
	var s Secret
	t := strings.TrimSpace(raw)
	if strings.HasPrefix(t, "{") && json.Unmarshal([]byte(t), &s) == nil {
		return s
	}
	return Secret{Community: raw}
}

func (s Secret) list() []string { return []string{s.Community, s.AuthPass, s.PrivPass} }

// CustomOID ist eine eigene OID am Host (eigener Dienst "oid:<OID>").
type CustomOID struct {
	OID     string  `json:"oid"`
	Name    string  `json:"name"`
	Unit    string  `json:"unit,omitempty"`
	Factor  float64 `json:"factor,omitempty"`  // 0 = 1
	Counter bool    `json:"counter,omitempty"` // Zaehler: Rate je Sekunde (mal Faktor)
	Rule    string  `json:"rule,omitempty"`    // optional Art fuer Schwellen (z. B. temp.system)
}

// Config ist die Konfiguration eines SNMP-Zugangs (ohne Geheimnisse ausser Secret).
type Config struct {
	Address      string        `json:"address"`                   // Host oder IP, optional mit Port
	Port         int           `json:"port,omitempty"`            // 0 = Port aus Address bzw. 161
	Version      string        `json:"version,omitempty"`         // "1", "2c" (Standard), "3"
	User         string        `json:"user,omitempty"`            // v3 Benutzer
	Level        string        `json:"level,omitempty"`           // v3: noAuthNoPriv, authNoPriv, authPriv (Standard)
	AuthProto    string        `json:"auth_proto,omitempty"`      // v3: SHA, SHA224, SHA256 (Standard), SHA384, SHA512, MD5
	PrivProto    string        `json:"priv_proto,omitempty"`      // v3: AES (Standard), AES192, AES256, AES192C, AES256C, DES
	ContextName  string        `json:"context,omitempty"`         // v3 Kontext (meist leer)
	Timeout      time.Duration `json:"timeout,omitempty"`         // je Anfrage
	Retries      int           `json:"retries,omitempty"`         // -1 = keine Wiederholung, 0 = Standard
	MaxRep       int           `json:"max_repetitions,omitempty"` // GETBULK
	RoundTimeout time.Duration `json:"round_timeout,omitempty"`   // ganze Runde
	Custom       []CustomOID   `json:"custom,omitempty"`
	Profiles     []string      `json:"profiles,omitempty"` // feste Profile (leer = automatisch)
	SeenUp       []string      `json:"seen_up,omitempty"`  // Port-Schluessel, die schon verbunden waren (vom Kern gemerkt)
	Secret       Secret        `json:"-"`
}

// Collector fragt einen SNMP-Agenten ab.
type Collector struct {
	cfg  Config
	mu   sync.Mutex
	c    conn
	dial func() (conn, error)
	now  func() time.Time

	sys      sysState
	counters map[string]ctr
	seenUp   map[string]bool
	maxSpeed map[string]float64
	absent   map[string]time.Time // MIB-Gruppe -> nicht fragen bis
	noHC     bool                 // keine 64-Bit-Zaehler (ifHC*): 32-Bit-Spalten nehmen

	ifStatic   map[string]ifInfo // ifIndex -> Name, Typ, Alias
	ifStaticAt time.Time
	portKeys   map[int]string  // ifIndex -> Dienst-Schluessel (Traps)
	ifUpNow    map[string]bool // ifIndex -> verbunden (letzte Runde, fuer LAG)

	sensorNames   map[string]string
	sensorNamesAt time.Time

	profiles  []*Profile
	profileAt time.Time
	profileOf string // sysObjectID|sysDescr der Auswahl
}

// New prueft die Konfiguration und baut den Sammler (verbindet noch nicht).
func New(cfg Config) (*Collector, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	c := &Collector{cfg: cfg, now: time.Now, counters: map[string]ctr{}, seenUp: map[string]bool{}, maxSpeed: map[string]float64{},
		absent: map[string]time.Time{}, portKeys: map[int]string{}}
	c.addSeenUp(cfg.SeenUp)
	c.dial = c.dialGoSNMP
	return c, nil
}

// AddSeenUp uebernimmt Ports, die schon einmal verbunden waren (vom Kern ueber Neustarts gemerkt, siehe SeenUp).
func (c *Collector) AddSeenUp(keys []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addSeenUp(keys)
}

func (c *Collector) addSeenUp(keys []string) {
	for _, k := range keys {
		if len(c.seenUp) >= maxSeenUp {
			return
		}
		if strings.HasPrefix(k, "if:") && len(k) <= maxKeyPartLen+32 {
			c.seenUp[k] = true
		}
	}
}

// normalize setzt Standardwerte und prueft die Felder.
func (cfg *Config) normalize() error {
	host, port := splitHostPort(cfg.Address)
	if host == "" {
		return errors.New(model.T("monitor64.txt.addr_required"))
	}
	if cfg.Port <= 0 {
		cfg.Port = port
	}
	if cfg.Port <= 0 {
		cfg.Port = DefaultPort
	}
	if cfg.Port > 65535 {
		return errors.New(model.T("monitor64.txt.port_bad"))
	}
	cfg.Address = host
	switch strings.ToLower(strings.TrimPrefix(cfg.Version, "v")) {
	case "", "2", "2c":
		cfg.Version = "2c"
	case "1":
		cfg.Version = "1"
	case "3":
		cfg.Version = "3"
	default:
		return errors.New(model.T("monitor64.txt.snmp_version", "v", cfg.Version))
	}
	if cfg.Version == "3" {
		if cfg.User == "" {
			return errors.New(model.T("monitor64.txt.snmp_v3_user"))
		}
		lvl, err := parseLevel(cfg.Level)
		if err != nil {
			return err
		}
		cfg.Level = lvl
		if lvl != "noAuthNoPriv" {
			if _, err := authProto(cfg.AuthProto); err != nil {
				return err
			}
			if len(cfg.Secret.AuthPass) < 8 {
				return errors.New(model.T("monitor64.txt.snmp_auth_short"))
			}
		}
		if lvl == "authPriv" {
			if _, err := privProto(cfg.PrivProto); err != nil {
				return err
			}
			if len(cfg.Secret.PrivPass) < 8 {
				return errors.New(model.T("monitor64.txt.snmp_priv_short"))
			}
		}
	} else if cfg.Secret.Community == "" {
		return errors.New(model.T("monitor64.txt.snmp_community"))
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	cfg.Timeout = min(cfg.Timeout, 30*time.Second)
	switch {
	case cfg.Retries < 0:
		cfg.Retries = 0
	case cfg.Retries == 0:
		cfg.Retries = DefaultRetries
	}
	cfg.Retries = min(cfg.Retries, 5)
	if cfg.MaxRep <= 0 {
		cfg.MaxRep = DefaultMaxRep
	}
	cfg.MaxRep = min(cfg.MaxRep, 100)
	if cfg.RoundTimeout <= 0 || cfg.RoundTimeout > DefaultRoundTimeout {
		cfg.RoundTimeout = DefaultRoundTimeout
	}
	if len(cfg.Custom) > maxCustom {
		return errors.New(model.T("monitor64.txt.snmp_custom_max", "n", maxCustom))
	}
	for i, co := range cfg.Custom {
		if err := co.validate(); err != nil {
			return fmt.Errorf("%s: %w", model.T("monitor64.txt.snmp_custom_n", "n", i+1), err)
		}
		cfg.Custom[i].OID = normOID(co.OID)
	}
	for _, id := range cfg.Profiles {
		if ProfileByID(id) == nil {
			return errors.New(model.T("monitor64.txt.snmp_profile_unknown", "v", id))
		}
	}
	return nil
}

func parseLevel(s string) (string, error) {
	switch strings.ToLower(s) {
	case "", "authpriv", "priv":
		return "authPriv", nil
	case "authnopriv", "auth":
		return "authNoPriv", nil
	case "noauthnopriv", "noauth":
		return "noAuthNoPriv", nil
	}
	return "", errors.New(model.T("monitor64.txt.snmp_level", "v", s))
}

func authProto(s string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch strings.ToUpper(strings.ReplaceAll(s, "-", "")) {
	case "", "SHA256":
		return gosnmp.SHA256, nil
	case "SHA", "SHA1":
		return gosnmp.SHA, nil
	case "SHA224":
		return gosnmp.SHA224, nil
	case "SHA384":
		return gosnmp.SHA384, nil
	case "SHA512":
		return gosnmp.SHA512, nil
	case "MD5":
		return gosnmp.MD5, nil
	}
	return gosnmp.NoAuth, errors.New(model.T("monitor64.txt.snmp_auth_proto", "v", s))
}

func privProto(s string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch strings.ToUpper(strings.ReplaceAll(s, "-", "")) {
	case "", "AES", "AES128":
		return gosnmp.AES, nil
	case "AES192":
		return gosnmp.AES192, nil
	case "AES256":
		return gosnmp.AES256, nil
	case "AES192C":
		return gosnmp.AES192C, nil
	case "AES256C":
		return gosnmp.AES256C, nil
	case "DES":
		return gosnmp.DES, nil
	}
	return gosnmp.NoPriv, errors.New(model.T("monitor64.txt.snmp_priv_proto", "v", s))
}

// USM baut die v3-Sicherheitsparameter (auch fuer den Trap-Empfaenger).
func USM(user, level, auth, priv string, sec Secret) (*gosnmp.UsmSecurityParameters, gosnmp.SnmpV3MsgFlags, error) {
	lvl, err := parseLevel(level)
	if err != nil {
		return nil, 0, err
	}
	sp := &gosnmp.UsmSecurityParameters{UserName: user, AuthenticationProtocol: gosnmp.NoAuth, PrivacyProtocol: gosnmp.NoPriv}
	flags := gosnmp.NoAuthNoPriv
	if lvl != "noAuthNoPriv" {
		a, err := authProto(auth)
		if err != nil {
			return nil, 0, err
		}
		sp.AuthenticationProtocol, sp.AuthenticationPassphrase = a, sec.AuthPass
		flags = gosnmp.AuthNoPriv
	}
	if lvl == "authPriv" {
		p, err := privProto(priv)
		if err != nil {
			return nil, 0, err
		}
		sp.PrivacyProtocol, sp.PrivacyPassphrase = p, sec.PrivPass
		flags = gosnmp.AuthPriv
	}
	return sp, flags, nil
}

func (co CustomOID) validate() error {
	if normOID(co.OID) == "" {
		return errors.New(model.T("monitor64.txt.oid_invalid", "v", co.OID))
	}
	if strings.TrimSpace(co.Name) == "" || len(co.Name) > maxTextLen {
		return errors.New(model.T("monitor64.txt.name_missing"))
	}
	if !validUnit(co.Unit) {
		return errors.New(model.T("monitor64.txt.unit_unknown", "v", co.Unit))
	}
	if co.Rule != "" && !validRule(co.Rule) {
		return errors.New(model.T("monitor64.txt.rule_unknown", "v", co.Rule))
	}
	if !finite(co.Factor) {
		return errors.New(model.T("monitor64.txt.factor_invalid"))
	}
	return nil
}

// splitHostPort trennt "host", "host:port", "[v6]:port" und "v6".
func splitHostPort(a string) (string, int) {
	a = strings.TrimSpace(a)
	if h, p, err := net.SplitHostPort(a); err == nil {
		n, _ := strconv.Atoi(p)
		return h, n
	}
	return strings.Trim(a, "[]"), 0
}

func (c *Collector) dialGoSNMP() (conn, error) {
	cfg := c.cfg
	g := &gosnmp.GoSNMP{Target: cfg.Address, Port: uint16(cfg.Port), Transport: "udp", Timeout: cfg.Timeout, Retries: cfg.Retries,
		MaxOids: maxGetOIDs, MaxRepetitions: uint32(cfg.MaxRep), Context: context.Background()}
	switch cfg.Version {
	case "1":
		g.Version, g.Community = gosnmp.Version1, cfg.Secret.Community
	case "2c":
		g.Version, g.Community = gosnmp.Version2c, cfg.Secret.Community
	case "3":
		sp, flags, err := USM(cfg.User, cfg.Level, cfg.AuthProto, cfg.PrivProto, cfg.Secret)
		if err != nil {
			return nil, err
		}
		g.Version, g.SecurityModel, g.MsgFlags, g.SecurityParameters, g.ContextName = gosnmp.Version3, gosnmp.UserSecurityModel, flags, sp, cfg.ContextName
	}
	if err := g.Connect(); err != nil {
		return nil, err
	}
	return &gsConn{g: g}, nil
}

// Close beendet die Verbindung.
func (c *Collector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetConn()
}

func (c *Collector) resetConn() {
	if c.c != nil {
		c.c.close()
		c.c = nil
	}
}

func (c *Collector) connect() (conn, error) {
	if c.c != nil {
		return c.c, nil
	}
	cn, err := c.dial()
	if err != nil {
		return nil, c.scrubErr(err)
	}
	c.c = cn
	return cn, nil
}

func (c *Collector) scrub(s string) string {
	for _, sec := range c.cfg.Secret.list() {
		if len(sec) >= 3 {
			s = strings.ReplaceAll(s, sec, "***")
		}
	}
	return s
}

func (c *Collector) scrubErr(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(c.scrub(err.Error()))
}

// partial sammelt Teilfehler einer Runde.
type partial struct {
	errs     []string
	prefixes map[string]bool
	scrub    func(string) string
}

func (p *partial) add(what string, err error, prefixes ...string) {
	if err == nil {
		return
	}
	msg := what + ": " + err.Error()
	if p.scrub != nil {
		msg = p.scrub(msg)
	}
	p.errs = append(p.errs, msg)
	if p.prefixes == nil {
		p.prefixes = map[string]bool{}
	}
	for _, pre := range prefixes {
		p.prefixes[pre] = true
	}
}

func (p *partial) result() error {
	if len(p.errs) == 0 {
		return nil
	}
	pre := make([]string, 0, len(p.prefixes))
	for k := range p.prefixes {
		pre = append(pre, k)
	}
	sort.Strings(pre)
	return &apis.PartialError{Errs: p.errs, Prefixes: pre}
}

// isAbsent: MIB-Gruppe gibt es auf dem Geraet nicht (bis zur naechsten Pruefung).
func (c *Collector) isAbsent(group string, now time.Time) bool {
	until, ok := c.absent[group]
	return ok && now.Before(until)
}

func (c *Collector) markAbsent(group string, now time.Time, absent bool) {
	if absent {
		c.absent[group] = now.Add(absentRetry)
	} else {
		delete(c.absent, group)
	}
}

// round ist der Zustand einer Abfragerunde.
type round struct {
	ctx  context.Context
	c    conn
	now  time.Time // Beginn der Runde
	at   time.Time // Messzeitpunkt der zuletzt gelesenen Werte (fuer Raten; Abfragen dauern unterschiedlich lange)
	part *partial
	sys  sysInfo
	out  []model.Service
	ifOK bool // Portstatus (IF-MIB) in dieser Runde gelesen
}

// Collect ist eine Abfragerunde (nicht gleichzeitig mit sich selbst aufrufen).
func (c *Collector) Collect(ctx context.Context) ([]model.Service, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, c.cfg.RoundTimeout)
	defer cancel()
	return c.collect(ctx)
}

func (c *Collector) collect(ctx context.Context) ([]model.Service, error) {
	cn, err := c.connect()
	if err != nil {
		return nil, err
	}
	now := c.now()
	r := &round{ctx: ctx, c: cn, now: now, at: now, part: &partial{scrub: c.scrub}}
	si, err := c.querySystem(r)
	if err != nil {
		c.resetConn() // v3: beim naechsten Mal neu erkennen (Engine-ID/Boots)
		return nil, c.scrubErr(err)
	}
	r.sys = si
	if s, ok := c.uptimeService(r); ok {
		r.out = append(r.out, s)
	}
	c.selectProfiles(r)
	c.collectIF(r)
	c.collectLAG(r)
	c.collectHost(r)
	c.collectSensors(r)
	c.collectPrinter(r)
	c.collectUPS(r)
	c.collectProfiles(r)
	c.collectCustom(r)
	c.cleanCounters(r.now)
	return finish(r.out), r.part.result()
}

// finish sortiert, fasst gleiche Schluessel zusammen und vergibt bei Doppelten einen Zusatz.
func finish(in []model.Service) []model.Service {
	idx := map[string]int{}
	var out []model.Service
	for _, s := range in {
		if i, ok := idx[s.Key]; ok {
			out[i] = mergeService(out[i], s)
			continue
		}
		idx[s.Key] = len(out)
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return kindOrder(out[i].Kind) < kindOrder(out[j].Kind) })
	return out
}

// mergeService ergaenzt a um Messgroessen, Facts und Text von b (a gewinnt bei gleichen Namen).
func mergeService(a, b model.Service) model.Service {
	have := map[string]bool{}
	for _, m := range a.Metrics {
		have[m.Name] = true
	}
	for _, m := range b.Metrics {
		if !have[m.Name] {
			a.Metrics = append(a.Metrics, m)
			have[m.Name] = true
		}
	}
	codes := map[string]bool{}
	for _, f := range a.Facts {
		codes[f.Code] = true
	}
	for _, f := range b.Facts {
		if !codes[f.Code] {
			a.Facts = append(a.Facts, f)
			codes[f.Code] = true
		}
	}
	switch {
	case a.Text == "":
		a.Text = b.Text
	case b.Text != "" && !strings.Contains(a.Text, b.Text):
		a.Text += " · " + b.Text
	}
	if a.Name == "" || a.Name == a.Key {
		a.Name = b.Name
	}
	a.Default = a.Default || b.Default
	return a
}

func kindOrder(k string) int {
	order := []string{"uptime", "cpu", "load", "mem", "swap", "temp", "ups", "printer", "supply", "tray", "fs", "store", "zfs",
		"raid", "disk", "if", "bond", "poe", "wlan", "fan", "psu", "oid"}
	for i, o := range order {
		if o == k {
			return i
		}
	}
	return len(order)
}

// PortKey liefert den Dienst-Schluessel eines Ports zum ifIndex (fuer linkDown/linkUp-Traps; "" = unbekannt).
func (c *Collector) PortKey(ifIndex int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.portKeys[ifIndex]
}

// SeenUp liefert die Ports, die schon einmal verbunden waren (der Kern kann sie in Config.SeenUp merken).
func (c *Collector) SeenUp() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.seenUp))
	for k := range c.seenUp {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Discovery ist das Ergebnis von "Verbindung testen" samt erkannten Diensten.
type Discovery struct {
	apis.TestResult
	ObjectID string          `json:"object_id,omitempty"`
	Descr    string          `json:"descr,omitempty"`
	Name     string          `json:"name,omitempty"`
	Uptime   int64           `json:"uptime,omitempty"` // Sekunden
	Device   string          `json:"device,omitempty"` // nas, ups, printer, switch, router, ap, server, device
	Profiles []ProfileInfo   `json:"profiles,omitempty"`
	Services []model.Service `json:"services,omitempty"`
}

// ProfileInfo nennt ein erkanntes Profil.
type ProfileInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Verified bool   `json:"verified"`
}

// Test prueft die Verbindung (Systemgruppe, Profilwahl) – fuer den Assistenten "Verbindung testen".
func (c *Collector) Test(ctx context.Context) apis.TestResult {
	d, err := c.Discover(ctx)
	if err != nil {
		return apis.TestResult{OK: false, Error: err.Error(), Warning: c.warning()}
	}
	return d.TestResult
}

// Discover fragt einmal alles ab und liefert System, Profile, Geraeteart und Dienste (Default = vorgeschlagen).
func (c *Collector) Discover(ctx context.Context) (*Discovery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, c.cfg.RoundTimeout)
	defer cancel()
	svcs, err := c.collect(ctx)
	if err != nil && !apis.IsPartial(err) {
		return nil, err
	}
	d := &Discovery{ObjectID: c.sys.objectID, Descr: c.sys.descr, Name: c.sys.name, Uptime: int64(c.sys.uptime / time.Second), Services: svcs}
	for _, p := range c.profiles {
		d.Profiles = append(d.Profiles, ProfileInfo{ID: p.ID, Name: p.Name, Verified: p.Verified})
	}
	d.Device = c.deviceKind(svcs)
	d.OK, d.Version, d.Node, d.Trusted = true, shorten(c.sys.descr, 120), c.sys.name, true
	warn := []string{}
	if w := c.warning(); w != "" {
		warn = append(warn, w)
	}
	if err != nil { // Teilfehler: erreichbar, aber nicht alles lesbar
		warn = append(warn, err.Error())
	}
	d.Warning = strings.Join(warn, " · ")
	d.Summary = summary(d, svcs)
	return d, nil
}

func (c *Collector) warning() string {
	var w []string
	if c.cfg.Version != "3" {
		w = append(w, model.T("monitor64.txt.snmp_warn_community"))
	} else {
		if strings.EqualFold(c.cfg.AuthProto, "MD5") && c.cfg.Level != "noAuthNoPriv" {
			w = append(w, model.T("monitor64.txt.snmp_warn_md5"))
		}
		if strings.EqualFold(c.cfg.PrivProto, "DES") && c.cfg.Level == "authPriv" {
			w = append(w, model.T("monitor64.txt.snmp_warn_des"))
		}
		if c.cfg.Level == "noAuthNoPriv" {
			w = append(w, model.T("monitor64.txt.snmp_warn_noauth"))
		}
	}
	return strings.Join(w, " · ")
}

func summary(d *Discovery, svcs []model.Service) string {
	var parts []string
	for _, p := range d.Profiles {
		parts = append(parts, model.Raw(p.Name))
	}
	count := map[string]int{}
	for _, s := range svcs {
		count[s.Kind]++
	}
	add := func(kind, one, many string) {
		switch n := count[kind]; n {
		case 0:
		case 1:
			parts = append(parts, model.T(one))
		default:
			parts = append(parts, model.T(many, "n", n))
		}
	}
	add("if", "monitor64.txt.sum_port", "monitor64.txt.sum_ports")
	add("fs", "monitor64.txt.sum_fs", "monitor64.txt.sum_fss")
	add("temp", "monitor64.txt.sum_temp", "monitor64.txt.sum_temps")
	add("disk", "monitor64.txt.sum_disk", "monitor64.txt.sum_disks")
	add("supply", "monitor64.txt.sum_supply", "monitor64.txt.sum_supplies")
	if count["ups"] > 0 {
		parts = append(parts, model.T("monitor64.svc.ups_plain"))
	}
	return strings.Join(parts, " · ")
}

// deviceKind: Geraeteart aus Profil bzw. Diensten.
func (c *Collector) deviceKind(svcs []model.Service) string {
	for _, p := range c.profiles {
		if p.Device != "" {
			return p.Device
		}
	}
	count := map[string]int{}
	for _, s := range svcs {
		count[s.Kind]++
	}
	d := strings.ToLower(c.sys.descr)
	switch {
	case count["ups"] > 0:
		return "ups"
	case count["printer"] > 0 || count["supply"] > 0:
		return "printer"
	case strings.Contains(d, "linux") || strings.Contains(d, "windows") || strings.Contains(d, "freebsd") || count["fs"] > 0:
		return "server"
	case count["if"] >= 8:
		return "switch"
	}
	return "device"
}

// Queries nennt die abgefragten OIDs/Tabellen im Klartext ("Was wird abgefragt?").
func (c *Collector) Queries() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	q := []string{
		"GET SNMPv2-MIB system (sysDescr, sysObjectID, sysUpTime, sysName), HOST-RESOURCES hrSystemUptime",
		"GETBULK IF-MIB ifTable/ifXTable (Status, Geschwindigkeit, Bytes, Pakete, Fehler, Verwerfungen; Namen alle 10 min), EtherLike dot3StatsDuplexStatus",
		"GETBULK IEEE8023-LAG-MIB dot3adAggTable, dot3adAggPortTable",
		"GETBULK HOST-RESOURCES hrStorageTable, hrProcessorLoad",
		"GET/GETBULK UCD-SNMP memory, laLoadInt, dskTable, ssCpuRaw*",
		"GETBULK ENTITY-SENSOR-MIB entPhySensorTable, GET entPhysicalName (alle 10 min)",
		"GETBULK Printer-MIB prtMarkerSuppliesTable, prtInputTable, prtMarkerLifeCount, hrPrinterTable",
		"GET/GETBULK UPS-MIB upsBattery, upsOutput, upsInput, upsAlarmTable",
	}
	q = append(q, "fehlende MIBs werden nur stündlich neu geprüft")
	for _, p := range c.profiles {
		q = append(q, "Profil "+p.Name+": "+strings.Join(p.oids(), ", "))
	}
	for _, co := range c.cfg.Custom {
		q = append(q, "GET "+co.OID+" ("+co.Name+")")
	}
	return q
}

func shorten(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
