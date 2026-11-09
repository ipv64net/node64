// Package trap ist der SNMP-Trap-Empfaenger von Monitor64 (Plan docs/PLAN-NODE64-MONITOR64.md, "SNMP – Traps"):
// UDP (Standard 162), v1/v2c-Traps und Informs, v3-Traps und -Informs (USM mit Benutzern je Host). Angenommen wird nur
// von bekannten Absendern mit passender Community bzw. passendem v3-Benutzer; alles andere wird gezaehlt und hoechstens
// als "unbekannter Absender" gemeldet. Groessen- und Ratenbegrenzung je Absender vor dem Dekodieren, keine Panics bei
// kaputten Paketen.
//
// Der Empfaenger entscheidet nichts ueber Zustaende: Jeder Trap wird als Event an den Rueckruf gegeben, bekannte Traps
// (linkDown/linkUp, UPS-MIB, APC, Neustart) mit dem betroffenen Dienst-Schluessel zum sofortigen Nachfragen. Der
// Zustand kommt weiter aus der Abfrage (Paket snmp).
package trap

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"

	"github.com/ipv64net/node64/internal/monitor64/snmp"
)

// Standardwerte.
const (
	DefaultListen      = ":162"
	DefaultMaxSize     = 64 * 1024 // Plan "Sicherheit": Trap max. 64 KB
	DefaultRate        = 10.0      // Traps je Sekunde und Absender
	DefaultBurst       = 50        // kurzzeitig mehr
	DefaultGlobalRate  = 500.0     // alle Absender zusammen
	DefaultMaxSenders  = 4096      // so viele Absender merkt sich die Ratenbegrenzung
	DefaultMaxVarbinds = 32        // Varbinds im Event
	DefaultMaxValueLen = 256       // Zeichen je Wert im Event
	queueSize          = 256       // Events bis zum Rueckruf

	timeWindow    = 150       // Sekunden: Zeitfenster fuer v3 (RFC 3414 3.2.7)
	maxEngineBoot = 1<<31 - 1 // snmpEngineBoots am Ende: keine Nachricht mehr gueltig
	maxTimeStates = 4096      // so viele Engine-ID/Benutzer merkt sich die Zeitpruefung
	localBoots    = 1         // eigene snmpEngineBoots (die eigene Zeit laeuft ab engineEpoch, ueber Neustarts weiter)
)

// engineEpoch: Beginn der eigenen snmpEngineTime (Sekunden seit diesem Zeitpunkt). Die Zeit laeuft so ueber Neustarts
// der Node weiter; Absender von v3-Informs behalten ihren Stand, wiederholte (mitgeschnittene) Informs fallen aus
// dem Zeitfenster.
var engineEpoch = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// User ist ein v3-Benutzer eines Hosts (Geheimnisse aus dem verschluesselten Secret des Zugangs).
type User struct {
	Name      string
	Level     string // noAuthNoPriv, authNoPriv, authPriv (Standard)
	AuthProto string // wie snmp.Config
	PrivProto string
	Secret    snmp.Secret
	EngineID  string // optional (hex): nur Traps dieser Engine-ID annehmen; leer = jede
}

// Host ist ein bekannter Absender.
type Host struct {
	ID          string       // Kennung im Kern (Host-UID)
	Addrs       []netip.Addr // Absender-Adressen
	Communities []string     // v1/v2c
	Users       []User       // v3
}

// Config ist die Konfiguration des Empfaengers.
type Config struct {
	Listen      string  // ":162" bzw. ":1162"
	MaxSize     int     // groessere Pakete werden verworfen
	Rate        float64 // je Absender und Sekunde
	Burst       int
	GlobalRate  float64
	MaxSenders  int
	MaxVarbinds int
	MaxValueLen int
	EngineID    string // lokale Engine-ID (hex) fuer v3-Informs; leer = zufaellig (der Kern sollte sie speichern)
}

// Varbind ist ein Wert aus dem Trap (gekuerzt, als Text).
type Varbind struct {
	OID   string `json:"oid"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Event ist ein empfangener Trap.
type Event struct {
	Time      time.Time  `json:"time"`
	From      netip.Addr `json:"from"`
	HostID    string     `json:"host_id,omitempty"` // "" = unbekannter Absender
	Known     bool       `json:"known"`
	Rejected  string     `json:"rejected,omitempty"` // bekannter Absender, aber "community", "user", "engine" bzw. "time" passt nicht
	Version   string     `json:"version"`            // 1, 2c, 3
	Inform    bool       `json:"inform,omitempty"`
	User      string     `json:"user,omitempty"` // v3-Benutzer
	TrapOID   string     `json:"trap_oid,omitempty"`
	TrapName  string     `json:"trap_name,omitempty"` // bekannte: linkDown, upsTrapOnBattery ...
	Uptime    uint32     `json:"uptime,omitempty"`    // 1/100 s laut Absender
	Varbinds  []Varbind  `json:"varbinds,omitempty"`
	Truncated bool       `json:"truncated,omitempty"` // Varbinds gekuerzt
	// Zuordnung bekannter Traps
	Kind    string `json:"kind,omitempty"`     // link_down, link_up, restart, ups_on_battery, ups_on_line, ups_battery_low ...
	IfIndex int    `json:"if_index,omitempty"` // linkDown/linkUp
	IfName  string `json:"if_name,omitempty"`  // falls mitgeschickt (ifName/ifDescr)
	Service string `json:"service,omitempty"`  // betroffener Dienst-Schluessel zum sofortigen Nachfragen ("ups", "if:<ifName>", "uptime")
}

// Stats zaehlt, was der Empfaenger verworfen hat.
type Stats struct {
	Received    uint64 `json:"received"`
	Accepted    uint64 `json:"accepted"`
	TooBig      uint64 `json:"too_big"`
	RateLimited uint64 `json:"rate_limited"`
	BadPacket   uint64 `json:"bad_packet"`
	Rejected    uint64 `json:"rejected"`
	Unknown     uint64 `json:"unknown"`
	QueueFull   uint64 `json:"queue_full"`
}

// hostEntry ist ein Host mit vorbereiteten v3-Parametern.
type hostEntry struct {
	h      Host
	comm   map[string]bool
	v3     *gosnmp.GoSNMP // Parameter-Tabelle der v3-Benutzer (nil = keine)
	engine map[string]string
}

// Receiver empfaengt Traps.
type Receiver struct {
	cfg      Config
	cb       func(Event)
	engineID string // roh (Bytes als string)

	mu     sync.Mutex
	pc     net.PacketConn
	done   chan struct{}
	queue  chan Event
	byAddr atomic.Pointer[map[netip.Addr]*hostEntry]

	lim   *limiter
	plain *gosnmp.GoSNMP // v1/v2c (und Kopf von v3)

	tmu   sync.Mutex
	times map[string]*engineTime // Engine-ID + Benutzer -> zuletzt angenommener Stand (v3 mit Authentifizierung)

	received, accepted, tooBig, rateLimited, badPacket, rejected, unknown, queueFull atomic.Uint64
	unknownEngineIDs                                                                 atomic.Uint32
	now                                                                              func() time.Time
}

// New baut den Empfaenger; cb bekommt jedes Event (in eigener Goroutine, nacheinander).
func New(cfg Config, cb func(Event)) (*Receiver, error) {
	if cb == nil {
		return nil, errors.New("Rueckruf fehlt")
	}
	if cfg.Listen == "" {
		cfg.Listen = DefaultListen
	}
	if cfg.MaxSize <= 0 || cfg.MaxSize > 65535 {
		cfg.MaxSize = DefaultMaxSize
	}
	if cfg.Rate <= 0 {
		cfg.Rate = DefaultRate
	}
	if cfg.Burst <= 0 {
		cfg.Burst = DefaultBurst
	}
	if cfg.GlobalRate <= 0 {
		cfg.GlobalRate = DefaultGlobalRate
	}
	if cfg.MaxSenders <= 0 {
		cfg.MaxSenders = DefaultMaxSenders
	}
	if cfg.MaxVarbinds <= 0 {
		cfg.MaxVarbinds = DefaultMaxVarbinds
	}
	if cfg.MaxValueLen <= 0 {
		cfg.MaxValueLen = DefaultMaxValueLen
	}
	eid := cfg.EngineID
	if eid == "" {
		eid = GenerateEngineID()
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(eid), "0x"))
	if err != nil || len(raw) < 5 || len(raw) > 32 {
		return nil, errors.New("ungueltige Engine-ID (5 bis 32 Bytes hex)")
	}
	r := &Receiver{cfg: cfg, cb: cb, engineID: string(raw), now: time.Now, times: map[string]*engineTime{},
		lim:   newLimiter(cfg.Rate, cfg.Burst, cfg.GlobalRate, cfg.MaxSenders),
		plain: &gosnmp.GoSNMP{Version: gosnmp.Version2c, Logger: gosnmp.NewLogger(nil)}}
	empty := map[netip.Addr]*hostEntry{}
	r.byAddr.Store(&empty)
	return r, nil
}

// GenerateEngineID erzeugt eine lokale Engine-ID (RFC 3411, Format 5 "Octets", zufaellig).
func GenerateEngineID() string {
	b := make([]byte, 13)
	copy(b, []byte{0x80, 0x00, 0x00, 0x00, 0x05})
	_, _ = rand.Read(b[5:])
	return hex.EncodeToString(b)
}

// EngineID liefert die lokale Engine-ID (hex) – Absender von v3-Informs brauchen sie (erkennen sie aber selbst).
func (r *Receiver) EngineID() string { return hex.EncodeToString([]byte(r.engineID)) }

// SetHosts ersetzt die bekannten Absender (auch im Betrieb).
func (r *Receiver) SetHosts(hosts []Host) error {
	m := map[netip.Addr]*hostEntry{}
	for _, h := range hosts {
		e := &hostEntry{h: h, comm: map[string]bool{}, engine: map[string]string{}}
		for _, c := range h.Communities {
			if c != "" {
				e.comm[c] = true
			}
		}
		if len(h.Users) > 0 {
			g := &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, Logger: gosnmp.NewLogger(nil)}
			tab := gosnmp.NewSnmpV3SecurityParametersTable(gosnmp.NewLogger(nil))
			for _, u := range h.Users {
				sp, _, err := snmp.USM(u.Name, u.Level, u.AuthProto, u.PrivProto, u.Secret)
				if err != nil {
					return fmt.Errorf("Host %s, Benutzer %s: %w", h.ID, u.Name, err)
				}
				if err := tab.Add(u.Name, sp); err != nil {
					return fmt.Errorf("Host %s, Benutzer %s: %w", h.ID, u.Name, scrub(err, u.Secret))
				}
				if u.EngineID != "" {
					raw, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(u.EngineID), "0x"))
					if err != nil || len(raw) < 5 || len(raw) > 32 {
						return fmt.Errorf("Host %s, Benutzer %s: ungueltige Engine-ID", h.ID, u.Name)
					}
					e.engine[u.Name] = string(raw)
				}
			}
			g.SetTrapSecurityParametersTable(tab)
			e.v3 = g
		}
		for _, a := range h.Addrs {
			m[a.Unmap()] = e
		}
	}
	r.byAddr.Store(&m)
	return nil
}

// Start oeffnet den Port (nur, wenn ein Host Traps nutzt – das entscheidet der Kern).
func (r *Receiver) Start() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pc != nil {
		return nil
	}
	pc, err := net.ListenPacket("udp", r.cfg.Listen)
	if err != nil {
		return err
	}
	r.pc, r.done, r.queue = pc, make(chan struct{}), make(chan Event, queueSize)
	go r.deliver(r.queue)
	go r.serve(pc, r.done, r.queue)
	return nil
}

// Stop schliesst den Port und wartet auf die Empfangs-Goroutine.
func (r *Receiver) Stop() {
	r.mu.Lock()
	pc, done, q := r.pc, r.done, r.queue
	r.pc = nil
	r.mu.Unlock()
	if pc == nil {
		return
	}
	_ = pc.Close()
	<-done
	close(q)
}

// Running sagt, ob der Port offen ist.
func (r *Receiver) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pc != nil
}

// Addr liefert die lokale Adresse (nil, wenn nicht gestartet).
func (r *Receiver) Addr() net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pc == nil {
		return nil
	}
	return r.pc.LocalAddr()
}

// Stats liefert die Zaehler.
func (r *Receiver) Stats() Stats {
	return Stats{Received: r.received.Load(), Accepted: r.accepted.Load(), TooBig: r.tooBig.Load(), RateLimited: r.rateLimited.Load(),
		BadPacket: r.badPacket.Load(), Rejected: r.rejected.Load(), Unknown: r.unknown.Load(), QueueFull: r.queueFull.Load()}
}

func (r *Receiver) serve(pc net.PacketConn, done chan struct{}, queue chan Event) {
	defer close(done)
	buf := make([]byte, r.cfg.MaxSize+1)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			time.Sleep(10 * time.Millisecond) // z. B. ICMP-Fehler: nicht heiss laufen
			continue
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		from, _ := netip.AddrFromSlice(ua.IP)
		reply, ev := r.process(buf[:n], from.Unmap())
		if reply != nil {
			_, _ = pc.WriteTo(reply, addr)
		}
		if ev != nil {
			select {
			case queue <- *ev:
			default:
				r.queueFull.Add(1)
			}
		}
	}
}

func (r *Receiver) deliver(q chan Event) {
	for ev := range q {
		func() {
			defer func() { _ = recover() }() // ein fehlerhafter Rueckruf beendet den Empfang nicht
			r.cb(ev)
		}()
	}
}

// process wertet ein Paket aus: Antwort (Inform, v3-Report) und Event (nil = verworfen). Sicher fuer jede Eingabe.
func (r *Receiver) process(b []byte, from netip.Addr) (reply []byte, ev *Event) {
	r.received.Add(1)
	if len(b) > r.cfg.MaxSize {
		r.tooBig.Add(1)
		return nil, nil
	}
	now := r.now()
	he := (*r.byAddr.Load())[from]
	if !r.lim.allow(from, he != nil, now) {
		r.rateLimited.Add(1)
		return nil, nil
	}
	defer func() {
		if p := recover(); p != nil { // Fehler im Dekodierer (gosnmp): Paket verwerfen, Empfang laeuft weiter
			r.badPacket.Add(1)
			if panicHook != nil {
				panicHook(p)
			}
			reply, ev = nil, nil
		}
	}()
	pkt := append([]byte(nil), b...) // gosnmp veraendert den Puffer (MAC ausblenden)
	version, ok := peekVersion(pkt)
	if !ok {
		r.badPacket.Add(1)
		return nil, nil
	}
	ev = &Event{Time: now, From: from, Version: version}
	if he != nil {
		ev.HostID, ev.Known = he.h.ID, true
	}
	switch version {
	case "1", "2c":
		p, err := r.plain.UnmarshalTrap(pkt, false)
		if err != nil || p == nil || !isNotification(p) {
			r.badPacket.Add(1)
			return nil, nil
		}
		if he == nil {
			r.unknown.Add(1)
			r.fill(ev, p) // Trap-OID fuer die Liste unbekannter Absender (ohne Community)
			ev.Varbinds, ev.Truncated = nil, false
			return nil, ev
		}
		if !he.comm[p.Community] {
			r.rejected.Add(1)
			return nil, &Event{Time: now, From: from, HostID: he.h.ID, Known: true, Rejected: "community", Version: version}
		}
		r.fill(ev, p)
		r.accepted.Add(1)
		if p.PDUType == gosnmp.InformRequest {
			reply = r.ack(p)
		}
		return reply, ev
	case "3":
		user, engine, probe, ok := peekV3(pkt)
		if !ok {
			r.badPacket.Add(1)
			return nil, nil
		}
		if probe { // Engine-Erkennung fuer v3-Informs: lokale Engine-ID melden (ohne Event), nur bekannten Absendern
			if he == nil { // gefaelschte Absender bekaemen sonst eine groessere Antwort (Verstaerkung)
				r.unknown.Add(1)
				return nil, nil
			}
			return r.report(pkt, now), nil
		}
		ev.User = user
		if he == nil {
			r.unknown.Add(1)
			return nil, ev
		}
		if he.v3 == nil {
			r.rejected.Add(1)
			ev.Rejected = "user"
			return nil, ev
		}
		if want, ok := he.engine[user]; ok && want != engine && engine != r.engineID { // Informs tragen unsere Engine-ID
			r.rejected.Add(1)
			ev.Rejected = "engine"
			return nil, ev
		}
		p, err := he.v3.UnmarshalTrap(pkt, true)
		if err != nil || p == nil {
			r.rejected.Add(1)
			ev.Rejected = "user"
			return nil, ev
		}
		if !isNotification(p) {
			r.badPacket.Add(1)
			return nil, nil
		}
		if p.PDUType == gosnmp.InformRequest && engine != r.engineID { // Inform muss die Engine-ID des Empfaengers tragen (RFC 3414 3.2.3)
			return r.report(pkt, now), nil
		}
		if usm, ok := p.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok && p.MsgFlags&gosnmp.AuthNoPriv != 0 &&
			!r.inTime(engine, user, usm.AuthoritativeEngineBoots, usm.AuthoritativeEngineTime, now) {
			r.rejected.Add(1) // ausserhalb des Zeitfensters: wiederholte (mitgeschnittene) Nachricht
			ev.Rejected = "time"
			return nil, ev
		}
		r.fill(ev, p)
		r.accepted.Add(1)
		if p.PDUType == gosnmp.InformRequest {
			reply = r.ack(p)
		}
		return reply, ev
	}
	r.badPacket.Add(1)
	return nil, nil
}

func isNotification(p *gosnmp.SnmpPacket) bool {
	return p.PDUType == gosnmp.Trap || p.PDUType == gosnmp.SNMPv2Trap || p.PDUType == gosnmp.InformRequest
}

// ack baut die Antwort auf einen Inform (gleiche Varbinds, Response-PDU).
func (r *Receiver) ack(p *gosnmp.SnmpPacket) []byte {
	resp := *p
	resp.PDUType = gosnmp.GetResponse
	resp.Error, resp.ErrorIndex = gosnmp.NoError, 0
	resp.MsgFlags &^= gosnmp.Reportable
	if usm, ok := resp.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok && resp.MsgFlags&gosnmp.AuthPriv == gosnmp.AuthPriv {
		if err := usm.InitPacket(&resp); err != nil {
			return nil
		}
	}
	b, err := resp.MarshalMsg()
	if err != nil || len(b) > r.cfg.MaxSize {
		return nil
	}
	return b
}

// report meldet die lokale Engine-ID mit Boots/Time (usmStatsUnknownEngineIDs, RFC 3414 3.2.3b).
func (r *Receiver) report(pkt []byte, now time.Time) []byte {
	hdr, _ := decodeV3Header(pkt) // nur Kopf noetig; der Inhalt kann verschluesselt sein
	if hdr == nil || hdr.MsgID == 0 {
		return nil
	}
	boots, etime := localEngineTime(now)
	sp := &gosnmp.UsmSecurityParameters{AuthoritativeEngineID: r.engineID, AuthoritativeEngineBoots: boots, AuthoritativeEngineTime: etime,
		Logger: gosnmp.NewLogger(nil)}
	if in, ok := hdr.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok && in != nil && in.UserName != headerUser {
		sp.UserName = in.UserName
	}
	rep := &gosnmp.SnmpPacket{Version: gosnmp.Version3, MsgFlags: gosnmp.NoAuthNoPriv, SecurityModel: gosnmp.UserSecurityModel,
		SecurityParameters: sp, MsgID: hdr.MsgID, RequestID: hdr.RequestID, MsgMaxSize: 65507, PDUType: gosnmp.Report,
		ContextEngineID: r.engineID, Logger: gosnmp.NewLogger(nil),
		Variables: []gosnmp.SnmpPDU{{Name: ".1.3.6.1.6.3.15.1.1.4.0", Type: gosnmp.Counter32, Value: r.unknownEngineIDs.Add(1)}}}
	b, err := rep.MarshalMsg()
	if err != nil {
		return nil
	}
	return b
}

// engineTime ist der zuletzt angenommene Stand einer fremden Engine (latestReceivedEngineTime) und die lokale Zeit dazu.
type engineTime struct {
	boots, time uint32
	at          time.Time
}

// localEngineTime: eigene snmpEngineBoots/snmpEngineTime (Empfaenger autoritativ, v3-Informs).
func localEngineTime(now time.Time) (uint32, uint32) {
	s := int64(now.Sub(engineEpoch) / time.Second)
	return localBoots, uint32(min(max(s, 0), maxEngineBoot))
}

// inTime prueft das Zeitfenster einer authentifizierten v3-Nachricht (RFC 3414 3.2.7). Informs tragen die eigene
// Engine-ID (Empfaenger autoritativ): Boots gleich, Time hoechstens 150 s daneben. Traps tragen die Engine-ID des
// Absenders: je Engine-ID und Benutzer zaehlt der zuletzt angenommene Stand – kleinere Boots oder eine Time mehr als
// 150 s hinter dem fortgeschriebenen Stand sind eine Wiederholung.
func (r *Receiver) inTime(engine, user string, boots, etime uint32, now time.Time) bool {
	if boots >= maxEngineBoot {
		return false
	}
	if engine == r.engineID {
		lb, lt := localEngineTime(now)
		d := int64(etime) - int64(lt)
		return boots == lb && d >= -timeWindow && d <= timeWindow
	}
	r.tmu.Lock()
	defer r.tmu.Unlock()
	key := engine + "\x00" + user
	st := r.times[key]
	switch {
	case st == nil:
		if len(r.times) >= maxTimeStates { // voll: den am laengsten stillen vergessen
			var oldest string
			for k, v := range r.times {
				if oldest == "" || v.at.Before(r.times[oldest].at) {
					oldest = k
				}
			}
			delete(r.times, oldest)
		}
		r.times[key] = &engineTime{boots: boots, time: etime, at: now}
		return true
	case boots > st.boots || (boots == st.boots && etime > st.time): // neuer Stand
		st.boots, st.time, st.at = boots, etime, now
		return true
	case boots < st.boots:
		return false
	}
	est := float64(st.time) + max(0, now.Sub(st.at).Seconds()) // fortgeschriebene fremde snmpEngineTime
	return float64(etime) >= est-timeWindow
}

// headerUser: Platzhalter, damit gosnmp den Kopf ohne Benutzer liest (wird vom Paket ueberschrieben).
const headerUser = "m64-header-placeholder"

// decodeV3Header liest den v3-Kopf ohne Schluessel (Inhalt nur, wenn unverschluesselt).
func decodeV3Header(b []byte) (*gosnmp.SnmpPacket, error) {
	g := &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, Logger: gosnmp.NewLogger(nil),
		SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: headerUser, Logger: gosnmp.NewLogger(nil)}, MsgFlags: gosnmp.NoAuthNoPriv}
	return g.SnmpDecodePacket(append([]byte(nil), b...))
}

// panicHook meldet abgefangene Panics (nur fuer den Fuzz-Test).
var panicHook func(any)

// Bekannte OIDs.
const (
	oidSysUpTime   = ".1.3.6.1.2.1.1.3.0"
	oidTrapOID     = ".1.3.6.1.6.3.1.1.4.1.0"
	oidSnmpTraps   = ".1.3.6.1.6.3.1.1.5"
	oidIfIndex     = ".1.3.6.1.2.1.2.2.1.1."
	oidIfDescr     = ".1.3.6.1.2.1.2.2.1.2."
	oidIfAdmin     = ".1.3.6.1.2.1.2.2.1.7."
	oidIfOper      = ".1.3.6.1.2.1.2.2.1.8."
	oidIfName      = ".1.3.6.1.2.1.31.1.1.1.1."
	oidUPSTraps    = ".1.3.6.1.2.1.33.2"
	oidAPC         = ".1.3.6.1.4.1.318"
	oidPrinterTrap = ".1.3.6.1.2.1.43.18.2.0.1"
)

// known: Trap-OID -> Name, Art, Dienst.
var known = map[string][3]string{
	oidSnmpTraps + ".1":           {"coldStart", "restart", "uptime"},
	oidSnmpTraps + ".2":           {"warmStart", "restart", "uptime"},
	oidSnmpTraps + ".3":           {"linkDown", "link_down", ""},
	oidSnmpTraps + ".4":           {"linkUp", "link_up", ""},
	oidSnmpTraps + ".5":           {"authenticationFailure", "auth_failure", ""},
	oidUPSTraps + ".1":            {"upsTrapOnBattery", "ups_on_battery", "ups"},
	oidUPSTraps + ".2":            {"upsTrapTestCompleted", "ups_test", "ups"},
	oidUPSTraps + ".3":            {"upsTrapAlarmEntryAdded", "ups_alarm", "ups"},
	oidUPSTraps + ".4":            {"upsTrapAlarmEntryRemoved", "ups_alarm_cleared", "ups"},
	oidAPC + ".0.2":               {"upsOverload", "ups_alarm", "ups"},
	oidAPC + ".0.5":               {"upsOnBattery", "ups_on_battery", "ups"},
	oidAPC + ".0.7":               {"lowBattery", "ups_battery_low", "ups"},
	oidAPC + ".0.9":               {"powerRestored", "ups_on_line", "ups"},
	oidAPC + ".0.11":              {"returnFromLowBattery", "ups_battery_ok", "ups"},
	oidAPC + ".0.17":              {"upsBatteryNeedsReplacement", "ups_battery_replace", "ups"},
	oidPrinterTrap:                {"printerV2Alert", "printer_alert", "printer"},
	".1.3.6.1.4.1.8072.4.0.1":     {"nsNotifyStart", "restart", "uptime"},
	".1.3.6.1.4.1.8072.4.0.2":     {"nsNotifyShutdown", "shutdown", "uptime"},
	".1.3.6.1.2.1.99.2.0.1":       {"entSensorThresholdNotification", "sensor", ""},
	".1.2.840.10006.300.43.2.0.1": {"lagPortStateChange", "lag", ""},
}

// fill traegt Trap-OID, Varbinds und die Zuordnung ins Event ein.
func (r *Receiver) fill(ev *Event, p *gosnmp.SnmpPacket) {
	ev.Inform = p.PDUType == gosnmp.InformRequest
	vars := p.Variables
	if p.PDUType == gosnmp.Trap { // v1: Trap-OID nach RFC 3584
		ev.Uptime = uint32(p.Timestamp)
		ent := norm(p.Enterprise)
		if p.GenericTrap >= 0 && p.GenericTrap < 6 {
			ev.TrapOID = oidSnmpTraps + "." + strconv.Itoa(p.GenericTrap+1)
		} else if ent != "" {
			ev.TrapOID = ent + ".0." + strconv.Itoa(p.SpecificTrap)
		}
	} else {
		for i, v := range vars {
			if i > 2 {
				break
			}
			switch norm(v.Name) {
			case oidSysUpTime:
				if t, ok := v.Value.(uint32); ok {
					ev.Uptime = t
				}
			case oidTrapOID:
				if s, ok := v.Value.(string); ok {
					ev.TrapOID = norm(s)
				}
			}
		}
	}
	if k, ok := known[ev.TrapOID]; ok {
		ev.TrapName, ev.Kind, ev.Service = k[0], k[1], k[2]
	}
	for _, v := range vars {
		name := norm(v.Name)
		switch {
		case strings.HasPrefix(name, oidIfIndex):
			if n, ok := toInt(v.Value); ok {
				ev.IfIndex = n
			}
		case strings.HasPrefix(name, oidIfAdmin), strings.HasPrefix(name, oidIfOper):
			if ev.IfIndex == 0 {
				if n, err := strconv.Atoi(name[strings.LastIndex(name, ".")+1:]); err == nil {
					ev.IfIndex = n
				}
			}
		case strings.HasPrefix(name, oidIfName):
			ev.IfName = valueText(v, r.cfg.MaxValueLen)
		case strings.HasPrefix(name, oidIfDescr):
			if ev.IfName == "" {
				ev.IfName = valueText(v, r.cfg.MaxValueLen)
			}
		}
	}
	if (ev.Kind == "link_down" || ev.Kind == "link_up") && ev.IfName != "" {
		ev.Service = "if:" + ev.IfName
	}
	if ev.Kind != "link_down" && ev.Kind != "link_up" {
		ev.IfIndex, ev.IfName = 0, ""
	}
	for i, v := range vars {
		if i >= r.cfg.MaxVarbinds {
			ev.Truncated = true
			break
		}
		ev.Varbinds = append(ev.Varbinds, Varbind{OID: norm(v.Name), Type: v.Type.String(), Value: valueText(v, r.cfg.MaxValueLen)})
	}
}

// peekVersion liest die Version aus dem Kopf (SEQUENCE, INTEGER).
func peekVersion(b []byte) (string, bool) {
	if len(b) < 5 || b[0] != 0x30 {
		return "", false
	}
	i := 1
	if b[i]&0x80 != 0 { // lange Laengenform
		n := int(b[i] & 0x7f)
		if n == 0 || n > 3 || i+1+n >= len(b) {
			return "", false
		}
		i += n
	}
	i++
	if i+2 >= len(b) || b[i] != 0x02 || b[i+1] != 0x01 {
		return "", false
	}
	switch b[i+2] {
	case 0:
		return "1", true
	case 1:
		return "2c", true
	case 3:
		return "3", true
	}
	return "", false
}

// peekV3 liest Benutzer und Engine-ID aus dem v3-Kopf (ohne Pruefung) und erkennt eine Engine-Erkennung.
func peekV3(b []byte) (user, engine string, probe, ok bool) {
	p, err := decodeV3Header(b)
	if p == nil {
		return "", "", false, false
	}
	sp, okc := p.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !okc || sp == nil {
		return "", "", false, false
	}
	user, engine = sp.UserName, sp.AuthoritativeEngineID
	if user == headerUser { // Kopf nicht bis zum Benutzer gelesen
		return "", "", false, false
	}
	if p.MsgFlags&gosnmp.AuthPriv == gosnmp.NoAuthNoPriv && p.MsgFlags&gosnmp.Reportable != 0 && user == "" && engine == "" {
		return "", "", err == nil && p.PDUType == gosnmp.GetRequest && len(p.Variables) == 0, true
	}
	if user == "" {
		return "", "", false, false
	}
	return cleanText(user, 64), engine, false, true
}

func norm(o string) string {
	o = strings.TrimSpace(o)
	if o == "" {
		return ""
	}
	if !strings.HasPrefix(o, ".") {
		o = "." + o
	}
	if len(o) > 512 {
		o = o[:512]
	}
	return o
}

func toInt(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case uint:
		return int(x), true
	case uint32:
		return int(x), true
	case int64:
		return int(x), true
	}
	return 0, false
}

// valueText: Wert als Text (OCTET STRING lesbar oder hex), gekuerzt.
func valueText(v gosnmp.SnmpPDU, max int) string {
	switch x := v.Value.(type) {
	case nil:
		return ""
	case []byte:
		if utf8.Valid(x) && printable(string(x)) {
			return cleanText(string(x), max)
		}
		if len(x) > max/2 {
			x = x[:max/2]
		}
		return hex.EncodeToString(x)
	case string:
		return cleanText(x, max)
	default:
		return cleanText(fmt.Sprint(x), max)
	}
}

func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

func cleanText(s string, max int) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			r = ' '
		}
		b.WriteRune(r)
		n++
		if n >= max {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

func scrub(err error, s snmp.Secret) error {
	msg := err.Error()
	for _, sec := range []string{s.Community, s.AuthPass, s.PrivPass} {
		if len(sec) >= 3 {
			msg = strings.ReplaceAll(msg, sec, "***")
		}
	}
	return errors.New(msg)
}

// ---- Ratenbegrenzung ----

type bucket struct {
	tokens float64
	last   time.Time
}

// limiter: Token-Bucket je Absender plus gesamt, getrennt fuer bekannte und unbekannte Absender; begrenzte Zahl
// gemerkter Absender. Zuerst zaehlt der Bucket des Absenders: wer flutet, verbraucht nur seine eigenen Token, und
// Unbekannte (auch gefaelschte Adressen) leeren bekannten Absendern den gemeinsamen Bucket nicht.
type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	max     int
	m       map[netip.Addr]*bucket
	known   bucket // gesamt fuer bekannte Absender
	unknown bucket // gesamt fuer unbekannte Absender
	grate   float64
}

func newLimiter(rate float64, burst int, global float64, max int) *limiter {
	return &limiter{rate: rate, burst: float64(burst), max: max, m: map[netip.Addr]*bucket{}, grate: global,
		known: bucket{tokens: global}, unknown: bucket{tokens: global}}
}

func (l *limiter) take(b *bucket, rate, burst float64, now time.Time) bool {
	if !b.last.IsZero() {
		if dt := now.Sub(b.last).Seconds(); dt > 0 {
			b.tokens = min(burst, b.tokens+dt*rate)
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *limiter) allow(a netip.Addr, known bool, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.m[a]
	if !ok {
		if len(l.m) >= l.max {
			// voll: Absender vergessen, die lange still waren; sonst alle (gefaelschte Adressen fluten sonst den Speicher)
			for k, v := range l.m {
				if now.Sub(v.last) > time.Minute {
					delete(l.m, k)
				}
			}
			if len(l.m) >= l.max {
				l.m = map[netip.Addr]*bucket{}
			}
		}
		b = &bucket{tokens: l.burst}
		l.m[a] = b
	}
	if !l.take(b, l.rate, l.burst, now) {
		return false
	}
	g := &l.unknown
	if known {
		g = &l.known
	}
	return l.take(g, l.grate, l.grate, now)
}
