// Package sonar ist der Kern von Sonar64, dem verteilten Community-Messnetz (Plan docs/PLAN-NODE64-SONAR64.md,
// Vertrag docs/SONAR64-VERTRAG.md). Der Kern holt den signierten Messplan von ipv64.net, misst innerhalb harter
// Grenzen (ICMP, UDP 6464), antwortet selbst auf UDP 6464 und meldet die Ergebnisse signiert zurueck.
//
// Der Kern haengt von keinem anderen Node64-Modul ab: cmd/sonar64 (ohne Dashboard, Pi Zero) baut nur ihn ein,
// das Node64-Modul internal/sonar64 bindet ihn ein. Die Verteilung der Aufgaben macht allein ipv64.
//
// Diese Datei enthaelt die Datenformate (JSON) zwischen Knoten und ipv64 – Aenderungen nur mit Vertrag und PHP.
package sonar

import (
	"encoding/json"
	"time"
)

// Feste Werte des Netzes.
const (
	ProtoVersion  = 1      // Version der Formate (Feld "v")
	Port          = 6464   // UDP-Echo des Knotens
	TokenPrefix   = "s64_" // Sonar-Token eines Knotens
	AnchorPrefix  = "s64a_"
	RoundInterval = 5 * time.Minute  // Runde
	PlanMaxAge    = 30 * time.Minute // laenger gilt kein Plan, egal was "expires" sagt
	AnchorOnlyFor = 2 * time.Hour    // ohne neuen Plan: so lange nur Anker, danach Pause
	BufferFor     = 6 * time.Hour    // Ergebnisse so lange puffern und nachreichen
)

// Methoden einer Messung.
const (
	MethodICMP  = "icmp"  // Echo an die oeffentliche IP (antwortet meist der Router)
	MethodUDP   = "udp"   // UDP 6464 bis zum Knoten
	MethodTrace = "trace" // Traceroute (Paris, ICMP oder UDP)
)

// Rollen und Budget-Stufen.
const (
	RoleNode   = "node"
	RoleAnchor = "anchor"

	BudgetLow    = "sparsam"
	BudgetNormal = "normal"
	BudgetHigh   = "grosszuegig"
)

// Target ist ein Ziel im Plan.
type Target struct {
	ID     string `json:"id"`                // Node-ID des Ziels (Anker: "a_<name>")
	Addr   string `json:"addr"`              // oeffentliche IP (nur fuer diese Messung, nie anzeigen/loggen ausser im eigenen Live-Log)
	Family int    `json:"fam"`               // 4 oder 6
	Method string `json:"method"`            // icmp | udp | trace
	Count  int    `json:"count"`             // Pakete (1..5); Trace: Versuche je Hop (1..3)
	MaxTTL int    `json:"max_ttl,omitempty"` // nur Trace (Standard 30)
}

// Round ist eine Messrunde.
type Round struct {
	Start   time.Time `json:"start"`   // Beginn (UTC); der Knoten verteilt seine Messungen zufaellig in [Start, Start+5 min)
	Targets []Target  `json:"targets"` // hoechstens Budget-Grenze; mehr werden lokal abgeschnitten
}

// Plan ist der Messplan eines Knotens (von ipv64 erzeugt und signiert).
type Plan struct {
	V       int       `json:"v"`
	NodeID  string    `json:"node_id"`
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"expires"` // hoechstens Issued + 30 min
	Rounds  []Round   `json:"rounds"`
	Anchors []Target  `json:"anchors"` // Rueckfall, wenn kein neuer Plan kommt (nur icmp/udp)
}

// SignedPlan ist die Antwort von GET /sonar/plan: Plan als rohes JSON, Ed25519-Signatur ueber genau diese Bytes.
type SignedPlan struct {
	Plan  json.RawMessage `json:"plan"`
	KeyID string          `json:"kid"` // Kennung des Plan-Schluessels (erste 8 Zeichen der Base64-URL des Public Keys)
	Sig   string          `json:"sig"` // Base64 (std, mit Padding)
}

// Hop ist ein Schritt einer Traceroute.
type Hop struct {
	TTL   int     `json:"ttl"`
	Addr  string  `json:"addr,omitempty"` // leer = keine Antwort
	RTTMs float64 `json:"rtt,omitempty"`
}

// Result ist das Ergebnis einer Messung (Zusammenfassung, keine Rohpakete).
type Result struct {
	Round    time.Time `json:"round"`  // Round.Start aus dem Plan
	Target   string    `json:"target"` // Target.ID
	Family   int       `json:"fam"`
	Method   string    `json:"method"`
	Sent     int       `json:"sent"`
	Recv     int       `json:"recv"`
	MinMs    float64   `json:"min,omitempty"`
	AvgMs    float64   `json:"avg,omitempty"`
	MaxMs    float64   `json:"max,omitempty"`
	JitterMs float64   `json:"jitter,omitempty"` // mittlere Abweichung aufeinanderfolgender RTTs
	At       time.Time `json:"at"`               // Zeitpunkt der Messung (UTC)
	Error    string    `json:"err,omitempty"`    // z. B. "no_route", "denied", "budget"
	Hops     []Hop     `json:"hops,omitempty"`   // nur Trace
}

// Inbound ist eine auf UDP 6464 beantwortete Probe (Pings gegen mich, live).
type Inbound struct {
	From   string    `json:"from"` // Node-ID-Kurzform aus der Probe (8 Hex), Zuordnung macht ipv64
	Family int       `json:"fam"`
	At     time.Time `json:"at"`
	Count  int       `json:"count"` // beantwortete Pakete in diesem Abschnitt
}

// Health ist der Selbstzustand des Knotens in jeder Meldung.
type Health struct {
	Version    string `json:"version"`
	Mode       string `json:"mode"` // module | headless | anchor
	Uplink     bool   `json:"uplink"`
	Paused     string `json:"paused,omitempty"` // Grund: uplink, quiet, no_plan, budget
	SentToday  int    `json:"sent_today"`       // Pakete heute (UTC)
	Budget     string `json:"budget"`
	Responder  bool   `json:"responder"` // UDP 6464 offen
	ICMPDenied bool   `json:"icmp_denied,omitempty"`
}

// Report ist eine Meldung (POST /sonar/results), alle 5 min.
type Report struct {
	V       int       `json:"v"`
	NodeID  string    `json:"node_id"`
	Seq     uint64    `json:"seq"`  // streng steigend je Knoten (auch nach Neustart, gespeichert)
	Sent    time.Time `json:"sent"` // UTC
	Results []Result  `json:"results"`
	Inbound []Inbound `json:"inbound,omitempty"`
	Health  Health    `json:"health"`
}

// SignedReport ist der Body von POST /sonar/results: Meldung als rohes JSON, Ed25519 des Knotens ueber diese Bytes.
type SignedReport struct {
	Report json.RawMessage `json:"report"`
	Sig    string          `json:"sig"` // Base64 (std)
}

// Register ist der Body von POST /sonar/register (einmal je Knoten, mit dem Token).
type Register struct {
	PubKey  string `json:"pubkey"`  // Ed25519 Public Key, Base64 (std)
	Version string `json:"version"` // Programmversion
	Mode    string `json:"mode"`    // module | headless | anchor
}

// Me ist der eigene Knoten (GET/PUT /sonar/me). Felder mit "ro" setzt nur ipv64.
type Me struct {
	NodeID   string    `json:"node_id"`           // ro
	Name     string    `json:"name"`              // Anzeigename (3..32, [A-Za-z0-9 ._-]), eindeutig
	Slug     string    `json:"slug"`              // ro, oeffentliche Seite /sonar/node/<slug>
	Lat      *float64  `json:"lat"`               // genauer Standort (nur fuer den Besitzer)
	Lon      *float64  `json:"lon"`               //
	PubLat   *float64  `json:"pub_lat"`           // ro, im Umkreis 1 km verschleiert (fester Versatz)
	PubLon   *float64  `json:"pub_lon"`           // ro
	Access   string    `json:"access"`            // fiber | dsl | cable | mobile | satellite | datacenter | other
	Device   string    `json:"device"`            // node64 | pi | mikrotik | linux | other (frei, kurz)
	Measured bool      `json:"measured"`          // auch gemessen werden (sonst nur ausgehend)
	Budget   string    `json:"budget"`            // sparsam | normal | grosszuegig
	Role     string    `json:"role"`              // ro: node | anchor
	Trust    string    `json:"trust"`             // ro: new | stable | trusted | pillar | anchor | quarantine
	Score    float64   `json:"score"`             // ro, 0..1
	ASN4     int       `json:"asn4,omitempty"`    // ro
	ASName4  string    `json:"asname4,omitempty"` // ro
	ASN6     int       `json:"asn6,omitempty"`    // ro
	ASName6  string    `json:"asname6,omitempty"` // ro
	Reach4   string    `json:"reach4,omitempty"`  // ro: icmp | udp | none
	Reach6   string    `json:"reach6,omitempty"`  // ro
	Since    time.Time `json:"since"`             // ro, erste Anmeldung
	Uptime30 float64   `json:"uptime30"`          // ro, Anteil 0..1
}

// InboundRow ist eine Zeile von GET /sonar/inbound (wer hat mich gemessen, aus den Ergebnissen bei ipv64).
type InboundRow struct {
	From   string    `json:"from"` // Node-ID
	Name   string    `json:"name"` // Anzeigename
	ASName string    `json:"asname"`
	Place  string    `json:"place"` // grober Ort (Stadt/Region), leer wenn unbekannt
	Trust  string    `json:"trust"`
	Family int       `json:"fam"`
	Method string    `json:"method"`
	AvgMs  float64   `json:"avg"`
	Loss   float64   `json:"loss"` // 0..1
	At     time.Time `json:"at"`
}
