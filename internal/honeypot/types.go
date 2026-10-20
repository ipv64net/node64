// Package honeypot ist das Modul Honeypot64: ein leichter Low-Interaction-Honeypot (Fallen-Dienste, die Logins
// annehmen und immer ablehnen, nie etwas ausfuehren und keine ausgehenden Verbindungen aufbauen). Laeuft als Modul
// neben den anderen oder allein im Modus ohne Oberflaeche (NODE64_MODE=honeypot). Plan: docs/PLAN-NODE64-HONEYPOT64.md.
//
// Aufbau (H1, nur lokal):
//   - sensor*.go  – die Dienste (SSH, Telnet, HTTP/HTTPS mit neutralen Login-Koedern, beliebige TCP-Ports,
//     Port-Scan-Erkennung); melden jedes Ereignis an eine Sink.
//   - store*.go   – Speicherung in der Datenbank der Node (Scope "honeypot"), Statistik, Aufraeumen (7 Tage, Obergrenze).
//   - module*.go, ui*.go – Modul mit Oberflaeche, API, Prometheus, Benachrichtigung.
//   - cmd/node64 (honeypot_mode.go) – Modus ohne Oberflaeche mit Info-Seite, /metrics und /health auf eigenem Port.
//
// Diese Datei ist die gemeinsame Schnittstelle der Teile.
package honeypot

import (
	"net/netip"
	"sync/atomic"
	"time"
)

// Name ist der technische Schluessel des Moduls.
const Name = "honeypot"

// Dienste (Service).
const (
	SvcSSH    = "ssh"
	SvcTelnet = "telnet"
	SvcHTTP   = "http"
	SvcHTTPS  = "https"
	SvcTCP    = "tcp"  // beliebiger Port: nur Verbindung und erste Bytes
	SvcScan   = "scan" // Port-Scan-Erkennung (keine eigene Verbindung, aus den anderen abgeleitet)
)

// Arten (Kind), feste Einteilung laut Plan Abschnitt 3. Neue Arten nur anhaengen, nie umbenennen.
const (
	KindSSHBrute     = "ssh:bruteforce"
	KindTelnetBrute  = "telnet:bruteforce"
	KindHTTPBrute    = "http:bruteforce"   // Login-Versuch auf einem Koeder
	KindHTTPExploit  = "http:exploit"      // bekannter Exploit-Pfad ohne genauere Einordnung
	KindHTTPSQLi     = "http:exploit:sqli" // OWASP-Kategorien (nur zur Bewertung)
	KindHTTPXSS      = "http:exploit:xss"  //
	KindHTTPTrav     = "http:exploit:traversal"
	KindHTTPRCE      = "http:exploit:rce"
	KindHTTPJNDI     = "http:exploit:jndi"
	KindHTTPSSRF     = "http:exploit:ssrf"
	KindHTTPUpload   = "http:exploit:upload"
	KindHTTPScan     = "http:scan" // Aufruf ohne Exploit-Merkmal (Verzeichnis-Scan, Sondierung)
	KindBadUA        = "http:bad-useragent"
	KindPortScan     = "generic:portscan"
	KindProbe        = "generic:probe" // bloßer Verbindungsaufbau / erste Bytes ohne Einordnung
	KindScannerResch = "scanner:research"
)

// Event ist ein Ereignis eines Fallen-Dienstes. Felder, die fuer den Dienst nicht passen, bleiben leer.
// Alle Texte sind bereits gekuerzt (Laengen siehe Max*), Payload hoechstens MaxPayload Bytes.
type Event struct {
	Time     time.Time
	Service  string // Svc*
	Port     int    // lokaler Port
	Kind     string // Kind*
	Src      netip.Addr
	SrcPort  int
	Username string // SSH/Telnet/HTTP-Login
	Password string // im Klartext (nur Honeypot, Plan Abschnitt 1a)
	Method   string // HTTP
	Path     string // HTTP: Pfad mit Abfrage
	Host     string // HTTP: Host-Kopfzeile bzw. SNI
	UA       string // HTTP: User-Agent
	Client   string // SSH-Client-Version, Telnet-Terminal o. ae.
	Page     string // Koeder (Pages)
	Payload  []byte // erste Bytes (TCP, HTTP-Body-Anfang)
	Detail   string // kurzer Zusatz (z. B. Schluessel-Fingerabdruck, erkannte Muster)

	Source string // SrcHoneypot ("" gilt als honeypot), SrcLog, SrcSyslog (H5)
	Rule   string // Regel-Kennung bei log/syslog, z. B. "sshd/bruteforce@1" (H5)
}

// Grenzen fuer Texte und Payload (vom Sensor durchgesetzt, vom Speicher noch einmal geprueft).
const (
	MaxText    = 256
	MaxPath    = 1024
	MaxPayload = 256
)

// Sink nimmt Ereignisse entgegen. Muss schnell zurueckkehren (gepuffert, darf bei Ueberlast verwerfen).
type Sink func(Event)

// Service ist ein eingeschalteter Fallen-Dienst.
type Service struct {
	Service string `json:"service"` // Svc* (nicht scan)
	Port    int    `json:"port"`
	Page    string `json:"page,omitempty"` // HTTP/HTTPS: Koeder, "" = Auswahl je Pfad (siehe Pages)
}

// Config ist die Einstellung des Sensors (Modul: aus der Datenbank; Modus ohne Oberflaeche: aus der Umgebung).
type Config struct {
	Services []Service `json:"services"`
	Scan     bool      `json:"scan"` // Port-Scan-Erkennung
	// Limits je Quell-IP gegen Ueberlast (0 = Standard).
	MaxConnsPerIP int `json:"max_conns_per_ip,omitempty"` // gleichzeitig, Standard 8
	MaxConnsTotal int `json:"max_conns_total,omitempty"`  // gleichzeitig, Standard 512
}

// Profile: vorgegebene Dienste (Plan Abschnitt 1, Sensor-Profile; H1 nur Stufe 1).
var Profiles = map[string][]Service{
	"minimal":  {{SvcSSH, 22, ""}, {SvcHTTP, 80, ""}},
	"standard": {{SvcSSH, 22, ""}, {SvcSSH, 2222, ""}, {SvcTelnet, 23, ""}, {SvcHTTP, 80, ""}, {SvcHTTPS, 443, ""}, {SvcHTTP, 8080, ""}, {SvcTCP, 3389, ""}, {SvcTCP, 5900, ""}},
	"full": {{SvcSSH, 22, ""}, {SvcSSH, 2222, ""}, {SvcTelnet, 23, ""}, {SvcTelnet, 2323, ""}, {SvcHTTP, 80, ""}, {SvcHTTPS, 443, ""}, {SvcHTTP, 8080, ""}, {SvcHTTPS, 8443, ""},
		{SvcTCP, 21, ""}, {SvcTCP, 25, ""}, {SvcTCP, 445, ""}, {SvcTCP, 1433, ""}, {SvcTCP, 1883, ""}, {SvcTCP, 2375, ""}, {SvcTCP, 3306, ""}, {SvcTCP, 3389, ""},
		{SvcTCP, 5432, ""}, {SvcTCP, 5900, ""}, {SvcTCP, 6379, ""}, {SvcTCP, 9200, ""}, {SvcTCP, 27017, ""}},
}

// Pages: Koeder auf HTTP/HTTPS. Bewusst schlichte, neutrale Login-Formulare ohne Logos, Markennamen oder
// Nachbau echter Herstellerseiten – Bots greifen Pfade an, nicht Optik. Der Schluessel nennt nur die Pfad-Gruppe,
// die der Koeder beantwortet (z. B. /wp-login.php, /phpmyadmin/, /admin/).
var Pages = []string{"generic", "wp-login", "phpmyadmin", "admin"}

// ServiceStatus ist der Zustand eines Dienstes (Oberflaeche, Info-Seite, Prometheus).
type ServiceStatus struct {
	Service string `json:"service"`
	Port    int    `json:"port"`
	Listen  bool   `json:"listen"`          // Port offen
	Error   string `json:"error,omitempty"` // warum nicht
	Conns   int64  `json:"conns"`           // Verbindungen seit dem Start
}

// Counters zaehlt seit dem Start (Prometheus, Info-Seite); vom Sensor erhoeht.
type Counters struct {
	Connections atomic.Int64 // alle angenommenen Verbindungen
	Logins      atomic.Int64 // Login-Versuche (SSH, Telnet, HTTP)
	Events      atomic.Int64 // an die Sink gegebene Ereignisse
	Dropped     atomic.Int64 // wegen Ueberlast verworfene Ereignisse oder abgewiesene Verbindungen
}

// Stats ist die Auswertung fuer Oberflaeche, Info-Seite und API (aus dem Speicher).
type Stats struct {
	Since      time.Time   `json:"since"`
	Events     int64       `json:"events"`
	Sources    int64       `json:"sources"` // verschiedene Quell-IPs
	Logins     int64       `json:"logins"`
	ByService  []Count     `json:"by_service"`
	ByPort     []Count     `json:"by_port"`
	ByKind     []Count     `json:"by_kind"`
	TopSources []Count     `json:"top_sources"` // Key = IP
	TopUsers   []Count     `json:"top_users"`
	TopPass    []Count     `json:"top_passwords"`
	TopCreds   []Count     `json:"top_credentials"` // Key = "user:pass"
	TopPaths   []Count     `json:"top_paths"`
	TopUAs     []Count     `json:"top_user_agents"`
	Timeline   []TimePoint `json:"timeline"` // je Stunde (24 h) bzw. je Tag (7 d)
}

// Count ist ein Eintrag einer Rangliste.
type Count struct {
	Key   string    `json:"key"`
	Count int64     `json:"count"`
	Last  time.Time `json:"last,omitzero"`
}

// TimePoint ist ein Punkt im Verlauf.
type TimePoint struct {
	Time   time.Time `json:"time"`
	Events int64     `json:"events"`
}
