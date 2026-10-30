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

// Stufe 2 (sensor_proto.go): weitere Dienste und Arten. Arten mit Endung "bruteforce" zaehlen bei ipv64 als starke
// Hinweise (wie Login/Exploit). Neue Werte nur anhaengen, Muster [a-z][a-z0-9-]*, Dienste hoechstens 16 Zeichen.
const (
	SvcFTP     = "ftp"
	SvcMySQL   = "mysql"
	SvcPostgre = "postgres"
	SvcMSSQL   = "mssql"
	SvcRedis   = "redis"
	SvcVNC     = "vnc"
	SvcMQTT    = "mqtt"
	SvcWinbox  = "winbox"       // MikroTik Winbox (8291)
	SvcMTAPI   = "mikrotik-api" // MikroTik API (8728, TLS 8729)
	SvcSNMP    = "snmp"         // UDP
	SvcSIP     = "sip"          // UDP
	SvcADB     = "adb"          // Android Debug Bridge (5555), H8
	SvcModbus  = "modbus"       // Modbus/TCP (502), H8
	SvcS7      = "s7"           // Siemens S7comm, ISO-on-TCP (102), H8
	SvcBACnet  = "bacnet"       // BACnet/IP (47808), UDP, H8

	KindFTPBrute    = "ftp:bruteforce"
	KindVNCBrute    = "vnc:bruteforce"
	KindMQTTBrute   = "mqtt:bruteforce"
	KindRouterBrute = "router:bruteforce" // Winbox, MikroTik API
	KindSNMPBrute   = "snmp:bruteforce"   // Community-Strings
	KindSIPBrute    = "sip:bruteforce"    // REGISTER mit Anmeldedaten
	KindSIPScan     = "sip:scan"          // OPTIONS/INVITE-Scanner (friendly-scanner, sipvicious)
	KindDBExploit   = "db:exploit"        // z. B. Redis CONFIG SET/SLAVEOF, MSSQL xp_cmdshell
	KindICSScan     = "ics:scan"          // Modbus, S7, BACnet: lesen, Erkennung (H8)
	KindICSExploit  = "ics:exploit"       // Modbus, S7, BACnet: schreiben, steuern, CPU starten/stoppen (H8)
	KindIoTExploit  = "iot:exploit"       // ADB shell/exec/sync, Befehle von Botnetzen (H8)
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

	Fingerprint string // H6: "ja4:<ja4>" (TLS ClientHello) bzw. "hassh:<md5>" (SSH-KEXINIT des Clients), sonst leer
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
	// Dienst-Profile (sensor_persona.go): je "dienst:port" ein Profil (fehlt = Standard fuer Port und Koeder) und
	// der Hostname der Fallen ("" = aus dem Seed erzeugt). Seed = Sensor-Kennung (nicht gespeichert; "" = Datei
	// sensor_id im Datenverzeichnis des Sensors, wie im Modus ohne Oberflaeche).
	Personas map[string]string `json:"personas,omitempty"`
	Hostname string            `json:"hostname,omitempty"`
	// „Verwundbar wirken“ (H8): je "dienst:port" aeltere, bekannt verwundbare Versionen in Banner und Kopfzeilen
	// (nur Dienste mit OldVersions; Standard aus). Zieht gezielte Scanner an; erfasst wird gleich.
	Vulnerable []string `json:"vulnerable,omitempty"`
	Seed       string   `json:"-"`
	// Gueltiges Zertifikat fuer Koeder-Namen (sensor_cert.go): Kennung in der zentralen Zertifikatsverwaltung (0 = aus,
	// alle Fallen selbst signiert) und Ports, die es auch bei Profilen mit selbst signiertem Zertifikat zeigen.
	CertID    int64 `json:"cert_id,omitempty"`
	CertPorts []int `json:"cert_ports,omitempty"`
	// Log-Sensor und Syslog-Empfaenger (H5); leer = aus. Der Sensor (Fallen-Dienste) beachtet das Feld nicht.
	Log LogConfig `json:"log,omitempty"`
	// Startseite der Web-Falle ("/", auch der PROXY64-Koeder): "" bzw. StartGateway = Gateway-Terminal (Matrix-Stil),
	// StartNeutral = schlichtes Anmeldeformular.
	StartPage string `json:"start_page,omitempty"`
}

// Startseiten der Web-Falle (Config.StartPage).
const (
	StartGateway = "gateway"
	StartNeutral = "neutral"
)

// StartPages: Auswahl in der Oberflaeche (Standard zuerst).
var StartPages = []string{StartGateway, StartNeutral}

// Profile: vorgegebene Dienste (Plan Abschnitt 1, Sensor-Profile; H1 nur Stufe 1).
var Profiles = map[string][]Service{
	"proxy":   {}, // nur ueber PROXY64 (keine eigenen Ports)
	"minimal": {{SvcSSH, 22, ""}, {SvcHTTP, 80, ""}},
	"standard": {{SvcSSH, 22, ""}, {SvcSSH, 2222, ""}, {SvcTelnet, 23, ""}, {SvcHTTP, 80, ""}, {SvcHTTPS, 443, ""}, {SvcHTTP, 8080, ""},
		{SvcFTP, 21, ""}, {SvcSMTP, 25, ""}, {SvcMySQL, 3306, ""}, {SvcRedis, 6379, ""}, {SvcRDP, 3389, ""}, {SvcVNC, 5900, ""},
		{SvcTCP, 8291, ""}, {SvcHTTPS, 8006, "pve"}, {SvcIMAP, 143, ""}, {SvcMQTT, 1883, ""}, {SvcHTTP, 8123, ""}, {SvcMTAPI, 8728, ""}},
	"full": {{SvcSSH, 22, ""}, {SvcSSH, 2222, ""}, {SvcTelnet, 23, ""}, {SvcTelnet, 2323, ""}, {SvcHTTP, 80, ""}, {SvcHTTPS, 443, ""}, {SvcHTTP, 8080, ""}, {SvcHTTPS, 8443, "unifi"},
		{SvcFTP, 21, ""}, {SvcSMTP, 25, ""}, {SvcSMTP, 587, ""}, {SvcPOP3, 110, ""}, {SvcIMAP, 143, ""}, {SvcTCP, 445, ""},
		{SvcMSSQL, 1433, ""}, {SvcMQTT, 1883, ""}, {SvcHTTP, 2375, "docker"}, {SvcMySQL, 3306, ""}, {SvcRDP, 3389, ""}, {SvcPostgre, 5432, ""},
		{SvcVNC, 5900, ""}, {SvcRedis, 6379, ""}, {SvcHTTPS, 8006, "pve"}, {SvcHTTPS, 8007, "pbs"}, {SvcHTTP, 5000, "nas"}, {SvcHTTPS, 5001, "nas"},
		{SvcHTTP, 3000, "grafana"}, {SvcHTTP, 8123, "homeassistant"}, {SvcHTTPS, 9443, "portainer"}, {SvcHTTPS, 10000, "webmin"}, {SvcHTTPS, 10443, "sslvpn"}, {SvcHTTPS, 4444, ""},
		{SvcHTTP, 9200, "elastic"}, {SvcHTTPS, 10250, "kubelet"}, {SvcTCP, 27017, ""},
		{SvcTCP, 8291, ""}, {SvcMTAPI, 8728, ""}, {SvcMTAPI, 8729, ""}, {SvcSNMP, 161, ""}, {SvcSIP, 5060, ""},
		{SvcADB, 5555, ""}, {SvcModbus, 502, ""}, {SvcS7, 102, ""}, {SvcBACnet, 47808, ""}},
}

// Pages: Koeder auf HTTP/HTTPS. Bewusst schlichte, neutrale Login-Formulare ohne Logos, Markennamen oder
// Nachbau echter Herstellerseiten – Bots greifen Pfade an, nicht Optik. Der Schluessel nennt nur die Pfad-Gruppe,
// die der Koeder beantwortet (z. B. /wp-login.php, /phpmyadmin/, /admin/).
var Pages = []string{"generic", "wp-login", "phpmyadmin", "admin",
	// Stufe 2: feste Koeder je Port (Pfade/API der Web-Oberflaechen, die Bots angreifen)
	"pve", "pbs", "nas", "unifi", "sslvpn", "grafana", "jenkins", "portainer", "homeassistant", "webmin", "docker", "elastic", "kubelet"}

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
	Since           time.Time   `json:"since"`
	Events          int64       `json:"events"`
	Sources         int64       `json:"sources"` // verschiedene Quell-IPs
	Logins          int64       `json:"logins"`
	ByService       []Count     `json:"by_service"`
	ByPort          []Count     `json:"by_port"`
	ByKind          []Count     `json:"by_kind"`
	BySource        []Count     `json:"by_source"`   // Key = honeypot, log, syslog (H5)
	TopSources      []Count     `json:"top_sources"` // Key = IP
	TopUsers        []Count     `json:"top_users"`
	TopPass         []Count     `json:"top_passwords"`
	TopCreds        []Count     `json:"top_credentials"` // Key = "user:pass"
	TopPaths        []Count     `json:"top_paths"`
	TopUAs          []Count     `json:"top_user_agents"`
	TopFingerprints []Count     `json:"top_fingerprints"` // H6: Key = "ja4:…" bzw. "hassh:…"
	Timeline        []TimePoint `json:"timeline"`         // je Stunde (24 h) bzw. je Tag (7 d)
	// Herkunft (geo.go): alle Laender mit Ereignissen, nach Anzahl; ohne Land = privat, unbekannt oder keine Daten.
	ByCountry      []CountryCount `json:"by_country"`
	CountryUnknown int64          `json:"country_unknown"`
	ByDecoy        []Count        `json:"by_decoy"` // Key = "page:<koeder>" bzw. "device:<geraet>" (Detail device=…)
}

// Count ist ein Eintrag einer Rangliste.
type Count struct {
	Key     string    `json:"key"`
	Count   int64     `json:"count"`
	Last    time.Time `json:"last,omitzero"`
	Country string    `json:"country,omitempty"` // nur top_sources: Land der IP (ISO 3166 alpha-2), "" = unbekannt
}

// TimePoint ist ein Punkt im Verlauf.
type TimePoint struct {
	Time   time.Time `json:"time"`
	Events int64     `json:"events"`
}
