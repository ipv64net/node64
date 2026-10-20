package honeypot

import (
	"net/netip"
	"time"
)

// Log-Sensor und Syslog-Empfaenger (Phase H5, Plan Abschnitt 1b/1c und „H5 Umsetzung“). Diese Datei ist der Vertrag
// der parallelen Teile:
//
//   - logengine.go, logtail.go, logrules_svc.go – Regeln anwenden, Schwellen, Dateien mitlesen, Regeln fuer Dienste
//     (sshd, Webserver, Mail, Proxmox, Nextcloud, Vaultwarden, Gitea/Forgejo, Home Assistant).
//   - syslog.go, logrules_fw.go – Syslog-Empfaenger (UDP/TCP), Regeln fuer Router/Firewalls (MikroTik,
//     OPNsense/pfSense, FortiGate, Sophos, UniFi).
//   - module.go, store.go, report_store.go, ui.go, honeypot_mode.go – Einbindung (Einstellungen, Speichern mit
//     Quelle/Regel, Meldung, Oberflaeche, Modus ohne Oberflaeche).
//
// Grundsaetze (Plan Abschnitt 1b, 13): nur lesend; gemeldet werden nur IP, Art, Dienst, Port, Anzahl, Zeitraum, Regel.
// Nie Benutzernamen, Passwoerter, Pfade, User-Agents oder andere Inhalte aus echten Logs (Event.Username/Password/
// Path/UA/Payload bleiben leer, Detail hoechstens der Regelname). Fuer die zentrale Bewertung zaehlen nur die
// mitgelieferten Regeln (Kennung und Version werden mitgeschickt).

// Quellen eines Ereignisses (Event.Source, Meldung sources[].source).
const (
	SrcHoneypot = "honeypot"
	SrcLog      = "log"
	SrcSyslog   = "syslog"
)

// Zusaetzliche Arten und Dienste fuer H5 (bei ipv64 schon bekannt, deploy/web/api_v2_honeypot.php HP_KINDS/HP_SERVICES;
// "vpn" kommt mit H5 dazu).
const (
	KindRDPBrute  = "rdp:bruteforce"
	KindMailBrute = "mail:auth-bruteforce"
	KindDBBrute   = "db:bruteforce"
	KindVPNBrute  = "vpn:bruteforce"

	SvcSMTP = "smtp"
	SvcIMAP = "imap"
	SvcPOP3 = "pop3"
	SvcRDP  = "rdp"
	SvcVPN  = "vpn"
)

// LogLine ist eine Zeile aus einer Datei oder eine Syslog-Nachricht, schon zerlegt.
type LogLine struct {
	Time    time.Time // aus der Zeile, sonst Empfangszeit (UTC)
	Origin  string    // SrcLog (Datei) oder SrcSyslog
	File    string    // Datei bzw. "udp://<absender>" / "tcp://<absender>" (nur lokal, fuer Fehlersuche)
	Format  string    // Hinweis auf das Format der Quelle: "syslog" (auth.log, mail.log, Syslog-Nachricht), "nginx", "apache",
	//                     "caddy" (JSON), "nextcloud" (JSON), "vaultwarden", "gitea", "proxmox", "homeassistant", "" = unbekannt
	Host    string // Hostname aus dem Syslog-Kopf ("" wenn keiner)
	Program string // Programm/Tag aus dem Syslog-Kopf ohne PID, z. B. "sshd", "postfix/smtpd", "dovecot", "filterlog"
	Message string // eigentliche Nachricht (ohne Kopf); bei Webserver-Logs die ganze Zeile
}

// LogHit ist ein Treffer einer Regel in einer Zeile.
type LogHit struct {
	Src     netip.Addr // Angreifer (Pflicht, sonst kein Treffer)
	Port    int        // angegriffener Port, 0 = Standard der Regel
	Success bool       // erfolgreiche Anmeldung dieser IP: setzt den Zaehler der Regel fuer die IP zurueck (Vertipper)
	Weight  int        // zaehlt so oft (0 = 1); z. B. ein eindeutiger Exploit-Pfad zaehlt gleich bis zur Schwelle
}

// LogRule ist eine mitgelieferte Regel (Parser + Szenario). Kennung "<quelle>/<szenario>", gemeldet als
// "<ID>@<Version>" (z. B. "sshd/bruteforce@1"). Regeln werden per init() mit RegisterLogRule angemeldet.
type LogRule struct {
	ID        string        // z. B. "sshd/bruteforce", "nginx/exploit", "mikrotik/login"
	Version   int           // >= 1; bei geaenderter Erkennung erhoehen
	Origins   []string      // in welchen Quellen die Regel gilt (SrcLog, SrcSyslog); leer = beide
	Kind      string        // Kind*
	Service   string        // Svc*
	Port      int           // Standard-Port fuer die Meldung (0 = unbekannt)
	Threshold int           // so viele Treffer derselben IP im Fenster, dann ein Ereignis (>= 1)
	Window    time.Duration // Fenster der Schwelle
	// Match prueft eine Zeile. Schnell und ohne Zuweisungen, wenn die Zeile nicht passt (vorher Program/Format pruefen).
	Match func(l *LogLine) (LogHit, bool)
}

// Tag ist die Regel-Kennung fuer die Meldung.
func (r *LogRule) Tag() string { return r.ID + "@" + itoa(r.Version) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

var logRules []*LogRule

// RegisterLogRule meldet eine Regel an (nur aus init()).
func RegisterLogRule(r *LogRule) { logRules = append(logRules, r) }

// LogRules liefert alle angemeldeten Regeln (nicht veraendern).
func LogRules() []*LogRule { return logRules }

// LogConfig ist die Einstellung von Log-Sensor und Syslog-Empfaenger (Teil von Config).
type LogConfig struct {
	// Dateien (Log-Sensor). Pfade bzw. Muster (filepath.Glob) innerhalb des Containers, z. B. /host/log/auth.log,
	// /host/log/nginx/*access.log. Leer = Log-Sensor aus.
	Files []LogFile `json:"files,omitempty"`
	// Syslog-Empfaenger: 0 = aus. UDP und TCP auf demselben Port (Standard-Vorschlag 514).
	SyslogPort int `json:"syslog_port,omitempty"`
	// Absender, die Syslog schicken duerfen (CIDR). Leer = nur private Netze und localhost.
	SyslogAllow []string `json:"syslog_allow,omitempty"`
}

// LogFile ist eine Datei (oder ein Muster) mit Formathinweis.
type LogFile struct {
	Path   string `json:"path"`
	Format string `json:"format,omitempty"` // siehe LogLine.Format; "" = automatisch (Endung/Inhalt)
}

// Grenzen des Log-Sensors.
const (
	LogMaxFiles       = 32               // Dateien je Einstellung (nach Glob)
	LogMaxLine        = 16 << 10         // laengere Zeilen werden gekuerzt
	LogMaxTracked     = 100000           // IPs mit offenem Zaehler je Regel insgesamt; voll = aelteste fallen weg
	LogPoll           = 2 * time.Second  // Abfrage der Dateien (keine inotify-Abhaengigkeit)
	SyslogMaxMsg      = 8 << 10          // Nachricht (UDP/TCP)
	SyslogMaxConns    = 64               // gleichzeitige TCP-Verbindungen
	SyslogIdleTimeout = 10 * time.Minute // TCP ohne Daten
)

// LogSensor ist der laufende Log-Sensor mit Syslog-Empfaenger (logengine.go). Start mit dem Sink des Moduls; jedes
// Ereignis hat Source = SrcLog bzw. SrcSyslog und Rule = LogRule.Tag().
//
//	ls := NewLogSensor(log)
//	st := ls.Apply(ctx, cfg, sink)  // startet/aendert/stoppt Dateien und Syslog; liefert den Zustand
//	ls.Stop()
type LogStatus struct {
	Files  []LogFileStatus `json:"files"`
	Syslog *SyslogStatus   `json:"syslog,omitempty"`
	Lines  int64           `json:"lines"` // gelesene Zeilen/Nachrichten seit dem Start
	Hits   int64           `json:"hits"`  // Treffer (vor der Schwelle)
	Events int64           `json:"events"`
}

// LogFileStatus ist der Zustand einer Datei.
type LogFileStatus struct {
	Path   string    `json:"path"`
	Format string    `json:"format"`
	OK     bool      `json:"ok"`
	Error  string    `json:"error,omitempty"` // z. B. "permission denied" (Gruppe adm fehlt)
	Lines  int64     `json:"lines"`
	Last   time.Time `json:"last,omitzero"`
}

// SyslogStatus ist der Zustand des Syslog-Empfaengers.
type SyslogStatus struct {
	Port     int    `json:"port"`
	UDP      bool   `json:"udp"`
	TCP      bool   `json:"tcp"`
	Error    string `json:"error,omitempty"`
	Messages int64  `json:"messages"`
	Denied   int64  `json:"denied"` // Absender nicht erlaubt
}
