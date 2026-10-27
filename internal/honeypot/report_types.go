package honeypot

import "time"

// Meldung an ipv64 (Phase H2, Plan Abschnitt 4/5): Format schema 1. Gemeinsamer Vertrag von Node64 (report*.go)
// und ipv64 (deploy/web/api_v2_honeypot.php, deploy/sql/honeypot.sql). Neue Felder nur optional anhaengen; aeltere
// Sensoren bleiben gueltig.
//
//	POST https://ipv64.net/api/v2/honeypot/reports   (Authorization: Bearer <API-Key>, Content-Type: application/json,
//	                                                   Content-Encoding: gzip erlaubt, hoechstens 2 MiB entpackt)
//	202 {"accepted": <sources>, "report_id": "..."}   angenommen
//	200 {"duplicate": true, "report_id": "..."}        report_id schon bekannt (zaehlt als Erfolg, nicht erneut senden)
//	400/413/422 {"error": ...}                          ungueltig (nicht wiederholen, verwerfen und zaehlen)
//	401/403                                             Key ungueltig / Klasse gesperrt (spaeter erneut versuchen)
//	429 (Retry-After)                                   zu oft; 5xx: spaeter erneut versuchen
//
// Gesendet wird alle 10 Minuten der Zeitraum seit der letzten erfolgreichen Meldung (hoechstens 7 Tage zurueck).
// Benutzernamen/Passwoerter stammen nur aus dem Honeypot. Die eigene oeffentliche IP des Sensors steht nie drin
// (ipv64 kennt sie aus der Verbindung).

// ReportSchema ist die aktuelle Fassung des Formats.
const ReportSchema = 1

// Grenzen je Meldung (Sensor kuerzt, ipv64 prueft).
const (
	ReportMaxSources = 5000
	ReportMaxSamples = 500 // je Probenart
	ReportEvery      = 10 * time.Minute
	ReportMaxBack    = 7 * 24 * time.Hour
)

// Report ist eine Meldung.
type Report struct {
	Schema   int            `json:"schema"`    // ReportSchema
	ReportID string         `json:"report_id"` // <sensor.id>-<period.start unix>; ipv64 verwirft Doppelte
	Sensor   ReportSensor   `json:"sensor"`
	Period   ReportPeriod   `json:"period"`
	Sources  []ReportSource `json:"sources"`           // je (ip, kind, service, port) zusammengefasst
	Samples  ReportSamples  `json:"samples,omitempty"` // Proben (nur Honeypot)
	Dropped  int64          `json:"dropped,omitempty"` // wegen Grenzen weggelassene Eintraege
}

// ReportSensor beschreibt den Sensor.
type ReportSensor struct {
	ID      string `json:"id"`                // fest je Installation (UUID), nicht die IP
	Version string `json:"version"`           // Programmversion
	Profile string `json:"profile"`           // minimal | standard | full | custom | proxy
	Mode    string `json:"mode"`              // module | headless
	Country string `json:"country,omitempty"` // eingestellter Standort (ISO 3166-1), nur Anzeige (Live-Karte)
}

// ReportPeriod ist der gemeldete Zeitraum (UTC, start inklusive, end exklusive).
type ReportPeriod struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ReportSource ist eine Quell-IP mit Art, Dienst und Anzahl.
type ReportSource struct {
	IP      string    `json:"ip"`
	Kind    string    `json:"kind"`    // Kind*
	Service string    `json:"service"` // Svc*
	Port    int       `json:"port"`
	Count   int64     `json:"count"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Source  string    `json:"source"`           // honeypot (spaeter log, syslog)
	Rule    string    `json:"rule,omitempty"`   // z. B. honeypot/ssh@1
	Detail  string    `json:"detail,omitempty"` // erkannte Muster (gekuerzt)
}

// ReportSamples sind Proben fuer die zentrale Statistik.
type ReportSamples struct {
	Credentials []ReportCred    `json:"credentials,omitempty"`
	Paths       []ReportKey     `json:"paths,omitempty"`
	UserAgents  []ReportKey     `json:"user_agents,omitempty"`
	Payloads    []ReportPayload `json:"payloads,omitempty"`
	// H6: Fingerabdruecke der Werkzeuge, Key "ja4:<ja4>" bzw. "hassh:<md5>" (optional, aeltere ipv64 ignorieren das Feld)
	Fingerprints []ReportKey `json:"fingerprints,omitempty"`
}

// ReportCred ist ein Paar Benutzername/Passwort (Klartext, nur Honeypot).
type ReportCred struct {
	Service string `json:"service"`
	User    string `json:"user"`
	Pass    string `json:"pass"`
	Count   int64  `json:"count"`
}

// ReportKey ist ein Text mit Anzahl (Pfad, User-Agent).
type ReportKey struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// ReportPayload ist der Anfang einer Payload (SHA-256 ueber die erfassten Bytes, Head base64).
type ReportPayload struct {
	SHA256  string `json:"sha256"`
	Head    string `json:"head"` // base64, hoechstens MaxPayload Bytes
	Service string `json:"service"`
	Port    int    `json:"port"`
	Count   int64  `json:"count"`
}
