package honeypot

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Dienst-Profile (Persona): wie sich eine Falle nach aussen gibt (SSH-Banner und Algorithmen, Telnet-Prompt,
// MySQL-Greeting, HTTP-Kopfzeilen und -Antworten, TLS-Zertifikat). Standard je Dienst, Port und Koeder; einstellbar
// je Port (Config.Personas, Schluessel "dienst:port"). Hostname, Patch-Versionen und Zertifikatsdaten variieren je
// Sensor stabil (Seed = Sensor-Kennung), damit nicht alle Honeypot64-Sensoren denselben Fingerabdruck haben.
// Geaendert wird nur, was die Falle sendet (keine Logos, keine nachgebauten Oberflaechen), nie was sie erfasst.

// Profile je Dienst.
const (
	PersonaNginx   = "nginx"
	PersonaApache  = "apache"
	PersonaPVE     = "pve"
	PersonaWebmin  = "webmin"
	PersonaHA      = "homeassistant"
	PersonaGrafana = "grafana"
	PersonaNAS     = "nas"
	PersonaElastic = "elasticsearch"

	PersonaOpenSSH       = "openssh" // Debian oder Ubuntu je Sensor
	PersonaOpenSSHDebian = "openssh-debian"
	PersonaOpenSSHUbuntu = "openssh-ubuntu"
	PersonaDropbear      = "dropbear"

	PersonaBusyBox = "busybox"
	PersonaLinux   = "linux"

	PersonaMySQL     = "mysql"
	PersonaMariaDB   = "mariadb"
	PersonaMariaDB11 = "mariadb11"
)

var personaWeb = []string{PersonaNginx, PersonaApache, PersonaPVE, PersonaWebmin, PersonaHA, PersonaGrafana, PersonaNAS, PersonaElastic}

// personaList: waehlbare Profile je Dienst (Dienste ohne Eintrag haben keine Auswahl).
var personaList = map[string][]string{
	SvcHTTP:   personaWeb,
	SvcHTTPS:  personaWeb,
	SvcSSH:    {PersonaOpenSSH, PersonaOpenSSHDebian, PersonaOpenSSHUbuntu, PersonaDropbear},
	SvcTelnet: {PersonaBusyBox, PersonaLinux},
	SvcMySQL:  {PersonaMySQL, PersonaMariaDB, PersonaMariaDB11},
}

// PersonaLabels: Anzeige in der Auswahl (Eigennamen, nicht uebersetzt).
var PersonaLabels = map[string]string{
	PersonaNginx: "nginx", PersonaApache: "Apache", PersonaPVE: "Proxmox VE", PersonaWebmin: "Webmin", PersonaHA: "Home Assistant",
	PersonaGrafana: "Grafana", PersonaNAS: "NAS (DSM-API)", PersonaElastic: "Elasticsearch",
	PersonaOpenSSH: "OpenSSH", PersonaOpenSSHDebian: "OpenSSH Debian 12", PersonaOpenSSHUbuntu: "OpenSSH Ubuntu 24.04", PersonaDropbear: "Dropbear",
	PersonaBusyBox: "BusyBox", PersonaLinux: "Linux (login)",
	PersonaMySQL: "MySQL 8.0", PersonaMariaDB: "MariaDB 10.11", PersonaMariaDB11: "MariaDB 11.4",
}

// Standard je Koeder bzw. Port (HTTP/HTTPS); alles andere ist nginx.
var (
	personaPageHTTP = map[string]string{"pve": PersonaPVE, "webmin": PersonaWebmin, "homeassistant": PersonaHA, "grafana": PersonaGrafana,
		"nas": PersonaNAS, "elastic": PersonaElastic}
	personaPortHTTP = map[int]string{8006: PersonaPVE, 10000: PersonaWebmin, 8123: PersonaHA, 3000: PersonaGrafana, 5000: PersonaNAS,
		5001: PersonaNAS, 9200: PersonaElastic}
)

// personaOld: Dienste, die „verwundbar wirken“ koennen (aeltere Versionen in Banner bzw. Kopfzeilen).
var personaOld = map[string]bool{SvcHTTP: true, SvcHTTPS: true, SvcSSH: true, SvcMySQL: true}

// OldVersions: der Dienst kann aeltere, bekannt verwundbare Versionen zeigen (Config.Vulnerable).
func OldVersions(service string) bool { return personaOld[service] }

// PersonasFor liefert die waehlbaren Profile eines Dienstes (nil = keine Auswahl).
func PersonasFor(service string) []string { return personaList[service] }

// DefaultPersona liefert das Standardprofil (Koeder vor Port), "" = Dienst ohne Profile.
func DefaultPersona(service string, port int, page string) string {
	switch service {
	case SvcHTTP, SvcHTTPS:
		if p := personaPageHTTP[page]; p != "" {
			return p
		}
		if p := personaPortHTTP[port]; p != "" {
			return p
		}
		return PersonaNginx
	case SvcSSH:
		return PersonaOpenSSH
	case SvcTelnet:
		return PersonaBusyBox
	case SvcMySQL:
		return PersonaMySQL
	}
	return ""
}

// PersonaKey ist der Schluessel in Config.Personas.
func PersonaKey(service string, port int) string { return service + ":" + strconv.Itoa(port) }

// personaValid: Profil gibt es fuer den Dienst.
func personaValid(service, persona string) bool {
	return slices.Contains(personaList[service], persona)
}

// parsePersonaKey zerlegt "dienst:port".
func parsePersonaKey(k string) (service string, port int, ok bool) {
	svc, p, found := strings.Cut(k, ":")
	n, err := strconv.Atoi(p)
	if !found || err != nil || n < 1 || n > 65535 {
		return "", 0, false
	}
	return svc, n, true
}

// PersonaProblems prueft Profile und Hostname (Modul und Modus ohne Oberflaeche); normalisiert die Schluessel und
// Werte (klein, leere Werte fallen weg). Liefert i18n-Schluessel mit Werten nach "|".
func PersonaProblems(c *Config) []string {
	var out []string
	c.Hostname = strings.ToLower(strings.TrimSpace(c.Hostname))
	if c.Hostname != "" && !ValidHostname(c.Hostname) {
		out = append(out, "honeypot.err.hostname|"+storeClip(c.Hostname, 80))
	}
	out = append(out, vulnerableProblems(c)...)
	if len(c.Personas) == 0 {
		c.Personas = nil
		return out
	}
	if len(c.Personas) > 128 {
		return append(out, "honeypot.err.persona_many|128")
	}
	norm := map[string]string{}
	keys := make([]string, 0, len(c.Personas))
	for k := range c.Personas {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := strings.ToLower(strings.TrimSpace(c.Personas[k]))
		if v == "" {
			continue
		}
		svc, port, ok := parsePersonaKey(strings.ToLower(strings.TrimSpace(k)))
		if !ok || !personaValid(svc, v) {
			out = append(out, "honeypot.err.persona|"+storeClip(k, 40)+"|"+storeClip(v, 40))
			continue
		}
		norm[PersonaKey(svc, port)] = v
	}
	c.Personas = norm
	if len(norm) == 0 {
		c.Personas = nil
	}
	return out
}

// vulnerableProblems normalisiert Config.Vulnerable (klein, sortiert, ohne Doppelte; nur Dienste mit OldVersions).
func vulnerableProblems(c *Config) []string {
	if len(c.Vulnerable) > 128 {
		return []string{"honeypot.err.vulnerable_many|128"}
	}
	var out, keep []string
	seen := map[string]bool{}
	for _, k := range c.Vulnerable {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" || seen[k] {
			continue
		}
		svc, port, ok := parsePersonaKey(k)
		if !ok || !OldVersions(svc) {
			out = append(out, "honeypot.err.vulnerable|"+storeClip(k, 40))
			continue
		}
		seen[k] = true
		keep = append(keep, PersonaKey(svc, port))
	}
	sort.Strings(keep)
	c.Vulnerable = keep
	return out
}

// personaErrEN: englische Texte fuer den Modus ohne Oberflaeche (dort gibt es keine Uebersetzung).
var personaErrEN = map[string]string{
	"honeypot.err.hostname":        "hostname %q is not valid (letters, digits, - and dots)",
	"honeypot.err.persona":         "profile %[2]q is not available for %[1]q (service:port=profile, e.g. ssh:22=dropbear)",
	"honeypot.err.persona_many":    "at most %s profiles",
	"honeypot.err.vulnerable":      "%q cannot look vulnerable (service:port of http, https, ssh or mysql, e.g. ssh:22)",
	"honeypot.err.vulnerable_many": "at most %s entries that look vulnerable",
}

// ValidatePersonas prueft und normalisiert Profile und Hostname wie das Modul, Fehler auf Englisch (Modus ohne
// Oberflaeche).
func ValidatePersonas(c *Config) error {
	var msgs []string
	for _, p := range PersonaProblems(c) {
		parts := strings.Split(p, "|")
		args := make([]any, 0, len(parts)-1)
		for _, v := range parts[1:] {
			args = append(args, v)
		}
		msgs = append(msgs, fmt.Sprintf(personaErrEN[parts[0]], args...))
	}
	if len(msgs) == 0 {
		return nil
	}
	return errors.New(strings.Join(msgs, "; "))
}

// ValidHostname: Hostname nach RFC 1123 (Labels a-z, 0-9, "-", hoechstens 63 Zeichen, insgesamt 253).
func ValidHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// sensorIdent ist die feste Identitaet eines Sensors: Hostname, Domain und Distribution, dazu stabile Auswahl von
// Versionen und Zufallswerten aus dem Seed.
type sensorIdent struct {
	seed   string
	host   string // kurz
	domain string
	distro string // debian, ubuntu
	set    bool   // Hostname eingestellt (nicht erzeugt)
	old    bool   // „verwundbar wirken“: aeltere, bekannt verwundbare Versionen (Kopie je Port, sensorPersonas.identFor)
}

// Bausteine erzeugter Hostnamen und Domains (wie haeufige Server-Namen).
var (
	identHostPrefix = []string{"srv", "server", "web", "app", "node", "host", "vps", "vm", "nas", "home", "lab", "box", "gw", "core",
		"db", "proxy", "dev", "prod", "backup", "pve"}
	identDomains = []string{"local", "lan", "home.arpa", "localdomain", "internal", "home"}
)

// newSensorIdent baut die Identitaet: hostname "" = aus dem Seed erzeugt; ein eingestellter FQDN liefert die Domain.
// Ein ausdrueckliches OpenSSH-Profil (Debian/Ubuntu) legt die Distribution fest, sonst der Seed.
func newSensorIdent(seed, hostname string, personas map[string]string) *sensorIdent {
	id := &sensorIdent{seed: seed}
	if hostname != "" {
		id.set = true
		id.host, id.domain, _ = strings.Cut(hostname, ".")
	} else {
		id.host = identHostPrefix[id.pick("host", len(identHostPrefix))]
		switch id.pick("host-fmt", 4) {
		case 1:
			id.host += strconv.Itoa(1 + id.pick("host-n", 9))
		case 2:
			id.host += fmt.Sprintf("%02d", 1+id.pick("host-n", 24))
		case 3:
			id.host += "-" + strconv.Itoa(1+id.pick("host-n", 9))
		}
	}
	if id.domain == "" {
		id.domain = identDomains[id.pick("domain", len(identDomains))]
	}
	id.distro = []string{"debian", "ubuntu"}[id.pick("distro", 2)]
	keys := make([]string, 0, len(personas))
	for k := range personas {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch personas[k] {
		case PersonaOpenSSHDebian:
			id.distro = "debian"
		case PersonaOpenSSHUbuntu:
			id.distro = "ubuntu"
		default:
			continue
		}
		break
	}
	return id
}

// sensorRandomSeed: Seed ohne Sensor-Kennung (nur im Speicher, z. B. Tests).
func sensorRandomSeed() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (id *sensorIdent) sum(salt string) [32]byte { return sha256.Sum256([]byte(id.seed + "|" + salt)) }

// pick liefert stabil eine Zahl in [0, n).
func (id *sensorIdent) pick(salt string, n int) int {
	if n <= 1 {
		return 0
	}
	h := id.sum(salt)
	return int(binary.BigEndian.Uint64(h[:8]) % uint64(n))
}

// choose waehlt stabil einen Eintrag.
func (id *sensorIdent) choose(salt string, list ...string) string {
	return list[id.pick(salt, len(list))]
}

// hex liefert stabil n Hex-Zeichen (n <= 64).
func (id *sensorIdent) hex(salt string, n int) string {
	h := id.sum(salt)
	return hex.EncodeToString(h[:])[:n]
}

func (id *sensorIdent) fqdn() string { return id.host + "." + id.domain }

func (id *sensorIdent) ubuntu() bool { return id.distro == "ubuntu" }

// Versionen je Sensor (plausible, veroeffentlichte Staende; der Seed waehlt innerhalb der Reihe).
// Mit old aeltere Staende mit bekannten Luecken (nur die Kennung; die Falle bleibt dieselbe): nginx 1.18/1.14
// (CVE-2021-23017), Apache 2.4.49/2.4.50 (CVE-2021-41773/42013), OpenSSH 8.2p1/7.9p1, Webmin 1.890-1.920
// (CVE-2019-15107), Grafana 8.0-8.3.0 (CVE-2021-43798), MySQL 5.7 bzw. MariaDB 10.3, dazu PHP 7.4 als X-Powered-By.
func (id *sensorIdent) nginxServer() string {
	switch {
	case id.old && id.ubuntu():
		return "nginx/1.18.0 (Ubuntu)"
	case id.old:
		return "nginx/1.14.2"
	case id.ubuntu():
		return "nginx/1.24.0 (Ubuntu)"
	}
	return "nginx/1.22.1"
}

func (id *sensorIdent) apacheServer() string {
	if id.old {
		return "Apache/2.4." + id.choose("apache-old", "49", "50") + " (Unix)"
	}
	if id.ubuntu() {
		return "Apache/2.4.58 (Ubuntu)"
	}
	return "Apache/2.4." + id.choose("apache", "62", "65") + " (Debian)"
}

// poweredBy: X-Powered-By der Webserver-Profile ("" = keiner; nur „verwundbar wirken“).
func (id *sensorIdent) poweredBy() string {
	if !id.old {
		return ""
	}
	return "PHP/7.4." + id.choose("php-old", "3", "21", "33")
}

// webminVersion: MiniServ-Version (Server-Kopf von Webmin).
func (id *sensorIdent) webminVersion() string {
	if id.old {
		return id.choose("webmin-old", "1.890", "1.900", "1.910", "1.920")
	}
	return id.choose("webmin", "2.105", "2.202", "2.302", "2.402")
}

// grafanaVersion: Version in /api/health.
func (id *sensorIdent) grafanaVersion() string {
	if id.old {
		return id.choose("grafana-old", "8.0.6", "8.1.7", "8.2.5", "8.3.0")
	}
	return id.choose("grafana", "10.4.12", "11.2.2", "11.3.1", "11.5.2", "12.0.2")
}

// osIssue ist /etc/issue.net (Telnet-Login unter Linux).
func (id *sensorIdent) osIssue() string {
	if id.ubuntu() {
		return "Ubuntu 24.04." + id.choose("issue", "1", "2", "3") + " LTS"
	}
	return "Debian GNU/Linux 12"
}

// sshBanner liefert die Versionskennung zum Profil (OpenSSH folgt der Distribution).
func (id *sensorIdent) sshBanner(persona string) string {
	if id.old {
		switch {
		case persona == PersonaDropbear:
			return "SSH-2.0-dropbear_" + id.choose("dropbear-old", "2019.78", "2020.81")
		case persona == PersonaOpenSSHUbuntu || persona != PersonaOpenSSHDebian && id.ubuntu():
			return "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0." + id.choose("ssh-ubuntu-old", "1", "3", "5")
		}
		return "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u" + id.choose("ssh-debian-old", "1", "2")
	}
	switch persona {
	case PersonaDropbear:
		return "SSH-2.0-dropbear_" + id.choose("dropbear", "2024.84", "2024.85", "2024.86")
	case PersonaOpenSSHUbuntu:
		return "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13." + id.choose("ssh-ubuntu", "5", "8", "11", "13")
	case PersonaOpenSSHDebian:
		return "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u" + id.choose("ssh-debian", "3", "5", "6", "7")
	}
	if id.ubuntu() {
		return id.sshBanner(PersonaOpenSSHUbuntu)
	}
	return id.sshBanner(PersonaOpenSSHDebian)
}

// telnetHost: Hostname im Telnet-Prompt (BusyBox ohne eingestellten Hostnamen: typische Geraete-Namen).
func (id *sensorIdent) telnetHost(persona string) string {
	if persona == PersonaBusyBox && !id.set {
		return id.choose("busybox-host", "localhost", "(none)", "router", "gateway", "OpenWrt")
	}
	return id.host
}

// sensorPersonas ist der Stand der Profile im Sensor (bei Apply ersetzt, je Verbindung gelesen).
type sensorPersonas struct {
	id    *sensorIdent
	idOld *sensorIdent      // wie id, mit aelteren Versionen („verwundbar wirken“)
	set   map[string]string // "dienst:port" -> Profil (nur gueltige)
	old   map[string]bool   // "dienst:port" wirkt verwundbar
	web   string            // fest fuer alle HTTP/HTTPS-Dienste ("" = je Port; PROXY64-Koeder: nginx)
}

func newSensorPersonas(seed, hostname string, personas map[string]string, vulnerable []string) *sensorPersonas {
	p := &sensorPersonas{set: map[string]string{}, old: map[string]bool{}}
	for k, v := range personas {
		if svc, port, ok := parsePersonaKey(k); ok && personaValid(svc, v) {
			p.set[PersonaKey(svc, port)] = v
		}
	}
	for _, k := range vulnerable {
		if svc, port, ok := parsePersonaKey(strings.ToLower(strings.TrimSpace(k))); ok && OldVersions(svc) {
			p.old[PersonaKey(svc, port)] = true
		}
	}
	p.id = newSensorIdent(seed, hostname, p.set)
	o := *p.id
	o.old = true
	p.idOld = &o
	return p
}

// identFor liefert die Identitaet fuer einen Dienst (mit aelteren Versionen, wenn er verwundbar wirken soll).
func (p *sensorPersonas) identFor(k sensorKey) *sensorIdent {
	if p.old[PersonaKey(k.Service, k.Port)] {
		return p.idOld
	}
	return p.id
}

// of liefert das Profil eines Dienstes (eingestellt oder Standard).
func (p *sensorPersonas) of(k sensorKey) string {
	if v := p.set[PersonaKey(k.Service, k.Port)]; v != "" {
		return v
	}
	if p.web != "" && (k.Service == SvcHTTP || k.Service == SvcHTTPS) {
		return p.web
	}
	return DefaultPersona(k.Service, k.Port, k.Page)
}

// personas liefert den aktuellen Stand (vor dem ersten Apply: Standard mit dem Seed des Sensors).
func (s *Sensor) personas() *sensorPersonas {
	if p := s.persona.Load(); p != nil {
		return p
	}
	return newSensorPersonas(s.seed, "", nil, nil)
}
