package honeypot

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Regeln fuer Router und Firewalls (Syslog, Plan Abschnitt 1c). Ergebnis ist immer nur die IP des Angreifers (und
// ggf. der angegriffene Port); Benutzernamen und andere Inhalte der Zeilen werden nie uebernommen.
//
// Eine Regel hat genau eine Art (Kind) und einen Dienst. Wo ein Geraet mehrere Dienste in derselben Meldung nennt
// (MikroTik "via ssh|web|telnet|winbox|api|ftp", FortiGate Admin per HTTPS oder SSH), gibt es deshalb je Art eine
// eigene Regel mit derselben Erkennung; jede Zeile trifft hoechstens eine davon.
//
// Formate nach Herstellerdoku bzw. bekannten Beispielzeilen (nicht an allen Geraeten geprueft):
//   - MikroTik RouterOS: "login failure for user admin from 192.0.2.7 via ssh" (Topics "system,error,critical" davor).
//   - OPNsense: "Web GUI authentication error for user 'root' from 192.0.2.7" (audit), pfSense: "/index.php:
//     webConfigurator authentication error for user 'admin' from: 192.0.2.7" (php-fpm).
//   - filterlog (beide): CSV, Felder 0-8 gemeinsam (Regel, Unterregel, Anker, Tracker/Label, Interface, Grund, Aktion,
//     Richtung, IP-Version); IPv4: 16 Protokoll, 18 Quelle, 19 Ziel, 21 Ziel-Port; IPv6: 12 Protokoll, 15 Quelle,
//     16 Ziel, 18 Ziel-Port. pfSense schreibt als Tracker eine Zahl, OPNsense als Label einen Hash.
//   - FortiGate: key=value (logdesc="Admin login failed" srcip=..., action="ssl-login-fail" remip=...,
//     IPsec action="negotiate" status="negotiate_error" remip=...).
//   - Sophos Firewall: key=value (log_component="GUI"/"SSL VPN Authentication" status="Failed" src_ip=...).
//   - UniFi (dropbear): "Bad password attempt for 'ubnt' from 192.0.2.7:52341", "Login attempt for nonexistent user
//     from 192.0.2.7:52341".
//
// sshd-Zeilen (OpenSSH auf OPNsense/pfSense/UniFi OS) wertet die allgemeine sshd-Regel aus (logrules_svc.go); hier
// nicht noch einmal, sonst zaehlte jede Zeile doppelt.

var (
	fwSyslogOnly = []string{SrcSyslog}
	fwSyslogLog  = []string{SrcSyslog, SrcLog} // OPNsense/pfSense: auch wenn jemand die Datei liest
)

// Schwellen
const (
	fwLoginThreshold = 5
	fwLoginWindow    = 10 * time.Minute
	fwIPsecThreshold = 10 // IKE-Fehler wiederholt auch eine falsch eingestellte Gegenstelle
	fwScanPorts      = 20 // verschiedene Ziel-Ports
	fwScanWindow     = 5 * time.Minute
	fwScanMaxTracked = 20000 // IPs mit offenem Zaehler je Regel
)

func init() {
	// MikroTik
	RegisterLogRule(&LogRule{ID: "mikrotik/login-ssh", Version: 1, Origins: fwSyslogOnly, Kind: KindSSHBrute,
		Service: SvcSSH, Port: 22, Threshold: fwLoginThreshold, Window: fwLoginWindow,
		Match: fwMikrotik(func(via string) bool { return via == "ssh" })})
	RegisterLogRule(&LogRule{ID: "mikrotik/login-web", Version: 1, Origins: fwSyslogOnly, Kind: KindHTTPBrute,
		Service: SvcHTTPS, Port: 443, Threshold: fwLoginThreshold, Window: fwLoginWindow,
		Match: fwMikrotik(func(via string) bool { return via == "web" })})
	RegisterLogRule(&LogRule{ID: "mikrotik/login-telnet", Version: 1, Origins: fwSyslogOnly, Kind: KindTelnetBrute,
		Service: SvcTelnet, Port: 23, Threshold: fwLoginThreshold, Window: fwLoginWindow,
		Match: fwMikrotik(func(via string) bool { return via == "telnet" })})
	RegisterLogRule(&LogRule{ID: "mikrotik/login", Version: 1, Origins: fwSyslogOnly, Kind: KindProbe,
		Service: SvcTCP, Port: 0, Threshold: fwLoginThreshold, Window: fwLoginWindow,
		Match: fwMikrotik(func(via string) bool {
			return via != "ssh" && via != "web" && via != "telnet" && fwMikrotikPort(via) > 0 // winbox, api, ftp
		})})

	// OPNsense / pfSense
	RegisterLogRule(&LogRule{ID: "opnsense/login", Version: 1, Origins: fwSyslogLog, Kind: KindHTTPBrute,
		Service: SvcHTTPS, Port: 443, Threshold: fwLoginThreshold, Window: fwLoginWindow, Match: fwOPNsenseLogin})
	RegisterLogRule(&LogRule{ID: "pfsense/login", Version: 1, Origins: fwSyslogLog, Kind: KindHTTPBrute,
		Service: SvcHTTPS, Port: 443, Threshold: fwLoginThreshold, Window: fwLoginWindow, Match: fwPfSenseLogin})
	opnScan, pfScan := newFwScan(false), newFwScan(true)
	RegisterLogRule(&LogRule{ID: "opnsense/portscan", Version: 1, Origins: fwSyslogLog, Kind: KindPortScan,
		Service: SvcScan, Port: 0, Threshold: fwScanPorts, Window: fwScanWindow, Match: opnScan.match})
	RegisterLogRule(&LogRule{ID: "pfsense/portscan", Version: 1, Origins: fwSyslogLog, Kind: KindPortScan,
		Service: SvcScan, Port: 0, Threshold: fwScanPorts, Window: fwScanWindow, Match: pfScan.match})

	// FortiGate
	RegisterLogRule(&LogRule{ID: "fortigate/admin-login", Version: 1, Origins: fwSyslogOnly, Kind: KindHTTPBrute,
		Service: SvcHTTPS, Port: 443, Threshold: fwLoginThreshold, Window: fwLoginWindow,
		Match: fwFortiAdmin(false)})
	RegisterLogRule(&LogRule{ID: "fortigate/admin-ssh", Version: 1, Origins: fwSyslogOnly, Kind: KindSSHBrute,
		Service: SvcSSH, Port: 22, Threshold: fwLoginThreshold, Window: fwLoginWindow,
		Match: fwFortiAdmin(true)})
	RegisterLogRule(&LogRule{ID: "fortigate/vpn", Version: 1, Origins: fwSyslogOnly, Kind: KindVPNBrute,
		Service: SvcVPN, Port: 443, Threshold: fwLoginThreshold, Window: fwLoginWindow, Match: fwFortiSSLVPN})
	RegisterLogRule(&LogRule{ID: "fortigate/ipsec", Version: 1, Origins: fwSyslogOnly, Kind: KindVPNBrute,
		Service: SvcVPN, Port: 500, Threshold: fwIPsecThreshold, Window: fwLoginWindow, Match: fwFortiIPsec})

	// Sophos Firewall
	RegisterLogRule(&LogRule{ID: "sophos/login", Version: 1, Origins: fwSyslogOnly, Kind: KindHTTPBrute,
		Service: SvcHTTPS, Port: 443, Threshold: fwLoginThreshold, Window: fwLoginWindow, Match: fwSophos(false)})
	RegisterLogRule(&LogRule{ID: "sophos/vpn", Version: 1, Origins: fwSyslogOnly, Kind: KindVPNBrute,
		Service: SvcVPN, Port: 0, Threshold: fwLoginThreshold, Window: fwLoginWindow, Match: fwSophos(true)})

	// UniFi (dropbear)
	RegisterLogRule(&LogRule{ID: "unifi/ssh", Version: 1, Origins: fwSyslogOnly, Kind: KindSSHBrute,
		Service: SvcSSH, Port: 22, Threshold: fwLoginThreshold, Window: fwLoginWindow, Match: fwUniFiSSH})
}

// --- MikroTik ---

// fwMikrotik erkennt "login failure for user <name> from <ip> via <dienst>"; want waehlt den Dienst.
func fwMikrotik(want func(via string) bool) func(*LogLine) (LogHit, bool) {
	return func(l *LogLine) (LogHit, bool) {
		m := l.Message
		i := strings.Index(m, "login failure for user ")
		if i < 0 {
			return LogHit{}, false
		}
		m = m[i:]
		v := strings.LastIndex(m, " via ")
		if v < 0 {
			return LogHit{}, false
		}
		via := fwWord(m[v+5:])
		f := strings.LastIndex(m[:v], " from ")
		if f < 0 || !want(via) {
			return LogHit{}, false
		}
		ip, ok := fwParseIP(m[f+6 : v])
		if !ok {
			return LogHit{}, false
		}
		return LogHit{Src: ip, Port: fwMikrotikPort(via)}, true
	}
}

// fwMikrotikPort liefert den Standard-Port fuer "via ..." (0 = nicht ueber das Netz, z. B. local, mac-telnet).
func fwMikrotikPort(via string) int {
	switch via {
	case "ssh":
		return 22
	case "telnet":
		return 23
	case "web":
		return 443
	case "winbox":
		return 8291
	case "api":
		return 8728
	case "api-ssl":
		return 8729
	case "ftp":
		return 21
	}
	return 0
}

// --- OPNsense / pfSense ---

func fwOPNsenseLogin(l *LogLine) (LogHit, bool) {
	m := l.Message
	i := fwIndexFold(m, "web gui authentication error for ")
	if i < 0 {
		i = fwIndexFold(m, "webgui authentication error for ")
	}
	if i < 0 {
		return LogHit{}, false
	}
	return fwAfterFrom(m[i:])
}

func fwPfSenseLogin(l *LogLine) (LogHit, bool) {
	m := l.Message
	i := fwIndexFold(m, "webconfigurator authentication error for ")
	if i < 0 {
		return LogHit{}, false
	}
	return fwAfterFrom(m[i:])
}

// fwAfterFrom nimmt die Adresse nach dem letzten " from " bzw. " from: ".
func fwAfterFrom(m string) (LogHit, bool) {
	f := strings.LastIndex(m, " from")
	if f < 0 {
		return LogHit{}, false
	}
	r := strings.TrimPrefix(m[f+5:], ":")
	if len(r) == 0 || r[0] != ' ' {
		return LogHit{}, false
	}
	ip, ok := fwParseIP(fwWord(strings.TrimLeft(r, " ")))
	if !ok {
		return LogHit{}, false
	}
	return LogHit{Src: ip}, true
}

// fwScan zaehlt je Quell-IP verschiedene Ziel-Ports geblockter eingehender Verbindungen (filterlog). Erst wenn
// fwScanPorts im Fenster erreicht sind, gibt es einen Treffer mit Weight = Schwelle; danach beginnt die IP von vorn.
type fwScan struct {
	pfsense bool // true: nur Zeilen mit numerischem Tracker (pfSense), false: die anderen (OPNsense-Label)
	mu      sync.Mutex
	ips     map[netip.Addr]*fwScanEntry
}

type fwScanEntry struct {
	first time.Time
	ports []uint16
}

func newFwScan(pfsense bool) *fwScan {
	return &fwScan{pfsense: pfsense, ips: map[netip.Addr]*fwScanEntry{}}
}

func (s *fwScan) match(l *LogLine) (LogHit, bool) {
	if l.Program != "filterlog" {
		return LogHit{}, false
	}
	src, port, ok := fwFilterlog(l.Message, s.pfsense)
	if !ok {
		return LogHit{}, false
	}
	now := l.Time
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.ips[src]
	if e != nil && (now.Sub(e.first) > fwScanWindow || now.Before(e.first)) {
		e.first, e.ports = now, e.ports[:0]
	}
	if e == nil {
		if len(s.ips) >= fwScanMaxTracked {
			s.prune(now)
		}
		e = &fwScanEntry{first: now, ports: make([]uint16, 0, 4)}
		s.ips[src] = e
	}
	for _, p := range e.ports {
		if p == port {
			return LogHit{}, false
		}
	}
	e.ports = append(e.ports, port)
	if len(e.ports) < fwScanPorts {
		return LogHit{}, false
	}
	delete(s.ips, src)
	return LogHit{Src: src, Weight: fwScanPorts}, true
}

// prune entfernt abgelaufene Eintraege; reicht das nicht, die Haelfte (zufaellige Reihenfolge der Map).
func (s *fwScan) prune(now time.Time) {
	for ip, e := range s.ips {
		if now.Sub(e.first) > fwScanWindow {
			delete(s.ips, ip)
		}
	}
	n := len(s.ips) / 2
	for ip := range s.ips {
		if len(s.ips) <= n || len(s.ips) < fwScanMaxTracked {
			break
		}
		delete(s.ips, ip)
	}
}

// fwFilterlog liefert Quelle und Ziel-Port einer geblockten eingehenden TCP/UDP-Verbindung. pfsense waehlt die Zeilen
// nach dem Tracker (Feld 3): Zahl = pfSense, sonst OPNsense.
func fwFilterlog(m string, pfsense bool) (netip.Addr, uint16, bool) {
	var f [22]string
	n := 0
	for n < len(f) {
		i := strings.IndexByte(m, ',')
		if i < 0 {
			f[n] = m
			n++
			break
		}
		f[n], m = m[:i], m[i+1:]
		n++
	}
	if n < 19 || f[6] != "block" || f[7] != "in" {
		return netip.Addr{}, 0, false
	}
	if fwAllDigits(f[3]) != pfsense {
		return netip.Addr{}, 0, false
	}
	var proto, src, dport string
	switch f[8] {
	case "4":
		if n < 22 {
			return netip.Addr{}, 0, false
		}
		proto, src, dport = f[16], f[18], f[21]
	case "6":
		proto, src, dport = f[12], f[15], f[18]
	default:
		return netip.Addr{}, 0, false
	}
	if proto != "tcp" && proto != "udp" {
		return netip.Addr{}, 0, false
	}
	ip, ok := fwParseIP(src)
	if !ok {
		return netip.Addr{}, 0, false
	}
	p, ok := fwPort(dport)
	if !ok {
		return netip.Addr{}, 0, false
	}
	return ip, uint16(p), true
}

// --- FortiGate ---

// fwFortiAdmin erkennt fehlgeschlagene Admin-Anmeldungen (logdesc="Admin login failed", logid 0100032002); ssh
// waehlt Anmeldungen per SSH/Telnet-Konsole (method bzw. ui) statt Weboberflaeche.
func fwFortiAdmin(ssh bool) func(*LogLine) (LogHit, bool) {
	return func(l *LogLine) (LogHit, bool) {
		m := l.Message
		if !strings.Contains(m, "srcip=") {
			return LogHit{}, false
		}
		d, _ := fwKV(m, "logdesc")
		id, _ := fwKV(m, "logid")
		if !strings.EqualFold(d, "Admin login failed") && id != "0100032002" {
			return LogHit{}, false
		}
		method, _ := fwKV(m, "method")
		if method == "" {
			ui, _ := fwKV(m, "ui")
			method = ui
		}
		isSSH := fwHasPrefixFold(method, "ssh") || fwHasPrefixFold(method, "telnet")
		if isSSH != ssh {
			return LogHit{}, false
		}
		v, _ := fwKV(m, "srcip")
		ip, ok := fwParseIP(v)
		if !ok {
			return LogHit{}, false
		}
		h := LogHit{Src: ip}
		if p, ok := fwKVPort(m, "dstport"); ok {
			h.Port = p
		}
		return h, true
	}
}

// fwFortiSSLVPN erkennt fehlgeschlagene SSL-VPN-Anmeldungen (action="ssl-login-fail", logdesc="SSL VPN login fail";
// reason z. B. "sslvpn_login_unknown_user", "sslvpn_login_permission_denied").
func fwFortiSSLVPN(l *LogLine) (LogHit, bool) {
	m := l.Message
	if !strings.Contains(m, "remip=") {
		return LogHit{}, false
	}
	a, _ := fwKV(m, "action")
	d, _ := fwKV(m, "logdesc")
	if a != "ssl-login-fail" && !strings.EqualFold(d, "SSL VPN login fail") {
		return LogHit{}, false
	}
	v, _ := fwKV(m, "remip")
	ip, ok := fwParseIP(v)
	if !ok {
		return LogHit{}, false
	}
	return LogHit{Src: ip}, true
}

// fwFortiIPsec erkennt IKE-Verhandlungsfehler (action="negotiate" status="negotiate_error").
func fwFortiIPsec(l *LogLine) (LogHit, bool) {
	m := l.Message
	if !strings.Contains(m, "remip=") {
		return LogHit{}, false
	}
	a, _ := fwKV(m, "action")
	st, _ := fwKV(m, "status")
	if a != "negotiate" || st != "negotiate_error" {
		return LogHit{}, false
	}
	v, _ := fwKV(m, "remip")
	ip, ok := fwParseIP(v)
	if !ok {
		return LogHit{}, false
	}
	h := LogHit{Src: ip}
	if p, ok := fwKVPort(m, "locport"); ok && (p == 500 || p == 4500) {
		h.Port = p
	}
	return h, true
}

// --- Sophos Firewall ---

// fwSophos erkennt fehlgeschlagene Anmeldungen (status="Failed" bzw. "login failed"/"failed to login" in message);
// vpn waehlt VPN-Anmeldungen (log_component/auth_client/message mit VPN, IPsec, L2TP, PPTP), sonst Admin/Benutzer.
func fwSophos(vpn bool) func(*LogLine) (LogHit, bool) {
	return func(l *LogLine) (LogHit, bool) {
		m := l.Message
		if !strings.Contains(m, "src_ip=") {
			return LogHit{}, false
		}
		st, _ := fwKV(m, "status")
		msg, _ := fwKV(m, "message")
		failed := strings.EqualFold(st, "Failed") || fwIndexFold(msg, "login failed") >= 0 ||
			fwIndexFold(msg, "failed to login") >= 0 || fwIndexFold(m, "admin login failed") >= 0 ||
			fwIndexFold(m, "user login failed") >= 0
		if !failed {
			return LogHit{}, false
		}
		comp, _ := fwKV(m, "log_component")
		sub, _ := fwKV(m, "log_subtype")
		client, _ := fwKV(m, "auth_client")
		login := strings.EqualFold(sub, "Authentication") || strings.EqualFold(sub, "Admin") ||
			fwIndexFold(msg, "login") >= 0 || fwIndexFold(m, "login failed") >= 0
		if !login {
			return LogHit{}, false
		}
		isVPN := fwSophosVPN(comp) || fwSophosVPN(client) || fwSophosVPN(msg)
		if isVPN != vpn {
			return LogHit{}, false
		}
		v, _ := fwKV(m, "src_ip")
		ip, ok := fwParseIP(v)
		if !ok {
			return LogHit{}, false
		}
		h := LogHit{Src: ip}
		if p, ok := fwKVPort(m, "dst_port"); ok {
			h.Port = p
		} else if !vpn && strings.EqualFold(sub, "Admin") {
			h.Port = 4444 // WebAdmin
		}
		return h, true
	}
}

func fwSophosVPN(s string) bool {
	return fwIndexFold(s, "vpn") >= 0 || fwIndexFold(s, "ipsec") >= 0 || fwIndexFold(s, "l2tp") >= 0 ||
		fwIndexFold(s, "pptp") >= 0
}

// --- UniFi (dropbear) ---

func fwUniFiSSH(l *LogLine) (LogHit, bool) {
	m := l.Message
	i := strings.Index(m, "Bad password attempt for ")
	if i < 0 {
		i = strings.Index(m, "Login attempt for nonexistent user")
	}
	if i < 0 {
		return LogHit{}, false
	}
	m = m[i:]
	f := strings.LastIndex(m, " from ")
	if f < 0 {
		return LogHit{}, false
	}
	ip, ok := fwParseIPPort(fwWord(m[f+6:]))
	if !ok {
		return LogHit{}, false
	}
	return LogHit{Src: ip}, true
}

// fwParseIPPort liest "<adresse>:<port>" mit Pflicht-Port; dropbear schreibt IPv6 ohne Klammern ("2001:db8::7:52341"),
// deshalb wird der letzte Teil immer als Port genommen.
func fwParseIPPort(s string) (netip.Addr, bool) {
	s = strings.TrimRight(strings.Trim(s, "\"'<>()"), ".,;")
	if len(s) > 0 && s[0] == '[' {
		return fwParseIP(s)
	}
	i := strings.LastIndexByte(s, ':')
	if i <= 0 {
		return fwParseIP(s)
	}
	if _, ok := fwPort(s[i+1:]); !ok {
		return netip.Addr{}, false
	}
	return fwParseIP(s[:i])
}

// --- Hilfen (ohne Zuweisungen) ---

// fwWord liefert das erste Wort (bis Leerzeichen).
func fwWord(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

// fwParseIP liest eine Adresse, auch in Anfuehrungszeichen, mit Port ("1.2.3.4:22", "[2001:db8::1]:22"), Praefix
// oder Satzzeichen am Ende. Unspezifizierte Adressen gelten nicht.
func fwParseIP(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"'<>()")
	s = strings.TrimRight(s, ".,;")
	if s == "" || len(s) > 64 {
		return netip.Addr{}, false
	}
	if s[0] == '[' {
		if j := strings.IndexByte(s, ']'); j > 0 {
			s = s[1:j]
		}
	}
	if s, _, ok := strings.Cut(s, "/"); ok {
		return fwParseIP(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		// mit Port: "a.b.c.d:p"
		i := strings.LastIndexByte(s, ':')
		if i <= 0 {
			return netip.Addr{}, false
		}
		if _, ok := fwPort(s[i+1:]); !ok {
			return netip.Addr{}, false
		}
		if a, err = netip.ParseAddr(s[:i]); err != nil {
			return netip.Addr{}, false
		}
	}
	a = a.Unmap().WithZone("")
	if !a.IsValid() || a.IsUnspecified() {
		return netip.Addr{}, false
	}
	return a, true
}

// fwPort liest einen Port 1-65535.
func fwPort(s string) (int, bool) {
	if len(s) == 0 || len(s) > 5 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, n >= 1 && n <= 65535
}

func fwAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// fwKV liefert den Wert zu key in einer key=value-Zeile (Wert in Anfuehrungszeichen oder bis zum Leerzeichen).
func fwKV(m, key string) (string, bool) {
	off := 0
	for {
		i := strings.Index(m[off:], key)
		if i < 0 {
			return "", false
		}
		i += off
		j := i + len(key)
		off = j
		if j >= len(m) || m[j] != '=' || (i > 0 && m[i-1] != ' ' && m[i-1] != '\t' && m[i-1] != ',') {
			continue
		}
		v := m[j+1:]
		if len(v) > 0 && v[0] == '"' {
			if k := strings.IndexByte(v[1:], '"'); k >= 0 {
				return v[1 : k+1], true
			}
			return v[1:], true
		}
		return fwWord(v), true
	}
}

func fwKVPort(m, key string) (int, bool) {
	v, ok := fwKV(m, key)
	if !ok {
		return 0, false
	}
	return fwPort(v)
}

// fwIndexFold sucht sub (klein geschrieben, ASCII) ohne Beachtung der Gross-/Kleinschreibung.
func fwIndexFold(s, sub string) int {
	n := len(sub)
	if n == 0 {
		return 0
	}
	first := sub[0]
	for i := 0; i+n <= len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != first {
			continue
		}
		ok := true
		for k := 1; k < n; k++ {
			d := s[i+k]
			if d >= 'A' && d <= 'Z' {
				d += 'a' - 'A'
			}
			if d != sub[k] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

func fwHasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
