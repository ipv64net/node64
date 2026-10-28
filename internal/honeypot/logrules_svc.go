package honeypot

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Mitgelieferte Regeln fuer Dienste (Log-Sensor, Plan Abschnitt 1b): sshd, nginx/Apache/Caddy, Postfix, Dovecot,
// Proxmox, Nextcloud, Vaultwarden, Gitea/Forgejo, Home Assistant. Jede Regel prueft zuerst Programm bzw. Format,
// damit fremde Zeilen billig verworfen werden. Keine Regel gibt Benutzernamen, Pfade oder andere Inhalte weiter –
// ein Treffer traegt nur die IP (und hoechstens Port, Gewicht, Erfolg).
//
// Wo der Angreifer selbst Text in die Zeile bringt (Benutzername), wird die IP so gesucht, dass ein Name wie
// "x from 192.0.2.1" keine fremde IP unterschieben kann (letztes Vorkommen bzw. Gegenprobe).

const (
	logLoginThr = 5 // fehlgeschlagene Logins im Fenster (Vertipper legitimer Nutzer bleiben darunter)
	logLoginWin = 10 * time.Minute
)

func init() {
	RegisterLogRule(&LogRule{ID: "sshd/bruteforce", Version: 1, Kind: KindSSHBrute, Service: SvcSSH, Port: 22,
		Threshold: logLoginThr, Window: logLoginWin, Match: matchSSHD})
	for _, srv := range []string{"nginx", "apache", "caddy"} {
		registerWebRules(srv)
	}
	RegisterLogRule(&LogRule{ID: "postfix/sasl-bruteforce", Version: 1, Kind: KindMailBrute, Service: SvcSMTP, Port: 25,
		Threshold: logLoginThr, Window: logLoginWin, Match: matchPostfixSASL})
	RegisterLogRule(&LogRule{ID: "dovecot/imap-bruteforce", Version: 1, Kind: KindMailBrute, Service: SvcIMAP, Port: 143,
		Threshold: logLoginThr, Window: logLoginWin, Match: matchDovecot("imap")})
	RegisterLogRule(&LogRule{ID: "dovecot/pop3-bruteforce", Version: 1, Kind: KindMailBrute, Service: SvcPOP3, Port: 110,
		Threshold: logLoginThr, Window: logLoginWin, Match: matchDovecot("pop3")})
	RegisterLogRule(&LogRule{ID: "proxmox/bruteforce", Version: 1, Kind: KindHTTPBrute, Service: SvcHTTPS, Port: 8006,
		Threshold: logLoginThr, Window: logLoginWin, Match: matchProxmox})
	RegisterLogRule(&LogRule{ID: "nextcloud/bruteforce", Version: 1, Kind: KindHTTPBrute, Service: SvcHTTPS, Port: 443,
		Threshold: logLoginThr, Window: logLoginWin, Match: matchNextcloud})
	RegisterLogRule(&LogRule{ID: "vaultwarden/bruteforce", Version: 1, Kind: KindHTTPBrute, Service: SvcHTTPS, Port: 443,
		Threshold: logLoginThr, Window: logLoginWin, Match: matchVaultwarden})
	RegisterLogRule(&LogRule{ID: "gitea/bruteforce", Version: 1, Kind: KindHTTPBrute, Service: SvcHTTP, Port: 3000,
		Threshold: logLoginThr, Window: logLoginWin, Match: matchGitea})
	RegisterLogRule(&LogRule{ID: "homeassistant/bruteforce", Version: 1, Kind: KindHTTPBrute, Service: SvcHTTP, Port: 8123,
		Threshold: logLoginThr, Window: logLoginWin, Match: matchHomeAssistant})
}

// Hilfen.

// logAddr liest eine IP aus einem Token ("1.2.3.4", "1.2.3.4.", "[::1]:22", "::ffff:1.2.3.4", "1.2.3.4:5678").
func logAddr(s string) (netip.Addr, bool) {
	s = strings.TrimRight(s, ".,;)'\"")
	s = strings.TrimLeft(s, "('\"")
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return a.Unmap().WithZone(""), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	return netip.Addr{}, false
}

// logToken liefert s bis zum ersten Leerzeichen.
func logToken(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

// logHitAfterLast: IP im Token nach dem letzten sep (der Angreifer-Text steht davor).
func logHitAfterLast(m, sep string) (LogHit, bool) {
	i := strings.LastIndex(m, sep)
	if i < 0 {
		return LogHit{}, false
	}
	a, ok := logAddr(logToken(m[i+len(sep):]))
	return LogHit{Src: a}, ok
}

// logHitBeforeLast: IP im Token vor dem letzten sep ("... user root 1.2.3.4 port 22 [preauth]").
func logHitBeforeLast(m, sep string) (LogHit, bool) {
	i := strings.LastIndex(m, sep)
	if i <= 0 {
		return LogHit{}, false
	}
	j := strings.LastIndexByte(m[:i], ' ')
	a, ok := logAddr(m[j+1 : i])
	return LogHit{Src: a}, ok
}

// sshd (auth.log, secure, Journal per Syslog). OpenSSH ab 9.8 schreibt als "sshd-session".
//
// Gezaehlt wird je Versuch eine Zeile: "Failed password|keyboard-interactive", "Invalid user", "maximum
// authentication attempts exceeded" und das Ende einer Verbindung ohne Login ("Disconnected from|Connection closed by
// authenticating|invalid user ... [preauth]"). Die Zeilen von pam_unix ("authentication failure; ... rhost=") und
// "error: PAM: Authentication failure" zaehlen bewusst nicht: sie stehen bei sshd immer zusaetzlich zu "Failed ..."
// und wuerden jeden Vertipper doppelt zaehlen. "Accepted ..." setzt den Zaehler der IP zurueck.
func matchSSHD(l *LogLine) (LogHit, bool) {
	if !strings.HasPrefix(l.Program, "sshd") {
		return LogHit{}, false
	}
	m := l.Message
	switch {
	case strings.HasPrefix(m, "Accepted "):
		h, ok := logHitAfterLast(m, " from ")
		h.Success = true
		return h, ok
	case strings.HasPrefix(m, "Failed password for "), strings.HasPrefix(m, "Failed keyboard-interactive"),
		strings.HasPrefix(m, "Failed challenge-response"), strings.HasPrefix(m, "Invalid user "):
		return logHitAfterLast(m, " from ")
	case strings.HasPrefix(m, "error: maximum authentication attempts exceeded for "),
		strings.HasPrefix(m, "maximum authentication attempts exceeded for "):
		// nur am Anfang: "Received disconnect from ...: <Text des Clients>" darf keine IP unterschieben
		return logHitAfterLast(m, " from ")
	case strings.HasSuffix(m, "[preauth]") && (strings.HasPrefix(m, "Disconnected from authenticating user ") ||
		strings.HasPrefix(m, "Connection closed by authenticating user ") ||
		strings.HasPrefix(m, "Disconnected from invalid user ") || strings.HasPrefix(m, "Connection closed by invalid user ")):
		return logHitBeforeLast(m, " port ")
	}
	return LogHit{}, false
}

// Webserver (nginx/Apache combined, Caddy JSON).

// webReq ist eine zerlegte Zugriffszeile. Alles Weitere (OWASP-Kategorie, Exploit-Pfad, Scanner) wird einmal je
// Zeile berechnet und von allen Web-Regeln geteilt.
type webReq struct {
	src    netip.Addr
	method string
	path   string // dekodiert, klein, ohne Abfrage
	status int
	tls    bool
	cat    int // erste OWASP-Kategorie (Index in sensorOWASP), -1 = keine
	expl   int // Exploit-Pfad: 0 = keiner, 1 = kommt auch harmlos vor (zaehlt nur ohne Erfolg), 2 = eindeutig
	badUA  bool
}

// webStrongPaths sind Exploit-Pfade, die auf einem echten Server nie harmlos aufgerufen werden (zaehlen sofort, auch
// mit Status 200). Die uebrigen aus sensorExploitPaths (z. B. /wp-content/plugins/, /xmlrpc.php, /cgi-bin/,
// /server-status) zaehlen nur, wenn der Server sie nicht ausliefert (Status >= 400).
var webStrongPaths = map[string]bool{
	"/.env": true, "/.git/": true, "/.git/config": true, "/.aws/": true, "/.ssh/": true, "/.svn/": true, "/.hg/": true,
	"/.htpasswd": true, "/.vscode/": true, "/.docker": true, "wp-config.php": true, "/boaform/": true, "/hnap1": true,
	"/vendor/phpunit/": true, "eval-stdin.php": true, "/remote/fgt_lang": true, "/setup.cgi": true, "/goform/": true,
	"/gponform/": true, "/tmui/": true, "/_ignition/": true, "/developmentserver/metadatauploader": true,
	"/php-cgi/": true, "/shell?": true, "/device.rsp": true,
}

// webLogins sind bekannte Login-Pfade: POST mit einem Status aus fail zaehlt als Fehlversuch, aus ok als Erfolg.
var webLogins = []struct {
	path     string
	fail, ok []int
}{
	{"/wp-login.php", []int{200, 401, 403}, []int{302}},
	{"/xmlrpc.php", []int{200, 401, 403}, nil},
	{"/administrator/index.php", []int{200, 401, 403}, []int{303}},
	{"/administrator", []int{200, 401, 403}, []int{303}},
	{"/user/login", []int{200, 401, 403}, []int{302, 303}},
	{"/login", []int{401, 403}, nil},
	{"/signin", []int{401, 403}, nil},
	{"/admin/login", []int{401, 403}, nil},
	{"/auth/login", []int{401, 403}, nil},
	{"/api/login", []int{401, 403}, nil},
	{"/api/auth/login", []int{401, 403}, nil},
}

// webCache haelt die zuletzt zerlegte Zeile: alle Web-Regeln einer Zeile zerlegen so nur einmal.
var webCache struct {
	sync.Mutex
	msg, format string
	r           webReq
	ok          bool
}

func webParse(l *LogLine) (webReq, bool) {
	webCache.Lock()
	if webCache.msg == l.Message && webCache.format == l.Format && webCache.msg != "" {
		r, ok := webCache.r, webCache.ok
		webCache.Unlock()
		return r, ok
	}
	webCache.Unlock()
	var r webReq
	var target, ua string
	var ok bool
	if l.Format == "caddy" {
		r, target, ua, ok = webParseCaddy(l.Message)
	} else {
		r, target, ua, ok = webParseCombined(l.Message)
	}
	if ok {
		webClassify(&r, target, ua)
	}
	webCache.Lock()
	webCache.msg, webCache.format, webCache.r, webCache.ok = l.Message, l.Format, r, ok
	webCache.Unlock()
	return r, ok
}

// webParseCombined zerlegt `1.2.3.4 - - [20/Oct/2026:12:00:01 +0200] "GET /x HTTP/1.1" 404 153 "ref" "UA"`.
func webParseCombined(s string) (r webReq, target, ua string, ok bool) {
	i := strings.IndexByte(s, ' ')
	if i <= 0 {
		return
	}
	a, good := logAddr(s[:i])
	if !good {
		return
	}
	r.src = a
	req, rest, good := webQuoted(s[i:])
	if !good {
		return
	}
	r.method, target = webSplitRequest(req)
	rest = strings.TrimLeft(rest, " ")
	r.status = webAtoi(logToken(rest))
	if _, rest, good = webQuoted(rest); good { // Referer
		ua, _, _ = webQuoted(rest)
	}
	return r, target, ua, true
}

// webQuoted liefert den Inhalt des naechsten "..." (\" zaehlt nicht als Ende) und den Rest dahinter.
func webQuoted(s string) (in, rest string, ok bool) {
	i := strings.IndexByte(s, '"')
	if i < 0 {
		return "", s, false
	}
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return s[i+1 : j], s[j+1:], true
		}
	}
	return "", s, false
}

// webSplitRequest trennt "GET /x HTTP/1.1" in Methode und Ziel (ohne Leerzeichen: alles Ziel).
func webSplitRequest(req string) (method, target string) {
	i := strings.IndexByte(req, ' ')
	if i < 0 {
		return "", req
	}
	method, target = req[:i], req[i+1:]
	if j := strings.LastIndex(target, " HTTP/"); j >= 0 {
		target = target[:j]
	}
	return method, target
}

func webAtoi(s string) int {
	if len(s) == 0 || len(s) > 3 {
		return 0
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// caddyLine ist der Teil einer Caddy-Zugriffszeile (JSON), den die Regeln brauchen.
type caddyLine struct {
	Request struct {
		RemoteIP string `json:"remote_ip"`
		ClientIP string `json:"client_ip"`
		Method   string `json:"method"`
		URI      string `json:"uri"`
		Headers  struct {
			UA []string `json:"User-Agent"`
		} `json:"headers"`
		TLS json.RawMessage `json:"tls"`
	} `json:"request"`
	Status int `json:"status"`
}

func webParseCaddy(s string) (r webReq, target, ua string, ok bool) {
	if !strings.HasPrefix(s, "{") || !strings.Contains(s, `"request"`) {
		return
	}
	var c caddyLine
	if json.Unmarshal([]byte(s), &c) != nil {
		return
	}
	ip := c.Request.ClientIP // hinter vertrauenswuerdigen Proxys die echte Quelle
	if ip == "" {
		ip = c.Request.RemoteIP
	}
	a, good := logAddr(ip)
	if !good {
		return
	}
	r.src, r.method, r.status = a, c.Request.Method, c.Status
	r.tls = len(c.Request.TLS) > 0 && string(c.Request.TLS) != "null"
	if len(c.Request.Headers.UA) > 0 {
		ua = c.Request.Headers.UA[0]
	}
	return r, c.Request.URI, ua, true
}

// webClassify ordnet die Anfrage wie die Koeder ein (sensor_classify.go): OWASP-Muster im dekodierten Ziel (JNDI auch
// im User-Agent), Exploit-Pfade, Scanner-User-Agents.
func webClassify(r *webReq, target, ua string) {
	dt := sensorUnescape(sensorUnescape(target))
	lua := strings.ToLower(ua)
	r.cat = -1
	for k, o := range sensorOWASP {
		if o.re.MatchString(dt) || (o.kind == KindHTTPJNDI && ua != "" && o.re.MatchString(ua)) {
			r.cat = k
			break
		}
	}
	p := strings.ToLower(dt)
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	r.path = p
	for _, x := range sensorExploitPaths {
		if strings.Contains(p, x) {
			r.expl = 1
			if webStrongPaths[x] {
				r.expl = 2
			}
			break
		}
	}
	r.badUA = sensorMatch(lua, sensorBadUAs) != ""
}

// webSofort sind OWASP-Kategorien, die schon mit einem Treffer melden (eindeutig, kaum Fehlalarme); die uebrigen
// (SQLi, XSS, SSRF) koennen in harmlosen Suchbegriffen oder Weiterleitungen auftauchen und brauchen mehrere Treffer.
var webSofort = map[string]bool{KindHTTPJNDI: true, KindHTTPRCE: true, KindHTTPUpload: true, KindHTTPTrav: true}

// registerWebRules meldet die Regeln eines Webservers an (Format srv der Zeile).
func registerWebRules(srv string) {
	const exThr = 3
	reg := func(scen, kind string, thr int, win time.Duration, f func(r *webReq) (LogHit, bool)) {
		RegisterLogRule(&LogRule{ID: srv + "/" + scen, Version: 1, Kind: kind, Service: SvcHTTP, Port: 80,
			Threshold: thr, Window: win, Match: webMatch(srv, f)})
	}
	reg("exploit", KindHTTPExploit, exThr, 10*time.Minute, func(r *webReq) (LogHit, bool) {
		switch {
		case r.cat >= 0:
			return LogHit{}, false // genauer eingeordnet (eigene Regel)
		case r.expl == 2:
			return LogHit{Weight: exThr}, true
		case r.expl == 1 && r.status >= 400:
			return LogHit{}, true
		}
		return LogHit{}, false
	})
	for k, o := range sensorOWASP {
		thr := exThr
		if webSofort[o.kind] {
			thr = 1
		}
		reg("exploit-"+o.tag, o.kind, thr, 10*time.Minute, func(r *webReq) (LogHit, bool) {
			return LogHit{}, r.cat == k
		})
	}
	reg("scan", KindHTTPScan, 30, time.Minute, func(r *webReq) (LogHit, bool) {
		return LogHit{}, r.status == 404
	})
	reg("bruteforce", KindHTTPBrute, 10, 5*time.Minute, webMatchLogin)
	reg("bad-useragent", KindBadUA, exThr, 10*time.Minute, func(r *webReq) (LogHit, bool) {
		return LogHit{}, r.badUA // nur die Art; der User-Agent selbst geht nicht ins Ereignis
	})
}

// webMatch prueft zuerst das Format, zerlegt dann (geteilt) und setzt Quelle und Port.
func webMatch(srv string, f func(r *webReq) (LogHit, bool)) func(l *LogLine) (LogHit, bool) {
	return func(l *LogLine) (LogHit, bool) {
		if l.Format != srv {
			return LogHit{}, false
		}
		r, ok := webParse(l)
		if !ok {
			return LogHit{}, false
		}
		h, ok := f(&r)
		if !ok {
			return LogHit{}, false
		}
		h.Src = r.src
		if r.tls {
			h.Port = 443
		}
		return h, true
	}
}

func webMatchLogin(r *webReq) (LogHit, bool) {
	if r.method != "POST" {
		return LogHit{}, false
	}
	p := strings.TrimSuffix(r.path, "/")
	for _, x := range webLogins {
		if p != x.path {
			continue
		}
		if webIn(r.status, x.ok) {
			return LogHit{Success: true}, true
		}
		return LogHit{}, webIn(r.status, x.fail)
	}
	return LogHit{}, false
}

func webIn(v int, list []int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Mail.

// matchPostfixSASL: "warning: unknown[1.2.3.4]: SASL LOGIN authentication failed: ..." (smtpd, submission, smtps);
// "client=host[1.2.3.4], sasl_method=PLAIN, ..." ist ein Erfolg.
func matchPostfixSASL(l *LogLine) (LogHit, bool) {
	if !strings.HasPrefix(l.Program, "postfix") {
		return LogHit{}, false
	}
	// Nur an fester Stelle: "warning: <host>[<ip>]: SASL ..." bzw. "<queue-id>: client=<host>[<ip>], sasl_method=...";
	// Text des Clients (HELO, Absender, Benutzername) steht immer dahinter und waehlt so keine IP aus.
	m := l.Message
	var h LogHit
	if rest, ok := strings.CutPrefix(m, "warning: "); ok {
		tok := logToken(rest) // "<host>[<ip>]:"
		j := strings.IndexByte(tok, '[')
		if j < 0 || !strings.HasSuffix(tok, "]:") || !strings.HasPrefix(rest[len(tok):], " SASL ") ||
			!strings.Contains(rest[len(tok):], " authentication failed") {
			return LogHit{}, false
		}
		a, ok := logAddr(tok[j+1 : len(tok)-2])
		if !ok {
			return LogHit{}, false
		}
		h.Src = a
	} else if id := logToken(m); strings.HasSuffix(id, ":") && strings.HasPrefix(m[len(id):], " client=") {
		tok := logToken(m[len(id)+len(" client="):]) // "<host>[<ip>],"
		j := strings.IndexByte(tok, '[')
		if j < 0 || !strings.HasSuffix(tok, "],") || !strings.HasPrefix(m[len(id)+len(" client=")+len(tok):], " sasl_method=") {
			return LogHit{}, false
		}
		a, ok := logAddr(tok[j+1 : len(tok)-2])
		if !ok {
			return LogHit{}, false
		}
		h.Src, h.Success = a, true
	} else {
		return LogHit{}, false
	}
	switch {
	case strings.Contains(l.Program, "submission"):
		h.Port = 587
	case strings.Contains(l.Program, "smtps"):
		h.Port = 465
	}
	return h, true
}

// matchDovecot: "imap-login: Disconnected (auth failed, 3 attempts in 15 secs): user=<x>, method=PLAIN, rip=1.2.3.4,
// lip=..." (zaehlt so oft wie Versuche genannt), "imap-login: Login: user=<x>, ..., rip=..." ist ein Erfolg.
func matchDovecot(proto string) func(l *LogLine) (LogHit, bool) {
	prefix := proto + "-login: "
	return func(l *LogLine) (LogHit, bool) {
		m := l.Message
		switch l.Program {
		case "dovecot":
			if !strings.HasPrefix(m, prefix) {
				return LogHit{}, false
			}
			m = m[len(prefix):]
		case proto + "-login":
		default:
			return LogHit{}, false
		}
		m = strings.TrimPrefix(m, "Info: ")
		var h LogHit
		switch {
		case strings.HasPrefix(m, "Login: "):
			h.Success = true
		case strings.Contains(m, "(auth failed, "):
			h.Weight = dovecotAttempts(m)
		default:
			return LogHit{}, false
		}
		i := strings.LastIndex(m, "rip=") // Benutzername steht davor
		if i < 0 {
			return LogHit{}, false
		}
		rest := m[i+4:]
		if j := strings.IndexByte(rest, ','); j >= 0 {
			rest = rest[:j]
		}
		a, ok := logAddr(rest)
		h.Src = a
		return h, ok
	}
}

// dovecotAttempts liest N aus "(auth failed, N attempts" (sonst 1).
func dovecotAttempts(m string) int {
	i := strings.Index(m, "(auth failed, ")
	if i < 0 {
		return 1
	}
	n := 0
	for _, c := range []byte(m[i+len("(auth failed, "):]) {
		if c < '0' || c > '9' || n > 1000 {
			break
		}
		n = n*10 + int(c-'0')
	}
	return max(n, 1)
}

// Anwendungen.

// matchProxmox: pvedaemon "authentication failure; rhost=::ffff:1.2.3.4 user=root@pam msg=...".
func matchProxmox(l *LogLine) (LogHit, bool) {
	if l.Program != "pvedaemon" && l.Program != "pveproxy" {
		return LogHit{}, false
	}
	const p = "authentication failure; rhost="
	if !strings.HasPrefix(l.Message, p) {
		return LogHit{}, false
	}
	a, ok := logAddr(logToken(l.Message[len(p):]))
	return LogHit{Src: a}, ok
}

// matchNextcloud: JSON-Zeile mit "message":"Login failed: ..." und "remoteAddr".
func matchNextcloud(l *LogLine) (LogHit, bool) {
	if l.Format != "nextcloud" || !strings.Contains(l.Message, "Login failed") {
		return LogHit{}, false
	}
	var v struct {
		RemoteAddr string          `json:"remoteAddr"`
		Message    json.RawMessage `json:"message"`
	}
	if json.Unmarshal([]byte(l.Message), &v) != nil || !bytes.HasPrefix(bytes.TrimLeft(v.Message, `"`), []byte("Login failed")) {
		return LogHit{}, false
	}
	a, ok := logAddr(v.RemoteAddr)
	return LogHit{Src: a}, ok
}

// vaultwardenMarks: Fehlversuche (danach folgt "IP: <ip>." und erst dann der Benutzername).
var vaultwardenMarks = []string{"Username or password is incorrect. Try again. IP: ", "Invalid admin token. IP: "}

// matchVaultwarden: "[...][vaultwarden::api::identity][ERROR] Username or password is incorrect. Try again. IP:
// 1.2.3.4. Username: x." (eigene Datei oder per Syslog mit Programm vaultwarden).
func matchVaultwarden(l *LogLine) (LogHit, bool) {
	if l.Format != "vaultwarden" && !strings.Contains(l.Program, "vaultwarden") && !strings.Contains(l.Program, "bitwarden") {
		return LogHit{}, false
	}
	for _, mk := range vaultwardenMarks {
		if i := strings.Index(l.Message, mk); i >= 0 {
			a, ok := logAddr(logToken(l.Message[i+len(mk):]))
			return LogHit{Src: a}, ok
		}
	}
	return LogHit{}, false
}

// matchGitea: "... [I] Failed authentication attempt for <name> from 1.2.3.4:5678: user does not exist [uid: 0,
// name: <name>]" (Gitea und Forgejo). Der Name kommt vom Angreifer und steht zweimal in der Zeile: die Trennstelle
// " from " gilt nur, wenn der Name davor auch am Ende steht; ohne Namen am Ende nur bei genau einem " from ".
func matchGitea(l *LogLine) (LogHit, bool) {
	if l.Format != "gitea" && !strings.HasPrefix(l.Program, "gitea") && !strings.HasPrefix(l.Program, "forgejo") {
		return LogHit{}, false
	}
	const mk = "Failed authentication attempt for "
	i := strings.Index(l.Message, mk)
	if i < 0 {
		return LogHit{}, false
	}
	m := l.Message[i+len(mk):]
	named := strings.HasSuffix(m, "]") && strings.Contains(m, "name: ")
	if !named && strings.Count(m, " from ") != 1 {
		return LogHit{}, false
	}
	for off := 0; ; {
		j := strings.Index(m[off:], " from ")
		if j < 0 {
			return LogHit{}, false
		}
		j += off
		if !named || strings.HasSuffix(m, "name: "+m[:j]+"]") {
			tok := strings.TrimSuffix(logToken(m[j+6:]), ":")
			a, ok := logAddr(tok)
			return LogHit{Src: a}, ok
		}
		off = j + 1
	}
}

// matchHomeAssistant: "Login attempt or request with invalid authentication from host (1.2.3.4). Requested URL:
// ..." bzw. aelter "... from 1.2.3.4".
func matchHomeAssistant(l *LogLine) (LogHit, bool) {
	if l.Format != "homeassistant" {
		return LogHit{}, false
	}
	const mk = "Login attempt or request with invalid authentication from "
	i := strings.Index(l.Message, mk)
	if i < 0 {
		return LogHit{}, false
	}
	rest := l.Message[i+len(mk):]
	host := logToken(rest)
	if strings.HasPrefix(rest[len(host):], " (") { // "host (ip)"
		in := rest[len(host)+2:]
		if j := strings.IndexByte(in, ')'); j > 0 {
			a, ok := logAddr(in[:j])
			return LogHit{Src: a}, ok
		}
		return LogHit{}, false
	}
	a, ok := logAddr(host)
	return LogHit{Src: a}, ok
}
