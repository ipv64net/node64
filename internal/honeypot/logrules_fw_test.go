package honeypot

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fwRuleIDs sind die Regeln dieser Datei (andere Regeln des Pakets bleiben bei den Tests aussen vor).
func fwRules(t *testing.T) []*LogRule {
	t.Helper()
	var out []*LogRule
	for _, r := range LogRules() {
		for _, p := range []string{"mikrotik/", "opnsense/", "pfsense/", "fortigate/", "sophos/", "unifi/"} {
			if strings.HasPrefix(r.ID, p) {
				out = append(out, r)
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("keine Firewall-Regeln angemeldet")
	}
	return out
}

func fwRuleByID(t *testing.T, id string) *LogRule {
	t.Helper()
	for _, r := range fwRules(t) {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("Regel %s fehlt", id)
	return nil
}

// fwApply zerlegt eine Syslog-Zeile und liefert alle Treffer der Firewall-Regeln (ID -> Treffer).
func fwApply(t *testing.T, raw string, now time.Time) map[string]LogHit {
	t.Helper()
	l := ParseSyslog([]byte(raw), netip.MustParseAddr("192.168.1.1"), now)
	out := map[string]LogHit{}
	for _, r := range fwRules(t) {
		if h, ok := r.Match(&l); ok {
			out[r.ID] = h
		}
	}
	return out
}

func TestFwRulesMeta(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range fwRules(t) {
		if seen[r.ID] {
			t.Errorf("%s doppelt", r.ID)
		}
		seen[r.ID] = true
		if r.Version != 1 || r.Threshold < 1 || r.Window <= 0 || r.Kind == "" || r.Service == "" || r.Match == nil || len(r.Origins) == 0 {
			t.Errorf("%s unvollstaendig: %+v", r.ID, r)
		}
		for _, o := range r.Origins {
			if o != SrcSyslog && o != SrcLog {
				t.Errorf("%s: Quelle %q", r.ID, o)
			}
		}
		if r.Tag() != r.ID+"@1" {
			t.Errorf("Tag %s", r.Tag())
		}
	}
	// Treffer enthalten nie Inhalte (nur Adresse, Port, Erfolg, Gewicht)
	ht := reflect.TypeOf(LogHit{})
	for i := 0; i < ht.NumField(); i++ {
		if k := ht.Field(i).Type.Kind(); k == reflect.String || k == reflect.Slice {
			t.Errorf("LogHit.%s kann Inhalte tragen", ht.Field(i).Name)
		}
	}
}

func TestFwRulesPositive(t *testing.T) {
	now := time.Now()
	cases := []struct {
		line string
		rule string
		ip   string
		port int
	}{
		// MikroTik
		{"<134>Oct 11 22:14:15 MikroTik system,error,critical login failure for user admin from 198.51.100.7 via ssh", "mikrotik/login-ssh", "198.51.100.7", 22},
		{"<134>system,error,critical login failure for user admin from 198.51.100.8 via web", "mikrotik/login-web", "198.51.100.8", 443},
		{"<134>system,error,critical login failure for user admin from 198.51.100.9 via telnet", "mikrotik/login-telnet", "198.51.100.9", 23},
		{"<134>system,error,critical login failure for user admin from 203.0.113.9 via winbox", "mikrotik/login", "203.0.113.9", 8291},
		{"<134>system,error,critical login failure for user admin from 203.0.113.10 via api", "mikrotik/login", "203.0.113.10", 8728},
		{"<134>system,error,critical login failure for user admin from 203.0.113.11 via ftp", "mikrotik/login", "203.0.113.11", 21},
		{"<134>system,error,critical login failure for user a from b from 2001:db8::5 via ssh", "mikrotik/login-ssh", "2001:db8::5", 22},
		// OPNsense / pfSense Weboberflaeche
		{`<37>1 2026-10-11T22:14:15+02:00 OPNsense.localdomain audit 81234 - [meta sequenceId="12"] /index.php: Web GUI authentication error for user 'root' from 198.51.100.11`, "opnsense/login", "198.51.100.11", 0},
		{"<37>Oct 11 22:14:15 opnsense webgui[1]: webgui authentication error for user 'root' from: 198.51.100.12", "opnsense/login", "198.51.100.12", 0},
		{"<43>Oct 11 22:14:15 php-fpm[12345]: /index.php: webConfigurator authentication error for user 'admin' from: 203.0.113.5", "pfsense/login", "203.0.113.5", 0},
		{"<43>php-fpm[12345]: /index.php: webConfigurator authentication error for user 'admin' from: 2001:db8::6", "pfsense/login", "2001:db8::6", 0},
		// FortiGate
		{`<185>date=2026-10-11 time=22:14:15 devname="FGT60F" devid="FGT60FTK00000000" eventtime=1760213655000000000 tz="+0200" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" sn="0" user="admin" ui="https(198.51.100.20)" method="https" srcip=198.51.100.20 dstip=192.0.2.1 action="login" status="failed" reason="passwd_invalid" msg="Administrator admin login failed from https(198.51.100.20) because of invalid password"`, "fortigate/admin-login", "198.51.100.20", 0},
		{`<185>date=2026-10-11 time=22:14:15 devname="FGT60F" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" user="admin" ui="ssh(198.51.100.21)" method="ssh" srcip=198.51.100.21 dstip=192.0.2.1 dstport=22 action="login" status="failed"`, "fortigate/admin-ssh", "198.51.100.21", 22},
		{`<189>date=2026-10-11 time=22:14:15 devname="FGT60F" logid="0101039426" type="event" subtype="vpn" level="alert" vd="root" logdesc="SSL VPN login fail" action="ssl-login-fail" tunneltype="ssl-web" tunnelid=0 remip=203.0.113.44 user="x" group="N/A" dst_host="N/A" reason="sslvpn_login_unknown_user" msg="SSL user failed to logged in"`, "fortigate/vpn", "203.0.113.44", 0},
		{`<187>date=2026-10-11 time=22:14:15 devname="FGT60F" logid="0101037124" type="event" subtype="vpn" level="error" vd="root" logdesc="IPsec phase 1 error" msg="IPsec phase 1 error" action="negotiate" remip=203.0.113.50 locip=192.0.2.1 remport=500 locport=500 outintf="wan1" status="negotiate_error" reason="peer SA proposal not match local policy"`, "fortigate/ipsec", "203.0.113.50", 500},
		{`<187>date=2026-10-11 time=22:14:15 logdesc="IPsec phase 1 error" action="negotiate" remip=2001:db8::50 locport=4500 status="negotiate_error"`, "fortigate/ipsec", "2001:db8::50", 4500},
		// Sophos Firewall
		{`<30>device="SFW" date=2026-10-11 time=22:14:15 timezone="CEST" device_name="XGS2100" device_id=X000000000 log_id=062910617701 log_type="Event" log_component="GUI" log_subtype="Admin" status="Failed" priority=Notice user_name="admin" src_ip=198.51.100.30 message="Admin login failed"`, "sophos/login", "198.51.100.30", 4444},
		{`<30>device="SFW" log_type="Event" log_component="Firewall Authentication" log_subtype="Authentication" status="Failed" user_name="x" auth_client="User Portal" src_ip=198.51.100.31 message="User x failed to login to User Portal through Local authentication mechanism"`, "sophos/login", "198.51.100.31", 0},
		{`<30>device="SFW" log_type="Event" log_component="SSL VPN Authentication" log_subtype="Authentication" status="Failed" user_name="x" src_ip=203.0.113.30 message="User x failed to login to SSL VPN through Local authentication mechanism"`, "sophos/vpn", "203.0.113.30", 0},
		{`<30>device_name="SFW" timestamp="2026-10-11T22:14:15+0200" log_type="Event" log_component="IPsec" log_subtype="Authentication" status="Failed" src_ip="2001:db8::31" dst_port=500 message="VPN login failed"`, "sophos/vpn", "2001:db8::31", 500},
		// UniFi (dropbear)
		{"<38>Oct 11 22:14:15 U7PG2,f09fc2000000,v6.5.28.14491 dropbear[1234]: Bad password attempt for 'ubnt' from 198.51.100.40:52341", "unifi/ssh", "198.51.100.40", 0},
		{"<38>Oct 11 22:14:15 UAP dropbear[1234]: Login attempt for nonexistent user from 2001:db8::40:52341", "unifi/ssh", "2001:db8::40", 0},
		{"<38>dropbear[1]: Login attempt for nonexistent user from [2001:db8::41]:2222", "unifi/ssh", "2001:db8::41", 0},
	}
	for _, c := range cases {
		hits := fwApply(t, c.line, now)
		if len(hits) != 1 {
			t.Errorf("%s: %d Treffer %v, want genau %s", c.rule, len(hits), hits, c.rule)
			continue
		}
		h, ok := hits[c.rule]
		if !ok {
			t.Errorf("%s: falsche Regel %v", c.rule, hits)
			continue
		}
		if h.Src != netip.MustParseAddr(c.ip) || h.Port != c.port || h.Success || h.Weight != 0 {
			t.Errorf("%s: Treffer %+v, want %s port %d", c.rule, h, c.ip, c.port)
		}
	}
}

func TestFwRulesNegative(t *testing.T) {
	now := time.Now()
	for _, line := range []string{
		"<134>system,info,account user admin logged in from 198.51.100.7 via ssh",
		"<134>system,error,critical login failure for user admin from 00:0C:42:11:22:33 via mac-winbox",
		"<134>system,error,critical login failure for user admin from 198.51.100.7 via local",
		"<134>system,error,critical login failure for user admin from 0.0.0.0 via ssh",
		"<134>system,error,critical login failure for user admin from kaputt via ssh",
		"<43>php-fpm[1]: /index.php: Successful login for user 'admin' from: 203.0.113.5 (Local Database)",
		"<37>1 - OPNsense audit 1 - - /index.php: Web GUI authentication error for user 'root' from",
		`<185>date=2026-10-11 logid="0100032001" logdesc="Admin login successful" srcip=198.51.100.20 method="https" status="success"`,
		`<189>date=2026-10-11 logdesc="SSL VPN tunnel up" action="tunnel-up" remip=203.0.113.44 reason="tunnel established"`,
		`<187>date=2026-10-11 logdesc="IPsec phase 1 status" action="negotiate" remip=203.0.113.50 status="success"`,
		`<30>device="SFW" log_type="Event" log_component="GUI" log_subtype="Admin" status="Successful" src_ip=198.51.100.30 message="User admin logged in"`,
		`<30>device="SFW" log_type="Firewall" log_component="Firewall Rule" status="Deny" src_ip=198.51.100.30 message=""`,
		"<38>dropbear[1]: Password auth succeeded for 'ubnt' from 198.51.100.40:52341",
		"<13>sshd[1]: Failed password for root from 198.51.100.50 port 22 ssh2", // sshd: allgemeine Regel
		"",
		"<13>",
		"srcip= remip= src_ip= login failure for user  from  via ",
		// Angreifer-Text in fremden Zeilen (User-Agent eines Webservers per Syslog, Disconnect-Text) waehlt keine IP
		`<190>Oct 11 22:14:15 web nginx: 203.0.113.1 - - [11/Oct/2026:22:14:15 +0200] "GET / HTTP/1.1" 200 1 "-" "x Web GUI authentication error for user 'x' from 9.9.9.9"`,
		`<190>Oct 11 22:14:15 web nginx: 203.0.113.1 - - [11/Oct/2026:22:14:15 +0200] "GET / HTTP/1.1" 200 1 "-" "/index.php: webConfigurator authentication error for user 'x' from: 9.9.9.9"`,
		`<190>Oct 11 22:14:15 web nginx: 203.0.113.1 - - [11/Oct/2026:22:14:15 +0200] "GET / HTTP/1.1" 200 1 "-" "login failure for user a from 9.9.9.9 via ssh`,
		`<190>Oct 11 22:14:15 web nginx: 203.0.113.1 - - "-" logdesc="Admin login failed" srcip=9.9.9.9 method="https"`,
		`<190>Oct 11 22:14:15 web nginx: 203.0.113.1 - - "-" action="ssl-login-fail" remip=9.9.9.9`,
		`<190>Oct 11 22:14:15 web nginx: 203.0.113.1 - - "-" status="Failed" message="Admin login failed" log_subtype="Admin" src_ip=9.9.9.9`,
		"<38>Oct 11 22:14:15 web nginx: Bad password attempt for 'x' from 9.9.9.9:22",
		"<38>Oct 11 22:14:15 UAP dropbear[1234]: Exit before auth: Bad password attempt for 'ubnt' from 9.9.9.9:52341",
		"<134>Oct 11 22:14:15 MikroTik web proxy: login failure for user admin from 9.9.9.9 via ssh",
	} {
		if hits := fwApply(t, line, now); len(hits) != 0 {
			t.Errorf("%q: unerwartete Treffer %v", line, hits)
		}
	}
}

// Angreifer-Text in Werten (Benutzername) und Zeilen aus Webserver-Logs bzw. von PROXY64 waehlen keine IP.
func TestFwRulesInjection(t *testing.T) {
	now := time.Now()
	for _, c := range []struct{ line, rule, ip string }{
		{`<185>date=2026-10-11 logid="0100032002" logdesc="Admin login failed" user="x srcip=9.9.9.9 y" ui="https(198.51.100.20)" method="https" srcip=198.51.100.20 status="failed"`, "fortigate/admin-login", "198.51.100.20"},
		{`<185>date=2026-10-11 user="a\" srcip=9.9.9.9 \"" logdesc="Admin login failed" method="https" srcip=198.51.100.21`, "fortigate/admin-login", "198.51.100.21"},
		{`<30>device="SFW" log_component="GUI" log_subtype="Admin" status="Failed" user_name="x src_ip=9.9.9.9" src_ip=198.51.100.30 message="Admin login failed"`, "sophos/login", "198.51.100.30"},
		{"<43>Oct 11 22:14:15 fw php-fpm[1]: /index.php: webConfigurator authentication error for user 'x from: 9.9.9.9' from: 203.0.113.5", "pfsense/login", "203.0.113.5"},
		{"<38>Oct 11 22:14:15 UAP dropbear[1]: Bad password attempt for 'x from 9.9.9.9:1' from 198.51.100.40:52341", "unifi/ssh", "198.51.100.40"},
	} {
		hits := fwApply(t, c.line, now)
		if h, ok := hits[c.rule]; len(hits) != 1 || !ok || h.Src != netip.MustParseAddr(c.ip) {
			t.Errorf("%s: %v, want %s", c.rule, hits, c.ip)
		}
	}
	// Webserver-Log bzw. PROXY64 (kein Syslog-Format): nie, auch wenn die Nachricht wie eine Firewall-Zeile aussieht
	for _, format := range []string{"nginx", "caddy", "proxy64", ""} {
		for _, msg := range []string{
			"Web GUI authentication error for user 'x' from 9.9.9.9",
			"login failure for user a from 9.9.9.9 via ssh",
			`date=2026-10-11 logdesc="Admin login failed" method="https" srcip=9.9.9.9`,
		} {
			l := LogLine{Time: now, Origin: SrcLog, File: format, Format: format, Program: "dropbear", Message: msg}
			for _, r := range fwRules(t) {
				if _, ok := r.Match(&l); ok {
					t.Errorf("%s/%q: Treffer %s", format, msg, r.ID)
				}
			}
		}
	}
	// fwKV: Schluessel nur ausserhalb von Anfuehrungszeichen
	for _, c := range []struct{ m, want string }{
		{`a="srcip=1" srcip=2`, "2"},
		{`a="x\" srcip=1" srcip=2`, "2"},
		{`a=b,srcip="3" c=1`, "3"},
		{`"srcip=1"`, ""},
		{`=x srcip=4`, "4"},
		{`a="unclosed srcip=1`, ""},
	} {
		if v, _ := fwKV(c.m, "srcip"); v != c.want {
			t.Errorf("fwKV(%q) = %q, want %q", c.m, v, c.want)
		}
	}
}

// filterlog-Zeilen (IPv4/IPv6, pfSense mit numerischem Tracker, OPNsense mit Label).
func fwPf4(src string, dport int) string {
	return fmt.Sprintf("<134>Oct 11 22:14:15 filterlog[12345]: 5,,,1000000103,igb0,match,block,in,4,0x0,,241,54321,0,none,6,tcp,44,%s,192.0.2.1,51234,%d,0,S,1234567890,,1024,,mss", src, dport)
}

func fwOpn4(src string, dport int, action, dir string) string {
	return fmt.Sprintf(`<134>1 2026-10-11T22:14:15+00:00 OPNsense.localdomain filterlog 54321 - [meta sequenceId="1"] 82,,,fae559338f65e11c53669fc3642c93c2,vtnet0,match,%s,%s,4,0x0,,64,0,0,DF,17,udp,60,%s,192.0.2.1,40000,%d,40`, action, dir, src, dport)
}

func fwPf6(src string, dport int) string {
	return fmt.Sprintf("<134>filterlog[1]: 5,,,1000000103,igb0,match,block,in,6,0x00,0x00000,255,tcp,6,40,%s,2001:db8::1,51234,%d,0,S,1,,1024,,mss", src, dport)
}

func TestFwPortscan(t *testing.T) {
	pf, opn := *fwRuleByID(t, "pfsense/portscan"), *fwRuleByID(t, "opnsense/portscan")
	if pf.Threshold != fwScanPorts || pf.Kind != KindPortScan || opn.Threshold != fwScanPorts {
		t.Fatalf("%+v", pf)
	}
	// frischer Zustand je Lauf (die angemeldeten Regeln behalten ihn ueber -count hinweg)
	pf.Match, opn.Match = newFwScan(true).match, newFwScan(false).match
	base := time.Date(2026, 10, 11, 22, 0, 0, 0, time.UTC)
	feed := func(r LogRule, raw string, at time.Time) (LogHit, bool) {
		l := ParseSyslog([]byte(raw), netip.Addr{}, at)
		l.Time = at
		return r.Match(&l)
	}

	// pfSense IPv4: 19 Ports (eins doppelt) ohne Treffer, der 20. verschiedene liefert Weight = Schwelle
	src := "198.51.100.60"
	for i := 0; i < fwScanPorts-1; i++ {
		if _, ok := feed(pf, fwPf4(src, 1000+i), base); ok {
			t.Fatalf("Treffer nach %d Ports", i+1)
		}
		if _, ok := feed(pf, fwPf4(src, 1000), base); ok {
			t.Fatal("doppelter Port gezaehlt")
		}
	}
	if _, ok := feed(opn, fwPf4(src, 2000), base); ok {
		t.Fatal("pfSense-Zeile von OPNsense-Regel gezaehlt")
	}
	h, ok := feed(pf, fwPf4(src, 2000), base)
	if !ok || h.Src != netip.MustParseAddr(src) || h.Weight != fwScanPorts || h.Port != 0 {
		t.Fatalf("Treffer %+v %v", h, ok)
	}
	// danach von vorn
	if _, ok := feed(pf, fwPf4(src, 3000), base); ok {
		t.Fatal("kein Neubeginn")
	}

	// Fenster: Ports ueber mehr als 5 Minuten verteilt ergeben keinen Treffer
	src = "198.51.100.61"
	for i := 0; i < 2*fwScanPorts; i++ {
		if _, ok := feed(pf, fwPf4(src, 1000+i), base.Add(time.Duration(i)*30*time.Second)); ok {
			t.Fatalf("Treffer trotz Fenster bei %d", i)
		}
	}

	// OPNsense IPv4 (UDP), nur block + in
	src = "203.0.113.60"
	for i := 0; i < fwScanPorts; i++ {
		if _, ok := feed(opn, fwOpn4(src, 1000+i, "pass", "in"), base); ok {
			t.Fatal("pass gezaehlt")
		}
		if _, ok := feed(opn, fwOpn4(src, 1000+i, "block", "out"), base); ok {
			t.Fatal("out gezaehlt")
		}
		if _, ok := feed(pf, fwOpn4(src, 1000+i, "block", "in"), base); ok {
			t.Fatal("OPNsense-Zeile von pfSense-Regel gezaehlt")
		}
	}
	var hit bool
	for i := 0; i < fwScanPorts; i++ {
		_, hit = feed(opn, fwOpn4(src, 1000+i, "block", "in"), base)
	}
	if !hit {
		t.Fatal("OPNsense: kein Treffer")
	}

	// IPv6
	src = "2001:db8::60"
	for i := 0; i < fwScanPorts; i++ {
		_, hit = feed(pf, fwPf6(src, 1000+i), base)
	}
	if !hit {
		t.Fatal("IPv6: kein Treffer")
	}

	// kaputte/fremde Zeilen
	for _, raw := range []string{
		"<134>filterlog[1]: 5,,,1000000103,igb0,match,block,in,4,0x0,,241,54321,0,none,1,icmp,28,198.51.100.62,192.0.2.1,request,1,1",
		"<134>filterlog[1]: 5,,,1000000103,igb0,match,block,in,4",
		"<134>filterlog[1]: 5,,,1000000103,igb0,match,block,in,9,a,b,c,d,e,f,g,h,i,j,k,l,m,n",
		"<134>filterlog[1]: 5,,,1000000103,igb0,match,block,in,4,0x0,,241,54321,0,none,6,tcp,44,kaputt,192.0.2.1,51234,22",
		"<134>filterlog[1]: 5,,,1000000103,igb0,match,block,in,4,0x0,,241,54321,0,none,6,tcp,44,198.51.100.62,192.0.2.1,51234,0",
		"<134>other[1]: 5,,,1000000103,igb0,match,block,in,4,0x0,,241,54321,0,none,6,tcp,44,198.51.100.62,192.0.2.1,51234,22",
		"<134>filterlog[1]: ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,",
	} {
		for i := 0; i < fwScanPorts+1; i++ {
			if _, ok := feed(pf, raw, base); ok {
				t.Fatalf("%q: Treffer", raw)
			}
		}
	}
}

func TestFwPortscanBounded(t *testing.T) {
	s := newFwScan(true)
	at := time.Date(2026, 10, 11, 22, 0, 0, 0, time.UTC)
	for i := 0; i < fwScanMaxTracked+500; i++ {
		ip := netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)})
		l := ParseSyslog([]byte(fwPf4(ip.String(), 22)), netip.Addr{}, at)
		l.Time = at
		s.match(&l)
	}
	if n := len(s.ips); n > fwScanMaxTracked {
		t.Errorf("%d IPs gemerkt", n)
	}
	// gleichzeitige Aufrufe (Engine liest Dateien und Syslog parallel)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				ip := netip.AddrFrom4([4]byte{203, 0, 113, byte(g)})
				l := ParseSyslog([]byte(fwPf4(ip.String(), 1000+i)), netip.Addr{}, at)
				l.Time = at
				s.match(&l)
			}
		}(g)
	}
	wg.Wait()
}

func TestFwHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"198.51.100.7": "198.51.100.7", "'198.51.100.7'": "198.51.100.7", `"2001:db8::1"`: "2001:db8::1",
		"198.51.100.7:22": "198.51.100.7", "[2001:db8::1]:22": "2001:db8::1", "198.51.100.7.": "198.51.100.7",
		"::ffff:198.51.100.7": "198.51.100.7", "198.51.100.7/32": "198.51.100.7", "fe80::1%eth0": "fe80::1",
	} {
		if a, ok := fwParseIP(in); !ok || a != netip.MustParseAddr(want) {
			t.Errorf("fwParseIP(%q) = %v %v", in, a, ok)
		}
	}
	for _, in := range []string{"", "0.0.0.0", "::", "kaputt", "1.2.3", "198.51.100.7:99999", strings.Repeat("1", 100)} {
		if a, ok := fwParseIP(in); ok {
			t.Errorf("fwParseIP(%q) = %v", in, a)
		}
	}
	if a, ok := fwParseIPPort("2001:db8::7:2222"); !ok || a != netip.MustParseAddr("2001:db8::7") {
		t.Errorf("dropbear IPv6: %v %v", a, ok)
	}
	m := `a=1 xsrcip=9.9.9.9 srcip=198.51.100.7 msg="x y" logdesc="Admin login failed" empty= q="offen`
	for k, want := range map[string]string{"a": "1", "srcip": "198.51.100.7", "msg": "x y", "logdesc": "Admin login failed", "empty": "", "q": "offen"} {
		if v, ok := fwKV(m, k); !ok || v != want {
			t.Errorf("fwKV(%s) = %q %v", k, v, ok)
		}
	}
	if _, ok := fwKV(m, "nicht"); ok {
		t.Error("fwKV fehlender Schluessel")
	}
	if fwIndexFold("Web GUI Authentication", "gui auth") != 4 || fwIndexFold("abc", "abcd") != -1 {
		t.Error("fwIndexFold")
	}
}
