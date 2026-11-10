package apis

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model/modeltest"
)

// fakeUPSD ist ein upsd mit den Antworten aus testdata/nut (eine Datei je USV, Zeilen "VAR <ups> <name> "<wert>"").
type fakeUPSD struct {
	t       *testing.T
	ln      net.Listener
	cert    *tls.Certificate // STARTTLS angeboten
	pass    string           // erwartetes Passwort ("" = beliebig)
	ups     map[string]string
	errs    map[string]string // USV -> ERR-Code bei LIST VAR
	extra   string            // zusaetzliche Zeile nach BEGIN LIST UPS (z. B. zu lang)
	mu      sync.Mutex
	cmds    []string // empfangene Befehle (mit "TLS:" davor nach STARTTLS)
	upsList []string
}

func newFakeUPSD(t *testing.T) *fakeUPSD {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUPSD{t: t, ln: ln, ups: map[string]string{}, errs: map[string]string{}}
	t.Cleanup(func() { _ = ln.Close() })
	go f.serve()
	return f
}

func (f *fakeUPSD) addr() string { return f.ln.Addr().String() }

func (f *fakeUPSD) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

func (f *fakeUPSD) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

func (f *fakeUPSD) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var conn net.Conn = c
	r := bufio.NewReader(conn)
	isTLS := false
	w := func(s string) { _, _ = conn.Write([]byte(s + "\n")) }
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return
		}
		l = strings.TrimRight(l, "\r\n")
		f.mu.Lock()
		if isTLS {
			f.cmds = append(f.cmds, "TLS:"+l)
		} else {
			f.cmds = append(f.cmds, l)
		}
		f.mu.Unlock()
		fl := nutFields(l)
		switch {
		case l == "STARTTLS":
			if f.cert == nil {
				w("ERR FEATURE-NOT-CONFIGURED")
				continue
			}
			w("OK STARTTLS")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*f.cert}})
			if err := tc.Handshake(); err != nil {
				return
			}
			conn, r, isTLS = tc, bufio.NewReader(tc), true
		case len(fl) == 2 && fl[0] == "USERNAME":
			w("OK")
		case len(fl) == 2 && fl[0] == "PASSWORD":
			if f.pass != "" && fl[1] != f.pass {
				w("ERR INVALID-PASSWORD")
				continue
			}
			w("OK")
		case l == "VER":
			w("Network UPS Tools upsd 2.8.1 - https://www.networkupstools.org/")
		case l == "LIST UPS":
			w("BEGIN LIST UPS")
			if f.extra != "" {
				w(f.extra)
			}
			for _, u := range f.upsList {
				w("UPS " + u + ` "Beschreibung \"` + u + `\""`)
			}
			w("END LIST UPS")
		case len(fl) == 3 && fl[0] == "LIST" && fl[1] == "VAR":
			if e, ok := f.errs[fl[2]]; ok {
				w("ERR " + e)
				continue
			}
			body, ok := f.ups[fl[2]]
			if !ok {
				w("ERR UNKNOWN-UPS")
				continue
			}
			w("BEGIN LIST VAR " + fl[2])
			for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
				w(strings.TrimRight(line, "\r"))
			}
			w("END LIST VAR " + fl[2])
		case l == "LOGOUT":
			w("OK Goodbye")
			return
		default:
			w("ERR UNKNOWN-COMMAND")
		}
	}
}

func nutFake(t *testing.T) *fakeUPSD {
	f := newFakeUPSD(t)
	f.ups["apc"] = fixture(t, "nut/apc.txt")
	f.ups["eaton"] = fixture(t, "nut/eaton.txt")
	f.errs["garage"] = "DATA-STALE"
	f.upsList = []string{"apc", "eaton", "garage"}
	return f
}

func TestNUTCollect(t *testing.T) {
	f := nutFake(t)
	n, err := NewNUT(NUTConfig{Address: f.addr()})
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := n.Collect(context.Background())
	pe := partialOf(t, err)
	if !hasPrefix(pe, "ups:garage") || !strings.Contains(deErr(pe), "DATA-STALE") {
		t.Errorf("Teilfehler = %+v", pe)
	}
	if len(svcs) != 2 || hasSvc(svcs, "ups:garage") {
		t.Fatalf("Dienste = %+v", svcs)
	}
	apc := svcByKey(t, svcs, "ups:apc")
	if apc.Name != "USV apc (American Power Conversion Back-UPS ES 700G)" || apc.Kind != "ups" || !apc.Default || len(apc.Facts) != 0 {
		t.Errorf("apc = %+v", apc)
	}
	if m := mustMetric(t, apc, "runtime"); m.Value != 2280 || m.Rule != ruleUPSRuntime || m.Unit != "s" {
		t.Errorf("runtime = %+v", m)
	}
	for name, want := range map[string]float64{"charge": 100, "load": 17, "input_voltage": 231, "on_battery": 0} {
		if m := mustMetric(t, apc, name); m.Value != want {
			t.Errorf("apc %s = %+v", name, m)
		}
	}
	if apc.Text != "Netzbetrieb, lädt · Ladung 100 % · Restlaufzeit 38 Min. · Last 17 % · Eingang 231 V" {
		t.Errorf("apc Text = %q", apc.Text)
	}
	eaton := svcByKey(t, svcs, "ups:eaton")
	for _, code := range []string{"ups_on_battery", "ups_low_battery", "ups_replace_battery", "ups_overload"} {
		if !hasFact(eaton, code) {
			t.Errorf("eaton ohne %s: %+v", code, eaton.Facts)
		}
	}
	if eaton.Facts[0].Text != "auf Batterie (Ladung 38 %, Restlaufzeit 6 Min.)" {
		t.Errorf("eaton Fact = %q", eaton.Facts[0].Text)
	}
	if m := mustMetric(t, eaton, "temp"); m.Value != 31.5 || m.Unit != "°C" {
		t.Errorf("eaton temp = %+v", m)
	}
	if m := mustMetric(t, eaton, "power"); m.Value != 1043 || m.Unit != "W" {
		t.Errorf("eaton power = %+v", m)
	}
	if !strings.Contains(eaton.Text, "Alarm: Replace battery! Overload!") || !strings.Contains(eaton.Text, "Selbsttest: Done and warning") {
		t.Errorf("eaton Text = %q", eaton.Text)
	}
	// Befehle: STARTTLS versucht, ohne Anmeldung, Abmeldung
	cmds := strings.Join(f.commands(), "|")
	if !strings.HasPrefix(cmds, "STARTTLS|LIST UPS|LIST VAR apc") || !strings.HasSuffix(cmds, "LOGOUT") || strings.Contains(cmds, "USERNAME") {
		t.Errorf("Befehle = %s", cmds)
	}
}

func TestNUTFilterAndAuth(t *testing.T) {
	f := nutFake(t)
	f.pass = testSecret
	n, err := NewNUT(NUTConfig{Address: "nut://" + f.addr(), UPS: []string{"eaton"}, User: "monuser", Password: testSecret, TLS: NUTTLSOff})
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := n.Collect(context.Background())
	if err != nil || len(svcs) != 1 || svcs[0].Key != "ups:eaton" {
		t.Fatalf("Collect = %+v, %v", svcs, err)
	}
	cmds := f.commands()
	if cmds[0] != `USERNAME "monuser"` || cmds[1] != `PASSWORD "`+testSecret+`"` {
		t.Errorf("Befehle = %v", cmds)
	}
	// Test: Version und Hinweis auf unverschluesseltes Passwort
	r := deRes(n.Test(context.Background()))
	if !r.OK || !strings.HasPrefix(r.Version, "Network UPS Tools upsd 2.8.1") || r.Summary != "1 USV: eaton (OB DISCHRG LB RB OVER)" ||
		!strings.Contains(r.Warning, "Passwort geht unverschlüsselt") {
		t.Errorf("Test = %+v", r)
	}
	// falsches Passwort: Fehler ohne Geheimnis
	n2, _ := NewNUT(NUTConfig{Address: f.addr(), User: "monuser", Password: "falsch-" + testSecret, TLS: NUTTLSOff})
	_, err = n2.Collect(context.Background())
	if err == nil || !strings.Contains(deErr(err), "INVALID-PASSWORD") || strings.Contains(deErr(err), testSecret) {
		t.Errorf("falsches Passwort: %v", err)
	}
	if r := deRes(n2.Test(context.Background())); r.OK || strings.Contains(r.Error, testSecret) {
		t.Errorf("Test falsches Passwort: %+v", r)
	}
}

func TestNUTStartTLS(t *testing.T) {
	f := nutFake(t)
	cert, pin := testCert(t)
	f.cert = &cert
	cfg := NUTConfig{Address: f.addr(), User: "monuser", Password: testSecret}
	n, _ := NewNUT(cfg)
	// ohne Pin: Zertifikat bestaetigen, nichts gesendet
	r := deRes(n.Test(context.Background()))
	if r.OK || !r.NeedConfirm || r.Fingerprint != pin || r.Error != "" || r.CertSubject != "CN=upsd-test" {
		t.Errorf("Test ohne Pin = %+v", r)
	}
	if _, err := n.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "nicht bestätigt") {
		t.Errorf("Collect ohne Pin: %v", err)
	}
	for _, c := range f.commands() {
		if strings.Contains(c, "USERNAME") || strings.Contains(c, testSecret) {
			t.Fatalf("Zugangsdaten vor der Bestaetigung gesendet: %v", f.commands())
		}
	}
	// mit Pin: alles nach STARTTLS verschluesselt
	cfg.Pin = pin
	n, _ = NewNUT(cfg)
	r = deRes(n.Test(context.Background()))
	if !r.OK || strings.Contains(r.Warning, "unverschlüsselt") || r.Fingerprint != pin {
		t.Errorf("Test mit Pin = %+v", r)
	}
	svcs, err := n.Collect(context.Background())
	if !IsPartial(err) || len(svcs) != 2 {
		t.Fatalf("Collect mit Pin = %d, %v", len(svcs), err)
	}
	for _, c := range f.commands() {
		if strings.Contains(c, testSecret) && !strings.HasPrefix(c, "TLS:") {
			t.Fatalf("Passwort unverschluesselt: %v", f.commands())
		}
	}
	// falscher Pin
	cfg.Pin = strings.Repeat("ab", 32)
	n, _ = NewNUT(cfg)
	if r := deRes(n.Test(context.Background())); r.OK || !strings.Contains(r.Error, "passt nicht") {
		t.Errorf("falscher Pin = %+v", r)
	}
	// Pflicht ohne Angebot
	f.cert = nil
	n, _ = NewNUT(NUTConfig{Address: f.addr(), TLS: NUTTLSRequire})
	if _, err := n.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "FEATURE-NOT-CONFIGURED") {
		t.Errorf("TLS Pflicht: %v", err)
	}
}

func TestNUTHostile(t *testing.T) {
	f := nutFake(t)
	f.extra = "UPS " + strings.Repeat("x", nutMaxLine+10)
	n, _ := NewNUT(NUTConfig{Address: f.addr(), Timeout: 5 * time.Second})
	if _, err := n.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "Zeile zu lang") {
		t.Errorf("lange Zeile: %v", err)
	}
	// ungueltiger Name vom Geraet wird nicht in Befehle uebernommen
	f.extra = `UPS "bad name; LIST VAR x" "x"`
	svcs, err := n.Collect(context.Background())
	if !IsPartial(err) || len(svcs) != 2 || !strings.Contains(deErr(err), "ungültiger USV-Name") {
		t.Errorf("ungueltiger Name: %d %v", len(svcs), err)
	}
	// keine Antwort: Zeitlimit
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			time.Sleep(3 * time.Second)
			c.Close()
		}
	}()
	n, _ = NewNUT(NUTConfig{Address: ln.Addr().String(), Timeout: 500 * time.Millisecond})
	start := time.Now()
	if _, err := n.Collect(context.Background()); err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("Zeitlimit: %v nach %v", err, time.Since(start))
	}
}

func TestNUTConfig(t *testing.T) {
	for _, c := range []NUTConfig{
		{Address: ""},
		{Address: "host:0"},
		{Address: "ups.lan", UPS: []string{"a b"}},
		{Address: "ups.lan", TLS: "maybe"},
		{Address: "ups.lan", TLS: NUTTLSOff, Pin: strings.Repeat("a", 64)},
		{Address: "ups.lan", User: "u\nLIST", Password: "x"},
		{Address: "ups.lan", Password: "x"},
		{Address: "ups.lan", Pin: "zz"},
	} {
		if _, err := NewNUT(c); err == nil {
			t.Errorf("%+v angenommen", c)
		}
	}
	for in, want := range map[string]string{"ups.lan": "ups.lan:3493", "nut://UPS.lan:3500": "ups.lan:3500", "fd00::5": "fd00::5:3493",
		"[fd00::5]:3493": "fd00::5:3493", "192.168.1.5": "192.168.1.5:3493"} {
		h, p, err := nutAddr(in)
		if err != nil || h+":"+p != want {
			t.Errorf("nutAddr(%q) = %s:%s %v", in, h, p, err)
		}
	}
}

func TestNUTFields(t *testing.T) {
	for in, want := range map[string]string{
		`VAR ups device.model "Back-UPS ES"`: `VAR|ups|device.model|Back-UPS ES`,
		`VAR ups x "a \"b\" c\\d"`:           `VAR|ups|x|a "b" c\d`,
		`VAR ups empty ""`:                   `VAR|ups|empty|`,
		`UPS  a   "b"`:                       `UPS|a|b`,
		`VAR ups unterminated "abc`:          `VAR|ups|unterminated|abc`,
	} {
		if got := strings.Join(nutFields(in), "|"); got != want {
			t.Errorf("nutFields(%q) = %q, erwartet %q", in, got, want)
		}
	}
	if got := nutQuote(`p"w\x`); got != `"p\"w\\x"` {
		t.Errorf("nutQuote = %s", got)
	}
}

func TestNUTServiceStates(t *testing.T) {
	s := modeltest.Service("de", nutService(nutUPS{Name: "u", Vars: map[string]string{"ups.status": "OL FSD", "battery.charge": "NaN", "battery.runtime": "Inf"}}))
	if !hasFact(s, "ups_low_battery") || hasFact(s, "ups_on_battery") || len(s.Metrics) != 1 {
		t.Errorf("FSD/NaN = %+v", s)
	}
	s = modeltest.Service("de", nutService(nutUPS{Name: "u", Desc: "Keller", Vars: map[string]string{}}))
	if s.Name != "USV u (Keller)" || !strings.HasPrefix(s.Text, "Status unbekannt") {
		t.Errorf("leer = %+v", s)
	}
	s = modeltest.Service("de", nutService(nutUPS{Name: "u", Vars: map[string]string{"ups.status": "OL", "battery.charge": "150", "ups.power": "300"}}))
	if m := mustMetric(t, s, "charge"); m.Value != 100 {
		t.Errorf("charge > 100 = %+v", m)
	}
	if m := mustMetric(t, s, "power"); m.Unit != "VA" {
		t.Errorf("power VA = %+v", m)
	}
}

// AP5: Modus auto, upsd lehnt STARTTLS ab – lesen ohne Anmeldung (kein Passwort im Klartext); hat upsd schon einmal
// TLS gesprochen, ist die Ablehnung ein Fehler statt eines stillen Wechsels auf Klartext.
func TestNUTNoDowngrade(t *testing.T) {
	f := nutFake(t)
	f.pass = testSecret
	n, _ := NewNUT(NUTConfig{Address: f.addr(), User: "monuser", Password: testSecret})
	svcs, err := n.Collect(context.Background())
	if !IsPartial(err) || len(svcs) != 2 {
		t.Fatalf("auto ohne TLS = %d, %v", len(svcs), err)
	}
	for _, c := range f.commands() {
		if strings.Contains(c, testSecret) || strings.HasPrefix(c, "USERNAME") {
			t.Fatalf("Anmeldung ohne TLS gesendet: %v", f.commands())
		}
	}
	if r := deRes(n.Test(context.Background())); !r.OK || !strings.Contains(r.Warning, "Anmeldung weggelassen") {
		t.Errorf("Test auto ohne TLS = %+v", r)
	}
	// erst TLS, dann abgelehnt
	cert, pin := testCert(t)
	f.mu.Lock()
	f.cert = &cert
	f.mu.Unlock()
	n, _ = NewNUT(NUTConfig{Address: f.addr(), User: "monuser", Password: testSecret, Pin: pin})
	n.cfg.Pin, n.pin = "", "" // Modus auto ohne Pflicht, Zertifikat vertraut
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	n.roots = x509.NewCertPool()
	n.roots.AddCert(leaf)
	if _, err := n.Collect(context.Background()); !IsPartial(err) {
		t.Fatalf("mit TLS: %v", err)
	}
	f.mu.Lock()
	f.cert = nil
	f.cmds = nil
	f.mu.Unlock()
	_, err = n.Collect(context.Background())
	if err == nil || IsPartial(err) || !strings.Contains(deErr(err), "bisher TLS") {
		t.Errorf("Ablehnung nach TLS: %v", err)
	}
	for _, c := range f.commands() {
		if strings.HasPrefix(c, "LIST") || strings.Contains(c, testSecret) {
			t.Errorf("nach abgelehntem STARTTLS weiter gesendet: %v", f.commands())
		}
	}
}

// AP8: die Antworten einer Runde sind in der Summe begrenzt (nicht nur je Zeile und Zeilenzahl).
func TestNUTMaxBytes(t *testing.T) {
	f := newFakeUPSD(t)
	var b strings.Builder
	for i := 0; i < 1500; i++ { // 1500 x ~4 KB = ~6 MB
		fmt.Fprintf(&b, "VAR big v%d \"%s\"\n", i, strings.Repeat("x", 4000))
	}
	f.ups["big"] = b.String()
	f.upsList = []string{"big"}
	n, _ := NewNUT(NUTConfig{Address: f.addr(), TLS: NUTTLSOff, Timeout: 10 * time.Second})
	if _, err := n.Collect(context.Background()); err == nil || !strings.Contains(deErr(err), "zu groß") {
		t.Errorf("6 MB angenommen: %v", err)
	}
}
