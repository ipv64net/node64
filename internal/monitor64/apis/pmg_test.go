package apis

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// fakePMG stellt die API eines Proxmox Mail Gateway nach (Formate aus pmg-api: PMG/API2/Nodes.pm, Services.pm,
// Postfix.pm, Statistics.pm, Quarantine.pm, Cluster.pm, ClamAV.pm): Anmeldung per Ticket, danach nur mit Cookie.
type fakePMG struct {
	mu      sync.Mutex
	pass    string
	ticket  string            // gueltiges Ticket ("" = jedes ablehnen)
	role    string            // Rolle in der Antwort der Anmeldung
	tfa     bool              // Anmeldung liefert ein TFA-Ticket
	routes  map[string]string // Pfad (mit Abfrage) -> JSON fuer "data"
	status  map[string]int    // Pfad -> HTTP-Status statt Daten
	logins  int
	hits    map[string]int
	issued  int
	noAuth  int // Anfragen ohne gueltiges Ticket
	lastQ   string
	cookies []string
}

const (
	pmgStatusJSON = `{"cpu":0.05,"wait":0.001,"cpuinfo":{"cpus":4,"model":"QEMU"},"loadavg":["0.10","0.20","0.30"],
		"memory":{"total":8000000000,"used":2000000000,"free":6000000000},"swap":{"total":1000000000,"used":0,"free":1000000000},
		"rootfs":{"total":50000000000,"used":10000000000,"avail":40000000000,"free":40000000000},"uptime":1000,
		"pmgversion":"pmg-api/9.0.3/abcdef12 (running kernel: 6.14.8-2-pve)","insync":1,"time":1794300000}`
	pmgServicesJSON = `[
		{"service":"pmgproxy","name":"pmgproxy","desc":"Proxmox Mail Gateway API","state":"running","unit-state":"enabled","active-state":"active"},
		{"service":"pmgdaemon","name":"pmgdaemon","desc":"Proxmox Mail Gateway API Daemon","state":"running","unit-state":"enabled","active-state":"active"},
		{"service":"postfix","name":"postfix","desc":"Postfix Mail Transport Agent","state":"exited","unit-state":"enabled","active-state":"active"},
		{"service":"postgres","name":"postgres","desc":"PostgreSQL Cluster 17-main","state":"running","unit-state":"enabled-runtime","active-state":"active"},
		{"service":"pmg-smtp-filter","name":"pmg-smtp-filter","desc":"Proxmox SMTP Filter Daemon","state":"failed","unit-state":"enabled","active-state":"failed"},
		{"service":"pmgpolicy","name":"pmgpolicy","desc":"Proxmox Mail Gateway Policy Daemon","state":"dead","unit-state":"enabled","active-state":"inactive"},
		{"service":"clamav-daemon","name":"clamav-daemon","desc":"Clam AntiVirus userspace daemon","state":"dead","unit-state":"disabled","active-state":"inactive"},
		{"service":"fetchmail","name":"fetchmail","desc":"LSB: init-Script for system wide fetchmail daemon","state":"dead","unit-state":"enabled","active-state":"inactive"},
		{"service":"pmg-daily","name":"pmg-daily","desc":"Daily Proxmox Mail Gateway activities","state":"success","unit-state":"static","active-state":"inactive"},
		{"service":"pmgreport","name":"pmgreport","desc":"Send Daily System Report Mail","state":"exit-code","unit-state":"static","active-state":"failed"},
		{"service":"chrony","name":"chrony","desc":"chrony","state":"running","unit-state":"enabled","active-state":"active"},
		{"service":"systemd-timesyncd","name":"systemd-timesyncd","state":"dead","unit-state":"not-found","active-state":"inactive"}]`
)

func newFakePMG() *fakePMG {
	return &fakePMG{pass: "geheim-pmg-1234", role: "audit", hits: map[string]int{}, status: map[string]int{}, routes: map[string]string{
		"/nodes/localhost/status":                        pmgStatusJSON,
		"/nodes/localhost/services":                      pmgServicesJSON,
		"/nodes/localhost/postfix/qshape?queue=deferred": `[{"domain":"TOTAL","total":"120","5m":"0"},{"domain":"t-online.de","total":"40"},{"domain":"gmail.com","total":"80"}]`,
		"/nodes/localhost/postfix/qshape?queue=active":   `[{"domain":"TOTAL","total":"2"},{"domain":"example.org","total":"2"}]`,
		"/nodes/localhost/postfix/qshape?queue=hold":     `[{"domain":"TOTAL","total":"0"}]`,
		"/statistics/mail":                               `{"count":150,"count_in":120,"count_out":30,"spamcount_in":40,"spamcount_out":1,"viruscount_in":2,"viruscount_out":0,"rbl_rejects":300,"pregreet_rejects":20,"avptime":1.234,"bytes_in":1,"bytes_out":1}`,
		"/quarantine/spamstatus":                         `{"count":240,"mbytes":35.5,"avgbytes":150000,"avgspam":8.1}`,
		"/quarantine/virusstatus":                        `{"count":3,"mbytes":0.5,"avgbytes":150000}`,
		"/config/cluster/status":                         `[{"cid":1,"type":"master","name":"pmg1","ip":"10.0.0.1","insync":1,"uptime":5},{"cid":2,"type":"node","name":"pmg2","ip":"10.0.0.2","conn_error":"500 Can't connect to 10.0.0.2:8006"},{"cid":3,"type":"node","name":"pmg3","ip":"10.0.0.3","insync":0}]`,
		"/nodes/localhost/clamav/database":               `[{"name":"main","type":"ClamAV-VDB","build_time":"16 Sep 2021 08-32 -0400","version":"62","nsigs":"6647427"},{"name":"daily","type":"ClamAV-VDB","build_time":"05 Nov 2026 09-12 +0000","version":"27812","nsigs":"2075000"}]`,
		"/nodes/localhost/apt/update":                    `[{"Package":"pmg-api","Version":"9.0.4","OldVersion":"9.0.3","Origin":"Proxmox","Title":"Proxmox Mail Gateway API"},{"Package":"openssl","Version":"3.5.2","OldVersion":"3.5.1","Origin":"Debian","Section":"utils","Title":"security update"}]`,
	}}
}

func (f *fakePMG) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	p := strings.TrimPrefix(r.URL.Path, "/api2/json")
	if p == "/access/ticket" && r.Method == http.MethodPost {
		f.logins++
		var in struct{ Username, Password string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if r.Header.Get("Cookie") != "" || in.Username != "monitor64@pmg" || in.Password != f.pass {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"data":null,"message":"authentication failure\n"}`))
			return
		}
		f.issued++
		f.ticket = "PMG:monitor64@pmg:6912A0B" + string(rune('0'+f.issued)) + "::abc+def/ghi=="
		tk := f.ticket
		if f.tfa {
			tk = "PMG:!tfa!%7B%22totp%22%3Atrue%7D:monitor64@pmg:6912A0B0::xyz"
		}
		b, _ := json.Marshal(map[string]any{"data": map[string]string{"ticket": tk, "CSRFPreventionToken": "6912A0B0:csrf", "username": in.Username, "role": f.role}})
		_, _ = w.Write(b)
		return
	}
	c := strings.TrimPrefix(r.Header.Get("Cookie"), "PMGAuthCookie=")
	f.cookies = append(f.cookies, c)
	if got, _ := url.QueryUnescape(c); f.ticket == "" || got != f.ticket {
		f.noAuth++
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"data":null,"message":"permission denied - invalid PMG ticket\n"}`))
		return
	}
	key := p
	if q := r.URL.Query().Get("queue"); q != "" {
		key += "?queue=" + q
	}
	if p == "/statistics/mail" {
		f.lastQ = r.URL.RawQuery
	}
	f.hits[key]++
	if st, ok := f.status[key]; ok {
		w.WriteHeader(st)
		_, _ = w.Write([]byte(`{"data":null,"message":"Permission check failed\n"}`))
		return
	}
	body, ok := f.routes[key]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"data":null}`))
		return
	}
	_, _ = w.Write([]byte(`{"data":` + body + `}`))
}

func pmgFor(t *testing.T, f *fakePMG, pass string) *PMG {
	t.Helper()
	addr, pin := tlsServer(t, f)
	p, err := NewPMG(PMGConfig{Address: addr, User: " monitor64@pmg ", Password: pass, Pin: pin})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestPMGCollect(t *testing.T) {
	f := newFakePMG()
	p := pmgFor(t, f, f.pass)
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	svcs, err := p.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", deErr(err))
	}
	keys := map[string]bool{}
	for _, s := range svcs {
		keys[s.Key] = true
	}
	for _, k := range []string{"cpu", "load", "mem", "swap", "fs:/", "updates", "systemd", "mailq", "mail", "quarantine", "cluster", "clamav"} {
		if !keys[k] {
			t.Errorf("Dienst %q fehlt (%v)", k, keys)
		}
	}
	// Dienste: fehlgeschlagen bzw. gestoppt, obwohl eingeschaltet; ausgeschaltete, fehlende und fetchmail zaehlen nicht
	sd := svcByKey(t, svcs, "systemd")
	if len(sd.Facts) != 1 || sd.Facts[0].Code != "systemd_failed" || sd.Facts[0].Text != "pmg-smtp-filter, pmgpolicy, pmgreport" {
		t.Errorf("systemd: %+v", sd.Facts)
	}
	if sd.Metrics[0].Value != 3 {
		t.Errorf("systemd failed = %v", sd.Metrics[0].Value)
	}
	// Warteschlange: zurueckgestellte Mails tragen die Schwelle, groesste Domains im Text
	mq := svcByKey(t, svcs, "mailq")
	if mq.Kind != "mailq" || mq.Metrics[0].Name != "deferred" || mq.Metrics[0].Value != 120 || mq.Metrics[0].Rule != model.RuleMailQueue ||
		mq.Metrics[1].Value != 2 || mq.Metrics[2].Value != 0 {
		t.Errorf("mailq: %+v", mq.Metrics)
	}
	if txt := deText(mq.Text); !strings.Contains(txt, "120 zurückgestellt, 2 aktiv, 0 angehalten") || !strings.Contains(txt, "(gmail.com 80, t-online.de 40)") {
		t.Errorf("mailq Text: %q", txt)
	}
	// Durchsatz der letzten Stunde
	ml := svcByKey(t, svcs, "mail")
	if txt := deText(ml.Text); txt != "letzte Stunde: 120 ein, 30 aus, 41 Spam, 2 Viren, 320 abgewiesen" {
		t.Errorf("mail Text: %q", txt)
	}
	if want := "starttime=" + itoa(now.Add(-time.Hour).Unix()) + "&endtime=" + itoa(now.Unix()); f.lastQ != want {
		t.Errorf("statistics/mail Abfrage %q, erwartet %q", f.lastQ, want)
	}
	qu := svcByKey(t, svcs, "quarantine")
	if qu.Metrics[0].Value != 240 || qu.Metrics[1].Value != 3 || qu.Metrics[2].Value != 36*1024*1024 {
		t.Errorf("quarantine: %+v", qu.Metrics)
	}
	// Cluster: nicht erreichbare Node offline, fehlender Abgleich als Warnung
	cl := svcByKey(t, svcs, "cluster")
	codes := map[string]string{}
	for _, fc := range cl.Facts {
		codes[fc.Code] = deText(fc.Text)
	}
	if codes["cluster_node_down"] != "pmg2 offline" || codes["device_warn"] != "nicht synchron: pmg3" || !strings.Contains(deText(cl.Text), "2 von 3 Nodes online") {
		t.Errorf("cluster: %v / %q", codes, deText(cl.Text))
	}
	// ClamAV: taegliche Signaturen 6 Tage alt
	cv := svcByKey(t, svcs, "clamav")
	if len(cv.Facts) != 1 || cv.Facts[0].Code != "device_warn" || !strings.Contains(deText(cv.Facts[0].Text), "seit 6 Tagen") || !strings.Contains(deText(cv.Text), "27812") {
		t.Errorf("clamav: %+v %q", cv.Facts, deText(cv.Text))
	}
	up := svcByKey(t, svcs, "updates")
	if len(up.Facts) != 1 || up.Facts[0].Code != "updates_security" {
		t.Errorf("updates: %+v", up.Facts)
	}
	if v := svcByKey(t, svcs, "fs:/"); v.Metrics[0].Value != 20 {
		t.Errorf("fs:/ = %v", v.Metrics[0].Value)
	}

	// zweite Runde: keine neue Anmeldung, langsame Teile nicht erneut; das Cookie ist URL-kodiert
	now = now.Add(time.Minute)
	if _, err := p.Collect(context.Background()); err != nil {
		t.Fatal(deErr(err))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.logins != 1 || f.noAuth != 0 {
		t.Errorf("Anmeldungen %d, ohne Ticket %d", f.logins, f.noAuth)
	}
	if f.hits["/nodes/localhost/status"] != 2 || f.hits["/nodes/localhost/postfix/qshape?queue=deferred"] != 2 || f.hits["/statistics/mail"] != 1 ||
		f.hits["/nodes/localhost/clamav/database"] != 1 || f.hits["/nodes/localhost/apt/update"] != 1 || f.hits["/config/cluster/status"] != 1 {
		t.Errorf("Abfragen: %v", f.hits)
	}
	if c := f.cookies[0]; strings.ContainsAny(c, "+/=: ") || !strings.Contains(c, "%3A") {
		t.Errorf("Cookie nicht kodiert: %q", c)
	}
}

func itoa(v int64) string { b, _ := json.Marshal(v); return string(b) }

// deText uebersetzt einen Text mit Tokens ins Deutsche (wie deErr fuer Fehler).
func deText(s string) string { return de(s) }

// Ticket abgelaufen bzw. PMG neu gestartet: einmal neu anmelden; nach einer Stunde vorsorglich erneuern.
func TestPMGTicketRenew(t *testing.T) {
	f := newFakePMG()
	p := pmgFor(t, f, f.pass)
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	if _, err := p.Collect(context.Background()); err != nil {
		t.Fatal(deErr(err))
	}
	f.mu.Lock()
	f.ticket = "PMG:anderes" // Ticket des Sammlers gilt nicht mehr
	f.mu.Unlock()
	now = now.Add(time.Minute)
	if _, err := p.Collect(context.Background()); err != nil {
		t.Fatalf("nach abgelaufenem Ticket: %v", deErr(err))
	}
	f.mu.Lock()
	if f.logins != 2 || f.noAuth != 1 {
		t.Errorf("Anmeldungen %d, abgelehnt %d", f.logins, f.noAuth)
	}
	f.mu.Unlock()
	now = now.Add(61 * time.Minute)
	if _, err := p.Collect(context.Background()); err != nil {
		t.Fatal(deErr(err))
	}
	f.mu.Lock()
	if f.logins != 3 || f.noAuth != 1 {
		t.Errorf("vorsorglich erneuert: Anmeldungen %d, abgelehnt %d", f.logins, f.noAuth)
	}
	// Passwort geaendert: Fehler mit Hinweis, das Passwort steht nie im Text
	f.pass, f.ticket = "neu", ""
	f.mu.Unlock()
	now = now.Add(time.Minute)
	_, err := p.Collect(context.Background())
	if err == nil || !strings.Contains(deErr(err), "Benutzer mit Realm") || strings.Contains(err.Error(), "geheim-pmg-1234") {
		t.Errorf("falsches Passwort: %v", err)
	}
}

func TestPMGTest(t *testing.T) {
	f := newFakePMG()
	p := pmgFor(t, f, f.pass)
	res := deRes(p.Test(context.Background()))
	if !res.OK || res.Version != "9.0.3" || res.Node != "localhost" || res.Warning != "" || !strings.Contains(res.Summary, "5 Dienste laufen") {
		t.Errorf("Test: %+v", res)
	}
	// Administrator: Hinweis, dass Auditor reicht
	f.mu.Lock()
	f.role = "admin"
	f.mu.Unlock()
	res = deRes(pmgFor(t, f, f.pass).Test(context.Background()))
	if !res.OK || !strings.Contains(res.Warning, "Auditor") {
		t.Errorf("Administrator: %+v", res)
	}
	// falsches Passwort
	res = deRes(pmgFor(t, f, "falsch").Test(context.Background()))
	if res.OK || !strings.Contains(res.Error, "Benutzer mit Realm") || strings.Contains(res.Error, "falsch") {
		t.Errorf("falsches Passwort: %+v", res)
	}
	// zweiter Faktor
	f.mu.Lock()
	f.tfa = true
	f.mu.Unlock()
	res = deRes(pmgFor(t, f, f.pass).Test(context.Background()))
	if res.OK || !strings.Contains(res.Error, "zweiten Faktor") {
		t.Errorf("TFA: %+v", res)
	}
	// ohne Pin: Zertifikat erst bestaetigen, keine Anmeldung gesendet
	f.mu.Lock()
	f.tfa, f.logins = false, 0
	f.mu.Unlock()
	addr, pin := tlsServer(t, f)
	np, err := NewPMG(PMGConfig{Address: addr, User: "monitor64@pmg", Password: f.pass})
	if err != nil {
		t.Fatal(err)
	}
	defer np.Close()
	res = np.Test(context.Background())
	f.mu.Lock()
	defer f.mu.Unlock()
	if res.OK || !res.NeedConfirm || res.Fingerprint != pin || f.logins != 0 {
		t.Errorf("ohne Pin: %+v, Anmeldungen %d", res, f.logins)
	}
}

// Einzelnes Gateway ohne Cluster, ohne ClamAV-Datenbank; fehlende Rechte kosten nur ihren Teil.
func TestPMGStandaloneAndPartial(t *testing.T) {
	f := newFakePMG()
	f.routes["/config/cluster/status"] = `[]`
	f.routes["/nodes/localhost/clamav/database"] = `[]`
	f.status["/nodes/localhost/apt/update"] = http.StatusForbidden
	f.status["/nodes/localhost/services"] = http.StatusForbidden
	p := pmgFor(t, f, f.pass)
	svcs, err := p.Collect(context.Background())
	var pe *PartialError
	if !errors.As(err, &pe) || !strings.Contains(deErr(err), "services") || !strings.Contains(deErr(err), "Auditor") {
		t.Fatalf("Teilfehler erwartet: %v", err)
	}
	keys := map[string]bool{}
	for _, s := range svcs {
		keys[s.Key] = true
	}
	if keys["cluster"] || keys["clamav"] || keys["systemd"] || !keys["mailq"] || !keys["cpu"] || !keys["updates"] {
		t.Errorf("Dienste: %v", keys)
	}
	if up := svcByKey(t, svcs, "updates"); len(up.Metrics) != 0 || up.Text == "" {
		t.Errorf("updates ohne Recht: %+v", up)
	}
}

func TestPMGConfig(t *testing.T) {
	for _, c := range []PMGConfig{
		{Address: "https://pmg.lan:8006", User: "", Password: "x"},
		{Address: "https://pmg.lan:8006", User: "monitor64@pmg", Password: ""},
		{Address: "http://pmg.lan:8006", User: "monitor64@pmg", Password: "x"},
		{Address: "https://pmg.lan:8006/api2", User: "monitor64@pmg", Password: "x"},
	} {
		if _, err := NewPMG(c); err == nil {
			t.Errorf("%+v angenommen", c)
		}
	}
	p, err := NewPMG(PMGConfig{Address: "fd00::25", User: "monitor64@pmg", Password: "x"})
	if err != nil || p.wc.t.base != "https://[fd00::25]:8006" {
		t.Errorf("IPv6 ohne Klammern: %v", err)
	}
	if got := (pmgStatus{Version: "pmg-api/8.2.1/x (running kernel: 6.8)"}).version(); got != "8.2.1" {
		t.Errorf("version = %q", got)
	}
	if _, ok := pmgClamTime("16 Mar 2016 23-17 +0000"); !ok {
		t.Error("pmgClamTime")
	}
}
