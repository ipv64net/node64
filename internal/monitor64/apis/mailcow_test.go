package apis

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// fakeMailcow stellt die API von mailcow nach (Formate aus data/web/api/openapi.yaml von mailcow-dockerized).
type fakeMailcow struct {
	mu     sync.Mutex
	key    string
	routes map[string]string
	hits   map[string]int
	denied bool // Adresse steht nicht in "API-Zugriff erlauben von"
}

const mcTestKey = "AAAAAA-BBBBBB-CCCCCC-DDDDDD-EEEEEE"

func newFakeMailcow() *fakeMailcow {
	return &fakeMailcow{key: mcTestKey, hits: map[string]int{}, routes: map[string]string{
		"/api/v1/get/status/containers": `{
			"postfix-mailcow":{"container":"postfix-mailcow","image":"mailcow/postfix:1.80","started_at":"2026-11-01T08:00:07Z","state":"running","type":"info"},
			"dovecot-mailcow":{"container":"dovecot-mailcow","image":"mailcow/dovecot:2.33","started_at":"2026-11-01T08:00:08Z","state":"running","type":"info"},
			"rspamd-mailcow":{"container":"rspamd-mailcow","image":"mailcow/rspamd:1.98","started_at":"2026-11-01T08:00:12Z","state":"exited","type":"info"},
			"sogo-mailcow":{"container":"sogo-mailcow","image":"mailcow/sogo:1.133","started_at":"2026-11-01T08:00:01Z","state":"running","type":"info"},
			"clamd-mailcow":{"container":"clamd-mailcow","image":"mailcow/clamd:1.70","started_at":"2026-11-01T08:00:01Z","state":"restarting","type":"info"}}`,
		"/api/v1/get/status/vmail":   `{"disk":"/dev/mapper/mail--vg-root","total":"41G","type":"info","used":"11G","used_percent":"28%"}`,
		"/api/v1/get/status/version": `{"version":"2026-10"}`,
		"/api/v1/get/mailq/all": `[
			{"arrival_time":1794300000,"message_size":1848,"queue_id":"B98C6260CA1","queue_name":"deferred","recipients":["a@gmail.com"],"sender":"x@mailcow.tld"},
			{"arrival_time":1794300001,"message_size":1848,"queue_id":"B98C6260CA2","queue_name":"deferred","recipients":["b@GMAIL.com","c@web.de"],"sender":"x@mailcow.tld"},
			{"arrival_time":1794300002,"message_size":1848,"queue_id":"B98C6260CA3","queue_name":"deferred","recipients":["d@t-online.de"],"sender":"x@mailcow.tld"},
			{"arrival_time":1794300003,"message_size":1848,"queue_id":"B98C6260CA4","queue_name":"active","recipients":["e@example.org"],"sender":"x@mailcow.tld"},
			{"arrival_time":1794300004,"message_size":1848,"queue_id":"B98C6260CA5","queue_name":"incoming","recipients":["f@example.org"],"sender":"x@mailcow.tld"},
			{"arrival_time":1794300005,"message_size":1848,"queue_id":"B98C6260CA6","queue_name":"hold","recipients":["g@example.org"],"sender":"x@mailcow.tld"}]`,
		"/api/v1/get/quarantine/all": `[{"created":1572688831,"id":33,"notified":1,"qid":"8224615004C1","rcpt":"admin@domain.tld","score":15.48,"sender":"b@send.domain.tld","subject":"x","virus_flag":0},
			{"created":1572688832,"id":34,"notified":1,"qid":"8224615004C2","rcpt":"admin@domain.tld","score":99,"sender":"b@send.domain.tld","subject":"y","virus_flag":1}]`,
	}}
}

func (f *fakeMailcow) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Header.Get("X-API-Key") != f.key:
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"error","msg":"authentication failed"}`))
		return
	case f.denied:
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"error","msg":"api access denied for ip 192.0.2.7"}`))
		return
	}
	f.hits[r.URL.Path]++
	body, ok := f.routes[r.URL.Path]
	if !ok {
		_, _ = w.Write([]byte(`{"type":"error","msg":"route not found"}`))
		return
	}
	_, _ = w.Write([]byte(body))
}

func mailcowFor(t *testing.T, f *fakeMailcow, key string) *Mailcow {
	t.Helper()
	addr, pin := tlsServer(t, f)
	m, err := NewMailcow(MailcowConfig{Address: addr, APIKey: " " + key + " ", Pin: pin})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}

func TestMailcowCollect(t *testing.T) {
	f := newFakeMailcow()
	m := mailcowFor(t, f, mcTestKey)
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	svcs, err := m.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", deErr(err))
	}
	if len(svcs) != 4 {
		t.Fatalf("%d Dienste", len(svcs))
	}
	// Container: jeder, der nicht laeuft, zaehlt
	c := svcByKey(t, svcs, "containers")
	if c.Kind != "ctr" || c.Metrics[0].Value != 3 || c.Metrics[1].Value != 2 || len(c.Facts) != 1 || c.Facts[0].Code != "guest_down" ||
		c.Facts[0].Text != "läuft nicht: clamd-mailcow (restarting), rspamd-mailcow (exited)" || !strings.HasPrefix(c.Text, "5 Container, 3 laufen") {
		t.Errorf("containers: %+v %q", c.Facts, c.Text)
	}
	// Mail-Speicher: Belegung aus used_percent, Groessen wie df -h
	v := svcByKey(t, svcs, "fs:vmail")
	if v.Kind != "fs" || v.Metrics[0].Value != 28 || v.Metrics[0].Rule != model.RuleFS || v.Metrics[0].Max != 41*(1<<30) || v.Metrics[1].Value != 30*(1<<30) {
		t.Errorf("vmail: %+v", v.Metrics)
	}
	// Warteschlange: zurueckgestellt traegt die Schwelle; incoming zaehlt zu aktiv; Domain des ersten Empfaengers
	q := svcByKey(t, svcs, "mailq")
	if q.Metrics[0].Name != "deferred" || q.Metrics[0].Value != 3 || q.Metrics[0].Rule != model.RuleMailQueue || q.Metrics[1].Value != 2 || q.Metrics[2].Value != 1 {
		t.Errorf("mailq: %+v", q.Metrics)
	}
	if q.Text != "3 zurückgestellt, 2 aktiv, 1 angehalten (gmail.com 2, t-online.de 1)" {
		t.Errorf("mailq Text: %q", q.Text)
	}
	qu := svcByKey(t, svcs, "quarantine")
	if qu.Metrics[0].Value != 1 || qu.Metrics[1].Value != 1 || qu.Text != "1 Spam, 1 Viren" {
		t.Errorf("quarantine: %+v %q", qu.Metrics, qu.Text)
	}
	// zweite Runde: Quarantaene nicht erneut
	now = now.Add(time.Minute)
	if _, err := m.Collect(context.Background()); err != nil {
		t.Fatal(deErr(err))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hits["/api/v1/get/status/containers"] != 2 || f.hits["/api/v1/get/mailq/all"] != 2 || f.hits["/api/v1/get/quarantine/all"] != 1 {
		t.Errorf("Abfragen: %v", f.hits)
	}
}

// Leere Listen kommen von mailcow als {} bzw. []; Fehler mit Status 200 als {"type":"error"}.
func TestMailcowEmptyAndErrors(t *testing.T) {
	f := newFakeMailcow()
	f.routes["/api/v1/get/mailq/all"] = `{}`
	f.routes["/api/v1/get/quarantine/all"] = `[]`
	delete(f.routes, "/api/v1/get/status/vmail") // {"type":"error"} mit Status 200
	m := mailcowFor(t, f, mcTestKey)
	svcs, err := m.Collect(context.Background())
	var pe *PartialError
	if !errors.As(err, &pe) || !strings.Contains(deErr(err), "status/vmail") || !strings.Contains(deErr(err), "route not found") {
		t.Fatalf("Teilfehler erwartet: %v", err)
	}
	if q := svcByKey(t, svcs, "mailq"); q.Metrics[0].Value != 0 || q.Text != "0 zurückgestellt, 0 aktiv, 0 angehalten" {
		t.Errorf("leere Warteschlange: %+v %q", q.Metrics, q.Text)
	}
	if qu := svcByKey(t, svcs, "quarantine"); qu.Metrics[0].Value != 0 {
		t.Errorf("leere Quarantaene: %+v", qu.Metrics)
	}
	// einzelnes Objekt statt Liste (wie in der API-Beschreibung)
	f.mu.Lock()
	f.routes["/api/v1/get/quarantine/all"] = `{"created":1572688831,"id":33,"virus_flag":1}`
	f.mu.Unlock()
	m2 := mailcowFor(t, f, mcTestKey)
	svcs, _ = m2.Collect(context.Background())
	if qu := svcByKey(t, svcs, "quarantine"); qu.Metrics[1].Value != 1 {
		t.Errorf("einzelnes Objekt: %+v", qu.Metrics)
	}
}

func TestMailcowTest(t *testing.T) {
	f := newFakeMailcow()
	res := deRes(mailcowFor(t, f, mcTestKey).Test(context.Background()))
	if !res.OK || res.Version != "2026-10" || !strings.HasPrefix(res.Summary, "5 Container, 3 laufen") {
		t.Errorf("Test: %+v", res)
	}
	// falscher Schluessel: Hinweis, der Schluessel steht nie im Text
	res = deRes(mailcowFor(t, f, "FALSCH-FALSCH").Test(context.Background()))
	if res.OK || !strings.Contains(res.Error, "API-Zugriff erlauben von") || strings.Contains(res.Error, "FALSCH") {
		t.Errorf("falscher Schluessel: %+v", res)
	}
	// Adresse der Node nicht erlaubt
	f.mu.Lock()
	f.denied = true
	f.mu.Unlock()
	m := mailcowFor(t, f, mcTestKey)
	res = deRes(m.Test(context.Background()))
	if res.OK || !strings.Contains(res.Error, "api access denied for ip") || !strings.Contains(res.Error, "API-Zugriff erlauben von") {
		t.Errorf("Adresse nicht erlaubt: %+v", res)
	}
	if _, err := m.Collect(context.Background()); err == nil || strings.Contains(err.Error(), mcTestKey) {
		t.Errorf("Collect ohne Zugriff: %v", err)
	}
}

func TestMailcowConfigAndSizes(t *testing.T) {
	for _, c := range []MailcowConfig{
		{Address: "https://mail.example.org", APIKey: ""},
		{Address: "http://mail.example.org", APIKey: "x"},
		{Address: "https://mail.example.org", APIKey: "a\nb"},
	} {
		if _, err := NewMailcow(c); err == nil {
			t.Errorf("%+v angenommen", c)
		}
	}
	for in, want := range map[string]float64{"41G": 41 * (1 << 30), "1.5T": 1.5 * (1 << 40), "512M": 512 * (1 << 20), "0": 0, "2,5G": 2.5 * (1 << 30), "100K": 100 * 1024} {
		if got, ok := mcSize(in); !ok || got != want {
			t.Errorf("mcSize(%q) = %v, %v", in, got, ok)
		}
	}
	if _, ok := mcSize("viel"); ok {
		t.Error("mcSize nimmt Unsinn an")
	}
	// ohne used_percent: aus den Groessen gerechnet
	if s, ok := (mcVmail{Total: "40G", Used: "10G"}).service(); !ok || s.Metrics[0].Value != 25 {
		t.Errorf("vmail ohne Prozent: %+v", s.Metrics)
	}
	if _, ok := (mcVmail{}).service(); ok {
		t.Error("leeres vmail ergibt einen Dienst")
	}
}
