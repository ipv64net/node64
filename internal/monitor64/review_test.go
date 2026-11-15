package monitor64

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Befunde aus dem Code-Review v1.5.0..d2ee60bb (Node64 1.7.2): je Punkt ein Test, der den Fehler vorher zeigt.

type rvHost struct {
	UID      string
	Accesses []struct {
		UID  string `json:"uid"`
		Type string `json:"type"`
	} `json:"accesses"`
}

func rvCreate(t *testing.T, e *testEnv, addr string, accs ...map[string]any) rvHost {
	t.Helper()
	rec := e.do("POST", "/api/monitor64/hosts", map[string]any{"name": "h-" + addr, "address": addr, "kind": "pve", "paused": true, "accesses": accs})
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var c struct{ UID string }
	decodeBody(t, rec.Body.Bytes(), &c)
	var hd rvHost
	rec = e.do("GET", "/api/monitor64/hosts/"+c.UID, nil)
	decodeBody(t, rec.Body.Bytes(), &hd)
	hd.UID = c.UID
	return hd
}

// Review 1: Wechsel der Art zu SNMP ohne neues Geheimnis behielt das alte (z. B. PVE-Token) und schickte es als
// v2c-Community im Klartext. SNMP zu SNMP darf das Geheimnis behalten.
func TestReviewSNMPTypeChangeNeedsSecret(t *testing.T) {
	e := newEnv(t)
	h := rvCreate(t, e, "192.0.2.50", map[string]any{"type": "pve", "config": map[string]any{"url": "https://192.0.2.50:8006", "token_id": "m@pve!n"}, "secret": "pve-token-geheim"})
	acc := h.Accesses[0].UID
	before := e.col(`SELECT secret FROM m64_access WHERE uid = ?`, acc)
	rec := e.do("PUT", "/api/monitor64/access/"+acc, map[string]any{"type": "snmp", "config": map[string]any{"snmp_version": "2c"}})
	if rec.Code == 200 {
		t.Fatalf("pve -> snmp ohne Geheimnis angenommen: %s", rec.Body)
	}
	if e.col(`SELECT type FROM m64_access WHERE uid = ?`, acc) != "pve" || e.col(`SELECT secret FROM m64_access WHERE uid = ?`, acc) != before {
		t.Fatal("Zugang trotz Ablehnung geaendert")
	}
	// mit neuer Community: ok, und das alte Geheimnis steckt nicht darin
	rec = e.do("PUT", "/api/monitor64/access/"+acc, map[string]any{"type": "snmp", "config": map[string]any{"snmp_version": "2c"}, "secret": `{"community":"neu-public"}`})
	if rec.Code != 200 {
		t.Fatalf("pve -> snmp mit Community: %d %s", rec.Code, rec.Body)
	}
	plain, err := e.m.box.Decrypt(e.col(`SELECT secret FROM m64_access WHERE uid = ?`, acc))
	if err != nil || plain == "" || strings.Contains(plain, "pve-token") {
		t.Fatalf("Geheimnis nach dem Wechsel: %q %v", plain, err)
	}
	// SNMP zu SNMP (Port geaendert) ohne Geheimnis: bleibt
	rec = e.do("PUT", "/api/monitor64/access/"+acc, map[string]any{"type": "snmp", "config": map[string]any{"snmp_version": "2c", "port": 1161}})
	if rec.Code != 200 {
		t.Fatalf("snmp -> snmp: %d %s", rec.Code, rec.Body)
	}
}

// Review 2: Neue Host-Adresse leitete gespeicherte Geheimnisse von Zugaengen ohne eigene Adresse an das neue Ziel
// (SNMP-Community, Unraid-Key per http, PVE ohne Pin ...). Gebundene Ziele (Pin, Hostschluessel) duerfen bleiben.
func TestReviewAddressChangeSecrets(t *testing.T) {
	e := newEnv(t)
	h := rvCreate(t, e, "192.0.2.60",
		map[string]any{"type": "snmp", "config": map[string]any{"snmp_version": "2c"}, "secret": `{"community":"geheim-comm"}`},
		map[string]any{"type": "pve", "config": map[string]any{"token_id": "m@pve!n", "pin": "aa" + strings.Repeat("0", 62)}, "secret": "pve-token-gebunden"},
		map[string]any{"type": "pbs", "config": map[string]any{"token_id": "m@pbs!n", "url": "https://192.0.2.60:8007"}, "secret": "pbs-eigene-url"})
	upd := map[string]any{"name": "h-192.0.2.60", "address": "192.0.2.99", "kind": "pve", "paused": true}
	rec := e.do("PUT", "/api/monitor64/hosts/"+h.UID, upd)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "address_secret") {
		t.Fatalf("neue Adresse ohne Bestaetigung: %d %s", rec.Code, rec.Body)
	}
	if e.col(`SELECT address FROM m64_hosts WHERE uid = ?`, h.UID) != "192.0.2.60" {
		t.Fatal("Adresse trotz Ablehnung geaendert")
	}
	upd["clear_secrets"] = true
	if rec := e.do("PUT", "/api/monitor64/hosts/"+h.UID, upd); rec.Code != 200 {
		t.Fatalf("mit Bestaetigung: %d %s", rec.Code, rec.Body)
	}
	for _, a := range h.Accesses {
		sec := e.col(`SELECT secret FROM m64_access WHERE uid = ?`, a.UID)
		if want := a.Type != "snmp"; (sec != "") != want {
			t.Errorf("%s: Geheimnis vorhanden=%v, erwartet %v", a.Type, sec != "", want)
		}
	}
	// gleiche Adresse (z. B. Pause): keine Rueckfrage
	delete(upd, "clear_secrets")
	upd["paused"] = false
	if rec := e.do("PUT", "/api/monitor64/hosts/"+h.UID, upd); rec.Code != 200 {
		t.Fatalf("ohne Adressaenderung: %d %s", rec.Code, rec.Body)
	}
}

// Review 4: "Fingerabdruck uebernehmen" nach dem Test schickt nur den Pin (ohne Geheimnis) - wurde immer mit
// secret_again abgelehnt. Erstmals einen Pin setzen bindet das Ziel enger und behaelt das Geheimnis; einen
// vorhandenen Pin aendern verlangt es weiter.
func TestReviewPinConfirmKeepsSecret(t *testing.T) {
	e := newEnv(t)
	h := rvCreate(t, e, "192.0.2.70", map[string]any{"type": "pve", "config": map[string]any{"url": "https://192.0.2.70:8006", "token_id": "m@pve!n"}, "secret": "pve-token-geheim"})
	acc := h.Accesses[0].UID
	sec := e.col(`SELECT secret FROM m64_access WHERE uid = ?`, acc)
	pin1, pin2 := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	rec := e.do("PUT", "/api/monitor64/access/"+acc, map[string]any{"config": map[string]any{"url": "https://192.0.2.70:8006", "token_id": "m@pve!n", "pin": pin1}})
	if rec.Code != 200 || e.col(`SELECT secret FROM m64_access WHERE uid = ?`, acc) != sec {
		t.Fatalf("Pin setzen: %d %s", rec.Code, rec.Body)
	}
	rec = e.do("PUT", "/api/monitor64/access/"+acc, map[string]any{"config": map[string]any{"url": "https://192.0.2.70:8006", "token_id": "m@pve!n", "pin": pin2}})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "secret_again") {
		t.Fatalf("Pin aendern ohne Geheimnis: %d %s", rec.Code, rec.Body)
	}
	rec = e.do("PUT", "/api/monitor64/access/"+acc, map[string]any{"config": map[string]any{"url": "https://192.0.2.70:8006", "token_id": "m@pve!n", "pin": pin2}, "secret": "neues-token"})
	if rec.Code != 200 {
		t.Fatalf("Pin aendern mit Geheimnis: %d %s", rec.Code, rec.Body)
	}
	// neue URL mit Pin: weiter nur mit Geheimnis
	rec = e.do("PUT", "/api/monitor64/access/"+acc, map[string]any{"config": map[string]any{"url": "https://192.0.2.71:8006", "token_id": "m@pve!n", "pin": pin2}})
	if rec.Code != 400 {
		t.Fatalf("neue URL ohne Geheimnis: %d %s", rec.Code, rec.Body)
	}
}

// Review 5: callSmart fehlte in ClusterCalls - der SMART-Dialog auf einer nicht zustaendigen Node lief ins 404. Jede
// Anfrage, die HandleClusterCall beantwortet, muss erlaubt sein.
func TestReviewClusterCallsComplete(t *testing.T) {
	vals := map[string]string{}
	files, _ := filepath.Glob("*.go")
	reConst := regexp.MustCompile(`(?m)^\s*(call[A-Z]\w*)\s*=\s*"([^"]+)"`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, m := range reConst.FindAllStringSubmatch(string(b), -1) {
			vals[m[1]] = m[2]
		}
	}
	b, err := os.ReadFile("cluster_series.go")
	if err != nil {
		t.Fatal(err)
	}
	cases := regexp.MustCompile(`case (call[A-Z]\w*):`).FindAllStringSubmatch(string(b), -1)
	if len(cases) < 5 {
		t.Fatalf("nur %d Faelle gefunden", len(cases))
	}
	for _, c := range cases {
		v, ok := vals[c[1]]
		if !ok || !slices.Contains(ClusterCalls, v) {
			t.Errorf("%s (%q) beantwortet, aber nicht in ClusterCalls", c[1], v)
		}
	}
}

// Review 6: Hier neuer ist das Aufheben einer Quittierung (ack leer) - ein aelterer, noch quittierter Stand einer
// anderen Node drehte es zurueck (und verteilte die Quittierung wieder).
func TestReviewClusterUnackLocalNewer(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	uid := "probUID0000000001"
	t1, t2 := "2026-11-15T10:00:00.000Z", "2026-11-15T10:05:00.000Z"
	if _, err := m.st.Writer().Exec(`INSERT INTO m64_problems (uid, node_id, host_uid, service_key, state, worst, opened_at, ack, updated_at)
		VALUES (?, 'nodeA', 'hostUID000000001', 'cpu', 'warn', 'warn', ?, '', ?)`, uid, t1, t2); err != nil {
		t.Fatal(err)
	}
	in, _ := json.Marshal(problemEntry{Node: "nodeA", Host: "hostUID000000001", Key: "cpu", State: "warn", Worst: "warn", Opened: t1,
		Ack: `{"by":{"kind":"user","name":"dennis"},"at":"` + t1 + `"}`, Updated: t1, Notified: []string{}})
	if err := m.problemApply(ctx, uid, in, false); err != nil {
		t.Fatal(err)
	}
	p, err := m.problemRow(ctx, uid)
	if err != nil || p == nil {
		t.Fatal(err)
	}
	if p.Ack != "" || p.Updated != t2 {
		t.Fatalf("Aufheben der Quittierung zurueckgedreht: ack=%q updated=%s", p.Ack, p.Updated)
	}
}

// Review 7: Fehlt ein Wert mit Warnung/Kritisch drei Intervalle, wurde der Tracker geloescht und der Dienst gruen
// (Entwarnung ohne Erholung). Nur ein gestoppter Dienst (running = 0: VM/Container aus) laesst Werte gewollt weg;
// laeuft er, wird der fehlende Wert "unbekannt".
func TestReviewMissingMetricRunningIsUnknown(t *testing.T) {
	for _, c := range []struct {
		name    string
		running float64
		want    eval.State
	}{{"laeuft", 1, eval.Unknown}, {"gestoppt", 0, eval.OK}} {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			m, _, _ := newTestModule(t)
			if err := m.Start(ctx); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = m.Stop(ctx) })
			hot := model.Metric{Name: "cpu", Value: 99, Unit: "%", Rule: model.RuleCPU}
			run := model.Metric{Name: "running", Value: 1}
			fake := &fakeCol{svcs: []model.Service{svc("vm:101", "vm", run, hot)}}
			rt := hostWithFake(t, m, fake)
			m.poll(ctx, rt)
			adoptAll(t, m, rt.host.UID)
			m.poll(ctx, rt)
			tr := rt.Trackers["vm:101|cpu"]
			if tr == nil {
				t.Fatal("kein Tracker")
			}
			tr.Level, tr.Changed = eval.Crit, time.Now().Add(-time.Hour)
			tr.WarnSince, tr.CritSince = time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)
			m.poll(ctx, rt)
			if st := svcState(rt, "vm:101"); st != eval.Crit {
				t.Fatalf("erwartet kritisch, %v", st)
			}
			// drei Intervalle ohne CPU-Wert
			fake.set([]model.Service{svc("vm:101", "vm", model.Metric{Name: "running", Value: c.running})}, nil)
			rt.mu.Lock()
			rt.Trackers["vm:101|cpu"].LastAt = time.Now().Add(-5 * time.Minute)
			rt.mu.Unlock()
			m.poll(ctx, rt)
			if st := svcState(rt, "vm:101"); st != c.want {
				t.Fatalf("Dienst nach fehlendem Wert: %v, erwartet %v", st, c.want)
			}
		})
	}
}

// Review 13 (#159 auch per SSH): Die Updates kamen fest stuendlich. Meldet das Skript einen neuen Stand der
// Paketdatenbank, sind sie fruehestens eine Minute nach dem letzten Lauf wieder faellig.
func TestReviewSSHUpdatesDue(t *testing.T) {
	t0 := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name             string
		after            time.Duration
		stamp, lastStamp string
		want             bool
	}{
		{"unveraendert", 10 * time.Minute, "a", "a", false},
		{"geaendert", 2 * time.Minute, "b", "a", true},
		{"geaendert, zu frueh", 30 * time.Second, "b", "a", false},
		{"ohne Stand", 10 * time.Minute, "", "a", false},
		{"erster Stand", 10 * time.Minute, "a", "", false},
		{"Stunde um", time.Hour, "a", "a", true},
	} {
		if got := updatesDue(t0.Add(c.after), t0, c.stamp, c.lastStamp); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

// Review 14: Hostnamen nach RFC 1123 statt Sonderregel fuer Ziffern und Punkte.
func TestReviewHostnameRFC1123(t *testing.T) {
	for _, bad := range []string{"-nas", "nas-", "nas..lan", ".nas", "nas.-lan", "host.123", strings.Repeat("a", 64) + ".lan",
		strings.Repeat("a.", 127) + "aa", "na$s", "nas:22:", "1.2.3", "nas.lan.:22x"} {
		if got, ok := cleanAddress(bad); ok {
			t.Errorf("%q angenommen als %q", bad, got)
		}
	}
	for _, good := range []string{"nas", "nas.lan", "nas.lan.", "1und1.example", "host-10.lan", "my_nas", "a.b-c.d", strings.Repeat("a", 63) + ".lan",
		"10.0.0.5", "nas.lan:2222", "xn--mnchen-3ya.de"} {
		if _, ok := cleanAddress(good); !ok {
			t.Errorf("%q abgelehnt", good)
		}
	}
}
