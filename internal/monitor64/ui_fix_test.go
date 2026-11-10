package monitor64

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Tests zu den Review-Funden in Oberflaeche und API (F9, F10, F6-K8, F11-K5).

// setView legt den Stand eines Hosts fest (ohne Abfrage), wie ihn der Kern nach einer Runde haette.
func (e *testEnv) setView(h *Host, svcs ...SvcView) {
	e.t.Helper()
	rt := &hostRT{host: h}
	rt.setView(&HostView{Host: h, Checked: time.Now(), Services: svcs})
	e.m.rtMu.Lock()
	if e.m.rts == nil {
		e.m.rts = map[string]*hostRT{}
	}
	e.m.rts[h.UID] = rt
	e.m.rtMu.Unlock()
}

func metricView(name string, v float64, unit, rule string) MetricView {
	return MetricView{Metric: model.Metric{Name: name, Value: v, Unit: unit, Rule: rule}, RuleKind: rule}
}

// F9-K3: nicht kodierbare Antwort (NaN) -> 500 mit Fehlercode statt 200 mit abgebrochenem Koerper.
func TestWriteJSONEncodeError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]float64{"v": math.NaN()})
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), `"error":"internal"`) {
		t.Fatalf("NaN: %d %q", rec.Code, rec.Body.String())
	}
	var x map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &x); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	rec = httptest.NewRecorder()
	writeJSON(rec, http.StatusCreated, map[string]int{"a": 1})
	if rec.Code != http.StatusCreated || strings.TrimSpace(rec.Body.String()) != `{"a":1}` {
		t.Fatalf("ok: %d %q", rec.Code, rec.Body.String())
	}
}

// F9-K5: Host entfernen schliesst seine offenen Probleme (mit Akteur).
func TestHostDeleteClosesProblems(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := &Host{Name: "alt01", Address: "10.0.0.9", IntervalSec: 60, Paused: true}
	if err := e.m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.st.Writer().Exec(`INSERT INTO m64_problems (uid, host_uid, service_key, state, worst, opened_at, closed_at, closed_how, closed_by, updated_at) VALUES ('px', ?, 'fs:/', 'warn', 'warn', ?, '', '', '', ?)`,
		h.UID, tsNow(), tsNow()); err != nil {
		t.Fatal(err)
	}
	if rec := e.do("DELETE", "/api/monitor64/hosts/"+h.UID, nil); rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if c := e.col(`SELECT closed_at FROM m64_problems WHERE uid = 'px'`); c == "" {
		t.Fatal("problem of removed host still open")
	}
	if by := e.col(`SELECT closed_by FROM m64_problems WHERE uid = 'px'`); !strings.Contains(by, "dennis") {
		t.Fatalf("closed_by: %s", by)
	}
	if n := e.m.store.openUnackedCount(ctx); n != 0 {
		t.Fatalf("open count: %d", n)
	}
}

// F7-K8/F9-K1: Stufe "dieser Host" je Regel-Art: eigener Block je Messgroesse, Speichern je Art, Pruefung je Art.
func TestServiceRulesPerKind(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := &Host{Name: "nas02", Address: "10.0.0.22", Kind: "ssh", IntervalSec: 60, Paused: true}
	if err := e.m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	found := []model.Service{{Key: "disk:S1", Name: "sda", Kind: "disk"}, {Key: "disk:S2", Name: "sdb", Kind: "disk"}}
	if _, err := e.m.store.UpsertDiscovered(ctx, h.UID, found, map[string]bool{"disk:S1": true, "disk:S2": true}, SystemActor); err != nil {
		t.Fatal(err)
	}
	disk := func(key, name string) SvcView {
		return SvcView{Key: key, Name: name, Kind: "disk", Adopted: 1, Metrics: []MetricView{metricView("temp", 41, "°C", eval.KindDiskTemp), metricView("wear", 12, "%", eval.KindSSDWear)}}
	}
	e.setView(h, disk("disk:S1", "sda"), disk("disk:S2", "sdb"))
	base := "/api/monitor64/hosts/" + h.UID + "/service"
	// zwei Arten in einem Aufruf, nur dieser Dienst
	rec := e.do("PUT", base, map[string]any{"key": "disk:S1", "rules": map[string]any{
		"disk.temp": map[string]any{"rule": map[string]any{"warn": 50, "crit": 60}},
		"ssd.wear":  map[string]any{"rule": map[string]any{"warn": 85}},
	}})
	if rec.Code != 200 {
		t.Fatalf("rules: %d %s", rec.Code, rec.Body)
	}
	if hr := e.col(`SELECT host_rule FROM m64_services WHERE host_uid = ? AND key = 'disk:S1'`, h.UID); hr != `{"disk.temp":{"warn":50,"crit":60},"ssd.wear":{"warn":85}}` {
		t.Fatalf("host_rule: %s", hr)
	}
	// nur eine Art aendern: die andere bleibt
	if rec := e.do("PUT", base, map[string]any{"key": "disk:S1", "rules": map[string]any{"ssd.wear": map[string]any{"rule": nil}}}); rec.Code != 200 {
		t.Fatalf("remove wear: %d %s", rec.Code, rec.Body)
	}
	if hr := e.col(`SELECT host_rule FROM m64_services WHERE host_uid = ? AND key = 'disk:S1'`, h.UID); hr != `{"disk.temp":{"warn":50,"crit":60}}` {
		t.Fatalf("host_rule after removing one kind: %s", hr)
	}
	// Pruefung je Art (eigene Warnung 99 liegt ueber dem geerbten Kritisch von disk.temp)
	if rec := e.do("PUT", base, map[string]any{"key": "disk:S2", "rules": map[string]any{"disk.temp": map[string]any{"rule": map[string]any{"warn": 99}}}}); rec.Code != 400 || !strings.Contains(rec.Body.String(), `"error":"rule_kind"`) {
		t.Fatalf("order per kind: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("PUT", base, map[string]any{"key": "disk:S2", "rules": map[string]any{"nope.kind": map[string]any{"rule": map[string]any{"warn": 1}}}}); rec.Code != 400 {
		t.Fatalf("unknown kind: %d", rec.Code)
	}
	if rec := e.do("PUT", base, map[string]any{"key": "disk:S2", "rules": map[string]any{"disk.temp": map[string]any{"rule": map[string]any{"warn": 1}, "scope": "all"}}}); rec.Code != 400 {
		t.Fatalf("bad scope: %d", rec.Code)
	}
	// alle Dienste dieses Hosts mit der Art: Einstellung nur dieses Dienstes fuer die Art weicht
	if rec := e.do("PUT", base, map[string]any{"key": "disk:S1", "rules": map[string]any{"disk.temp": map[string]any{"rule": map[string]any{"warn": 45, "crit": 52}, "scope": "kind"}}}); rec.Code != 200 {
		t.Fatalf("kind scope: %d %s", rec.Code, rec.Body)
	}
	if hr := e.col(`SELECT host_rule FROM m64_services WHERE host_uid = ? AND key = 'disk:S1'`, h.UID); hr != "" {
		t.Fatalf("service rule should give way: %s", hr)
	}
	if r := e.col(`SELECT rule FROM m64_host_rules WHERE host_uid = ? AND kind = 'disk.temp' AND deleted = 0`, h.UID); r != `{"warn":45,"crit":52}` {
		t.Fatalf("host kind rule: %s", r)
	}
	// Host-Seite: je Messgroesse ein Block; die Art-Regel gilt auch fuer den zweiten Dienst, ssd.wear nicht
	var hd hostDetail
	decodeBody(t, e.do("GET", "/api/monitor64/hosts/"+h.UID, nil).Body.Bytes(), &hd)
	if len(hd.Services) != 2 {
		t.Fatalf("services: %d", len(hd.Services))
	}
	for _, s := range hd.Services {
		// erst die Messgroessen, dann die Zustandsregeln der Art (SMART)
		if len(s.Rules) != 2+len(factKinds["disk"]) || s.Rules[0].Kind != eval.KindDiskTemp || s.Rules[0].Metric != "temp" || s.Rules[1].Kind != eval.KindSSDWear || !s.Rules[2].State {
			t.Fatalf("rules of %s: %d", s.Key, len(s.Rules))
		}
		if s.Rules[0].HostKind == nil || s.Rules[0].Eff.Warn.V != 45 || s.Rules[0].Eff.Origin["warn"] != eval.StageHostKind {
			t.Fatalf("kind rule not applied to %s: %+v", s.Key, s.Rules[0].Eff)
		}
		if s.Rules[1].HostKind != nil || s.Rules[1].Service != nil {
			t.Fatalf("wear must not inherit the temp rule: %+v", s.Rules[1])
		}
		if s.Levels == nil || s.Levels.Kind != eval.KindDiskTemp || s.Primary != 0 {
			t.Fatalf("primary: %d %+v", s.Primary, s.Levels)
		}
	}
	// Schwellen-Seite: "am Host eingestellt" je Art
	var rules struct {
		Own []ownOut `json:"own"`
	}
	decodeBody(t, e.do("GET", "/api/monitor64/rules", nil).Body.Bytes(), &rules)
	if len(rules.Own) != 1 || rules.Own[0].Kind != eval.KindDiskTemp || rules.Own[0].Key != "" {
		t.Fatalf("own: %+v", rules.Own)
	}
	// auf Standard zurueck fuer eine Art
	if rec := e.do("PUT", base, map[string]any{"key": "disk:S2", "rules": map[string]any{"disk.temp": map[string]any{"reset": true}}}); rec.Code != 200 {
		t.Fatalf("reset kind: %d %s", rec.Code, rec.Body)
	}
	if n := e.col(`SELECT COUNT(*) FROM m64_host_rules WHERE host_uid = ? AND deleted = 0`, h.UID); n != "0" {
		t.Fatalf("reset kind rule: %s", n)
	}
	// Zustandsregeln eines Dienstes ohne doppelte guest.down (F9 schwach)
	ctr := []model.Service{{Key: "ctr:web", Name: "web", Kind: "ctr"}}
	if _, err := e.m.store.UpsertDiscovered(ctx, h.UID, ctr, map[string]bool{"ctr:web": true}, SystemActor); err != nil {
		t.Fatal(err)
	}
	e.setView(h, SvcView{Key: "ctr:web", Name: "web", Kind: "ctr", Adopted: 1})
	decodeBody(t, e.do("GET", "/api/monitor64/hosts/"+h.UID, nil).Body.Bytes(), &hd)
	seen := map[string]int{}
	for _, l := range hd.Services[0].Rules {
		seen[l.Kind]++
		if !l.State {
			t.Fatalf("state rule expected: %+v", l)
		}
	}
	if seen[eval.KindGuestDown] != 1 || seen[eval.KindCtrUnhealthy] != 1 {
		t.Fatalf("state kinds: %v", seen)
	}
	if rec := e.do("PUT", base, map[string]any{"key": "ctr:web", "rules": map[string]any{"guest.down": map[string]any{"rule": map[string]any{"severity": "warn"}}}}); rec.Code != 200 {
		t.Fatalf("state rule: %d %s", rec.Code, rec.Body)
	}
	if hr := e.col(`SELECT host_rule FROM m64_services WHERE host_uid = ? AND key = 'ctr:web'`, h.UID); hr != `{"guest.down":{"severity":"warn"}}` {
		t.Fatalf("state host_rule: %s", hr)
	}
}

// F9-K7: Vorschau rechnet wie eval.Resolve – eine eigene Host-Schwelle erbt feldweise, "vorher" und "danach"
// beide ohne Dauer.
func TestEffectPreviewInherits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	mk := func(name string, used float64, rule string) *Host {
		h := &Host{Name: name, Address: "10.0.0.1", Tags: []string{"backup"}, IntervalSec: 60, Paused: true}
		if err := e.m.store.SaveHost(ctx, h, SystemActor); err != nil {
			t.Fatal(err)
		}
		if _, err := e.m.store.UpsertDiscovered(ctx, h.UID, []model.Service{{Key: "fs:/", Name: "/", Kind: "fs"}}, map[string]bool{"fs:/": true}, SystemActor); err != nil {
			t.Fatal(err)
		}
		if rule != "" {
			if err := e.m.store.UpdateService(ctx, h.UID, "fs:/", svcPatch{HostRule: &rule}, SystemActor); err != nil {
				t.Fatal(err)
			}
		}
		mv := metricView("used", used, "%", eval.KindFSUsed)
		mv.Status = eval.Status{Level: eval.Crit} // Tracker-Stand darf die Vorschau nicht beeinflussen
		e.setView(h, SvcView{Key: "fs:/", Name: "/", Kind: "fs", Adopted: 1, Metrics: []MetricView{mv}})
		return h
	}
	mk("a", 92, "")                                  // nur Abweichung
	mk("b", 92, `{"fs.used":{"warn":91}}`)           // eigene Warnung, Kritisch aus der Abweichung
	mk("c", 92, `{"fs.used":{"warn":70,"crit":80}}`) // alles am Host: Abweichung wirkt nicht
	mk("d", 92, `{"disk.temp":{"warn":10}}`)         // Regel einer anderen Art: Abweichung wirkt
	list := []eval.Override{{ID: "o", Tag: "backup", Kind: eval.KindFSUsed, Rule: eval.Rule{Warn: eval.L(95), Crit: eval.L(98)}}}
	ef := e.m.effectOf(ctx, eval.Defaults(), nil, list, 0)
	if ef.Services != 3 || len(ef.Own) != 1 || ef.Own[0] != "c" {
		t.Fatalf("effect: %+v", ef)
	}
	// vorher (Standard 80/90): a, d kritisch (92), b kritisch; danach: a, d OK, b Warnung (eigene 91)
	if ef.Before.Crit != 3 || ef.Before.Warn != 0 || ef.After.Warn != 1 || ef.After.Crit != 0 {
		t.Fatalf("before/after: %+v / %+v", ef.Before, ef.After)
	}
}

// F6-K8/F9-K6 und kleinere: Zugaenge (hostkey reset per PUT, PUT ohne config, Docker ssh://, Pin, Geheimnis-Grenzen).
func TestAccessUpdateRules(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := &Host{Name: "dock01", Address: "10.0.0.30", Kind: "docker", IntervalSec: 60, Paused: true}
	if err := e.m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + strings.Repeat("A", 6000) + "\n-----END OPENSSH PRIVATE KEY-----"
	rec := e.do("POST", "/api/monitor64/hosts/"+h.UID+"/access", map[string]any{"type": "docker", "config": map[string]any{"url": "ssh://monitor@10.0.0.30", "pin": "SHA256:" + strings.Repeat("a", 43)}, "secret": pem})
	if rec.Code != http.StatusCreated {
		t.Fatalf("docker ssh: %d %s", rec.Code, rec.Body)
	}
	var a accessOut
	decodeBody(t, rec.Body.Bytes(), &a)
	if rec := e.do("POST", "/api/monitor64/hosts/"+h.UID+"/access", map[string]any{"type": "docker", "secret": strings.Repeat("x", 70<<10)}); rec.Code != 400 {
		t.Fatalf("docker secret limit: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/monitor64/hosts/"+h.UID+"/access", map[string]any{"type": "pve", "secret": strings.Repeat("x", 5000)}); rec.Code != 400 {
		t.Fatalf("pve secret limit: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/monitor64/hosts/"+h.UID+"/access", map[string]any{"type": "pve", "config": map[string]any{"pin": "SHA256:kurz"}}); rec.Code != 400 {
		t.Fatalf("bad pin: %d", rec.Code)
	}
	// PUT ohne config: Felder bleiben
	if rec := e.do("PUT", "/api/monitor64/access/"+a.UID, map[string]any{"enabled": false}); rec.Code != 200 {
		t.Fatalf("put without config: %d %s", rec.Code, rec.Body)
	}
	if c := e.col(`SELECT config FROM m64_access WHERE uid = ?`, a.UID); !strings.Contains(c, "ssh://monitor@10.0.0.30") || !strings.Contains(c, "SHA256:") {
		t.Fatalf("config lost: %s", c)
	}
	// hostkey "reset" per PUT
	if _, err := e.m.st.Writer().Exec(`UPDATE m64_access SET hostkey = 'SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG' WHERE uid = ?`, a.UID); err != nil {
		t.Fatal(err)
	}
	if rec := e.do("PUT", "/api/monitor64/access/"+a.UID, map[string]any{"hostkey": "reset"}); rec.Code != 200 {
		t.Fatalf("hostkey reset: %d %s", rec.Code, rec.Body)
	}
	if hk := e.col(`SELECT hostkey FROM m64_access WHERE uid = ?`, a.UID); hk != "" {
		t.Fatalf("hostkey not reset: %s", hk)
	}
	if rec := e.do("POST", "/api/monitor64/hosts/"+h.UID+"/access", map[string]any{"type": "agent", "hostkey": "reset"}); rec.Code != 400 {
		t.Fatalf("reset on create: %d", rec.Code)
	}
}

// F6-K8: "Verbindung testen" fuer API-Zugaenge nutzt apis.Test: unbekanntes Zertifikat -> Fingerabdruck zum
// Bestaetigen, kein Token gesendet, keine Dienste.
func TestAPIAccessTestNeedsConfirm(t *testing.T) {
	e := newEnv(t)
	gotToken := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			gotToken = true
		}
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer srv.Close()
	var res testResult
	rec := e.do("POST", "/api/monitor64/test", map[string]any{"address": "127.0.0.1", "access": map[string]any{"type": "pve", "config": map[string]any{"url": srv.URL, "token_id": "monitor@pve!node64"}, "secret": "geheim"}})
	decodeBody(t, rec.Body.Bytes(), &res)
	if rec.Code != 200 || res.OK || !res.NeedConfirm || res.Fingerprint == "" || len(res.Services) != 0 {
		t.Fatalf("test: %d %+v", rec.Code, res)
	}
	if gotToken {
		t.Fatal("token sent to an unconfirmed certificate")
	}
	if strings.Contains(rec.Body.String(), "geheim") {
		t.Fatal("secret in answer")
	}
}

// F10-K7/F9-K8: Wartung in der Zeitzone der Node; erneutes Speichern verschiebt nichts.
func TestMaintLocalTimes(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.m.st.SetSetting(ctx, "node.timezone", "America/New_York"); err != nil {
		t.Fatal(err)
	}
	h := &Host{Name: "x1", Address: "10.0.0.2", IntervalSec: 60, Paused: true}
	if err := e.m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"title": "Plan", "hosts": []string{h.UID}, "mode": "plan", "start": "2030-01-10T22:00", "end": "2030-01-10T23:30"}
	var mu struct{ UID string }
	decodeBody(t, e.do("POST", "/api/monitor64/maintenance", body).Body.Bytes(), &mu)
	var ml struct {
		Items []maintOut `json:"items"`
		TZ    string     `json:"tz"`
		Now   string     `json:"now_local"`
	}
	decodeBody(t, e.do("GET", "/api/monitor64/maintenance", nil).Body.Bytes(), &ml)
	if ml.TZ != "America/New_York" || len(ml.Now) != len(localMinute) || len(ml.Items) != 1 || ml.Items[0].StartLocal != "2030-01-10T22:00" || ml.Items[0].EndLocal != "2030-01-10T23:30" {
		t.Fatalf("maint: %+v", ml)
	}
	if !ml.Items[0].Start.Equal(time.Date(2030, 1, 11, 3, 0, 0, 0, time.UTC)) {
		t.Fatalf("start instant: %v", ml.Items[0].Start)
	}
	// erneut speichern mit den gelieferten Werten
	body["start"], body["end"] = ml.Items[0].StartLocal, ml.Items[0].EndLocal
	if rec := e.do("PUT", "/api/monitor64/maintenance/"+mu.UID, body); rec.Code != 200 {
		t.Fatalf("resave: %d %s", rec.Code, rec.Body)
	}
	decodeBody(t, e.do("GET", "/api/monitor64/maintenance", nil).Body.Bytes(), &ml)
	if ml.Items[0].StartLocal != "2030-01-10T22:00" {
		t.Fatalf("shifted: %s", ml.Items[0].StartLocal)
	}
	// Wartungsende erscheint unter "Zuletzt"
	decodeBody(t, e.do("POST", "/api/monitor64/maintenance", map[string]any{"title": "Jetzt", "hosts": []string{h.UID}, "mode": "now"}).Body.Bytes(), &mu)
	if rec := e.do("POST", "/api/monitor64/maintenance/"+mu.UID+"/end", nil); rec.Code != 200 {
		t.Fatalf("end: %d", rec.Code)
	}
	ov := e.m.overview(ctx)
	if len(ov.Recent) == 0 || ov.Recent[0].Kind != "maint_end" {
		t.Fatalf("recent: %+v", ov.Recent)
	}
	if tzLabel(time.FixedZone("", 3600), time.Now()) != "UTC+01:00" {
		t.Fatal(tzLabel(time.FixedZone("", 3600), time.Now()))
	}
}

// F11-K5 und F10-K6: neue Zustandsarten einstellbar; Windows "kommt bald". Seit Runde 3 bietet die Node die
// Agent-Dateien selbst an: das Skript darf auf /monitor64/agent/ zeigen, weil es die Route gibt (agentdist.go).
func TestUIMetaPhase(t *testing.T) {
	for _, k := range []string{eval.KindCtrUnhealthy, eval.KindBackupOld, eval.KindJobFailed, eval.KindStoreInactive, eval.KindClusterQuorum, eval.KindClusterNodeDown, eval.KindHAError, eval.KindCephWarn, eval.KindCephErr, eval.KindAccessFailed, eval.KindFSTrendDays} {
		if _, ok := ruleKindOf(k); !ok {
			t.Errorf("rule kind %s missing", k)
		}
	}
	if k, _ := hostKindOf("windows"); k.Soon { // Windows-Agent seit Phase 2
		t.Error("windows must not be 'soon'")
	}
	if !strings.Contains(string(bundleJS), "'/monitor64/agent/'") {
		t.Error("script does not offer the agent files of this node (/monitor64/agent/)")
	}
	if !strings.Contains(string(bundleJS), "smartctl -j -a -n standby /dev/*") || strings.Contains(string(bundleJS), "NOPASSWD: /usr/sbin/smartctl')") {
		t.Error("sudoers line not restricted")
	}
	e := newEnv(t)
	body := e.do("GET", "/monitor64/new", nil).Body.String()
	mustContain(t, "new", body, `kind-tile" data-kind="windows"`)
	mustContain(t, "new", body, `kind-tile" data-kind="snmp"`) // SNMP seit Phase 2
	mustContain(t, "new", body, `kind-tile" data-kind="nas"`)
	if strings.Contains(body, "kind-tile disabled") {
		t.Error("no host kind may be 'soon' any more")
	}
	set := e.do("GET", "/monitor64/settings", nil).Body.String()
	mustContain(t, "settings", set, `href="/monitor64/agent" id="m64-agent-link"`) // Verweis auf die Seite Agent
	mustContain(t, "settings", set, `id="m64-trap-port"`)
	mustContain(t, "settings", set, `id="m64-traps"`)
	pb := e.do("GET", "/monitor64/problems", nil).Body.String()
	mustContain(t, "problems", pb, `pb-table" data-nosort`)
	// Texte des Kerns stehen dem Skript zur Verfuegung
	var d map[string]any
	ov := e.do("GET", "/monitor64", nil).Body.String()
	i := strings.Index(ov, `id="m64-data">`)
	j := strings.Index(ov[i:], "</script>")
	if i < 0 || j < 0 {
		t.Fatal("no m64-data")
	}
	if err := json.Unmarshal([]byte(ov[i+len(`id="m64-data">`):i+j]), &d); err != nil {
		t.Fatal(err)
	}
	tx, _ := d["t"].(map[string]any)
	for _, k := range coreTexts {
		if _, ok := tx[k]; !ok {
			t.Errorf("core text %s not passed to the script", k)
		}
	}
}

// UI8: jeder Fehlercode der API (errBad/apiError im Paket) hat einen Text in beiden Sprachen; sonst zeigt die
// Oberflaeche nur den Schluessel und das Detail ({error}) geht verloren.
func TestErrTextsComplete(t *testing.T) {
	b, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?:errBad\(|code:\s*)"([a-z0-9_]+)"`)
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]string{}
	for _, en := range ents {
		if en.IsDir() || !strings.HasSuffix(en.Name(), ".go") || strings.HasSuffix(en.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(en.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, mm := range re.FindAllSubmatch(raw, -1) {
			codes[string(mm[1])] = en.Name()
		}
	}
	if len(codes) < 40 {
		t.Fatalf("only %d error codes found", len(codes))
	}
	for _, lang := range []string{"de", "en"} {
		for c, file := range codes {
			if k := "monitor64.err." + c; b.T(lang, k) == k {
				t.Errorf("%s: missing %s (%s)", lang, k, file)
			}
		}
	}
	// Detail der eigenen Metriken (Prometheus) erscheint in der Meldung
	if got := b.T("de", "monitor64.err.metrics", "error", "zeile 3"); !strings.Contains(got, "zeile 3") {
		t.Errorf("metrics without detail: %q", got)
	}
}
