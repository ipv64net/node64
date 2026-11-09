package monitor64

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64agent"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

func decodeBody(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
}

func (e *testEnv) col(q string, args ...any) string {
	e.t.Helper()
	var s string
	if err := e.m.st.Reader().QueryRow(q, args...).Scan(&s); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
	return s
}

// Host mit Zugang anlegen, aendern, Geheimnis nie zurueck, Akteur in Tabelle und Audit-Log, Entfernen mit Verlauf.
func TestAPIHostsAndSecrets(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u, err := e.m.st.CreateUser(ctx, "dennis", "x", "de", "Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	rec := e.do("POST", "/api/monitor64/hosts", map[string]any{"name": "pve01", "address": "192.0.2.10", "kind": "pve", "group": "Keller", "paused": true, "tags": []string{"Proxmox", "produktiv"},
		"accesses": []map[string]any{{"type": "pve", "config": map[string]any{"url": "https://192.0.2.10:8006", "token_id": "monitor@pve!node64"}, "secret": "tok-SEHR-geheim"}},
		"services": []map[string]any{{"key": "cpu", "name": "CPU", "kind": "cpu", "default": true}, {"key": "fs:/", "name": "Dateisystem /", "kind": "fs", "default": true}},
		"adopt":    []string{"cpu"}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created struct{ UID string }
	decodeBody(t, rec.Body.Bytes(), &created)
	uid := created.UID
	if by := e.col(`SELECT created_by FROM m64_hosts WHERE uid = ?`, uid); !strings.Contains(by, `"name":"dennis"`) || !strings.Contains(by, `"uid":"`+u.UID+`"`) || !strings.Contains(by, `"ip":"10.0.0.42"`) || !strings.Contains(by, `"method":"local"`) {
		t.Fatalf("actor of create: %s", by)
	}
	if !e.audited("monitor64.host.create|pve01|") {
		t.Fatal("create not in audit log")
	}
	rows, _ := e.m.store.Services(ctx, uid)
	if len(rows) != 2 {
		t.Fatalf("services: %d", len(rows))
	}
	for _, r := range rows {
		if (r.Key == "cpu") != (r.Adopted == 1) {
			t.Fatalf("adopt state of %s: %d", r.Key, r.Adopted)
		}
	}
	// Geheimnis verschluesselt gespeichert, nie in Antworten
	secret := e.col(`SELECT secret FROM m64_access WHERE host_uid = ?`, uid)
	if secret == "" || strings.Contains(secret, "tok-SEHR-geheim") {
		t.Fatalf("secret not encrypted: %q", secret)
	}
	for _, path := range []string{"/api/monitor64/hosts/" + uid, "/api/monitor64/hosts", "/api/monitor64/overview", "/monitor64/host/" + uid} {
		b := e.do("GET", path, nil).Body.String()
		if strings.Contains(b, "tok-SEHR-geheim") || strings.Contains(b, secret) {
			t.Fatalf("%s leaks the secret", path)
		}
	}
	var hd hostDetail
	decodeBody(t, e.do("GET", "/api/monitor64/hosts/"+uid, nil).Body.Bytes(), &hd)
	if len(hd.Accesses) != 1 || !hd.Accesses[0].SecretSet || hd.Host.Name != "pve01" || len(hd.New) != 1 || hd.Host.Tags[0] != "proxmox" {
		t.Fatalf("host detail: %+v", hd)
	}
	acc := hd.Accesses[0].UID
	// Aendern ohne Geheimnis: bleibt; clear_secret: entfernt
	if rec := e.do("PUT", "/api/monitor64/access/"+acc, map[string]any{"config": map[string]any{"url": "https://10.0.0.11:8006", "token_id": "monitor@pve!node64"}}); rec.Code != 200 {
		t.Fatalf("access update: %d %s", rec.Code, rec.Body)
	}
	if got := e.col(`SELECT secret FROM m64_access WHERE uid = ?`, acc); got != secret {
		t.Fatal("secret changed without new value")
	}
	if rec := e.do("PUT", "/api/monitor64/access/"+acc, map[string]any{"config": map[string]any{"url": "https://10.0.0.11:8006"}, "clear_secret": true}); rec.Code != 200 || strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("access clear: %d %s", rec.Code, rec.Body)
	}
	if got := e.col(`SELECT secret FROM m64_access WHERE uid = ?`, acc); got != "" {
		t.Fatal("secret not cleared")
	}
	// strenge Konfiguration
	if rec := e.do("PUT", "/api/monitor64/access/"+acc, map[string]any{"config": map[string]any{"url": "ftp://x"}}); rec.Code != 400 || !strings.Contains(rec.Body.String(), `"error":"url"`) {
		t.Fatalf("bad url: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("PUT", "/api/monitor64/access/"+acc, map[string]any{"config": map[string]any{"evil": 1}}); rec.Code != 400 {
		t.Fatalf("unknown field accepted: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/monitor64/hosts", map[string]any{"name": "", "address": "x"}); rec.Code != 400 || !strings.Contains(rec.Body.String(), "monitor64.err.name") {
		t.Fatalf("empty name: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/api/monitor64/hosts", map[string]any{"name": "a", "address": "a b; rm -rf"}); rec.Code != 400 {
		t.Fatalf("bad address: %d", rec.Code)
	}
	// Host aendern mit API-Key: Akteur ist der Key
	raw, _, err := e.m.st.NewAPIKey(ctx, u.ID, "Home Assistant")
	if err != nil {
		t.Fatal(err)
	}
	if rec := e.do("PUT", "/api/monitor64/hosts/"+uid, map[string]any{"name": "pve01", "address": "192.0.2.10", "kind": "pve", "group": "Rack", "interval_sec": 120, "paused": true}, "Authorization", "Bearer "+raw); rec.Code != 200 {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	if by := e.col(`SELECT updated_by FROM m64_hosts WHERE uid = ?`, uid); !strings.Contains(by, `"kind":"api"`) || !strings.Contains(by, `"name":"Home Assistant"`) {
		t.Fatalf("api actor: %s", by)
	}
	if g := e.col(`SELECT group_name FROM m64_hosts WHERE uid = ?`, uid); g != "Rack" {
		t.Fatal(g)
	}
	// Verlauf schreiben und mit dem Host loeschen
	e.m.appendSeries(uid, "cpu", "util", time.Now().Add(-time.Minute), 12)
	e.m.appendSeries(uid, "cpu", "util", time.Now(), 14)
	var ser struct {
		Series []seriesOut `json:"series"`
	}
	decodeBody(t, e.do("GET", "/api/monitor64/series?host="+uid+"&s=cpu|util&range=6h", nil).Body.Bytes(), &ser)
	if len(ser.Series) != 1 || len(ser.Series[0].Points) != 2 {
		t.Fatalf("series: %+v", ser)
	}
	if rec := e.do("GET", "/api/monitor64/series?host="+uid+"&s=bad", nil); rec.Code != 400 {
		t.Fatalf("bad series: %d", rec.Code)
	}
	rec = e.do("DELETE", "/api/monitor64/hosts/"+uid+"?history=delete", nil)
	var del struct {
		Deleted int `json:"series_deleted"`
	}
	decodeBody(t, rec.Body.Bytes(), &del)
	if rec.Code != 200 || del.Deleted != 1 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if !e.audited("monitor64.host.delete|pve01|") {
		t.Fatal("delete not audited")
	}
	if e.m.viewOf(uid) != nil {
		t.Fatal("host still scheduled")
	}
	if rec := e.do("GET", "/api/monitor64/hosts/"+uid, nil); rec.Code != 404 {
		t.Fatalf("deleted host: %d", rec.Code)
	}
}

// Dienste: uebernehmen/ignorieren/entfernen, Anzeigename, Soll, Schwelle "dieser Host" (Dienst und Art), Pruefung.
func TestAPIServices(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	by := Actor{Kind: "user", Name: "x"}
	h := &Host{Name: "nas01", Address: "192.0.2.20", Kind: "ssh", IntervalSec: 60, Paused: true}
	if err := e.m.store.SaveHost(ctx, h, by); err != nil {
		t.Fatal(err)
	}
	found := []model.Service{{Key: "fs:/", Name: "Dateisystem /", Kind: "fs"}, {Key: "fs:/data", Name: "Dateisystem /data", Kind: "fs"}, {Key: "ctr:web", Name: "web", Kind: "ctr"}}
	if _, err := e.m.store.UpsertDiscovered(ctx, h.UID, found, nil, SystemActor); err != nil {
		t.Fatal(err)
	}
	base := "/api/monitor64/hosts/" + h.UID
	if rec := e.do("POST", base+"/services/adopt", map[string]any{"keys": []string{"fs:/", "fs:/data", "ctr:web"}, "state": 1}); rec.Code != 200 {
		t.Fatalf("adopt: %d %s", rec.Code, rec.Body)
	}
	if by := e.col(`SELECT updated_by FROM m64_services WHERE host_uid = ? AND key = 'fs:/'`, h.UID); !strings.Contains(by, "dennis") {
		t.Fatalf("adopt actor: %s", by)
	}
	if rec := e.do("POST", base+"/services/adopt", map[string]any{"keys": []string{"fs:/"}, "state": 7}); rec.Code != 400 {
		t.Fatalf("bad state: %d", rec.Code)
	}
	// nur dieser Dienst
	rule := map[string]any{"warn": 85, "crit": 95}
	if rec := e.do("PUT", base+"/service", map[string]any{"key": "fs:/", "rules": map[string]any{"fs.used": map[string]any{"rule": rule}}, "name": "Root", "soll": "", "report": ""}); rec.Code != 200 {
		t.Fatalf("service rule: %d %s", rec.Code, rec.Body)
	}
	if hr := e.col(`SELECT host_rule FROM m64_services WHERE host_uid = ? AND key = 'fs:/'`, h.UID); hr != `{"fs.used":{"warn":85,"crit":95}}` {
		t.Fatalf("host_rule: %s", hr)
	}
	if n := e.col(`SELECT name FROM m64_services WHERE host_uid = ? AND key = 'fs:/'`, h.UID); n != "Root" {
		t.Fatal(n)
	}
	// Warnung ueber Kritisch wird abgelehnt (mit geerbtem Feld)
	if rec := e.do("PUT", base+"/service", map[string]any{"key": "fs:/data", "rules": map[string]any{"fs.used": map[string]any{"rule": map[string]any{"warn": 95}}}}); rec.Code != 400 || !strings.Contains(rec.Body.String(), `"error":"rule_kind"`) {
		t.Fatalf("order check: %d %s", rec.Code, rec.Body)
	}
	// alle Dateisysteme dieses Hosts
	if rec := e.do("PUT", base+"/service", map[string]any{"key": "fs:/data", "rules": map[string]any{"fs.used": map[string]any{"rule": map[string]any{"mode": "free", "warn_free": 500, "crit_free": 200}, "scope": "kind"}}}); rec.Code != 200 {
		t.Fatalf("kind rule: %d %s", rec.Code, rec.Body)
	}
	if r := e.col(`SELECT rule FROM m64_host_rules WHERE host_uid = ? AND kind = 'fs.used' AND deleted = 0`, h.UID); !strings.Contains(r, `"mode":"free"`) {
		t.Fatalf("kind rule row: %s", r)
	}
	if kr := e.m.config().hostKind[h.UID+"|fs.used"]; kr == nil || kr.Mode == nil || *kr.Mode != eval.ModeFree {
		t.Fatal("config not reloaded after kind rule")
	}
	// Soll-Zustand
	if rec := e.do("PUT", base+"/service", map[string]any{"key": "ctr:web", "soll": "off"}); rec.Code != 200 {
		t.Fatalf("soll: %d", rec.Code)
	}
	if rec := e.do("PUT", base+"/service", map[string]any{"key": "ctr:web", "soll": "maybe"}); rec.Code != 400 {
		t.Fatalf("bad soll: %d", rec.Code)
	}
	// auf Standard zurueck: beide Stufen am Host weg
	if rec := e.do("PUT", base+"/service", map[string]any{"key": "fs:/", "reset": true}); rec.Code != 200 {
		t.Fatalf("reset: %d", rec.Code)
	}
	if hr := e.col(`SELECT host_rule FROM m64_services WHERE host_uid = ? AND key = 'fs:/'`, h.UID); hr != "" {
		t.Fatalf("reset host_rule: %s", hr)
	}
	if n := e.col(`SELECT COUNT(*) FROM m64_host_rules WHERE host_uid = ? AND deleted = 0`, h.UID); n != "0" {
		t.Fatalf("reset kind rule: %s", n)
	}
	if rec := e.do("PUT", base+"/service", map[string]any{"key": "nope"}); rec.Code != 404 {
		t.Fatalf("unknown service: %d", rec.Code)
	}
	// entfernen
	if rec := e.do("POST", base+"/services/remove", map[string]any{"keys": []string{"ctr:web"}}); rec.Code != 200 {
		t.Fatalf("remove: %d", rec.Code)
	}
	if by := e.col(`SELECT updated_by FROM m64_services WHERE host_uid = ? AND key = 'ctr:web' AND deleted = 1`, h.UID); !strings.Contains(by, "dennis") {
		t.Fatalf("remove actor: %s", by)
	}
	if !e.audited("monitor64.services.remove|nas01|") || !e.audited("monitor64.service.update|nas01 · fs:/|") {
		t.Fatal("services not audited")
	}
}

// Probleme: Liste, Quittieren mit Akteur, Kommentar, als geloest markieren, CSV gegen Formel-Einschleusung.
func TestAPIProblems(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := &Host{Name: "=HYPERLINK(\"x\")", Address: "10.0.0.5", IntervalSec: 60}
	if err := e.m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, p := range []struct{ uid, key, closed string }{{"p1", "fs:/", ""}, {"p2", "cpu", ts(now.Add(-time.Hour))}} {
		if _, err := e.m.st.Writer().Exec(`INSERT INTO m64_problems (uid, host_uid, service_key, state, worst, opened_at, closed_at, closed_how, closed_by, updated_at) VALUES (?, ?, ?, 'warn', 'crit', ?, ?, ?, ?, ?)`,
			p.uid, h.UID, p.key, ts(now.Add(-2*time.Hour)), p.closed, map[bool]string{true: "auto", false: ""}[p.closed != ""], SystemActor.json(), tsNow()); err != nil {
			t.Fatal(err)
		}
	}
	var out problemsOut
	decodeBody(t, e.do("GET", "/api/monitor64/problems?status=all&range=24h", nil).Body.Bytes(), &out)
	if len(out.Problems) != 2 || out.Counts.Open != 1 || out.Counts.Closed != 1 {
		t.Fatalf("problems: %+v", out)
	}
	decodeBody(t, e.do("GET", "/api/monitor64/problems?status=open", nil).Body.Bytes(), &out)
	if len(out.Problems) != 1 || out.Problems[0].UID != "p1" {
		t.Fatalf("open: %+v", out.Problems)
	}
	if rec := e.do("POST", "/api/monitor64/problems/action", map[string]any{"host": h.UID, "key": "fs:/", "action": "ack", "comment": "Platte bestellt"}); rec.Code != 200 {
		t.Fatalf("ack: %d %s", rec.Code, rec.Body)
	}
	if ack := e.col(`SELECT ack FROM m64_problems WHERE uid = 'p1'`); !strings.Contains(ack, `"name":"dennis"`) || !strings.Contains(ack, "Platte bestellt") {
		t.Fatalf("ack: %s", ack)
	}
	if rec := e.do("POST", "/api/monitor64/problems/action", map[string]any{"host": h.UID, "key": "fs:/", "action": "comment", "comment": ""}); rec.Code != 400 {
		t.Fatalf("empty comment: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/monitor64/problems/action", map[string]any{"host": h.UID, "key": "fs:/", "action": "comment", "comment": "kommt Mittwoch"}); rec.Code != 200 {
		t.Fatalf("comment: %d", rec.Code)
	}
	// Person-Filter
	decodeBody(t, e.do("GET", "/api/monitor64/problems?status=all&who=user:dennis", nil).Body.Bytes(), &out)
	if len(out.Problems) != 1 || len(out.People) < 2 {
		t.Fatalf("who filter: %d problems, people %+v", len(out.Problems), out.People)
	}
	decodeBody(t, e.do("GET", "/api/monitor64/problems?status=all&who=system", nil).Body.Bytes(), &out)
	if len(out.Problems) != 1 || out.Problems[0].UID != "p2" {
		t.Fatalf("system filter: %+v", out.Problems)
	}
	// Ablauf
	var pd struct {
		Events []eventRow `json:"events"`
	}
	decodeBody(t, e.do("GET", "/api/monitor64/problems/p1", nil).Body.Bytes(), &pd)
	if len(pd.Events) != 2 || pd.Events[0].Kind != "ack" || pd.Events[1].Kind != "comment" || pd.Events[1].Actor.IP != "10.0.0.42" {
		t.Fatalf("events: %+v", pd.Events)
	}
	// CSV: Formel-Einschleusung entschaerft
	rec := e.do("GET", "/api/monitor64/problems.csv?status=all", nil)
	csv := rec.Body.String()
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") || !strings.Contains(csv, `'=HYPERLINK`) || strings.Contains(csv, ";=HYPERLINK") || !strings.Contains(csv, "Platte bestellt") {
		t.Fatalf("csv: %d %q", rec.Code, csv)
	}
	if csvCell("-1+1") != "'-1+1" || csvCell("@x") != "'@x" || csvCell("ok") != "ok" {
		t.Fatal("csvCell")
	}
	// als geloest markieren
	if rec := e.do("POST", "/api/monitor64/problems/action", map[string]any{"host": h.UID, "key": "fs:/", "action": "resolve", "comment": "erledigt"}); rec.Code != 200 {
		t.Fatalf("resolve: %d", rec.Code)
	}
	if how := e.col(`SELECT closed_how FROM m64_problems WHERE uid = 'p1'`); how != "user" {
		t.Fatal(how)
	}
	if rec := e.do("POST", "/api/monitor64/problems/action", map[string]any{"host": h.UID, "key": "fs:/", "action": "ack"}); rec.Code != 404 {
		t.Fatalf("ack closed: %d", rec.Code)
	}
	if !e.audited("monitor64.problem.ack|") || !e.audited("monitor64.problem.resolve|") {
		t.Fatal("problem actions not audited")
	}
}

// Schwellen: Standard speichern, Abweichung anlegen mit Vorschau, verschieben, aendern, entfernen.
func TestAPIRules(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	std := map[string]any{"rules": map[string]any{"fs.used": map[string]any{"warn": 85, "crit": 95, "for": 0}, "cpu.util": map[string]any{"warn": 90, "crit": 95, "for": 900}, "smart.failed": map[string]any{"severity": "warn"}}}
	rec := e.do("PUT", "/api/monitor64/rules/std", std)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"fs.used"`) || strings.Contains(rec.Body.String(), `"cpu.util"`) {
		t.Fatalf("std: %d %s", rec.Code, rec.Body)
	}
	if c := e.m.config(); c.std[eval.KindFSUsed].Warn.V != 85 || *c.std[eval.KindSmartFailed].Severity != eval.SevWarn {
		t.Fatal("std not applied")
	}
	if rec := e.do("PUT", "/api/monitor64/rules/std", map[string]any{"rules": map[string]any{"fs.used": map[string]any{"warn": 95, "crit": 90}}}); rec.Code != 400 {
		t.Fatalf("std order: %d", rec.Code)
	}
	if rec := e.do("PUT", "/api/monitor64/rules/std", map[string]any{"rules": map[string]any{"nope": map[string]any{}}}); rec.Code != 400 {
		t.Fatalf("std kind: %d", rec.Code)
	}
	ov := map[string]any{"target_type": "tag", "target": "Backup", "kind": "store.used", "rule": map[string]any{"warn": 95, "crit": 98}}
	if rec := e.do("POST", "/api/monitor64/rules/preview", ov); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"services":0`) {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body)
	}
	var a, b struct{ UID string }
	decodeBody(t, e.do("POST", "/api/monitor64/rules/overrides", ov).Body.Bytes(), &a)
	decodeBody(t, e.do("POST", "/api/monitor64/rules/overrides", map[string]any{"target_type": "group", "target": "Büro", "kind": "mem.used", "rule": map[string]any{"warn": 90, "crit": 95}}).Body.Bytes(), &b)
	if a.UID == "" || b.UID == "" {
		t.Fatal("overrides not created")
	}
	if c := e.m.config(); len(c.overrides) != 2 || c.overrides[0].Tag != "backup" || c.overrides[1].Group != "Büro" {
		t.Fatalf("overrides: %+v", c.overrides)
	}
	if rec := e.do("POST", "/api/monitor64/rules/overrides/"+b.UID+"/move", map[string]any{"dir": -1}); rec.Code != 200 {
		t.Fatalf("move: %d", rec.Code)
	}
	if c := e.m.config(); c.overrides[0].ID != b.UID {
		t.Fatal("move not applied")
	}
	if by := e.col(`SELECT updated_by FROM m64_overrides WHERE uid = ?`, b.UID); !strings.Contains(by, "dennis") {
		t.Fatalf("move actor: %s", by)
	}
	if rec := e.do("PUT", "/api/monitor64/rules/overrides/"+a.UID, map[string]any{"target_type": "tag", "target": "backup", "kind": "store.used", "rule": map[string]any{"mode": "free", "warn_free": 500, "crit_free": 200}}); rec.Code != 200 {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/api/monitor64/rules/overrides", map[string]any{"target_type": "tag", "target": "x", "kind": "fs.used", "rule": map[string]any{}}); rec.Code != 400 {
		t.Fatalf("empty rule: %d", rec.Code)
	}
	var rules struct {
		Overrides []ruleOverrideOut `json:"overrides"`
	}
	decodeBody(t, e.do("GET", "/api/monitor64/rules", nil).Body.Bytes(), &rules)
	if len(rules.Overrides) != 2 || rules.Overrides[1].Rule.Mode == nil {
		t.Fatalf("rules: %+v", rules.Overrides)
	}
	if rec := e.do("DELETE", "/api/monitor64/rules/overrides/"+a.UID, nil); rec.Code != 200 {
		t.Fatalf("delete: %d", rec.Code)
	}
	if len(e.m.config().overrides) != 1 {
		t.Fatal("delete not applied")
	}
	if !e.audited("monitor64.rules.std|") || !e.audited("monitor64.rules.override.create|tag:backup|") || !e.audited("monitor64.rules.override.delete|") {
		t.Fatal("rules not audited")
	}
	_ = ctx
}

// Vorschau rechnet mit dem aktuellen Stand: betroffene Dienste, ueberdeckt, am Host eingestellt, danach Warnungen.
func TestEffectPreview(t *testing.T) {
	e := newEnv(t)
	mk := func(uid, name string, tags []string, used float64) {
		h := &Host{UID: uid, Name: name, Tags: tags}
		rt := &hostRT{host: h}
		rt.setView(&HostView{Host: h, Services: []SvcView{{Key: "fs:/", Name: "/", Kind: "fs", Metrics: []MetricView{{Metric: model.Metric{Name: "used", Value: used, Unit: "%", Rule: eval.KindFSUsed, Max: 1e12}}}}}})
		e.m.rtMu.Lock()
		if e.m.rts == nil {
			e.m.rts = map[string]*hostRT{}
		}
		e.m.rts[uid] = rt
		e.m.rtMu.Unlock()
	}
	mk("h1", "nas01", []string{"backup"}, 92)
	mk("h2", "nas02", []string{"backup", "vip"}, 50)
	mk("h3", "pi", nil, 99)
	std := eval.Defaults()
	list := []eval.Override{{ID: "a", Tag: "vip", Kind: eval.KindFSUsed, Rule: eval.Rule{Warn: eval.L(40)}}, {ID: "b", Tag: "backup", Kind: eval.KindFSUsed, Rule: eval.Rule{Warn: eval.L(95), Crit: eval.L(98)}}}
	ef := e.m.effectOf(context.Background(), std, list[:1], list, 1)
	if ef.Services != 1 || len(ef.Hosts) != 1 || ef.Hosts[0] != "nas01" || len(ef.Shadow[0]) != 1 || ef.After.Warn != 0 || ef.After.Crit != 0 {
		t.Fatalf("effect: %+v", ef)
	}
	free := eval.ModeFree
	ef = e.m.effectOf(context.Background(), std, nil, []eval.Override{{Tag: "backup", Kind: eval.KindFSUsed, Rule: eval.Rule{Mode: &free, WarnFree: eval.L(100), CritFree: eval.L(50)}}}, 0)
	if ef.Services != 2 || ef.After.Crit != 0 || ef.After.Warn != 1 {
		t.Fatalf("free effect: %+v", ef) // nas01: 80 GB frei -> Warnung (unter 100); nas02: 500 GB frei -> OK
	}
}

// Benachrichtigung, Wartung und Einstellungen.
func TestAPINotifyMaintSettings(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if rec := e.do("PUT", "/api/monitor64/notify", map[string]any{"channels": []map[string]any{{"id": "99", "warn": true, "crit": true}}}); rec.Code != 400 {
		t.Fatalf("unknown channel: %d", rec.Code)
	}
	if rec := e.do("PUT", "/api/monitor64/notify", map[string]any{"channels": []map[string]any{{"id": "default", "warn": false, "crit": true}}, "remind_crit": 14400, "remind_warn": 0, "crit_in_quiet": true}); rec.Code != 200 {
		t.Fatalf("notify: %d %s", rec.Code, rec.Body)
	}
	if c := e.m.config().notify; len(c.Channels) != 1 || c.Channels[0].Warn || !c.CritInQuiet || time.Duration(c.RemindCrit) != 4*time.Hour {
		t.Fatalf("notify config: %+v", c)
	}
	if rec := e.do("PUT", "/api/monitor64/notify", map[string]any{"remind_crit": 60}); rec.Code != 400 {
		t.Fatalf("remind: %d", rec.Code)
	}
	var no struct{ UID string }
	decodeBody(t, e.do("POST", "/api/monitor64/notify/overrides", map[string]any{"target_type": "group", "target": "Keller", "channels": []map[string]any{{"id": "default", "warn": true, "crit": true}}, "only_crit": true}).Body.Bytes(), &no)
	if c := e.m.config(); no.UID == "" || len(c.notifyOverrides) != 1 || c.notifyOverrides[0].Group != "Keller" || !*c.notifyOverrides[0].OnlyCrit {
		t.Fatalf("notify override: %+v", c.notifyOverrides)
	}
	if rec := e.do("POST", "/api/monitor64/notify/test", nil); rec.Code != 200 {
		t.Fatalf("test: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("DELETE", "/api/monitor64/notify/overrides/"+no.UID, nil); rec.Code != 200 || len(e.m.config().notifyOverrides) != 0 {
		t.Fatalf("notify override delete: %d", rec.Code)
	}
	// Wartung
	h := &Host{Name: "pbs01", Address: "10.0.0.12", Group: "Keller", IntervalSec: 60}
	if err := e.m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	if rec := e.do("POST", "/api/monitor64/maintenance", map[string]any{"title": "x", "mode": "now"}); rec.Code != 400 {
		t.Fatalf("no targets: %d", rec.Code)
	}
	var mu struct{ UID string }
	decodeBody(t, e.do("POST", "/api/monitor64/maintenance", map[string]any{"title": "Kernel-Update", "hosts": []string{h.UID}, "mode": "now", "minutes": 60}).Body.Bytes(), &mu)
	if in, w := e.m.inMaintenance(time.Now(), hostRef(h)); !in || w.Reason != "Kernel-Update" {
		t.Fatal("maintenance not active")
	}
	if rec := e.do("POST", "/api/monitor64/maintenance", map[string]any{"title": "Backup", "tags": []string{"Backup"}, "mode": "recur", "days": []int{0}, "from": "02:00", "to": "04:00"}); rec.Code != 200 {
		t.Fatalf("recur: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/api/monitor64/maintenance", map[string]any{"title": "Plan", "groups": []string{"Keller"}, "mode": "plan", "start": "2026-11-10T22:00", "end": "2026-11-10T21:00"}); rec.Code != 400 {
		t.Fatalf("plan order: %d", rec.Code)
	}
	var ml struct {
		Items []maintOut `json:"items"`
	}
	decodeBody(t, e.do("GET", "/api/monitor64/maintenance", nil).Body.Bytes(), &ml)
	if len(ml.Items) != 2 || ml.Items[0].Status != "running" || ml.Items[1].Status != "recurring" || ml.Items[0].By.Name != "dennis" {
		t.Fatalf("maint list: %+v", ml.Items)
	}
	if rec := e.do("POST", "/api/monitor64/maintenance/"+mu.UID+"/end", nil); rec.Code != 200 {
		t.Fatalf("end: %d", rec.Code)
	}
	if in, _ := e.m.inMaintenance(time.Now(), hostRef(h)); in {
		t.Fatal("maintenance still active")
	}
	if n := e.col(`SELECT COUNT(*) FROM m64_events WHERE kind IN ('maint', 'maint_end') AND actor LIKE '%dennis%'`); n != "3" {
		t.Fatalf("maint events: %s", n)
	}
	// Einstellungen
	if rec := e.do("PUT", "/api/monitor64/settings", map[string]any{"interval": 10, "workers": 4}); rec.Code != 400 {
		t.Fatalf("interval: %d", rec.Code)
	}
	if rec := e.do("PUT", "/api/monitor64/settings", map[string]any{"interval": 300, "workers": 4}); rec.Code != 200 {
		t.Fatalf("settings: %d", rec.Code)
	}
	if e.m.defaultInterval(ctx) != 300 || e.m.workers(ctx) != 4 {
		t.Fatal("settings not stored")
	}
	var so settingsOut
	decodeBody(t, e.do("GET", "/api/monitor64/settings", nil).Body.Bytes(), &so)
	if so.Interval != 300 || so.RetRawH != 48 || !strings.HasPrefix(so.PublicKey, "ssh-ed25519 ") || so.Port != 6465 {
		t.Fatalf("settings out: %+v", so)
	}
	if !e.audited("monitor64.notify.save|") || !e.audited("monitor64.maint.create|Kernel-Update|") || !e.audited("monitor64.maint.end|") || !e.audited("monitor64.settings|") {
		t.Fatal("not audited")
	}
}

// "Verbindung testen" fragt einen Agent einmal ab, ohne etwas zu speichern; Hostschluessel nur gemeldet.
func TestAPITestConnection(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	line, err := e.m.PublicKeyLine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	if err := os.WriteFile(keys, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hk, err := m64agent.LoadOrCreateHostKey(filepath.Join(dir, "hostkey"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := m64agent.New(m64agent.Config{HostKey: hk, KeysFile: keys, Collector: &fakeHost{fsUsed: 40}, Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var res testResult
	rec := e.do("POST", "/api/monitor64/test", map[string]any{"address": "127.0.0.1", "access": map[string]any{"type": "agent", "config": json.RawMessage(`{"port":` + port + `}`)}})
	decodeBody(t, rec.Body.Bytes(), &res)
	if rec.Code != 200 || !res.OK || res.Error != "" || !strings.HasPrefix(res.Fingerprint, "SHA256:") || len(res.Services) < 3 {
		t.Fatalf("test: %d %+v", rec.Code, res)
	}
	if e.m.pool.Len() != 0 {
		t.Fatal("test connection left a pooled client")
	}
	if n := e.col(`SELECT COUNT(*) FROM m64_access`); n != "0" {
		t.Fatal("test connection stored something")
	}
	// Host mit gemerktem Fingerabdruck und bestaetigten Diensten anlegen
	svcs := []map[string]any{}
	for _, s := range res.Services {
		svcs = append(svcs, map[string]any{"key": s.Key, "name": s.Name, "kind": s.Kind, "default": s.Default})
	}
	rec = e.do("POST", "/api/monitor64/hosts", map[string]any{"name": "test01", "address": "127.0.0.1", "kind": "linux-agent",
		"accesses": []map[string]any{{"type": "agent", "config": json.RawMessage(`{"port":` + port + `}`), "hostkey": res.Fingerprint}}, "services": svcs, "adopt": []string{res.Services[0].Key}})
	var c struct{ UID string }
	decodeBody(t, rec.Body.Bytes(), &c)
	if hkStored := e.col(`SELECT hostkey FROM m64_access WHERE host_uid = ?`, c.UID); hkStored != res.Fingerprint {
		t.Fatalf("host key not pinned: %q", hkStored)
	}
	// Dienste jetzt erkennen: eine Runde sofort
	rec = e.do("POST", "/api/monitor64/hosts/"+c.UID+"/discover", nil)
	if rec.Code != 200 {
		t.Fatalf("discover: %d %s", rec.Code, rec.Body)
	}
	if v := e.m.viewOf(c.UID); v == nil || v.Checked.IsZero() || len(v.Services) != 1 {
		t.Fatalf("view after discover: %+v", v)
	}
	// gespeicherten Zugang testen
	var hd hostDetail
	decodeBody(t, e.do("GET", "/api/monitor64/hosts/"+c.UID, nil).Body.Bytes(), &hd)
	rec = e.do("POST", "/api/monitor64/access/"+hd.Accesses[0].UID+"/test", nil)
	decodeBody(t, rec.Body.Bytes(), &res)
	if !res.OK || res.Error != "" {
		t.Fatalf("stored access test: %+v", res)
	}
	// Schluessel zuruecksetzen
	if rec := e.do("POST", "/api/monitor64/access/"+hd.Accesses[0].UID+"/hostkey-reset", nil); rec.Code != 200 {
		t.Fatalf("hostkey reset: %d", rec.Code)
	}
	if !e.audited("monitor64.access.hostkey_reset|") {
		t.Fatal("hostkey reset not audited")
	}
}
