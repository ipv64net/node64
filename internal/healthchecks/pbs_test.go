package healthchecks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/proxmox"
)

// pbsFake antwortet wie ein Proxmox Backup Server 4.2 (Feldnamen wie gemessen).
func pbsFake(t *testing.T) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "PBSAPIToken=node64@pbs!monitor:") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		reply := func(v any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": v}) }
		switch r.URL.Path {
		case "/api2/json/version":
			reply(map[string]any{"version": "4.2", "release": "6", "repoid": "x"})
		case "/api2/json/nodes/localhost/status":
			reply(map[string]any{"cpu": 0.1, "cpuinfo": map[string]any{"cpus": 4}, "memory": map[string]any{"total": 8000, "used": 2000},
				"root": map[string]any{"total": 50000, "used": 10000}, "uptime": 3600, "current-kernel": map[string]any{"sysname": "pbs1"}})
		case "/api2/json/nodes/localhost/rrd":
			reply([]map[string]any{{"time": 1, "netin": 1500, "netout": 2500, "read_bytes": 10, "write_bytes": 20}})
		case "/api2/json/status/datastore-usage":
			reply([]map[string]any{
				{"store": "main", "total": 1000, "used": 950, "avail": 50, "estimated-full-date": time.Now().Add(5 * 24 * time.Hour).Unix(),
					"history-delta": 1800, "gc-status": map[string]any{"disk-bytes": 100, "index-data-bytes": 320}},
				{"store": "archive", "total": 4000, "used": 1000, "avail": 3000, "estimated-full-date": 100},
			})
		case "/api2/json/nodes/localhost/services":
			reply([]map[string]any{{"service": "proxmox-backup", "state": "running"}, {"service": "proxmox-backup-proxy", "state": "running"}})
		case "/api2/json/nodes/localhost/apt/update":
			reply([]map[string]any{{"Package": "proxmox-backup-server", "OldVersion": "4.2.6-1", "Version": "4.2.8-1"}})
		case "/api2/json/admin/datastore/main/namespace", "/api2/json/admin/datastore/archive/namespace":
			reply([]map[string]any{{"ns": ""}, {"ns": "web"}})
		case "/api2/json/admin/datastore/main/groups", "/api2/json/admin/datastore/archive/groups":
			if r.URL.Query().Get("ns") == "web" && strings.Contains(r.URL.Path, "/main/") {
				reply([]map[string]any{{"backup-type": "vm", "backup-id": "100", "backup-count": 4, "last-backup": time.Now().Add(-time.Hour).Unix()}})
				return
			}
			reply([]map[string]any{})
		case "/api2/json/nodes/localhost/tasks":
			reply([]map[string]any{{"worker_type": "backup", "worker_id": "main:vm/100", "starttime": time.Now().Add(-2 * time.Hour).Unix(),
				"endtime": time.Now().Add(-2*time.Hour).Unix() + 5, "status": "backup failed: connection error"}})
		default:
			w.WriteHeader(http.StatusNotImplemented)
		}
	})
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestPBSPagesAndAPI(t *testing.T) {
	fsrv := pbsFake(t)
	core := pveCore(t)
	m, srv, _ := newPVEModule(t, core, pveBox(t, 1))

	// zwei Buttons rechts oben bzw. im leeren Zustand
	if code, body := pveGet(t, srv, "/healthchecks/proxmox"); code != 200 || !strings.Contains(body, `href="/healthchecks/proxmox/new?kind=pbs"`) ||
		!strings.Contains(body, "pve.pbs.add") || !strings.Contains(body, "pve.add") {
		t.Fatalf("buttons: %d %s", code, body)
	}
	// Assistent fuer PBS: eigene Befehle, Port 8007, Art im Formular
	code, body := pveGet(t, srv, "/healthchecks/proxmox/new?kind=pbs")
	if code != 200 || !strings.Contains(body, `name="kind" value="pbs"`) || !strings.Contains(body, "https://pbs.lan:8007") ||
		!strings.Contains(body, "proxmox-backup-manager acl update / Audit --auth-id 'node64@pbs!monitor'") || strings.Contains(body, "pveum") {
		t.Fatalf("pbs wizard: %d %s", code, body)
	}

	// Anlegen ueber die API (kind pbs), Abfrage
	code, b := call(t, srv, "POST", "/api/healthchecks/proxmox/systems", map[string]any{"kind": "pbs", "addresses": []string{fsrv.URL},
		"token_id": "node64@pbs!monitor", "secret": pveTestSecret, "pin_sha256": pvePinOf(fsrv), "interval": 30})
	if code != http.StatusCreated || strings.Contains(string(b), pveTestSecret) {
		t.Fatalf("create: %d %s", code, b)
	}
	var created struct {
		ID   int64  `json:"id"`
		Kind string `json:"kind"`
		Name string `json:"name"`
	}
	_ = json.Unmarshal(b, &created)
	if created.Kind != proxmox.KindPBS || created.Name != "127.0.0.1" {
		t.Fatalf("created: %+v", created)
	}
	if code, _ := call(t, srv, "POST", "/api/healthchecks/proxmox/systems", map[string]any{"kind": "docker", "addresses": []string{fsrv.URL}}); code != 422 {
		t.Fatalf("kind docker over proxmox api: %d", code)
	}
	id := created.ID
	s := pvePollNow(t, m, id)
	if !s.OK || len(s.Resources) != 1 || s.PBS == nil || len(s.PBS.Datastores) != 2 || s.PBS.Update != "4.2.8-1" {
		t.Fatalf("poll: %+v", s)
	}

	// API: Liste ohne Art enthaelt PBS mit Datastores, kind=pve nicht
	_, b = call(t, srv, "GET", "/api/healthchecks/proxmox/systems", nil)
	if !strings.Contains(string(b), `"kind":"pbs"`) || !strings.Contains(string(b), `"store":"main"`) || !strings.Contains(string(b), `"version":"4.2.6"`) {
		t.Fatalf("list: %s", b)
	}
	if _, b = call(t, srv, "GET", "/api/healthchecks/proxmox/systems?kind=pve", nil); strings.Contains(string(b), `"kind":"pbs"`) {
		t.Fatalf("list pve: %s", b)
	}

	// Uebersicht: Badge PBS, Datastores statt Gaeste, Versions-Hinweis aus apt des PBS (nicht aus dem Repository)
	latestSet(t, "pbs/4", "4.9.0")
	_, body = pveGet(t, srv, "/healthchecks/proxmox")
	if !strings.Contains(body, `title="Proxmox Backup Server">PBS</span>`) || !strings.Contains(body, `bi-database"></i> 2`) ||
		!strings.Contains(body, "bi-arrow-up-circle\"></i> 4.2.8") || strings.Contains(body, "4.9.0") {
		t.Fatalf("overview: %s", body)
	}

	// Systemseite: Node mit Netz, Datastores mit Belegung und Schaetzung, keine Gaeste, Regeln ohne Gast-Zustaende
	sp := fmt.Sprintf("/healthchecks/proxmox/system/%d", id)
	_, body = pveGet(t, srv, sp)
	for _, want := range []string{"PBS 4.2.6", `id="pbs-ds"`, "main", "archive", "95 %", "bg-danger", "pve.pbs.ds_full_none", "2500B/s", "node/localhost",
		time.Now().Add(5 * 24 * time.Hour).Format("2006-01-02"), "pve.rule.unreachable", "pve.rule.cpu", "3.2×", "proxmox-backup-proxy: running",
		`id="pbs-tasks"`, "backup failed: connection error", "main:vm/100", "pve.pbs.ds_groups"} {
		if !strings.Contains(body, want) {
			t.Fatalf("system page: %q missing: %s", want, body)
		}
	}
	for _, not := range []string{"bi-boxes", "pve.rule.stopped", "pve.rule.crashed", "pveum", `id="pbs-services"`} {
		if strings.Contains(body, not) {
			t.Fatalf("system page: %q present: %s", not, body)
		}
	}

	// Host als Check: Typ proxmox (laeuft nur lokal, wie bei Proxmox VE)
	resp, _ := pvePost(t, srv, sp+"/ascheck", url.Values{"key": {"node/localhost"}, "on": {"1"}, "back": {sp}})
	set, _ := m.pve.st.Settings(context.Background(), id)
	it := set.Item("node/localhost")
	if resp.StatusCode != 303 || it == nil || !it.AsCheck {
		t.Fatalf("as check: %d %+v", resp.StatusCode, it)
	}
	c, _ := m.st.Check(context.Background(), it.CheckToken)
	if c == nil || c.Type != checks.TypeProxmox || c.Execution != "local" {
		t.Fatalf("check: %+v", c)
	}
	var p checks.ProxmoxParams
	if err := json.Unmarshal(c.Params, &p); err != nil || p.Key != "node/localhost" || p.SystemID != id {
		t.Fatalf("params %s %v", c.Params, err)
	}

	// Bearbeiten: Art bleibt PBS, Formular mit PBS-Texten
	code, body = pveGet(t, srv, sp+"/edit")
	if code != 200 || !strings.Contains(body, "pve.pbs.rights") || strings.Contains(body, `name="kind"`) {
		t.Fatalf("edit: %d %s", code, body)
	}
}

// Cluster: ein PBS geht wie ein Proxmox-VE-System ueber den Bereich proxmox und bleibt auf der anderen Node ein PBS.
func TestPBSCluster(t *testing.T) {
	ctx := context.Background()
	coreA, coreB := pveCore(t), pveCore(t)
	mA, _, _ := newPVEModule(t, coreA, pveBox(t, 1))
	mB, _, _ := newPVEModule(t, coreB, pveBox(t, 2))
	const nodeA, nodeB = "nodeA_0123456789abcdef", "nodeB_0123456789abcdef"
	mA.SetCluster(ClusterHooks{Change: func(context.Context, string, string, bool) {}, Members: func(context.Context, string) []Peer { return []Peer{{ID: nodeB, Online: true}} }})
	mB.SetCluster(ClusterHooks{Change: func(context.Context, string, string, bool) {}, Members: func(context.Context, string) []Peer { return []Peer{{ID: nodeA, Online: true}} }})
	setSelfID(t, nodeA)
	sys := &proxmox.System{Kind: proxmox.KindPBS, Name: "backup", Addresses: []string{"pbs.lan"}, TokenID: "node64@pbs!monitor", Secret: pveTestSecret,
		Interval: 30, Enabled: true}
	if err := mA.pveSaveSystemBy(ctx, sys, "test"); err != nil {
		t.Fatal(err)
	}
	if ids, _ := mA.ClusterIDs(ctx, ClusterItemProxmox); len(ids) != 1 || ids[0] != sys.UID {
		t.Fatalf("ids: %v", ids)
	}
	data, found, err := mA.ClusterGet(ctx, ClusterItemProxmox, sys.UID)
	if err != nil || !found || !strings.Contains(string(data), `"kind":"pbs"`) {
		t.Fatalf("cluster data: %s %v", data, err)
	}
	setSelfID(t, nodeB)
	if err := mB.ClusterApply(ctx, ClusterItemProxmox, sys.UID, data, false); err != nil {
		t.Fatal(err)
	}
	got, err := mB.pve.st.SystemByUID(ctx, sys.UID)
	if err != nil || !got.IsPBS() || got.Addresses[0] != "https://pbs.lan:8007" || got.Secret != pveTestSecret {
		t.Fatalf("system on B: %+v %v", got, err)
	}
}

// Fuellstand der Datastores: Regeln nur beim PBS (Systemebene), Meldung ueber den normalen Weg (Schwelle), Markierung
// in der Tabelle, API mit den Regelfeldern.
func TestPBSDatastoreRules(t *testing.T) {
	fsrv := pbsFake(t)
	core := pveCore(t)
	m, srv, rec := newPVEModule(t, core, pveBox(t, 1))
	code, b := call(t, srv, "POST", "/api/healthchecks/proxmox/systems", map[string]any{"kind": "pbs", "addresses": []string{fsrv.URL},
		"token_id": "node64@pbs!monitor", "secret": pveTestSecret, "pin_sha256": pvePinOf(fsrv), "interval": 30})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, b)
	}
	var created struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(b, &created)
	id := created.ID
	sp := fmt.Sprintf("/healthchecks/proxmox/system/%d", id)
	ds := func() map[string]string { // Ursache -> Art der Meldungen zu Datastores
		out := map[string]string{}
		for _, a := range rec.take() {
			if w := a.Data["what"]; w == proxmox.WhatDatastore || w == proxmox.WhatDatastoreFull {
				out[w+":"+a.Data["detail"]] = string(a.Kind)
				if !strings.Contains(a.EventID, "-"+w+"-"+a.Data["detail"]+"-") || a.Data["path"] != sp {
					t.Fatalf("alert: %+v", a)
				}
			}
		}
		return out
	}

	// Standard 90 %: main (95 %) meldet nach der Verzoegerung (2 Abfragen), archive (25 %) nicht
	pvePollNow(t, m, id)
	pvePollNow(t, m, id)
	if got := ds(); len(got) != 1 || got["datastore:main"] != string(notify.KindProxmoxThreshold) {
		t.Fatalf("alerts: %v", got)
	}

	// Systemseite: Regeln „belegt ab“ und „voll in weniger als … Tagen“, main markiert
	_, body := pveGet(t, srv, sp)
	for _, want := range []string{`name="r_datastore"`, `name="r_datastore_days"`, "pve.rules.days", "pve.pbs.ds_over"} {
		if !strings.Contains(body, want) {
			t.Fatalf("system page: %q missing: %s", want, body)
		}
	}
	// Proxmox VE: nur „Speicher belegt ab“ (ohne „voll in N Tagen“), Docker keine
	if f := fmt.Sprint(pveRulesFor(&proxmox.SystemSettings{Kind: proxmox.KindPVE}, "", "", "").Fields); !strings.Contains(f, "pve.rule.storage") ||
		strings.Contains(f, "datastore_days") {
		t.Fatalf("pve rules: %s", f)
	}
	if f := fmt.Sprint(pveRulesFor(&proxmox.SystemSettings{Kind: proxmox.KindDocker}, "", "", "").Fields); strings.Contains(f, "datastore") {
		t.Fatalf("docker rules: %s", f)
	}

	// ungueltige Tage werden abgewiesen; voll in weniger als 10 Tagen (main: 5 Tage), Grenze 99 %
	resp, _ := pvePost(t, srv, sp+"/settings", url.Values{"key": {""}, "op": {"save"}, "r_datastore_days": {"-3"}})
	if !strings.Contains(resp.Header.Get("X-Flash"), "danger:pve.err.datastore_days") {
		t.Fatalf("invalid days: %v", resp.Header)
	}
	pvePost(t, srv, sp+"/settings", url.Values{"key": {""}, "op": {"save"}, "r_datastore": {"99"}, "r_datastore_days": {"10"}})
	set, _ := m.pve.st.Settings(context.Background(), id)
	if r := set.Effective("", ""); r.Datastore.Percent != 99 || r.DatastoreDays != 10 {
		t.Fatalf("rule: %+v", r)
	}
	pvePollNow(t, m, id)
	pvePollNow(t, m, id)
	// Grenze von 90 auf 99 % geaendert: still zurueckgesetzt (wie bei den Host-Schwellen); voll bald meldet
	if got := ds(); len(got) != 1 || got["datastore_full:main"] != string(notify.KindProxmoxThreshold) {
		t.Fatalf("alerts: %v", got)
	}
	_, body = pveGet(t, srv, sp)
	if !strings.Contains(body, "pve.pbs.ds_full_over") || strings.Contains(body, "pve.pbs.ds_over") {
		t.Fatalf("marks: %s", body)
	}

	// API: Regelfelder schreiben und lesen
	code, b = call(t, srv, "PUT", fmt.Sprintf("/api/healthchecks/proxmox/systems/%d/settings", id), map[string]any{
		"rules": map[string]any{"datastore": map[string]any{"percent": 80, "minutes": 0}, "datastore_days": 0}})
	if code != 200 || !strings.Contains(string(b), `"datastore":{"percent":80,"minutes":0}`) || !strings.Contains(string(b), `"datastore_days":0`) {
		t.Fatalf("api settings: %d %s", code, b)
	}
}
