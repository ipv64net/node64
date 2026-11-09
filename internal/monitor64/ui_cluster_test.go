package monitor64

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/i18n"
)

// Oberflaeche im Cluster: Karte "Cluster" der Einstellungen, "ueberwacht von" auf Uebersicht und Host-Seite,
// Zustaendigkeit am Host (Ansicht, Aendern, Uebernahmen).

// clusterEnv: Modul als node-a ("node01") in einem Schein-Cluster mit node-b (offline) und node-c (online); ein
// eigener Host und einer, den node-b ueberwacht (zustaendige Node nicht erreichbar).
func clusterEnv(t *testing.T) (e *testEnv, own, foreign *Host) {
	t.Helper()
	ctx := context.Background()
	e = newEnvWith(t, func(m *Module) { // vor dem Start: der erste Blick des Moduls sieht schon den Cluster
		_ = m.st.SetSetting(ctx, "node.name", "node01")
		m.SetCluster(ClusterHooks{
			Self: func() string { return "node-a" },
			Members: func(context.Context, string) []ClusterPeer {
				return []ClusterPeer{{ID: "node-b", Name: "node02", Online: false}, {ID: "node-c", Name: "node03", Online: true}}
			},
		})
	})
	if s := e.m.clusterRefresh(ctx); !s.Active || !s.Majority {
		t.Fatalf("cluster not active: %+v", s)
	}
	own = &Host{Name: "nas01", Address: "192.0.2.10", Kind: "ssh", IntervalSec: 60, Paused: true}
	foreign = &Host{Name: "pve02", Address: "192.0.2.20", Kind: "pve", IntervalSec: 60, Paused: true, PreferredNode: "node-b"}
	for _, h := range []*Host{own, foreign} {
		if err := e.m.store.SaveHost(ctx, h, testActor); err != nil {
			t.Fatal(err)
		}
	}
	rtOwn, rtForeign := &hostRT{host: own}, &hostRT{host: foreign}
	rtOwn.setView(&HostView{Host: own, Checked: time.Now(), Cluster: e.m.clusterSelfRef(roleReport)})
	e.m.idleView(rtForeign, "node-b")
	e.m.rtMu.Lock()
	if e.m.rts == nil {
		e.m.rts = map[string]*hostRT{}
	}
	e.m.rts[own.UID], e.m.rts[foreign.UID] = rtOwn, rtForeign
	e.m.rtMu.Unlock()
	e.m.event(ctx, "", foreign.UID, "", "takeover", i18nText("monitor64.detail.cluster_takeover", "from", "node03", "to", "node02"), SystemActor, time.Now())
	return e, own, foreign
}

func TestClusterPagesRender(t *testing.T) {
	e, own, foreign := clusterEnv(t)

	// Einstellungen: Karte mit Mitgliedern, Mehrheit, Hosts je Node, Schluessel (vom Skript gefuellt)
	rec := e.do("GET", "/monitor64/settings", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("settings: %d", rec.Code)
	}
	body := rec.Body.String()
	mustContain(t, "settings", body, `id="m64-cluster"`, "monitor64.cluster.majority_yes", `data-cl-row="node-a"`, `data-cl-row="node-b"`, `data-cl-row="node-c"`,
		">node01<", ">node02<", ">node03<", "monitor64.cluster.offline", "monitor64.cluster.stable", "monitor64.cluster.orphans", `id="m64-cl-key"`, `id="m64-cl-pending"`,
		`id="m64-cl-rotate"`, `id="m64-cl-retire"`, `"fingerprint":"SHA256:`, `"authorized_key":"ssh-ed25519 `, `"pending":[]`)

	// Uebersicht: "ueberwacht von" je Host fuer das Skript
	body = e.do("GET", "/monitor64", nil).Body.String()
	mustContain(t, "overview", body, `"refs":{`, `"self_name":"node01"`, `"note":"owner_unreachable"`, `"here":true`)

	// Host einer anderen Node: Badge im Kopf, Karte Zustaendigkeit, Hinweis und Uebernahme
	body = e.do("GET", "/monitor64/host/"+foreign.UID, nil).Body.String()
	mustContain(t, "host", body, `id="m64-cl-badge"`, "monitor64.cluster.by", `id="m64-cluster-host"`, `data-act="cluster-edit"`, `id="m64-cl-body"`, `id="m64-chart-note"`,
		`"note":"owner_unreachable"`, `"owner":"node-b"`, `"owner_name":"node02"`, `"role":"idle"`, `"kind":"takeover"`, "detail.cluster_takeover")
	if !strings.Contains(e.do("GET", "/monitor64/host/"+own.UID, nil).Body.String(), `"here":true`) {
		t.Fatal("own host: missing own cluster ref")
	}

	// Assistent: Mitglieder zur Wahl der bevorzugten Node
	body = e.do("GET", "/monitor64/new", nil).Body.String()
	mustContain(t, "new", body, `"cluster":{"active":true`, `"self":"node-a"`, `"name":"node03"`)

	// Name im Kopf (serverseitig): Name der ueberwachenden Node, auch fuer eigene Hosts
	for _, c := range []struct {
		h    *Host
		want string
	}{{foreign, "node02"}, {own, "node01"}} {
		ch := e.m.clusterHostInfo(context.Background(), c.h)
		if got := ch.OwnerLabel(); got != c.want {
			t.Errorf("%s: owner label %q, want %q", c.h.Name, got, c.want)
		}
	}
}

// Ohne Cluster: keine Karte, kein Badge, keine Daten fuer den Assistenten.
func TestClusterPagesWithoutCluster(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := &Host{Name: "nas01", Address: "192.0.2.10", Kind: "ssh", IntervalSec: 60, Paused: true}
	if err := e.m.store.SaveHost(ctx, h, testActor); err != nil {
		t.Fatal(err)
	}
	e.setView(h)
	for path, bad := range map[string][]string{
		"/monitor64/settings":          {`id="m64-cluster"`},
		"/monitor64/host/" + h.UID:     {`id="m64-cluster-host"`, `id="m64-cl-badge"`, `"cluster":{`},
		"/monitor64/new":               {`"cluster":{`},
		"/monitor64":                   {`"note":`},
		"/api/monitor64/cluster/views": {`"active":true`},
	} {
		body := e.do("GET", path, nil).Body.String()
		for _, b := range bad {
			if strings.Contains(body, b) {
				t.Errorf("%s: unexpected %s", path, b)
			}
		}
	}
}

// UI3: ohne aktiven Cluster (z. B. nach dem Entfernen einer Node) bleibt der Schluessel-Teil der Karte, solange es
// einen Cluster-Schluessel, alte Schluessel oder offene Umstellungen gibt; Mitglieder und Mehrheit entfallen.
func TestClusterCardKeysWithoutCluster(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if c := e.m.clusterCardOf(ctx); c != nil {
		t.Fatalf("card without cluster and keys: %+v", c)
	}
	if err := e.m.RotateKey(ctx); err != nil {
		t.Fatal(err)
	}
	c := e.m.clusterCardOf(ctx)
	if c == nil || c.Active || c.Key == nil || !c.Key.Cluster {
		t.Fatalf("card with cluster key: %+v", c)
	}
	body := e.do("GET", "/monitor64/settings", nil).Body.String()
	mustContain(t, "settings", body, `id="m64-cluster"`, `id="m64-cl-inactive"`, "monitor64.cluster.inactive_keys", `id="m64-cl-key"`, `id="m64-cl-rotate"`, `id="m64-cl-pending"`,
		`"cluster":{"active":false`, `"cluster":true`)
	for _, bad := range []string{`id="m64-cl-majority"`, `id="m64-cl-nodes"`, "monitor64.cluster.card_hint"} {
		if strings.Contains(body, bad) {
			t.Errorf("settings without cluster: unexpected %s", bad)
		}
	}
	// nur offene Umstellung (eigener Schluessel): Karte bleibt
	if err := e.m.st.SetSetting(ctx, setKeyCluster, ""); err != nil {
		t.Fatal(err)
	}
	_ = e.m.st.SetSetting(ctx, setOldKeys, "[]")
	if c := e.m.clusterCardOf(ctx); c != nil {
		t.Fatalf("card with own key only: %+v", c.Key)
	}
	if _, err := e.m.st.Writer().ExecContext(ctx, `INSERT INTO m64_keypending (access_uid, host_uid, type, target_fp, created_at) VALUES ('acc1', 'h1', 'agent', 'SHA256:x', ?)`, tsNow()); err != nil {
		t.Fatal(err)
	}
	if c := e.m.clusterCardOf(ctx); c == nil || len(c.Key.Pending) != 1 {
		t.Fatalf("card with pending switch: %+v", c)
	}
}

// API der Oberflaeche: Hinweise je Host, Zustaendigkeit eines Hosts, bevorzugte Node und Ersatz-Nodes setzen.
func TestClusterUIAPI(t *testing.T) {
	e, own, foreign := clusterEnv(t)
	var v clusterViewsOut
	if err := json.Unmarshal(e.do("GET", "/api/monitor64/cluster/views", nil).Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if !v.Active || v.SelfName != "node01" || len(v.Refs) != 2 || !v.Refs[own.UID].Here || v.Refs[foreign.UID].Note != noteOwnerUnreachable || v.Refs[foreign.UID].Name != "node02" {
		t.Fatalf("views: %+v", v)
	}
	var one clusterViewsOut
	if err := json.Unmarshal(e.do("GET", "/api/monitor64/cluster/views?host="+own.UID, nil).Body.Bytes(), &one); err != nil || len(one.Refs) != 1 || one.Refs[own.UID] == nil {
		t.Fatalf("views of one host: %+v %v", one, err)
	}
	var hi clusterHostInfo
	if err := json.Unmarshal(e.do("GET", "/api/monitor64/cluster/hosts/"+foreign.UID, nil).Body.Bytes(), &hi); err != nil {
		t.Fatal(err)
	}
	if !hi.Active || hi.Host.Owner != "node-b" || hi.Host.Role != "idle" || hi.Host.Reachable || len(hi.Nodes) != 3 || !hi.Nodes[0].Self || len(hi.Events) != 1 || hi.Events[0].Kind != "takeover" {
		t.Fatalf("host info: %+v", hi)
	}
	if rec := e.do("GET", "/api/monitor64/cluster/hosts/nope", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host: %d", rec.Code)
	}
	// unbekannte Ersatz-Node: Fehler mit Text
	rec := e.do("PUT", "/api/monitor64/cluster/hosts/"+own.UID, map[string]any{"preferred_node": "node-a", "backup_nodes": []string{"node-x"}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error":"cluster_node"`) || !strings.Contains(rec.Body.String(), "monitor64.err.cluster_node") {
		t.Fatalf("unknown node: %d %s", rec.Code, rec.Body)
	}
	rec = e.do("PUT", "/api/monitor64/cluster/hosts/"+own.UID, map[string]any{"preferred_node": "node-a", "backup_nodes": []string{"node-c"}})
	if rec.Code != http.StatusOK || !e.audited("monitor64.host.cluster|nas01|preferred=node-a backups=node-c") {
		t.Fatalf("save: %d %s %v", rec.Code, rec.Body, e.audits)
	}
	hi = clusterHostInfo{}
	if err := json.Unmarshal(e.do("GET", "/api/monitor64/cluster/hosts/"+own.UID, nil).Body.Bytes(), &hi); err != nil || hi.Host.Preferred != "node-a" || len(hi.Host.Backups) != 1 || hi.Host.Backups[0] != "node-c" {
		t.Fatalf("after save: %+v %v", hi.Host, err)
	}
}

// Texte des Clusters ausserhalb von monitor64.* (Cluster-Seite des Kerns, Audit-Log) stehen in beiden Sprachen.
func TestClusterTexts(t *testing.T) {
	b, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{ClusterTitleKey, "cluster.item.monitor64_config", "cluster.item.monitor64_status", "cluster.monitor64_hint", "monitor64.err.cluster_node",
		"monitor64.how.handover", "monitor64.ev.takeover", "monitor64.ev.handover"}
	for _, a := range []string{"host.cluster", "key.rotate", "key.confirm", "key.retire"} {
		keys = append(keys, "audit.actions."+strings.ReplaceAll("monitor64."+a, ".", "_"))
	}
	for _, lang := range []string{"de", "en"} {
		for _, k := range keys {
			if b.T(lang, k) == k {
				t.Errorf("%s: missing %s", lang, k)
			}
		}
	}
}
