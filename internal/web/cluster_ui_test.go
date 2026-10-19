package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/peer"
)

// newClusterApp: Test-App mit Cluster (peer.Manager ohne Account, ohne Healthchecks) und einem Mitglied.
func newClusterApp(t *testing.T) *testApp {
	t.Helper()
	a := newTestAppDeps(t, func(d *Deps) {
		ctx := context.Background()
		ms, _ := peer.Migrations()
		if err := d.Store.Migrate(ctx, "peer", ms); err != nil {
			t.Fatal(err)
		}
		m, err := peer.New(ctx, peer.Deps{Core: d.Store, Log: d.Log.Slog(), Version: "test",
			NodeID: func() string { return "node-a" }, NodeName: func() string { return "Node A" }, AccountID: func() int64 { return 0 }})
		if err != nil {
			t.Fatal(err)
		}
		d.Peer = m
	})
	if _, err := a.store.Writer().ExecContext(context.Background(), `INSERT INTO peer_members (node_id, name, url, pubkey, account_id, added_at, added_by, sync)
		VALUES ('node-b', 'Node B', 'https://192.168.1.20:8443', 'cHVi', 0, '2026-10-19T10:00:00Z', 'test', 'healthchecks/checks,certs/certificates')`); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestClusterPageAndSwitches(t *testing.T) {
	a := newClusterApp(t)
	loginAs(t, a, "admin", "sehr geheimes passwort")

	resp, body := a.get(t, "/cluster")
	if resp.StatusCode != 200 {
		t.Fatalf("cluster page: %d", resp.StatusCode)
	}
	for _, want := range []string{`href="/cluster"`, "Node B", "NODE64_HTTPS_PORT", `id="sync_healthchecks_checks"`, `action="/cluster/node-b/url"`,
		`title="Auf dieser Node aus – wird nicht abgeglichen.">Checks</span>`, `>certs/certificates</span>`, "/docs/cluster/", "Diese Node hat keinen ipv64-Account."} {
		if !strings.Contains(body, want) {
			t.Fatalf("cluster page misses %q", want)
		}
	}
	if strings.Contains(body, "cluster.") { // kein fehlender Schluessel
		i := strings.Index(body, "cluster.")
		t.Fatalf("untranslated key: %q", body[i:min(len(body), i+60)])
	}
	csrf := csrfOf(t, body)

	// Healthchecks-Sync-Seite: Gruppen-Block weg, Schalter und Link zum Cluster
	_, link := a.get(t, "/link")
	if strings.Contains(link, "/link/group") || !strings.Contains(link, `id="cluster_hc"`) || !strings.Contains(link, `href="/cluster"`) {
		t.Fatal("link page: cluster hint missing or old group block left")
	}

	// Bereich aus (Checkbox nicht gesendet), zurueck auf /cluster
	resp, _ = a.post(t, "/cluster/sync", url.Values{"_csrf": {csrf}, "module": {"healthchecks"}, "item": {"maintenance"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/cluster" {
		t.Fatalf("sync item: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Modul von der Healthchecks-Sync-Seite aus: zurueck auf /link
	resp, _ = a.post(t, "/cluster/sync", url.Values{"_csrf": {csrf}, "module": {"healthchecks"}, "from": {"link"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/link" {
		t.Fatalf("sync module from link: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, m := range a.s.Peer.SyncModules(context.Background()) {
		if m.ID != "healthchecks" {
			continue
		}
		if m.Enabled {
			t.Fatal("healthchecks module still on")
		}
		for _, it := range m.Items {
			if it.ID == "maintenance" && it.Enabled {
				t.Fatal("maintenance still on")
			}
		}
	}
	resp, _ = a.post(t, "/cluster/sync", url.Values{"_csrf": {csrf}, "module": {"gibtsnicht"}, "enabled": {"on"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unknown module: %d", resp.StatusCode)
	}
	list, _ := a.store.AuditList(context.Background(), 50, 0)
	n := 0
	for _, e := range list {
		if e.Action == "peer.sync" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("audit peer.sync: %d", n)
	}
}

func TestClusterAPI(t *testing.T) {
	a := newClusterApp(t)
	ctx := context.Background()
	hash, _ := HashPassword("sehr geheimes passwort")
	u, _ := a.store.CreateUser(ctx, "admin", hash, "de", "UTC")
	key, _, err := a.store.NewAPIKey(ctx, u.ID, "script")
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, a.srv.URL+path, rd)
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := a.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	code, g := call("GET", "/api/group", "")
	if code != 200 || g["https_port"] != float64(0) || g["sync_modules"] == nil {
		t.Fatalf("get: %d %v", code, g)
	}
	mem := g["members"].([]any)[0].(map[string]any)
	if mem["state"] != "active" || len(mem["sync"].([]any)) != 2 {
		t.Fatalf("member: %v", mem)
	}

	code, out := call("PUT", "/api/group/sync", `{"module":"healthchecks","item":"checks","enabled":false}`)
	mods, _ := out["sync_modules"].([]any)
	if code != 200 || len(mods) == 0 {
		t.Fatalf("put sync: %d %v", code, out)
	}
	hc := mods[0].(map[string]any)
	if it := hc["items"].([]any)[0].(map[string]any); hc["id"] != "healthchecks" || it["id"] != "checks" || it["enabled"] != false {
		t.Fatalf("put sync result: %v", hc)
	}
	if code, _ := call("PUT", "/api/group/sync", `{"module":"healthchecks","item":"gibtsnicht","enabled":true}`); code != http.StatusNotFound {
		t.Fatalf("unknown item: %d", code)
	}
	if code, _ := call("PUT", "/api/group/sync", `{"module":"healthchecks"}`); code != http.StatusUnprocessableEntity {
		t.Fatalf("missing enabled: %d", code)
	}
	// Wiederaufnahme: Route vorhanden, eine nicht ausgesetzte/unbekannte Node wird abgelehnt
	if code, out := call("POST", "/api/group/members/gibtsnicht/resume", ""); code < 400 || out["error"] == nil {
		t.Fatalf("resume unknown: %d %v", code, out)
	}
}

// Ausgesetzte Mitglieder zeigen Grund und Knopf "Wieder aufnehmen" (Zustand kommt aus dem peer-Paket).
func TestClusterSuspendedMember(t *testing.T) {
	a := newClusterApp(t)
	g := groupData{Available: true, HTTPSPort: 8443, Account: 42, Members: []memberRow{
		{Member: peer.Member{NodeID: "node-c", Name: "Node C", State: "suspended", Reason: "tls_binding"}, NoSync: true}}}
	v := &View{s: a.s, Lang: "de", Errors: map[string]string{}, Form: map[string]string{}, Data: g}
	var buf bytes.Buffer
	if err := a.s.pages["cluster"].ExecuteTemplate(&buf, "layout.html", v); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	for _, want := range []string{"ausgesetzt", "Proxy", `action="/cluster/node-c/resume"`, "Wieder aufnehmen", "#42", "Ältere Version"} {
		if !strings.Contains(body, want) {
			t.Fatalf("suspended member misses %q", want)
		}
	}
	if strings.Contains(body, "NODE64_HTTPS_PORT") {
		t.Fatal("https warning shown although port set")
	}
}

func TestClusterSelfURL(t *testing.T) {
	for _, c := range []struct {
		host string
		port int
		want string
	}{
		{"192.168.1.5:8080", 8443, "https://192.168.1.5:8443"},
		{"[fd00::1]:8080", 8443, "https://[fd00::1]:8443"},
		{"node.local", 8443, "https://node.local:8443"},
		{"192.168.1.5:8080", 0, "http://192.168.1.5:8080"},
	} {
		r := httptest.NewRequest("GET", "/cluster", nil)
		r.Host = c.host
		if got := selfURL(r, c.port); got != c.want {
			t.Fatalf("%s/%d: %q", c.host, c.port, got)
		}
	}
}
