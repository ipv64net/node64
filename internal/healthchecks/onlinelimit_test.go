package healthchecks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Online-/Hybrid-Checks werden wie im Portal gegen die Account-Klasse geprueft: Standorte je Check und Online-Limit.
func TestOnlineLimitOnSave(t *testing.T) {
	m, srv := newTestModule(t)
	m.SetLinked(func() bool { return true })
	m.SetQuota(func() (int, int, int) { return 0, 1000, 2 })
	m.SetAccount(func() (string, int) { return "Supporter", 3 })
	mk := func(name string, locs []string) (int, string) {
		code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": name, "type": "http", "target": "https://example.org", "execution": "online", "locations": locs})
		return code, string(b)
	}
	if code, b := mk("a", []string{"nbg", "fsn"}); code != 201 {
		t.Fatalf("first: %d %s", code, b)
	}
	// 2 von 3 belegt, ein weiterer mit 2 Standorten passt nicht mehr, mit einem schon
	if code, b := mk("b", []string{"nbg", "fsn"}); code != 422 || !strings.Contains(b, "online limit") {
		t.Fatalf("over limit: %d %s", code, b)
	}
	if code, b := mk("c", []string{"nbg"}); code != 201 {
		t.Fatalf("one location: %d %s", code, b)
	}
	// Klasse mit einem Standort je Check
	m.SetAccount(func() (string, int) { return "Free", 100 })
	m.SetQuota(func() (int, int, int) { return 0, 1000, 1 })
	if code, b := mk("d", []string{"nbg", "fsn"}); code != 422 || !strings.Contains(b, "location(s) per check") {
		t.Fatalf("locations per check: %d %s", code, b)
	}
}

// Nicht verknuepft: Online und Hybrid nur, wenn eine verknuepfte Node des Clusters weiterreicht.
func TestOnlineViaCluster(t *testing.T) {
	m, srv := newTestModule(t)
	m.SetLinked(func() bool { return false })
	via := false
	m.SetViaCluster(func() bool { return via })
	mk := func(name, exec string) (int, string) {
		code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": name, "type": "http", "target": "https://example.org", "execution": exec})
		return code, string(b)
	}
	if code, b := mk("ohne", "online"); code != 422 || !strings.Contains(b, "ipv64 link") {
		t.Fatalf("without link and cluster: %d %s", code, b)
	}
	via = true
	// Grenzen des Accounts nicht lesbar (kein API-Key, ipv64 antwortet nicht): nicht online anlegen
	m.SetAccount(func() (string, int) { return "", 0 })
	if code, b := mk("grenzen unbekannt", "online"); code != 422 || !strings.Contains(b, "limits of the ipv64 account") {
		t.Fatalf("unknown limits: %d %s", code, b)
	}
	// Grenzen ueber die API v2: Standorte je Check und Online-Messstellen gelten wie verknuepft
	m.SetAccount(func() (string, int) { return "Supporter", 4 })
	m.SetQuota(func() (int, int, int) { return 0, 1000, 2 })
	for _, exec := range []string{"online", "both"} {
		if code, b := mk("ueber cluster "+exec, exec); code != 201 {
			t.Fatalf("via cluster %s: %d %s", exec, code, b)
		}
	}
	code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "zu viele", "type": "http", "target": "https://example.org", "execution": "online", "locations": []string{"nbg", "fsn"}})
	if code != 422 || !strings.Contains(string(b), "online limit") {
		t.Fatalf("online limit via cluster: %d %s", code, b)
	}
}

// Push-Checks ueber den Cluster (nicht verknuepft): ein hier empfangener Push geht direkt an ipv64 (health.php),
// die API nennt bei reinen Online-Checks die Adresse bei ipv64.
func TestOnlinePushViaCluster(t *testing.T) {
	m, srv := newTestModule(t)
	m.SetLinked(func() bool { return false })
	m.SetViaCluster(func() bool { return true })
	m.SetAccount(func() (string, int) { return "Supporter", 0 })
	got := make(chan string, 4)
	ipv64 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.URL.RawQuery }))
	defer ipv64.Close()
	old := onlinePushBase
	onlinePushBase = ipv64.URL + "/health.php?token="
	t.Cleanup(func() { onlinePushBase = old })
	code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "Cron", "type": "push", "execution": "both", "interval_seconds": 300})
	if code != 201 {
		t.Fatalf("create: %d %s", code, b)
	}
	var c struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(b, &c)
	if code, _ := call(t, srv, "GET", "/api/push/"+c.Token+"?status=down&msg=voll", nil); code != 200 {
		t.Fatalf("push: %d", code)
	}
	select {
	case q := <-got:
		if !strings.Contains(q, "token="+c.Token) || !strings.Contains(q, "status=down") || !strings.Contains(q, "msg=voll") {
			t.Fatalf("forwarded push: %q", q)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("push not forwarded to ipv64")
	}
	code, b = call(t, srv, "POST", "/api/checks", map[string]any{"name": "Nur online", "type": "push", "execution": "online", "interval_seconds": 300})
	if code != 201 || !strings.Contains(string(b), `"push_url":"`+OnlinePushURL) {
		t.Fatalf("online push check must show the ipv64 push address: %d %s", code, b)
	}
}
