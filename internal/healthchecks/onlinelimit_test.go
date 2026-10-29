package healthchecks

import (
	"strings"
	"testing"
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
	for _, exec := range []string{"online", "both"} {
		if code, b := mk("ueber cluster "+exec, exec); code != 201 {
			t.Fatalf("via cluster %s: %d %s", exec, code, b)
		}
	}
}
