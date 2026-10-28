package sonar

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testPlanKey(t *testing.T) (ed25519.PrivateKey, []ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv, []ed25519.PublicKey{pub}, base64.StdEncoding.EncodeToString(pub)
}

func signRaw(priv ed25519.PrivateKey, raw []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))
}

func TestVerifyPlan(t *testing.T) {
	priv, keys, _ := testPlanKey(t)
	now := time.Now().UTC()
	p := Plan{V: 1, NodeID: "nabc123def45", Issued: now, Expires: now.Add(30 * time.Minute),
		Anchors: []Target{
			{ID: "a_fsn", Addr: "1.2.3.4", Family: 4, Method: MethodICMP, Count: 3},
			{ID: "a_nbg", Addr: "10.0.0.1", Family: 4, Method: MethodICMP, Count: 3},
			{ID: "a_x", Addr: "1.2.3.5", Family: 4, Method: MethodTrace, Count: 1},
		}}
	raw := mustJSON(t, p)
	// Leerzeichen: es zaehlen die exakten Bytes
	raw = []byte(strings.Replace(string(raw), `"v":1,`, `"v": 1, `, 1))
	sig := signRaw(priv, raw)
	got, err := verifyPlan(raw, sig, keys, "nabc123def45", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Anchors) != 1 || got.Anchors[0].ID != "a_fsn" {
		t.Fatalf("anchors not cleaned: %+v", got.Anchors)
	}
	if _, err := verifyPlan(raw, sig, keys, "nother000000", now); err == nil {
		t.Error("plan for another node accepted")
	}
	if _, err := verifyPlan(append(raw[:len(raw):len(raw)], ' '), sig, keys, "nabc123def45", now); err == nil {
		t.Error("changed bytes accepted")
	}
	_, other, _ := testPlanKey(t)
	if _, err := verifyPlan(raw, sig, other, "nabc123def45", now); err == nil {
		t.Error("wrong key accepted")
	}
	if _, err := verifyPlan(raw, sig, nil, "nabc123def45", now); err == nil {
		t.Error("no key accepted")
	}
	if _, err := verifyPlan(raw, "!!", keys, "nabc123def45", now); err == nil {
		t.Error("bad signature encoding accepted")
	}
	if _, err := verifyPlan(raw, sig, keys, "nabc123def45", now.Add(3*time.Hour)); err == nil {
		t.Error("plan older than 2 h accepted")
	}
	p.V = 2
	raw2 := mustJSON(t, p)
	if _, err := verifyPlan(raw2, signRaw(priv, raw2), keys, "nabc123def45", now); err == nil {
		t.Error("unknown version accepted")
	}
	p.V, p.Expires = 1, p.Issued.Add(-time.Second)
	raw3 := mustJSON(t, p)
	if _, err := verifyPlan(raw3, signRaw(priv, raw3), keys, "nabc123def45", now); err == nil {
		t.Error("expires before issued accepted")
	}
	if _, err := verifyPlan([]byte("{"), signRaw(priv, []byte("{")), keys, "nabc123def45", now); err == nil {
		t.Error("garbage accepted")
	}
}

func TestWindow(t *testing.T) {
	now := time.Now()
	p := &Plan{Issued: now, Expires: now.Add(5 * time.Hour)} // Server will 5 h: Kern nimmt hoechstens 30 min
	v, a := window(p, now)
	if !v.Equal(now.Add(PlanMaxAge)) || !a.Equal(now.Add(AnchorOnlyFor)) {
		t.Fatalf("window %v %v", v, a)
	}
	p = &Plan{Issued: now.Add(-20 * time.Minute), Expires: now.Add(10 * time.Minute)}
	v, a = window(p, now)
	if !v.Equal(now.Add(10*time.Minute)) || !a.Equal(now.Add(-20*time.Minute+AnchorOnlyFor)) {
		t.Fatalf("window %v %v", v, a)
	}
	// Server-Uhr vorn: Empfang zaehlt
	p = &Plan{Issued: now.Add(time.Hour), Expires: now.Add(90 * time.Minute)}
	v, _ = window(p, now)
	if !v.Equal(now.Add(PlanMaxAge)) {
		t.Fatalf("window %v", v)
	}
}

func TestParsePlanKeys(t *testing.T) {
	_, _, pub := testPlanKey(t)
	if k, err := parsePlanKeys([]string{pub}); err != nil || len(k) != 1 {
		t.Fatal(err)
	}
	if _, err := parsePlanKeys([]string{"AAAA"}); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestKeyFile(t *testing.T) {
	dir := t.TempDir()
	k1, err := loadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := loadOrCreateKey(dir)
	if err != nil || !k1.Equal(k2) {
		t.Fatalf("key not stable: %v", err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(dir, keyFile))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("key mode %v", fi.Mode().Perm())
		}
	}
	os.WriteFile(filepath.Join(dir, keyFile), []byte("kaputt"), 0o600)
	if _, err := loadOrCreateKey(dir); err == nil {
		t.Fatal("damaged key accepted (would change identity)")
	}
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"v": 1,  "x":"<&>"}`)
	st := persisted{NodeID: "nabc123def45", TokenID: "00", Seq: 42, Day: "2026-10-28", SentToday: 7, PlanRaw: raw, ETag: `"e"`}
	if err := writeState(dir, st); err != nil {
		t.Fatal(err)
	}
	got, err := loadState(dir)
	if err != nil || got.Seq != 42 || string(got.PlanRaw) != string(raw) || got.NodeID != st.NodeID {
		t.Fatalf("state %+v %v", got, err)
	}
	os.WriteFile(filepath.Join(dir, stateFile), []byte(`{"node_id":"../../x"}`), 0o600)
	if got, _ := loadState(dir); got.NodeID != "" {
		t.Fatal("bad node id loaded")
	}
	os.WriteFile(filepath.Join(dir, stateFile), []byte("{nonsense"), 0o600)
	if _, err := loadState(dir); err == nil {
		t.Fatal("garbage state accepted")
	}
}
