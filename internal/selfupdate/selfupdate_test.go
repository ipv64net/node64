package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testRelease: Schluessel, Quelle mit Manifest und Programm (Inhalt bin) fuer version.
func testRelease(t *testing.T, version string, bin []byte) (*httptest.Server, ed25519.PrivateKey, *[]byte) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	old := PublicKeys
	PublicKeys = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { PublicKeys = old })
	var manifest []byte
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(bin)
	m := Manifest{Version: version, Channel: "preview", Files: map[string]File{Arch(): {URL: srv.URL + "/" + version + "/node64-linux-" + Arch(), Size: int64(len(bin)), SHA256: hex.EncodeToString(sum[:])}}}
	manifest, _ = json.Marshal(m)
	mux.HandleFunc("/preview/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifest) })
	mux.HandleFunc("/preview/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(Sign(manifest, priv)) })
	mux.HandleFunc("/"+version+"/node64-linux-"+Arch(), func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(bin) })
	t.Setenv("NODE64_UPDATE_URL", srv.URL)
	return srv, priv, &manifest
}

func TestVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	raw := []byte(`{"version":"1.2.3","files":{"amd64":{"url":"https://x/y","size":1,"sha256":"00"}}}`)
	if _, err := Verify(raw, Sign(raw, priv), []ed25519.PublicKey{other, pub}); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if _, err := Verify(raw, Sign(raw, priv), []ed25519.PublicKey{other}); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := Verify(append(raw, ' '), Sign(raw, priv), []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("modified manifest accepted")
	}
	if _, err := Verify(raw, Sign(raw, priv), nil); err == nil {
		t.Fatal("no keys accepted")
	}
}

func TestApplyAndChoose(t *testing.T) {
	dir := t.TempDir()
	bin := []byte("#!/bin/true\nnew node64")
	_, _, manifest := testRelease(t, "0.13.0", bin)
	if err := os.WriteFile(filepath.Join(dir, "node64.db"), []byte("db-old"), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted := 0
	u := New(dir, "0.12.0")
	u.Backup = func(_ context.Context, dest string) error { return os.WriteFile(dest, []byte("db-old"), 0o600) }
	u.Restart = func() { restarted++ }
	ctx := context.Background()
	m, err := u.Check(ctx, "preview")
	if err != nil || m.Version != "0.13.0" || !u.Newer(m) {
		t.Fatalf("check: %+v %v", m, err)
	}
	if err := u.Apply(ctx, m); err != nil || restarted != 1 {
		t.Fatalf("apply: %v (restart %d)", err, restarted)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "bin", "node64-0.13.0"))
	if string(got) != string(bin) {
		t.Fatal("binary not stored")
	}
	// Starter waehlt die neue Version (Probe, Start 1)
	if v, p := choose(dir, "0.12.0"); v != "0.13.0" || !strings.HasSuffix(p, "node64-0.13.0") {
		t.Fatalf("choose: %q %q", v, p)
	}
	st, _ := LoadState(dir)
	if st.Trial == nil || st.Trial.Attempts != 1 || st.Trial.Backup == "" {
		t.Fatalf("trial: %+v", st.Trial)
	}
	// neue Version hat die Datenbank geaendert, startet aber nicht stabil: nach MaxAttempts zurueck, Datenbank von vorher
	_ = os.WriteFile(filepath.Join(dir, "node64.db"), []byte("db-migrated"), 0o600)
	for i := 0; i < MaxAttempts-1; i++ {
		choose(dir, "0.12.0")
	}
	if v, _ := choose(dir, "0.12.0"); v != "" {
		t.Fatalf("no rollback: %q", v)
	}
	if db, _ := os.ReadFile(filepath.Join(dir, "node64.db")); string(db) != "db-old" {
		t.Fatalf("database not restored: %q", db)
	}
	s := u.Status()
	if s.Rollback == nil || s.Rollback.From != "0.13.0" || s.Rollback.To != "0.12.0" || len(s.Bad) != 1 {
		t.Fatalf("status after rollback: %+v", s)
	}
	// Rueckfall wird einmal gemeldet
	var events []Event
	Watch(ctx, dir, "0.12.0", func(e Event) { events = append(events, e) })
	Watch(ctx, dir, "0.12.0", func(e Event) { events = append(events, e) })
	if len(events) != 1 || events[0].OK || events[0].Version != "0.13.0" {
		t.Fatalf("events: %+v", events)
	}
	// ausdruecklich erneut installieren, dann gesund
	if err := u.Apply(ctx, m); err != nil {
		t.Fatal(err)
	}
	if v, _ := choose(dir, "0.12.0"); v != "0.13.0" {
		t.Fatalf("re-apply: %q", v)
	}
	if from, done, err := MarkHealthy(dir, "0.13.0"); err != nil || !done || from != "" {
		t.Fatalf("healthy: %q %v %v", from, done, err)
	}
	for i := 0; i < MaxAttempts+2; i++ { // gesund: keine Startzaehlung mehr
		if v, _ := choose(dir, "0.12.0"); v != "0.13.0" {
			t.Fatalf("after healthy: %q", v)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", "db-before-0.13.0.db")); !os.IsNotExist(err) {
		t.Fatal("backup kept after healthy")
	}
	// manipulierte Datei: Image-Version
	_ = os.WriteFile(filepath.Join(dir, "bin", "node64-0.13.0"), []byte("evil"), 0o750)
	if v, _ := choose(dir, "0.12.0"); v != "" {
		t.Fatal("tampered binary chosen")
	}
	// neueres Image: bin/ wird aufgeraeumt
	if err := u.Apply(ctx, m); err != nil {
		t.Fatal(err)
	}
	if v, _ := choose(dir, "0.13.1"); v != "" {
		t.Fatalf("older update chosen over newer image: %q", v)
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", "node64-0.13.0")); !os.IsNotExist(err) {
		t.Fatal("old binary not removed")
	}
	// Zurueck zur Image-Version: bin/ leer, Neustart
	if err := u.Apply(ctx, m); err != nil {
		t.Fatal(err)
	}
	before := restarted
	if err := u.Reset(); err != nil || restarted != before+1 {
		t.Fatalf("reset: %v", err)
	}
	if v, _ := choose(dir, "0.12.0"); v != "" {
		t.Fatalf("after reset: %q", v)
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "bin")); len(entries) != 1 { // nur state.json
		t.Fatalf("bin not emptied: %d files", len(entries))
	}
	_ = manifest
}

func TestApplyRejects(t *testing.T) {
	dir := t.TempDir()
	srv, priv, manifest := testRelease(t, "0.13.0", []byte("payload"))
	u := New(dir, "0.12.0")
	ctx := context.Background()
	// falsche Pruefsumme im Manifest
	var m Manifest
	_ = json.Unmarshal(*manifest, &m)
	f := m.Files[Arch()]
	f.SHA256 = strings.Repeat("0", 64)
	m.Files[Arch()] = f
	if err := u.Apply(ctx, &m); err == nil {
		t.Fatal("checksum mismatch accepted")
	}
	// fremder Host
	f.URL = "https://example.com/x"
	m.Files[Arch()] = f
	if err := u.Apply(ctx, &m); err == nil {
		t.Fatal("foreign host accepted")
	}
	// nicht neuer
	m.Version = "0.11.0"
	if err := u.Apply(ctx, &m); err == nil {
		t.Fatal("downgrade accepted")
	}
	// Mindestversion
	m2, err := u.Check(ctx, "preview")
	if err != nil {
		t.Fatal(err)
	}
	m2.MinVersion = "0.12.5"
	if err := u.Apply(ctx, m2); err == nil || !strings.Contains(err.Error(), "image") {
		t.Fatalf("min version: %v", err)
	}
	_, _ = srv, priv
}

// Mindestversion gilt fuer das Image, nicht fuer die laufende Version aus bin/.
func TestApplyMinVersionImage(t *testing.T) {
	dir := t.TempDir()
	_, _, _ = testRelease(t, "0.13.0", []byte("payload"))
	t.Setenv(envChild, "0.12.9")
	t.Setenv(envImageVersion, "0.12.0")
	u := New(dir, "0.12.9")
	ctx := context.Background()
	m, err := u.Check(ctx, "preview")
	if err != nil {
		t.Fatal(err)
	}
	m.MinVersion = "0.12.5"
	if err := u.Apply(ctx, m); err == nil || !strings.Contains(err.Error(), "image") {
		t.Fatalf("min version against image: %v", err)
	}
}

// Rueckfall: eigene Zwischendatei (eine hochgeladene node64.db.restore bleibt), bei Fehler bleibt die Sicherung.
func TestRollbackRestore(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	_ = os.MkdirAll(bin, 0o750)
	_ = os.WriteFile(filepath.Join(dir, "node64.db"), []byte("db-migrated"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "node64.db.restore"), []byte("db-upload"), 0o600)
	_ = os.WriteFile(filepath.Join(bin, "db-before-0.13.0.db"), []byte("db-old"), 0o600)
	st := &State{Current: "0.13.0", Versions: map[string]Installed{}, Trial: &Trial{Version: "0.13.0", Backup: "db-before-0.13.0.db"}}
	st.rollback(dir, "0.12.0")
	if db, _ := os.ReadFile(filepath.Join(dir, "node64.db")); string(db) != "db-old" {
		t.Fatalf("database not restored: %q", db)
	}
	if up, _ := os.ReadFile(filepath.Join(dir, "node64.db.restore")); string(up) != "db-upload" {
		t.Fatalf("staged restore clobbered: %q", up)
	}
	// Kopie schlaegt fehl (Sicherung ist ein Verzeichnis): keine halbe Datei, Sicherung unter backups/
	_ = os.Mkdir(filepath.Join(bin, "db-before-0.14.0.db"), 0o750)
	st = &State{Current: "0.14.0", Versions: map[string]Installed{}, Trial: &Trial{Version: "0.14.0", Backup: "db-before-0.14.0.db"}}
	st.rollback(dir, "0.12.0")
	if db, _ := os.ReadFile(filepath.Join(dir, "node64.db")); string(db) != "db-old" {
		t.Fatalf("database changed by failed restore: %q", db)
	}
	if _, err := os.Stat(filepath.Join(dir, "node64.db.rollback.tmp")); !os.IsNotExist(err) {
		t.Fatal("partial copy left behind")
	}
	if _, err := os.Stat(filepath.Join(dir, "backups", "db-before-0.14.0.db")); err != nil {
		t.Fatalf("backup not kept: %v", err)
	}
}

func TestWindowAndMode(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 10, 26, h, m, 0, 0, time.UTC) }
	cases := []struct {
		w    string
		t    time.Time
		want bool
	}{{"03:00-05:00", at(3, 0), true}, {"03:00-05:00", at(5, 0), false}, {"03:00-05:00", at(2, 59), false},
		{"23:00-02:00", at(23, 30), true}, {"23:00-02:00", at(1, 0), true}, {"23:00-02:00", at(12, 0), false}, {"kaputt", at(3, 0), false}}
	for _, c := range cases {
		if got := InWindow(c.w, c.t); got != c.want {
			t.Errorf("InWindow(%q,%v)=%v", c.w, c.t, got)
		}
	}
	get := func(m map[string]string) Getter {
		return func(k, d string) string {
			if v, ok := m[k]; ok {
				return v
			}
			return d
		}
	}
	if Mode(get(nil)) != "off" || Mode(get(map[string]string{"updates.check": "1"})) != "notify" || Mode(get(map[string]string{SetMode: "auto"})) != "auto" {
		t.Fatal("mode")
	}
	if Channel(get(nil), "0.12.0-alpha.16") != "preview" || Channel(get(nil), "0.12.0") != "stable" || Channel(get(map[string]string{SetChannel: "stable"}), "0.12.0-alpha.1") != "stable" {
		t.Fatal("channel")
	}
	if Window(get(map[string]string{SetWindow: "x"})) != "03:00-05:00" || Window(get(map[string]string{SetWindow: "01:00-02:30"})) != "01:00-02:30" {
		t.Fatal("window")
	}
}
