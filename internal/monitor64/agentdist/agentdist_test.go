package agentdist

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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/selfupdate"
)

// release ist eine Test-Quelle: ein Ordner im Aufbau der Ablage, signiert mit einem Test-Schluessel.
type release struct {
	t    *testing.T
	root string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newRelease(t *testing.T) *release {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &release{t: t, root: t.TempDir(), pub: pub, priv: priv}
}

func (r *release) keys() []ed25519.PublicKey { return []ed25519.PublicKey{r.pub} }

// publish legt eine Version ab: Programme fuer linux/amd64 und windows/amd64, Skripte, Kopfzeilen, Verzeichnis.
func (r *release) publish(version string) *Index {
	r.t.Helper()
	dir := filepath.Join(r.root, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		r.t.Fatal(err)
	}
	files := map[string]string{
		FileName("linux", "amd64"):   "\x7fELF linux " + version,
		FileName("linux", "arm"):     "\x7fELF armv7 " + version,
		FileName("windows", "amd64"): "MZ windows " + version,
		"install.sh":                 "#!/bin/sh\necho " + version + "\n",
		"install.ps1":                "Write-Host " + version + "\n",
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
	ix, err := Build(version, dir)
	if err != nil {
		r.t.Fatal(err)
	}
	for _, f := range ix.Files {
		r.signHeader(version, f, r.priv)
	}
	if err := os.WriteFile(filepath.Join(dir, SumsFile), ix.Sums(), 0o644); err != nil {
		r.t.Fatal(err)
	}
	r.writeIndex(ix, r.priv)
	return ix
}

func (r *release) signHeader(version string, f File, key ed25519.PrivateKey) {
	r.t.Helper()
	h := m64proto.UpdateHeader{Version: version, OS: f.OS, Arch: f.Arch, Size: f.Size, SHA256: f.SHA256}
	h.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, m64proto.SignedMessage(h.Version, h.OS, h.Arch, h.SHA256)))
	b, _ := json.Marshal(h)
	if err := os.WriteFile(filepath.Join(r.root, version, f.Name+HeaderSuffix), append(b, '\n'), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *release) writeIndex(ix *Index, key ed25519.PrivateKey) {
	r.t.Helper()
	raw, _ := json.MarshalIndent(ix, "", "  ")
	if err := os.WriteFile(filepath.Join(r.root, IndexFile), raw, 0o644); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.root, IndexFile+".sig"), selfupdate.Sign(raw, key), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

// serve liefert den Ordner per HTTP und zaehlt die Abrufe je Pfad.
func (r *release) serve() (*httptest.Server, *hits) {
	h := &hits{n: map[string]int{}}
	fs := http.FileServer(http.Dir(r.root))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h.add(req.URL.Path)
		fs.ServeHTTP(w, req)
	}))
	r.t.Cleanup(srv.Close)
	return srv, h
}

type hits struct {
	mu sync.Mutex
	n  map[string]int
}

func (h *hits) add(p string) { h.mu.Lock(); h.n[p]++; h.mu.Unlock() }
func (h *hits) get(p string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.n[p]
}

func (r *release) store(t *testing.T, dir string, bases ...string) *Store {
	t.Helper()
	s := New(Options{Dir: dir, Bases: bases, AllowHTTP: true, Keys: r.keys})
	t.Cleanup(s.Abort)
	return s
}

func TestFileNames(t *testing.T) {
	want := map[string]string{"linux-amd64": "monitor64-agent-linux-amd64", "linux-arm64": "monitor64-agent-linux-arm64", "linux-armv7": "monitor64-agent-linux-armv7",
		"windows-amd64": "monitor64-agent-windows-amd64.exe", "freebsd-amd64": "monitor64-agent-freebsd-amd64", "freebsd-arm64": "monitor64-agent-freebsd-arm64"}
	if len(Platforms) != len(want) {
		t.Fatalf("platforms: %d", len(Platforms))
	}
	for _, p := range Platforms {
		name := FileName(p.OS, p.Arch)
		if want[Key(p.OS, p.Arch)] != name {
			t.Errorf("%s/%s: %s", p.OS, p.Arch, name)
		}
		goos, goarch, ok := ParseFileName(name)
		if !ok || goos != p.OS || goarch != p.Arch {
			t.Errorf("parse %s: %s %s %v", name, goos, goarch, ok)
		}
	}
	for _, bad := range []string{"", "monitor64-agent-", "monitor64-agent-linux", "monitor64-agent-linux-amd64.exe", "monitor64-agent-windows-amd64", "monitor64-agent-linux-amd64/../x",
		"monitor64-agent-linux-../x", "monitor64-agent-linux-arm", "monitor64-agent-Linux-amd64", "node64-linux-amd64", "monitor64-agent-linux-amd64.update.json"} {
		if _, _, ok := ParseFileName(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

// Verzeichnis bauen, signieren, pruefen; Manipulation und fremder Schluessel fallen auf.
func TestIndexSignature(t *testing.T) {
	r := newRelease(t)
	ix := r.publish("0.4.0")
	if len(ix.Files) != 3 || len(ix.Scripts) != 2 || ix.Files["linux-armv7"].Arch != "arm" {
		t.Fatalf("index: %+v", ix)
	}
	raw, _ := os.ReadFile(filepath.Join(r.root, IndexFile))
	sig, _ := os.ReadFile(filepath.Join(r.root, IndexFile+".sig"))
	got, err := Verify(raw, sig, r.keys())
	if err != nil || got.Version != "0.4.0" {
		t.Fatalf("verify: %v %+v", err, got)
	}
	if _, err := Verify(append([]byte(" "), raw...), sig, r.keys()); err == nil {
		t.Fatal("modified index accepted")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(raw, sig, []ed25519.PublicKey{other}); err == nil {
		t.Fatal("foreign key accepted")
	}
	if _, err := Verify(raw, sig, nil); err == nil {
		t.Fatal("no key accepted")
	}
	// SHA256SUMS: je Programm eine Zeile, keine Skripte
	sums := string(ix.Sums())
	if strings.Count(sums, "\n") != 3 || !strings.Contains(sums, ix.Files["linux-amd64"].SHA256+"  monitor64-agent-linux-amd64\n") || strings.Contains(sums, "install.sh") {
		t.Fatalf("sums:\n%s", sums)
	}
	if f, prog, ok := ix.Lookup("install.sh"); !ok || prog || f.Size == 0 {
		t.Fatal("lookup install.sh")
	}
	if _, _, ok := ix.Lookup("SHA256SUMS"); ok {
		t.Fatal("lookup of an unknown name")
	}
}

// Parse lehnt alles ab, was als Pfad oder Dateiname missbraucht werden koennte.
func TestParseRejects(t *testing.T) {
	sha := strings.Repeat("a", 64)
	good := func() map[string]any {
		return map[string]any{"version": "1.2.3", "files": map[string]any{"linux-amd64": map[string]any{"name": "monitor64-agent-linux-amd64", "os": "linux", "arch": "amd64", "size": 10, "sha256": sha}},
			"scripts": map[string]any{"install.sh": map[string]any{"name": "install.sh", "size": 5, "sha256": sha}}}
	}
	parse := func(m map[string]any) error {
		b, _ := json.Marshal(m)
		_, err := Parse(b)
		return err
	}
	if err := parse(good()); err != nil {
		t.Fatal(err)
	}
	file := func(m map[string]any) map[string]any {
		return m["files"].(map[string]any)["linux-amd64"].(map[string]any)
	}
	cases := map[string]func(m map[string]any){
		"version path":   func(m map[string]any) { m["version"] = "../1.2.3" },
		"version short":  func(m map[string]any) { m["version"] = "1.2" },
		"version slash":  func(m map[string]any) { m["version"] = "1.2.3-a/b" },
		"no files":       func(m map[string]any) { m["files"] = map[string]any{} },
		"name traversal": func(m map[string]any) { file(m)["name"] = "../../etc/passwd" },
		"name other":     func(m map[string]any) { file(m)["name"] = "monitor64-agent-linux-arm64" },
		"os upper":       func(m map[string]any) { file(m)["os"] = "Linux" },
		"size zero":      func(m map[string]any) { file(m)["size"] = 0 },
		"size huge":      func(m map[string]any) { file(m)["size"] = m64proto.MaxUpdateBytes + 1 },
		"sha upper":      func(m map[string]any) { file(m)["sha256"] = strings.Repeat("A", 64) },
		"sha short":      func(m map[string]any) { file(m)["sha256"] = "abc" },
		"script path": func(m map[string]any) {
			m["scripts"] = map[string]any{"../x.sh": map[string]any{"name": "../x.sh", "size": 5, "sha256": sha}}
		},
		"script name": func(m map[string]any) {
			m["scripts"] = map[string]any{"install.sh": map[string]any{"name": "other.sh", "size": 5, "sha256": sha}}
		},
		"script big": func(m map[string]any) {
			m["scripts"] = map[string]any{"install.sh": map[string]any{"name": "install.sh", "size": MaxScriptBytes + 1, "sha256": sha}}
		},
	}
	for name, mod := range cases {
		m := good()
		mod(m)
		if err := parse(m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte(strings.Repeat(" ", MaxIndexBytes+1))); err == nil {
		t.Error("oversized index accepted")
	}
}

// Verzeichnis holen, Datei beim ersten Bedarf laden und pruefen, danach ohne Netz aus der Ablage.
func TestStoreDownload(t *testing.T) {
	r := newRelease(t)
	ix := r.publish("0.4.0")
	srv, h := r.serve()
	dir := t.TempDir()
	s := r.store(t, dir, srv.URL+"/")
	ctx := context.Background()
	if s.Index() != nil || !s.Due(time.Hour, time.Hour) {
		t.Fatal("fresh store has an index")
	}
	if _, _, err := s.Program(ctx, FileName("linux", "amd64")); err != ErrNoIndex {
		t.Fatalf("without index: %v", err)
	}
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	if st.Error != "" || st.Source != srv.URL || st.OK.IsZero() || s.Due(time.Hour, time.Hour) {
		t.Fatalf("status: %+v", st)
	}
	name := FileName("linux", "amd64")
	if s.Cached(name) || h.get("/0.4.0/"+name) != 0 {
		t.Fatal("file loaded before it was needed")
	}
	// gleichzeitige Anfragen: ein Download
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := s.Program(ctx, name); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	path, hdr, err := s.Program(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if n := h.get("/0.4.0/" + name); n != 1 {
		t.Fatalf("downloads: %d", n)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "\x7fELF linux 0.4.0" || hdr.Version != "0.4.0" || hdr.OS != "linux" || hdr.Arch != "amd64" || hdr.SHA256 != ix.Files["linux-amd64"].SHA256 {
		t.Fatalf("file %q header %+v", data, hdr)
	}
	if !s.Cached(name) || s.Cached(FileName("windows", "amd64")) {
		t.Fatal("cached state")
	}
	sh, err := s.Script(ctx, "install.sh")
	if err != nil || string(sh) != "#!/bin/sh\necho 0.4.0\n" {
		t.Fatalf("script: %v %q", err, sh)
	}
	if _, err := s.Script(ctx, name); err != ErrUnknownFile {
		t.Fatalf("program as script: %v", err)
	}
	for _, bad := range []string{"../agents.json", "agents.json", "SHA256SUMS", "monitor64-agent-plan9-amd64", "install.sh/../x", "..", ""} {
		if _, _, err := s.Program(ctx, bad); err != ErrUnknownFile {
			t.Errorf("program %q: %v", bad, err)
		}
		if _, err := s.Script(ctx, bad); err != ErrUnknownFile {
			t.Errorf("script %q: %v", bad, err)
		}
	}
	// Neustart ohne Netz: Verzeichnis und Dateien kommen aus der Ablage
	srv.Close()
	s2 := r.store(t, dir, srv.URL)
	if s2.Index() == nil || s2.Index().Version != "0.4.0" {
		t.Fatal("stored index not loaded")
	}
	if _, _, err := s2.Program(ctx, name); err != nil {
		t.Fatalf("offline program: %v", err)
	}
	if b, err := s2.Script(ctx, "install.sh"); err != nil || len(b) == 0 {
		t.Fatalf("offline script: %v", err)
	}
	if _, _, err := s2.Program(ctx, FileName("windows", "amd64")); err == nil {
		t.Fatal("offline download of a file that was never loaded")
	}
	if err := s2.Refresh(ctx); err == nil || s2.Status().Error == "" || s2.Index() == nil {
		t.Fatalf("refresh without source: %v", err)
	}
	// abgelegte Datei veraendert: faellt beim naechsten Start auf (kein Ausliefern)
	if err := os.WriteFile(path, []byte("\x7fELF boese!!!!!!"), 0o640); err != nil {
		t.Fatal(err)
	}
	s3 := r.store(t, dir, srv.URL)
	if _, _, err := s3.Program(ctx, name); err == nil {
		t.Fatal("tampered stored file accepted")
	}
}

// Falsche Pruefsumme, falsche Groesse und falsche Signatur der Kopfzeile: nichts wird abgelegt.
func TestStoreRejects(t *testing.T) {
	ctx := context.Background()
	name := FileName("linux", "amd64")
	leftovers := func(t *testing.T, dir string) {
		t.Helper()
		ents, _ := os.ReadDir(filepath.Join(dir, "0.4.0"))
		for _, e := range ents {
			t.Errorf("left behind: %s", e.Name())
		}
	}
	t.Run("checksum", func(t *testing.T) {
		r := newRelease(t)
		r.publish("0.4.0")
		if err := os.WriteFile(filepath.Join(r.root, "0.4.0", name), []byte("\x7fELF linux 0.4.X"), 0o644); err != nil { // gleiche Groesse
			t.Fatal(err)
		}
		srv, _ := r.serve()
		dir := t.TempDir()
		s := r.store(t, dir, srv.URL)
		if err := s.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Program(ctx, name); err == nil || !strings.Contains(err.Error(), "does not match the index") {
			t.Fatalf("err = %v", err)
		}
		leftovers(t, dir)
	})
	t.Run("size", func(t *testing.T) {
		r := newRelease(t)
		r.publish("0.4.0")
		if err := os.WriteFile(filepath.Join(r.root, "0.4.0", name), []byte(strings.Repeat("x", 4096)), 0o644); err != nil {
			t.Fatal(err)
		}
		srv, _ := r.serve()
		dir := t.TempDir()
		s := r.store(t, dir, srv.URL)
		if err := s.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Program(ctx, name); err == nil || !strings.Contains(err.Error(), "differs from the index") {
			t.Fatalf("err = %v", err)
		}
		leftovers(t, dir)
	})
	t.Run("size without length", func(t *testing.T) { // Antwort ohne Content-Length: nie mehr als Size+1 Byte lesen
		r := newRelease(t)
		ix := r.publish("0.4.0")
		var sent atomic.Int64
		fs := http.FileServer(http.Dir(r.root))
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path != "/0.4.0/"+name {
				fs.ServeHTTP(w, req)
				return
			}
			w.WriteHeader(http.StatusOK)
			for range 4096 {
				n, err := w.Write([]byte(strings.Repeat("x", 1024)))
				sent.Add(int64(n))
				if err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
		}))
		t.Cleanup(srv.Close)
		dir := t.TempDir()
		s := r.store(t, dir, srv.URL)
		if err := s.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Program(ctx, name); err == nil {
			t.Fatal("oversized download accepted")
		}
		leftovers(t, dir)
		_ = ix
	})
	t.Run("header signature", func(t *testing.T) {
		r := newRelease(t)
		ix := r.publish("0.4.0")
		_, other, _ := ed25519.GenerateKey(rand.Reader)
		r.signHeader("0.4.0", ix.Files["linux-amd64"], other)
		srv, h := r.serve()
		dir := t.TempDir()
		s := r.store(t, dir, srv.URL)
		if err := s.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Program(ctx, name); err == nil || !strings.Contains(err.Error(), "signature does not match") {
			t.Fatalf("err = %v", err)
		}
		if h.get("/0.4.0/"+name) != 0 {
			t.Fatal("program loaded although the header signature is wrong")
		}
		leftovers(t, dir)
		// Kopfzeile einer anderen Plattform bzw. Version passt nicht zum Verzeichnis
		f := ix.Files["linux-amd64"]
		good := m64proto.UpdateHeader{Version: "0.4.0", OS: "linux", Arch: "amd64", Size: f.Size, SHA256: f.SHA256}
		sign := func(h m64proto.UpdateHeader) m64proto.UpdateHeader {
			h.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(r.priv, m64proto.SignedMessage(h.Version, h.OS, h.Arch, h.SHA256)))
			return h
		}
		if err := CheckHeader(sign(good), "0.4.0", f, r.keys()); err != nil {
			t.Fatal(err)
		}
		for what, mod := range map[string]func(h *m64proto.UpdateHeader){
			"version": func(h *m64proto.UpdateHeader) { h.Version = "0.5.0" },
			"os":      func(h *m64proto.UpdateHeader) { h.OS = "freebsd" },
			"arch":    func(h *m64proto.UpdateHeader) { h.Arch = "arm64" },
			"size":    func(h *m64proto.UpdateHeader) { h.Size++ },
			"sha":     func(h *m64proto.UpdateHeader) { h.SHA256 = strings.Repeat("0", 64) },
		} {
			h := good
			mod(&h)
			if err := CheckHeader(sign(h), "0.4.0", f, r.keys()); err == nil {
				t.Errorf("header with other %s accepted", what)
			}
		}
		bad := sign(good)
		bad.Signature = "AAAA"
		if err := CheckHeader(bad, "0.4.0", f, r.keys()); err == nil {
			t.Error("broken signature accepted")
		}
	})
	t.Run("script", func(t *testing.T) {
		r := newRelease(t)
		r.publish("0.4.0")
		if err := os.WriteFile(filepath.Join(r.root, "0.4.0", "install.sh"), []byte("#!/bin/sh\nrm -rf /    \n"), 0o644); err != nil {
			t.Fatal(err)
		}
		srv, _ := r.serve()
		dir := t.TempDir()
		s := r.store(t, dir, srv.URL)
		if err := s.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Script(ctx, "install.sh"); err == nil {
			t.Fatal("modified script accepted")
		}
		leftovers(t, dir)
	})
}

// Verzeichnis: ungueltige Signatur, aelterer Stand, Ausweichquelle, alte Versionen aufraeumen.
func TestStoreIndex(t *testing.T) {
	ctx := context.Background()
	r := newRelease(t)
	r.publish("0.4.0")
	srv, _ := r.serve()
	dir := t.TempDir()
	dead := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dead.Close)
	s := r.store(t, dir, dead.URL, srv.URL) // erste Quelle liefert nichts: Ausweichquelle
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if st := s.Status(); st.Source != srv.URL || st.Error != "" {
		t.Fatalf("status %+v", st)
	}
	name := FileName("linux", "amd64")
	if _, _, err := s.Program(ctx, name); err != nil {
		t.Fatal(err)
	}
	// neue Version: Verzeichnis wechselt, alter Ordner verschwindet, Datei wird neu geladen
	r.publish("0.5.0")
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if s.Index().Version != "0.5.0" || s.Cached(name) {
		t.Fatalf("index %s cached %v", s.Index().Version, s.Cached(name))
	}
	if _, err := os.Stat(filepath.Join(dir, "0.4.0")); !os.IsNotExist(err) {
		t.Fatal("old version not removed")
	}
	path, hdr, err := s.Program(ctx, name)
	if err != nil || hdr.Version != "0.5.0" || !strings.Contains(path, "0.5.0") {
		t.Fatalf("new version: %v %+v", err, hdr)
	}
	// aelterer Stand der Quelle (z. B. Ausweichquelle noch nicht aktualisiert): nicht uebernehmen
	old, _ := Build("0.4.0", filepath.Join(r.root, "0.4.0"))
	r.writeIndex(old, r.priv)
	if err := s.Refresh(ctx); err == nil || !strings.Contains(err.Error(), "older than the stored") {
		t.Fatalf("older index: %v", err)
	}
	if s.Index().Version != "0.5.0" || s.Status().Error == "" {
		t.Fatal("older index adopted")
	}
	if !s.Due(time.Hour, 0) || s.Due(time.Hour, time.Hour) {
		t.Fatal("retry after an error")
	}
	// Signatur eines fremden Schluessels
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	cur, _ := Build("0.6.0", filepath.Join(r.root, "0.5.0"))
	r.writeIndex(cur, other)
	if err := s.Refresh(ctx); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("foreign signature: %v", err)
	}
	if s.Index().Version != "0.5.0" {
		t.Fatal("index with a foreign signature adopted")
	}
	// leerer Zwischenspeicher mit ungueltiger Signatur: kein Verzeichnis, keine Dateien
	s2 := r.store(t, t.TempDir(), srv.URL)
	if err := s2.Refresh(ctx); err == nil || s2.Index() != nil {
		t.Fatal("unsigned index adopted")
	}
	if _, _, err := s2.Program(ctx, name); err != ErrNoIndex {
		t.Fatalf("program without index: %v", err)
	}
}

// Nur https (http nur fuer eine Test-Quelle), keine Weiterleitung auf einen anderen Host.
func TestStoreSources(t *testing.T) {
	ctx := context.Background()
	r := newRelease(t)
	r.publish("0.4.0")
	srv, h := r.serve()
	s := New(Options{Dir: t.TempDir(), Bases: []string{srv.URL}, Keys: r.keys}) // ohne AllowHTTP
	t.Cleanup(s.Abort)
	if err := s.Refresh(ctx); err == nil || !strings.Contains(err.Error(), "url not allowed") {
		t.Fatalf("http source: %v", err)
	}
	if h.get("/"+IndexFile) != 0 {
		t.Fatal("http source was contacted")
	}
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, srv.URL+req.URL.Path, http.StatusFound)
	}))
	t.Cleanup(redir.Close)
	s2 := r.store(t, t.TempDir(), redir.URL)
	if err := s2.Refresh(ctx); err == nil || !strings.Contains(err.Error(), "redirect to another host refused") {
		t.Fatalf("redirect: %v", err)
	}
	if h.get("/"+IndexFile) != 0 {
		t.Fatal("redirect to another host was followed")
	}
	// Weiterleitung auf demselben Host ist erlaubt
	fs := http.FileServer(http.Dir(r.root))
	same := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if p, ok := strings.CutPrefix(req.URL.Path, "/old/"); ok {
			http.Redirect(w, req, "/"+p, http.StatusMovedPermanently)
			return
		}
		fs.ServeHTTP(w, req)
	}))
	t.Cleanup(same.Close)
	s3 := r.store(t, t.TempDir(), same.URL+"/old")
	if err := s3.Refresh(ctx); err != nil {
		t.Fatalf("redirect on the same host: %v", err)
	}
	// ohne Quelle
	s4 := r.store(t, t.TempDir())
	if err := s4.Refresh(ctx); err == nil {
		t.Fatal("refresh without a source")
	}
}

// Ein haengender Download endet mit dem Zeitlimit des Aufrufers; Abort beendet den Abruf.
func TestStoreAbort(t *testing.T) {
	r := newRelease(t)
	r.publish("0.4.0")
	name := FileName("linux", "amd64")
	fs := http.FileServer(http.Dir(r.root))
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/0.4.0/"+name {
			select {
			case <-block:
			case <-req.Context().Done():
			}
			return
		}
		fs.ServeHTTP(w, req)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(block) })
	s := r.store(t, t.TempDir(), srv.URL)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, _, err := s.Program(ctx, name); err != context.DeadlineExceeded {
		t.Fatalf("err = %v", err)
	}
	done := make(chan struct{})
	go func() { s.Abort(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("abort did not end the download")
	}
}

// Die Pruefsumme im Verzeichnis ist die der Datei (Gegenprobe zu Build).
func TestBuildChecksums(t *testing.T) {
	r := newRelease(t)
	ix := r.publish("1.0.0-rc.1")
	for _, f := range ix.Files {
		b, err := os.ReadFile(filepath.Join(r.root, "1.0.0-rc.1", f.Name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if f.Size != int64(len(b)) || f.SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: %+v", f.Name, f)
		}
	}
	if _, err := Build("1.0", r.root); err == nil {
		t.Error("invalid version accepted")
	}
	if _, err := Build("1.0.0", t.TempDir()); err == nil {
		t.Error("empty folder accepted")
	}
	// Kopfzeilen und fremde Dateien zaehlen nicht als Programm
	if _, ok := ix.Files["linux-amd64.update.json"]; ok || len(ix.Files) != 3 {
		t.Errorf("files: %v", ix.Files)
	}
}
