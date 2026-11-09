package m64agent

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

func TestSemver(t *testing.T) {
	order := []string{"0.0.9", "0.1.0-alpha", "0.1.0-alpha.1", "0.1.0-alpha.beta", "0.1.0-beta.2", "0.1.0-beta.11",
		"0.1.0-rc.1", "0.1.0", "0.1.1", "0.10.0", "1.0.0"}
	for i := 0; i+1 < len(order); i++ {
		a, ok1 := parseSemver(order[i])
		b, ok2 := parseSemver(order[i+1])
		if !ok1 || !ok2 || compareSemver(a, b) >= 0 || compareSemver(b, a) <= 0 {
			t.Errorf("%s < %s failed", order[i], order[i+1])
		}
	}
	a, _ := parseSemver("v1.2.3+build5")
	b, _ := parseSemver("1.2.3")
	if compareSemver(a, b) != 0 {
		t.Error("build metadata must not count")
	}
	for _, bad := range []string{"", "1.2", "1.2.3.4", "01.2.3", "1.2.x", "1.2.3-", "dev"} {
		if _, ok := parseSemver(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

// signedUpdate baut Header und Inhalt fuer Tests.
func signedUpdate(priv ed25519.PrivateKey, version, goos, goarch string, body []byte) m64proto.UpdateHeader {
	sum := sha256.Sum256(body)
	h := m64proto.UpdateHeader{Version: version, OS: goos, Arch: goarch, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}
	h.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, m64proto.SignedMessage(h.Version, h.OS, h.Arch, h.SHA256)))
	return h
}

func TestCheckUpdateHeader(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	keys := []ed25519.PublicKey{pub}
	body := []byte("new binary")
	good := signedUpdate(priv, "1.2.0", runtime.GOOS, runtime.GOARCH, body)
	if err := checkUpdateHeader(good, "1.1.9", keys); err != nil {
		t.Fatalf("valid update refused: %v", err)
	}
	if err := checkUpdateHeader(good, "dev", keys); err != nil {
		t.Fatalf("dev build must accept: %v", err)
	}
	tamper := good
	tamper.Version = "1.3.0" // Signatur passt nicht mehr
	cases := map[string]struct {
		h       m64proto.UpdateHeader
		current string
		keys    []ed25519.PublicKey
		want    string
	}{
		"no keys":      {good, "1.0.0", nil, "no release key"},
		"same version": {good, "1.2.0", keys, "not newer"},
		"downgrade":    {good, "1.10.0", keys, "not newer"},
		"wrong key":    {signedUpdate(other, "1.2.0", runtime.GOOS, runtime.GOARCH, body), "1.0.0", keys, "signature"},
		"tampered":     {tamper, "1.0.0", keys, "signature"},
		"wrong os":     {signedUpdate(priv, "1.2.0", "plan9", runtime.GOARCH, body), "1.0.0", keys, "platform"},
		"too large":    {func() m64proto.UpdateHeader { h := good; h.Size = m64proto.MaxUpdateBytes + 1; return h }(), "1.0.0", keys, "size"},
		"bad version":  {signedUpdate(priv, "latest", runtime.GOOS, runtime.GOARCH, body), "1.0.0", keys, "version"},
	}
	for name, c := range cases {
		err := checkUpdateHeader(c.h, c.current, c.keys)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

func TestApplyUpdate(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	exe := filepath.Join(dir, "monitor64-agent")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("brand new binary")
	h := signedUpdate(priv, "2.0.0", runtime.GOOS, runtime.GOARCH, body)

	// zu kurz: alte Datei bleibt
	if err := applyUpdate(bytes.NewReader(body[:5]), h, exe); err == nil {
		t.Fatal("short body accepted")
	}
	// falscher Inhalt: alte Datei bleibt
	if err := applyUpdate(bytes.NewReader([]byte("brand new BINARY")), h, exe); err == nil {
		t.Fatal("wrong sha accepted")
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("old file changed: %q", b)
	}
	// richtig (mit ueberzaehligen Bytes dahinter, die nicht gelesen werden)
	if err := applyUpdate(bytes.NewReader(append(body, "trailing"...)), h, exe); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != string(body) {
		t.Fatalf("new file = %q", b)
	}
	// F1-K5: vorherige Version bleibt als .old
	if b, _ := os.ReadFile(exe + oldSuffix); string(b) != "old" {
		t.Fatalf("old file = %q", b)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 {
		t.Fatalf("leftover files: %v", ents)
	}
}

// F1-K5: Merker nach dem Update; startet die neue Version zweimal ohne Bestaetigung, kommt die alte zurueck und die
// Version wird nicht erneut angenommen.
func TestUpdateFallback(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	exe := filepath.Join(dir, "monitor64-agent")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("new")
	h := signedUpdate(priv, "2.0.0", runtime.GOOS, runtime.GOARCH, body)
	if err := applyUpdate(bytes.NewReader(body), h, exe); err != nil {
		t.Fatal(err)
	}
	if err := WriteUpdateMarker(exe, "1.0.0", "2.0.0"); err != nil {
		t.Fatal(err)
	}
	// erster Start der neuen Version: wartet auf Bestaetigung
	if pending, rolled, err := UpdateStart(exe, "2.0.0"); !pending || rolled || err != nil {
		t.Fatalf("first start: pending %v rolled %v err %v", pending, rolled, err)
	}
	// zweiter Start ohne Bestaetigung: zurueck auf die alte Datei
	if pending, rolled, err := UpdateStart(exe, "2.0.0"); pending || !rolled || err != nil {
		t.Fatalf("second start: pending %v rolled %v err %v", pending, rolled, err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("exe after rollback = %q", b)
	}
	if _, err := os.Stat(exe + markerSuffix); !os.IsNotExist(err) {
		t.Fatal("marker left after rollback")
	}
	// alte Version startet normal
	if pending, rolled, err := UpdateStart(exe, "1.0.0"); pending || rolled || err != nil {
		t.Fatalf("old start: pending %v rolled %v err %v", pending, rolled, err)
	}
	// dieselbe Version wird nicht erneut eingespielt, eine neuere schon
	if err := applyUpdate(bytes.NewReader(body), h, exe); err == nil || !strings.Contains(err.Error(), "did not start") {
		t.Fatalf("failed version accepted again: %v", err)
	}
	h3 := signedUpdate(priv, "2.0.1", runtime.GOOS, runtime.GOARCH, body)
	if err := applyUpdate(bytes.NewReader(body), h3, exe); err != nil {
		t.Fatal(err)
	}

	// bestaetigt: Merker weg, kein Rueckfall
	if err := WriteUpdateMarker(exe, "1.0.0", "2.0.1"); err != nil {
		t.Fatal(err)
	}
	if pending, _, _ := UpdateStart(exe, "2.0.1"); !pending {
		t.Fatal("pending expected")
	}
	ConfirmUpdate(exe, "2.0.1")
	if pending, rolled, _ := UpdateStart(exe, "2.0.1"); pending || rolled {
		t.Fatal("confirmed update rolled back")
	}
	// fremder Merker (andere Version): wird verworfen
	if err := WriteUpdateMarker(exe, "1.0.0", "9.9.9"); err != nil {
		t.Fatal(err)
	}
	if pending, rolled, _ := UpdateStart(exe, "2.0.1"); pending || rolled {
		t.Fatal("foreign marker used")
	}
	if b, _ := os.ReadFile(exe); string(b) != "new" {
		t.Fatalf("exe = %q", b)
	}
}

// S1-K4: Schreibweise der Version ("v1.3.0" / "1.3.0") darf den Rueckfall nicht ausschalten, auch nicht fuer die
// Sperre einer gescheiterten Version.
func TestUpdateFallbackVersionSpelling(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	exe := filepath.Join(dir, "monitor64-agent")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("new")
	h := signedUpdate(priv, "v1.3.0", runtime.GOOS, runtime.GOARCH, body)
	if err := applyUpdate(bytes.NewReader(body), h, exe); err != nil {
		t.Fatal(err)
	}
	if err := WriteUpdateMarker(exe, "1.2.0", "v1.3.0"); err != nil {
		t.Fatal(err)
	}
	if pending, rolled, err := UpdateStart(exe, "1.3.0"); !pending || rolled || err != nil {
		t.Fatalf("first start: pending %v rolled %v err %v", pending, rolled, err)
	}
	if pending, rolled, err := UpdateStart(exe, "1.3.0+build7"); pending || !rolled || err != nil {
		t.Fatalf("second start: pending %v rolled %v err %v", pending, rolled, err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("exe after rollback = %q", b)
	}
	// gescheiterte Version wird auch in der anderen Schreibweise nicht erneut angenommen
	h2 := signedUpdate(priv, "v1.3.0", runtime.GOOS, runtime.GOARCH, body)
	if err := applyUpdate(bytes.NewReader(body), h2, exe); err == nil || !strings.Contains(err.Error(), "did not start") {
		t.Fatalf("failed version accepted again: %v", err)
	}
	for _, c := range []struct {
		a, b string
		want bool
	}{{"v1.3.0", "1.3.0", true}, {"1.3.0\n", "1.3.0", true}, {"1.3.0+x", "v1.3.0", true}, {"1.3.0-rc.1", "1.3.0", false},
		{"dev", "vdev", true}, {"1.3.1", "1.3.0", false}} {
		if got := sameVersion(c.a, c.b); got != c.want {
			t.Errorf("sameVersion(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

// S1-K6: der Bestaetigungs-Timer der laufenden (unbestaetigten) Version loescht den Merker eines weiteren Updates
// nicht.
func TestConfirmUpdateKeepsNewerMarker(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "monitor64-agent")
	if err := os.WriteFile(exe, []byte("c"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteUpdateMarker(exe, "2.0.0", "2.1.0"); err != nil {
		t.Fatal(err)
	}
	ConfirmUpdate(exe, "2.0.0")
	if _, err := os.Stat(exe + markerSuffix); err != nil {
		t.Fatal("marker of the next update removed by the old version")
	}
	if pending, _, _ := UpdateStart(exe, "2.1.0"); !pending {
		t.Fatal("next version not pending")
	}
	ConfirmUpdate(exe, "v2.1.0")
	if _, err := os.Stat(exe + markerSuffix); !os.IsNotExist(err) {
		t.Fatal("own marker not removed")
	}
	// kaputter Merker wird weggeraeumt
	if err := os.WriteFile(exe+markerSuffix, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	ConfirmUpdate(exe, "2.1.0")
	if _, err := os.Stat(exe + markerSuffix); !os.IsNotExist(err) {
		t.Fatal("broken marker left")
	}
}

func TestReadUpdateHeader(t *testing.T) {
	if _, err := readUpdateHeader(bufio.NewReader(strings.NewReader(strings.Repeat("x", maxUpdateHeader+10) + "\n"))); err == nil {
		t.Fatal("oversized header accepted")
	}
	if _, err := readUpdateHeader(bufio.NewReader(strings.NewReader(`{"version":"1.0.0"`))); err == nil {
		t.Fatal("header without newline accepted")
	}
	h, err := readUpdateHeader(bufio.NewReader(strings.NewReader(`{"version":"1.0.0","size":3}` + "\nabc")))
	if err != nil || h.Version != "1.0.0" || h.Size != 3 {
		t.Fatalf("h=%+v err=%v", h, err)
	}
}

func TestParseReleaseKeys(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	s := base64.StdEncoding.EncodeToString(pub) + "," + base64.StdEncoding.EncodeToString(pub2)
	keys, err := ParseReleaseKeys(s)
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys %d err %v", len(keys), err)
	}
	if k, err := ParseReleaseKeys(""); err != nil || len(k) != 0 {
		t.Fatal("empty must give no keys")
	}
	if _, err := ParseReleaseKeys("abc"); err == nil {
		t.Fatal("garbage accepted")
	}
}

// F1-K5: update ueber SSH - Probestart schlaegt fehl: alte Datei zurueck, Version gesperrt; sonst Merker und Neustart.
func TestUpdateRequestProbe(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	exe := filepath.Join(dir, "monitor64-agent")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	cs, cl := testSigner(t)
	keys := filepath.Join(dir, "keys")
	if err := WriteKeysFile(keys, []byte(cl+"\n")); err != nil {
		t.Fatal(err)
	}
	var probeOK atomic.Bool // Zugriff aus dem Server-Goroutine
	updated := make(chan string, 1)
	_, addr := startServer(t, Config{KeysFile: keys, Version: "1.0.0", ReleaseKeys: []ed25519.PublicKey{pub}, ExePath: exe,
		Probe: func(string, string) error {
			if probeOK.Load() {
				return nil
			}
			return errors.New("exec format error")
		},
		OnUpdated: func(v string) { updated <- v }}, nil)
	send := func(version string) string {
		body := []byte("new " + version)
		h := signedUpdate(priv, version, runtime.GOOS, runtime.GOARCH, body)
		hb, _ := json.Marshal(h)
		c, err := dialAgent(addr, cs, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		out, _ := runAgent(c, "update", append(append(hb, '\n'), body...))
		return out
	}
	if out := send("2.0.0"); !strings.Contains(out, "new version does not start") {
		t.Fatalf("probe failure not reported: %q", out)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("exe after failed probe = %q", b)
	}
	if out := send("2.0.0"); !strings.Contains(out, "did not start on this host before") {
		t.Fatalf("failed version accepted again: %q", out)
	}
	probeOK.Store(true)
	if out := send("2.0.1"); !strings.Contains(out, `"ok":true`) {
		t.Fatalf("update refused: %q", out)
	}
	select {
	case v := <-updated:
		if v != "2.0.1" {
			t.Fatalf("OnUpdated(%q)", v)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OnUpdated not called")
	}
	if b, _ := os.ReadFile(exe + markerSuffix); !strings.Contains(string(b), `"to":"2.0.1"`) {
		t.Fatalf("marker = %q", b)
	}
	if b, _ := os.ReadFile(exe + oldSuffix); string(b) != "old" {
		t.Fatalf(".old = %q", b)
	}
}
