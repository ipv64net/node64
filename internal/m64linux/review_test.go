package m64linux

import (
	"strings"
	"testing"
	"time"
)

// Review 13 (#159 per SSH): Das Skript meldet je Runde den Stand der Paketdatenbank (dieselben Dateien wie der
// Agent), der Parser legt ihn in Report.PkgStamp ab.
func TestReviewScriptPkgStamp(t *testing.T) {
	for _, p := range pkgFiles {
		if !strings.Contains(Script, " "+p+" ") && !strings.Contains(Script, " "+p+";") {
			t.Errorf("%s fehlt im Skript", p)
		}
	}
	out := "\n<<<m64:start>>>\n\n<<<m64:pkgstamp>>>\n/var/lib/dpkg/status 1234 1794300000\n/var/lib/apt/lists 4096 1794300001\n\n<<<m64:end>>>\n"
	r, err := ParseScriptOutput([]byte(out), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.PkgStamp, "/var/lib/dpkg/status 1234 1794300000") || !strings.Contains(r.PkgStamp, "apt/lists") {
		t.Fatalf("PkgStamp = %q", r.PkgStamp)
	}
}
