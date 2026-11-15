package monitor64

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// AG-2: Die Node nennt im Installationsbefehl die Pruefsumme von SHA256SUMS aus ihrem signierten Verzeichnis - erst
// ab dem Release, dessen Skripte die Option kennen (aeltere brechen mit "unknown option" ab).
func TestAG2SumsInCommand(t *testing.T) {
	for _, c := range []struct {
		version string
		want    bool
	}{{"0.1.7", false}, {"0.1.8", true}, {"0.4.0", true}} {
		rel := newAgentRel(t)
		ix := rel.publish(c.version)
		m, _, _ := newTestModule(t)
		rel.use(m)
		ctx := context.Background()
		if err := m.Start(ctx); err != nil {
			t.Fatal(err)
		}
		if got := m.agentCmdInfo().SumsSHA256; got != "" {
			t.Fatalf("%s: Pruefsumme ohne Verzeichnis: %q", c.version, got)
		}
		if err := m.agents().dist.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(ix.Sums())
		got := m.agentCmdInfo().SumsSHA256
		if (got == hex.EncodeToString(sum[:])) != c.want || (!c.want && got != "") {
			t.Errorf("%s: SumsSHA256 = %q", c.version, got)
		}
		_ = m.Stop(ctx)
	}
}
