package dns64

import (
	"context"
	"testing"
)

// Rebinding-Schutz: Standard an, feste Ausnahmen (ipv64-Domains, plex.direct), eigene Endungen und die Endungen der
// Docker-Labels; aus = kein Schutz (Review DN-3).
func TestRebindConfig(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	c := m.loadConfig(ctx)
	if !c.Rebind {
		t.Fatal("rebinding protection off by default")
	}
	c.RebindAllow, c.DockerDomains = []string{"*.Mein.Example.", "lab.test"}, "docker.example"
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	c = m.loadConfig(ctx)
	if len(c.RebindAllow) != 2 || c.RebindAllow[0] != "mein.example" {
		t.Fatalf("stored: %v", c.RebindAllow)
	}
	f := c.rebindFunc()
	for name, want := range map[string]bool{"evil.example": true, "nas.home64.de": false, "x.y.ipv64.net": false, "1-2-3-4.abc.plex.direct": false,
		"mein.example": false, "nas.mein.example": false, "lab.test": false, "app.docker.example": false, "notmein.example": true, "ipv64.net.evil.example": true} {
		if got := f(name); got != want {
			t.Errorf("%s: protected %v, want %v", name, got, want)
		}
	}
	c.RebindAllow = []string{"-bad.example"}
	if err := m.saveConfig(ctx, c); err == nil {
		t.Fatal("invalid suffix accepted")
	}
	c.RebindAllow, c.Rebind = nil, false
	if err := m.saveConfig(ctx, c); err != nil || m.loadConfig(ctx).rebindFunc() != nil {
		t.Fatalf("switch off: %v", err)
	}
}
