package apis

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Gegen eine echte UniFi Network Application (Konsole oder selbst gehosteter Server): Test mit Bestaetigung des
// Fingerabdrucks, zwei Runden, falsche Zugangsdaten. Zugangsdaten nur ueber die Umgebung, nie im Repo:
//
//	M64_UF_ADDR=https://127.0.0.1:18444 M64_UF_USER=monitor64 M64_UF_SECRET=... [M64_UF_SITE=default] go test -run TestIntegrationUnifi -v ./internal/monitor64/apis/
//
// Ohne M64_UF_USER gilt M64_UF_SECRET als API-Schluessel (nur UniFi OS).
func TestIntegrationUnifi(t *testing.T) {
	addr := os.Getenv("M64_UF_ADDR")
	if addr == "" {
		t.Skip("M64_UF_ADDR nicht gesetzt")
	}
	cfg := UnifiConfig{Address: addr, User: os.Getenv("M64_UF_USER"), Secret: os.Getenv("M64_UF_SECRET"), Site: os.Getenv("M64_UF_SITE")}
	u, err := NewUnifi(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res := u.Test(context.Background())
	u.Close()
	if !res.NeedConfirm || res.Fingerprint == "" {
		t.Fatalf("ohne Pin: %+v", res)
	}
	t.Logf("Zertifikat %s (%s)", res.Fingerprint, res.CertSubject)
	cfg.Pin = res.Fingerprint
	if u, err = NewUnifi(cfg); err != nil {
		t.Fatal(err)
	}
	res = u.Test(context.Background())
	if !res.OK {
		u.Close()
		t.Fatalf("Test: %s", de(res.Error))
	}
	t.Logf("Test: Version %q, %s, UniFi OS=%v", res.Version, de(res.Summary), u.unifiOS)
	for round := 1; round <= 2; round++ {
		svcs, err := u.Collect(context.Background())
		if err != nil {
			t.Errorf("Runde %d: %v", round, deErr(err))
		}
		for _, s := range svcs {
			var ms []string
			for _, x := range s.Metrics {
				ms = append(ms, fmt.Sprintf("%s=%g%s", x.Name, x.Value, x.Unit))
			}
			t.Logf("Runde %d: %-28s %-8s vorgewaehlt=%-5v %s | %s | %v", round, s.Key, s.Kind, s.Default, de(s.Name), de(s.Text), ms)
		}
		if len(svcs) < 2 {
			t.Fatalf("Runde %d: nur %d Dienste", round, len(svcs))
		}
	}
	t.Logf("Alarme entfernt seit: %v", u.alarmsGone)
	u.Close()
	bad := cfg
	bad.Secret += "-falsch"
	b, err := NewUnifi(bad)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.Collect(context.Background()); err == nil || strings.Contains(deErr(err), cfg.Secret) {
		t.Errorf("falsche Zugangsdaten: %v", err)
	} else {
		t.Logf("falsche Zugangsdaten: %s", deErr(err))
	}
}
