package apis

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Gegen ein echtes RouterOS (z. B. CHR in einer Test-VM): Test mit Bestaetigung des Fingerabdrucks, zwei Runden,
// falsches Passwort. Zugangsdaten nur ueber die Umgebung (Testwerte der VM), nie im Repo:
//
//	M64_MT_ADDR=https://127.0.0.1:18443 M64_MT_USER=monitor64 M64_MT_PASS=... go test -run TestIntegrationMikrotik -v ./internal/monitor64/apis/
func TestIntegrationMikrotik(t *testing.T) {
	addr := os.Getenv("M64_MT_ADDR")
	if addr == "" {
		t.Skip("M64_MT_ADDR nicht gesetzt")
	}
	user, pass := os.Getenv("M64_MT_USER"), os.Getenv("M64_MT_PASS")
	m, err := NewMikrotik(MikrotikConfig{Address: addr, User: user, Password: pass})
	if err != nil {
		t.Fatal(err)
	}
	res := m.Test(context.Background())
	m.Close()
	if !res.NeedConfirm || res.Fingerprint == "" {
		t.Fatalf("ohne Pin: %+v", res)
	}
	t.Logf("Zertifikat %s (%s)", res.Fingerprint, res.CertSubject)
	m, err = NewMikrotik(MikrotikConfig{Address: addr, User: user, Password: pass, Pin: res.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	res = m.Test(context.Background())
	if !res.OK {
		t.Fatalf("Test: %s", de(res.Error))
	}
	t.Logf("Test: Version %q, %s", res.Version, de(res.Summary))
	wait := 5 * time.Second
	for round := 1; round <= 2; round++ {
		svcs, err := m.Collect(context.Background())
		if err != nil {
			t.Errorf("Runde %d: %v", round, deErr(err))
		}
		for _, s := range svcs {
			var ms []string
			for _, x := range s.Metrics {
				ms = append(ms, fmt.Sprintf("%s=%g%s", x.Name, x.Value, x.Unit))
			}
			t.Logf("Runde %d: %-22s %-8s vorgewaehlt=%-5v %s | %s | %v", round, s.Key, s.Kind, s.Default, de(s.Name), de(s.Text), ms)
		}
		if len(svcs) < 4 {
			t.Fatalf("Runde %d: nur %d Dienste", round, len(svcs))
		}
		if round == 1 {
			time.Sleep(wait)
		}
	}
	t.Logf("nicht vorhandene Menues: %v", m.absent)
	bad, err := NewMikrotik(MikrotikConfig{Address: addr, User: user, Password: pass + "-falsch", Pin: res.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if _, err := bad.Collect(context.Background()); err == nil || strings.Contains(deErr(err), pass) {
		t.Errorf("falsches Passwort: %v", err)
	} else {
		t.Logf("falsches Passwort: %s", deErr(err))
	}
}
