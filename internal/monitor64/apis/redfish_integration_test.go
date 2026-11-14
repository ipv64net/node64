package apis

import (
	"context"
	"fmt"
	"os"
	"testing"
)

// Gegen einen echten Redfish-Dienst (BMC oder den DMTF-Mockup-Server): Test mit Bestaetigung des Fingerabdrucks und
// eine Runde. Zugangsdaten nur ueber die Umgebung, nie im Repo:
//
//	M64_RF_ADDR=https://127.0.0.1:18445 M64_RF_USER=... M64_RF_PASS=... go test -run TestIntegrationRedfish -v ./internal/monitor64/apis/
func TestIntegrationRedfish(t *testing.T) {
	addr := os.Getenv("M64_RF_ADDR")
	if addr == "" {
		t.Skip("M64_RF_ADDR nicht gesetzt")
	}
	cfg := RedfishConfig{Address: addr, User: os.Getenv("M64_RF_USER"), Password: os.Getenv("M64_RF_PASS")}
	r, err := NewRedfish(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res := r.Test(context.Background())
	r.Close()
	if !res.NeedConfirm || res.Fingerprint == "" {
		t.Fatalf("ohne Pin: %+v", res)
	}
	cfg.Pin = res.Fingerprint
	if r, err = NewRedfish(cfg); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	res = r.Test(context.Background())
	if !res.OK {
		t.Fatalf("Test: %s", de(res.Error))
	}
	t.Logf("Test: %s · %s · %s · Schraegstrich=%v", de(res.Version), res.Node, de(res.Summary), r.slash.Load())
	svcs, err := r.Collect(context.Background())
	if err != nil {
		t.Errorf("Collect: %v", deErr(err))
	}
	for _, s := range svcs {
		var ms []string
		for _, x := range s.Metrics {
			ms = append(ms, fmt.Sprintf("%s=%g%s", x.Name, x.Value, x.Unit))
		}
		t.Logf("%-40s %-8s %s | %s | %v", s.Key, s.Kind, de(s.Name), de(s.Text), ms)
	}
	if len(svcs) == 0 {
		t.Fatal("keine Dienste")
	}
}
