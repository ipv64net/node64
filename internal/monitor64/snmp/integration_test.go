package snmp

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Test gegen einen echten Agenten (z. B. net-snmp im Container), normal uebersprungen:
//
//	M64_SNMP_TARGET=host:161 M64_SNMP_COMMUNITY=... M64_SNMP_V3="user:level:auth:authpass:priv:privpass;..." go test -run Integration
//
// Zugangsdaten nur ueber die Umgebung (Testwerte des Containers), nie im Repo.
func TestIntegrationAgent(t *testing.T) {
	target := os.Getenv("M64_SNMP_TARGET")
	if target == "" {
		t.Skip("M64_SNMP_TARGET nicht gesetzt")
	}
	check := func(name string, cfg Config, rounds int) {
		t.Helper()
		cfg.Address = target
		c, err := New(cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		defer c.Close()
		var svcs []string
		for i := 0; i < rounds; i++ {
			if i > 0 {
				time.Sleep(5 * time.Second)
			}
			s, err := c.Collect(context.Background())
			if err != nil {
				t.Fatalf("%s Runde %d: %v", name, i+1, err)
			}
			svcs = svcs[:0]
			for _, sv := range s {
				var ms []string
				for _, m := range sv.Metrics {
					ms = append(ms, fmt.Sprintf("%s=%g%s", m.Name, m.Value, m.Unit))
				}
				svcs = append(svcs, sv.Key+" ["+strings.Join(ms, " ")+"] "+sv.Text)
			}
		}
		t.Logf("%s:\n  %s", name, strings.Join(svcs, "\n  "))
		joined := strings.Join(svcs, "\n")
		for _, want := range []string{"uptime [", "cpu [util=", "load [", "mem [used=", "if:eth0 [in="} {
			if !strings.Contains(joined, want) {
				t.Errorf("%s: %q fehlt", name, want)
			}
		}
		d, err := c.Discover(context.Background())
		if err != nil || !d.OK {
			t.Fatalf("%s Discover: %v", name, err)
		}
		t.Logf("%s Discover: Geraet=%s Profile=%v Summary=%q Warnung=%q", name, d.Device, d.Profiles, d.Summary, d.Warning)
	}
	if comm := os.Getenv("M64_SNMP_COMMUNITY"); comm != "" {
		check("v2c", Config{Secret: Secret{Community: comm}}, 2)
		check("v1", Config{Version: "1", Secret: Secret{Community: comm}}, 2)
		c, _ := New(Config{Address: target, Secret: Secret{Community: comm + "-falsch"}, Timeout: 500 * time.Millisecond, Retries: -1})
		if _, err := c.Collect(context.Background()); err == nil || strings.Contains(deErr(err), comm) {
			t.Errorf("falsche Community: %v", err)
		}
		c.Close()
	}
	for _, spec := range strings.Split(os.Getenv("M64_SNMP_V3"), ";") {
		f := strings.Split(spec, ":")
		if len(f) != 6 {
			continue
		}
		cfg := Config{Version: "3", User: f[0], Level: f[1], AuthProto: f[2], PrivProto: f[4], Secret: Secret{AuthPass: f[3], PrivPass: f[5]}}
		check("v3 "+f[0]+" "+f[1], cfg, 2)
		if f[1] != "noAuthNoPriv" {
			bad := cfg
			bad.Address, bad.Secret.AuthPass, bad.Timeout, bad.Retries = target, "falsches-passwort", 500*time.Millisecond, -1
			c, err := New(bad)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Collect(context.Background()); err == nil || strings.Contains(deErr(err), "falsches-passwort") {
				t.Errorf("v3 %s falsches Passwort: %v", f[0], err)
			}
			c.Close()
		}
	}
}
