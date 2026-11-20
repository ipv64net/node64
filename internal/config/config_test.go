package config

import "testing"

func TestCheckWebPorts(t *testing.T) {
	for _, c := range []struct {
		h, s int
		want error
	}{{8080, 0, nil}, {0, 8443, nil}, {8080, 8443, nil}, {0, 0, ErrPortsOff}, {8080, 8080, ErrPortsSame}, {70000, 0, ErrPortRange}, {8080, -1, ErrPortRange}} {
		if got := CheckWebPorts(c.h, c.s); got != c.want {
			t.Errorf("%d/%d: %v, want %v", c.h, c.s, got, c.want)
		}
	}
}

func TestPortsFile(t *testing.T) {
	c := &Config{DataDir: t.TempDir(), HTTPPort: 8091, HTTPSPort: 0}
	if _, _, ok := c.ReadPortsFile(); ok {
		t.Fatal("ohne Datei keine Ports")
	}
	if err := c.WritePortsFile(); err != nil {
		t.Fatal(err)
	}
	if h, s, ok := c.ReadPortsFile(); !ok || h != 8091 || s != 0 {
		t.Fatalf("gelesen: %d %d %v", h, s, ok)
	}
}

func TestLoadKeepsEnvPorts(t *testing.T) {
	t.Setenv("NODE64_HTTP_PORT", "8091")
	t.Setenv("NODE64_HTTPS_PORT", "8443")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.EnvHTTPPort != 8091 || c.EnvHTTPSPort != 8443 {
		t.Fatalf("Umgebung: %d %d", c.EnvHTTPPort, c.EnvHTTPSPort)
	}
}
