package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/web"
)

// freePort: ein gerade freier TCP-Port.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestApplyWebPorts(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(ctx, filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	core, _ := store.CoreMigrations()
	if err := st.Migrate(ctx, "core", core); err != nil {
		t.Fatal(err)
	}
	newCfg := func() *config.Config {
		return &config.Config{DataDir: dir, BindAddr: "127.0.0.1", HTTPPort: 8080, EnvHTTPPort: 8080}
	}

	// ohne Einstellung: Umgebung, Datei fuer den Healthcheck trotzdem
	cfg := newCfg()
	applyWebPorts(ctx, cfg, st, log)
	if h, hs, ok := cfg.ReadPortsFile(); cfg.HTTPPort != 8080 || !ok || h != 8080 || hs != 0 {
		t.Fatalf("ohne Einstellung: %d, Datei %d %d %v", cfg.HTTPPort, h, hs, ok)
	}

	// eingestellt: gilt vor der Umgebung
	p := freePort(t)
	st.SetSetting(ctx, web.SettingHTTPPort, strconv.Itoa(p))
	cfg = newCfg()
	applyWebPorts(ctx, cfg, st, log)
	if h, _, _ := cfg.ReadPortsFile(); cfg.HTTPPort != p || h != p {
		t.Fatalf("eingestellt: %d, Datei %d", cfg.HTTPPort, h)
	}

	// belegt: zurueck auf die Umgebung (sonst waere die Oberflaeche weg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	st.SetSetting(ctx, web.SettingHTTPPort, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	cfg = newCfg()
	applyWebPorts(ctx, cfg, st, log)
	if h, _, _ := cfg.ReadPortsFile(); cfg.HTTPPort != 8080 || h != 8080 {
		t.Fatalf("belegt: %d, Datei %d", cfg.HTTPPort, h)
	}

	// gleicher Port in beiden: Web-Port (spricht HTTPS mit), kein eigener HTTPS-Port
	same := strconv.Itoa(freePort(t))
	st.SetSetting(ctx, web.SettingHTTPPort, same)
	st.SetSetting(ctx, web.SettingHTTPSPort, same)
	cfg = newCfg()
	applyWebPorts(ctx, cfg, st, log)
	if strconv.Itoa(cfg.HTTPPort) != same || cfg.HTTPSPort != 0 {
		t.Fatalf("gleicher Port: %d %d", cfg.HTTPPort, cfg.HTTPSPort)
	}

	// ungueltig (beide aus): Umgebung
	st.SetSetting(ctx, web.SettingHTTPPort, "0")
	st.SetSetting(ctx, web.SettingHTTPSPort, "0")
	cfg = newCfg()
	applyWebPorts(ctx, cfg, st, log)
	if cfg.HTTPPort != 8080 || cfg.HTTPSPort != 0 {
		t.Fatalf("ungueltig: %d %d", cfg.HTTPPort, cfg.HTTPSPort)
	}
}
