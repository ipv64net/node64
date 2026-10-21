package web

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/healthchecks"
)

// Datenhaltung und der MCP-Schalter ziehen mit der Konfiguration um, MCP-Schluessel nie.
func TestExportDataSettingsAndMCP(t *testing.T) {
	ctx := context.Background()
	a := newTestApp(t)
	for k, v := range map[string]string{healthchecks.SettingRawDays: "180", healthchecks.SettingHourlyDays: "0", healthchecks.SettingChartDetail: "fine",
		SettingAuditDays: "90", setMCPEnabled: "1"} {
		_ = a.store.SetSetting(ctx, k, v)
	}
	u, err := a.store.CreateUser(ctx, "admin2", "x", "", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.store.NewMCPKey(ctx, u.ID, "claude", []string{"healthchecks:read"}); err != nil {
		t.Fatal(err)
	}
	cf, err := a.s.buildExport(ctx, "password", "export-passwort")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(cf)
	if strings.Contains(string(raw), "claude") || strings.Contains(string(raw), "mcp_") {
		t.Fatalf("mcp key in export: %s", raw)
	}
	b := newTestApp(t)
	if _, _, err := b.s.applyImport(ctx, raw, "export-passwort"); err != nil {
		t.Fatal(err)
	}
	if healthchecks.RawDays(b.store) != 180 || healthchecks.HourlyDays(b.store) != 0 || healthchecks.ChartDetail(b.store) != "fine" || AuditDays(b.store) != 90 ||
		b.store.SettingOr(ctx, setMCPEnabled, "") != "1" {
		t.Fatal("data settings or mcp switch not imported")
	}
}
