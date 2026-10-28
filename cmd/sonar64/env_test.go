package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/sonar"
)

const (
	testNodeTok   = "s64_" + "abcdefghijABCDEFGHIJ0123456789abcdefghij"
	testAnchorTok = "s64a_" + "abcdefghijABCDEFGHIJ0123456789abcdefghij"
	testPlanKey   = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadEnvDefaults(t *testing.T) {
	o, err := loadEnv(env(map[string]string{"SONAR64_TOKEN": testNodeTok}))
	if err != nil {
		t.Fatal(err)
	}
	c := o.Config
	if c.Token != testNodeTok || c.Mode != "headless" || c.Measured || c.Budget != sonar.BudgetLow ||
		c.DataDir != "/data" || c.Quiet != [2]int{} || c.APIBase != "" || c.PlanKeys != nil {
		t.Fatalf("defaults: %+v", c)
	}
	if o.StatusAddr != "" || o.LogLevel != slog.LevelInfo {
		t.Fatalf("status/log: %+v", o)
	}
}

func TestLoadEnvAll(t *testing.T) {
	o, err := loadEnv(env(map[string]string{
		"SONAR64_TOKEN":     " " + testNodeTok + " ",
		"SONAR64_MODE":      "headless",
		"SONAR64_MEASURED":  "1",
		"SONAR64_BUDGET":    "Normal",
		"SONAR64_QUIET":     "23-6",
		"SONAR64_DATA":      "/var/lib/sonar64",
		"SONAR64_STATUS":    "8064",
		"SONAR64_API":       "http://127.0.0.1:9999/api/v2/",
		"SONAR64_PLAN_KEY":  testPlanKey,
		"SONAR64_LOG_LEVEL": "debug",
	}))
	if err != nil {
		t.Fatal(err)
	}
	c := o.Config
	if !c.Measured || c.Budget != sonar.BudgetNormal || c.Quiet != [2]int{23, 6} || c.DataDir != "/var/lib/sonar64" ||
		c.APIBase != "http://127.0.0.1:9999/api/v2" || o.StatusAddr != ":8064" || o.LogLevel != slog.LevelDebug {
		t.Fatalf("all: %+v / %+v", c, o)
	}
	if len(sonar.PlanKeys) == 0 && (len(c.PlanKeys) != 1 || c.PlanKeys[0] != testPlanKey) {
		t.Fatalf("plan key: %v", c.PlanKeys)
	}
	if len(o.Warnings) < 2 {
		t.Fatalf("warnings: %v", o.Warnings)
	}
}

func TestLoadEnvAnchor(t *testing.T) {
	o, err := loadEnv(env(map[string]string{"SONAR64_TOKEN": testAnchorTok, "SONAR64_MEASURED": "0"}))
	if err != nil {
		t.Fatal(err)
	}
	if o.Config.Mode != sonar.RoleAnchor || !o.Config.Measured {
		t.Fatalf("anchor: %+v", o.Config)
	}
	if _, err := loadEnv(env(map[string]string{"SONAR64_TOKEN": testAnchorTok, "SONAR64_MODE": "anchor"})); err != nil {
		t.Fatal(err)
	}
}

func TestLoadEnvErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"no token":          {},
		"short token":       {"SONAR64_TOKEN": "s64_abc"},
		"bad token chars":   {"SONAR64_TOKEN": "s64_" + strings.Repeat("a", 39) + "\n"},
		"api key as token":  {"SONAR64_TOKEN": strings.Repeat("a", 32)},
		"bad mode":          {"SONAR64_TOKEN": testNodeTok, "SONAR64_MODE": "module"},
		"anchor w/ node":    {"SONAR64_TOKEN": testNodeTok, "SONAR64_MODE": "anchor"},
		"headless w/ anch":  {"SONAR64_TOKEN": testAnchorTok, "SONAR64_MODE": "headless"},
		"bad measured":      {"SONAR64_TOKEN": testNodeTok, "SONAR64_MEASURED": "ja"},
		"bad budget":        {"SONAR64_TOKEN": testNodeTok, "SONAR64_BUDGET": "max"},
		"bad quiet":         {"SONAR64_TOKEN": testNodeTok, "SONAR64_QUIET": "23:6"},
		"quiet hour 24":     {"SONAR64_TOKEN": testNodeTok, "SONAR64_QUIET": "22-24"},
		"quiet same":        {"SONAR64_TOKEN": testNodeTok, "SONAR64_QUIET": "5-5"},
		"status host name":  {"SONAR64_TOKEN": testNodeTok, "SONAR64_STATUS": "example.com:8064"},
		"status port 0":     {"SONAR64_TOKEN": testNodeTok, "SONAR64_STATUS": ":0"},
		"status no port":    {"SONAR64_TOKEN": testNodeTok, "SONAR64_STATUS": "127.0.0.1"},
		"api http remote":   {"SONAR64_TOKEN": testNodeTok, "SONAR64_API": "http://ipv64.net/api/v2"},
		"api other scheme":  {"SONAR64_TOKEN": testNodeTok, "SONAR64_API": "ftp://ipv64.net/"},
		"api with user":     {"SONAR64_TOKEN": testNodeTok, "SONAR64_API": "https://u:p@ipv64.net/"},
		"bad plan key":      {"SONAR64_TOKEN": testNodeTok, "SONAR64_PLAN_KEY": "abc"},
		"bad log level":     {"SONAR64_TOKEN": testNodeTok, "SONAR64_LOG_LEVEL": "trace"},
		"nul in data dir":   {"SONAR64_TOKEN": testNodeTok, "SONAR64_DATA": "/data\x00x"},
		"plan key 31 bytes": {"SONAR64_TOKEN": testNodeTok, "SONAR64_PLAN_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="},
	}
	for name, m := range cases {
		if _, err := loadEnv(env(m)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLoadEnvNoTokenInErrors(t *testing.T) {
	bad := "s64_" + strings.Repeat("Z", 41)
	_, err := loadEnv(env(map[string]string{"SONAR64_TOKEN": bad, "SONAR64_MODE": "anchor"}))
	if err == nil || strings.Contains(err.Error(), bad) || strings.Contains(err.Error(), "ZZZZ") {
		t.Fatalf("error must not contain the token: %v", err)
	}
}

func TestLoadEnvLogLevelOnError(t *testing.T) {
	o, err := loadEnv(env(map[string]string{"SONAR64_LOG_LEVEL": "warn"}))
	if err == nil || o.LogLevel != slog.LevelWarn {
		t.Fatalf("level %v err %v", o.LogLevel, err)
	}
}

func TestParseStatusAddr(t *testing.T) {
	for in, want := range map[string]string{
		":8064": ":8064", "8064": ":8064", "127.0.0.1:8064": "127.0.0.1:8064", "[::1]:8064": "[::1]:8064",
		"localhost:1": "localhost:1", "0.0.0.0:65535": "0.0.0.0:65535",
	} {
		got, err := parseStatusAddr(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
}

func TestPrepareDataDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	if err := prepareDataDir(dir); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Fatalf("probe file left: %v", ents)
	}
	if os.Getuid() != 0 {
		ro := t.TempDir()
		_ = os.Chmod(ro, 0o500)
		if err := prepareDataDir(ro); err == nil {
			t.Fatal("expected error for read-only dir")
		}
	}
}
