package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

// pveTestStore oeffnet eine leere Datenbank mit Kern- und allen Healthchecks-Migrationen (inkl. 0015_proxmox).
func pveTestStore(t *testing.T) (*Store, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	cm, _ := store.CoreMigrations()
	if err := core.Migrate(context.Background(), "core", cm); err != nil {
		t.Fatal(err)
	}
	hm, err := store.ReadMigrations(os.DirFS("../healthchecks"), "migrations")
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Migrate(context.Background(), "healthchecks", hm); err != nil {
		t.Fatal(err)
	}
	box, err := secrets.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return NewStore(core, box), core
}

const pveTestSecret = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

func pveNewSystem(t *testing.T, s *Store) *System {
	t.Helper()
	sys := &System{Name: "Lab", Addresses: []string{"pve1.example.com"}, TokenID: "monitor@pve!node64", Secret: pveTestSecret, Enabled: true}
	if err := s.SaveSystem(context.Background(), sys); err != nil {
		t.Fatal(err)
	}
	return sys
}

func TestStoreSystems(t *testing.T) {
	ctx := context.Background()
	s, core := pveTestStore(t)
	sys := pveNewSystem(t, s)
	if sys.ID == 0 || sys.Interval != DefaultInterval || sys.Addresses[0] != "https://pve1.example.com:8006" {
		t.Fatalf("normalisiert: %+v", sys)
	}
	var raw string
	if err := core.Reader().QueryRow(`SELECT secret FROM pve_systems WHERE id = ?`, sys.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !secrets.IsEncrypted(raw) || strings.Contains(raw, pveTestSecret) {
		t.Fatalf("Secret nicht verschluesselt: %q", raw)
	}
	got, err := s.System(ctx, sys.ID)
	if err != nil || got.Secret != pveTestSecret || got.TokenID != sys.TokenID || !got.Enabled || got.Created.IsZero() {
		t.Fatalf("System: %+v %v", got, err)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), pveTestSecret) {
		t.Fatalf("Secret im JSON: %s", b)
	}

	// Aendern ohne Secret behaelt das alte
	got.Secret, got.Name, got.Interval = "", "Lab 2", 60
	got.Addresses = []string{"https://10.0.0.1:8006", "10.0.0.2", "https://10.0.0.1:8006"}
	if err := s.SaveSystem(ctx, got); err != nil {
		t.Fatal(err)
	}
	again, _ := s.System(ctx, sys.ID)
	if again.Secret != pveTestSecret || again.Name != "Lab 2" || again.Interval != 60 || len(again.Addresses) != 2 {
		t.Fatalf("nach Aendern: %+v", again)
	}
	again.Secret = "neu"
	if err := s.SaveSystem(ctx, again); err != nil {
		t.Fatal(err)
	}
	if x, _ := s.System(ctx, sys.ID); x.Secret != "neu" {
		t.Fatalf("neues Secret: %q", x.Secret)
	}

	pveNewSystem(t, s)
	list, err := s.Systems(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("Systems: %d %v", len(list), err)
	}

	// Loeschen mit Einstellungen
	if err := s.SaveSettings(ctx, &Settings{SystemID: sys.ID, Key: "qemu/100", Muted: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSystem(ctx, sys.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.System(ctx, sys.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nach Loeschen: %v", err)
	}
	var n int
	core.Reader().QueryRow(`SELECT count(*) FROM pve_settings WHERE system_id = ?`, sys.ID).Scan(&n)
	if n != 0 {
		t.Fatalf("Einstellungen nicht geloescht: %d", n)
	}
	if err := s.DeleteSystem(ctx, sys.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("zweites Loeschen: %v", err)
	}
	if err := s.SaveSystem(ctx, &System{ID: 999, Addresses: []string{"h"}, TokenID: "a@b!c"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unbekanntes System: %v", err)
	}
}

func TestStoreNoBox(t *testing.T) {
	_, core := pveTestStore(t)
	s := NewStore(core, nil)
	err := s.SaveSystem(context.Background(), &System{Addresses: []string{"h"}, TokenID: "a@b!c", Secret: "x"})
	if !errors.Is(err, ErrNoBox) {
		t.Fatalf("ohne Box: %v", err)
	}
}

func TestValidateSystem(t *testing.T) {
	ok := func() System {
		return System{Addresses: []string{"https://pve:8006"}, TokenID: "root@pam!mon", Secret: "x", Interval: 30}
	}
	cases := []struct {
		name  string
		mod   func(*System)
		field string
	}{
		{"ok", func(*System) {}, ""},
		{"http", func(s *System) { s.Addresses = []string{"http://pve:8006"} }, "addresses"},
		{"ohne Adresse", func(s *System) { s.Addresses = []string{" "} }, "addresses"},
		{"Port 0", func(s *System) { s.Addresses = []string{"https://pve:0"} }, "addresses"},
		{"Port zu gross", func(s *System) { s.Addresses = []string{"pve:70000"} }, "addresses"},
		{"IPv6", func(s *System) { s.Addresses = []string{"[fd00::1]"} }, ""},
		{"IPv6 mit Zone", func(s *System) { s.Addresses = []string{"fe80::1%eth0"} }, "addresses"},
		{"Token ohne !", func(s *System) { s.TokenID = "root@pam" }, "token_id"},
		{"Token ohne @", func(s *System) { s.TokenID = "root!mon" }, "token_id"},
		{"ohne Secret", func(s *System) { s.Secret = "" }, "secret"},
		{"Interval klein", func(s *System) { s.Interval = 10 }, "interval"},
		{"Interval gross", func(s *System) { s.Interval = 301 }, "interval"},
		{"Interval 0 = Standard", func(s *System) { s.Interval = 0 }, ""},
		{"Pin mit Doppelpunkten", func(s *System) { s.PinSHA256 = strings.Repeat("AB:", 31) + "AB" }, ""},
		{"Pin kurz", func(s *System) { s.PinSHA256 = "abcd" }, "pin_sha256"},
		{"Pin kein hex", func(s *System) { s.PinSHA256 = strings.Repeat("g", 64) }, "pin_sha256"},
	}
	for _, c := range cases {
		s := ok()
		c.mod(&s)
		err := ValidateSystem(&s, true)
		var fe *FieldError
		switch {
		case c.field == "" && err != nil:
			t.Errorf("%s: unerwarteter Fehler %v", c.name, err)
		case c.field != "" && (!errors.As(err, &fe) || fe.Field != c.field):
			t.Errorf("%s: erwartet Feld %s, bekommen %v", c.name, c.field, err)
		}
	}
	s := ok()
	s.PinSHA256 = strings.Repeat("AB:", 31) + "AB"
	s.Addresses = []string{"[FD00::1]"}
	ValidateSystem(&s, true)
	if s.PinSHA256 != strings.Repeat("ab", 32) || s.Addresses[0] != "https://[fd00::1]:8006" {
		t.Fatalf("normalisiert: %q %q", s.PinSHA256, s.Addresses)
	}
	// IPv6 ohne Klammern: ganze Adresse ist der Host, Port der Standard
	if a, ok := NormalizeAddress("fd00::10"); !ok || a != "https://[fd00::10]:8006" {
		t.Fatalf("ipv6 ohne klammern: %q %v", a, ok)
	}
	if a, ok := NormalizeAddressFor(KindPBS, " 2001:DB8::1 "); !ok || a != "https://[2001:db8::1]:8007" {
		t.Fatalf("ipv6 ohne klammern pbs: %q %v", a, ok)
	}
	s = ok()
	s.Secret = ""
	if err := ValidateSystem(&s, false); err != nil {
		t.Fatalf("Aendern ohne Secret: %v", err)
	}
}

func pveBool(b bool) *bool { return &b }

// pveEffective: wirksame Regel einer Ebene aus dem Speicher.
func pveEffective(ctx context.Context, s *Store, id int64, key, node string) (Rule, error) {
	ss, err := s.Settings(ctx, id)
	if err != nil {
		return Rule{}, err
	}
	return ss.Effective(key, node), nil
}

func TestRulesInheritance(t *testing.T) {
	ctx := context.Background()
	s, _ := pveTestStore(t)
	sys := pveNewSystem(t, s)

	def, err := pveEffective(ctx, s, sys.ID, "qemu/100", "pve1")
	if err != nil || !reflect.DeepEqual(def, DefaultRule()) {
		t.Fatalf("Standard: %+v %v", def, err)
	}
	if d := DefaultRule(); !d.Crashed || !d.Stopped || !d.Restarted || d.CPU != (Threshold{90, 10}) || d.Mem != (Threshold{95, 10}) ||
		d.Disk != (Threshold{90, 0}) || d.Delay != 2 {
		t.Fatalf("Standardwerte: %+v", d)
	}
	delay := 3
	must := func(st *Settings) {
		t.Helper()
		if err := s.SaveSettings(ctx, st); err != nil {
			t.Fatal(err)
		}
	}
	must(&Settings{SystemID: sys.ID, Key: "", Rules: RuleSet{CPU: &Threshold{80, 5}, Delay: &delay}})
	must(&Settings{SystemID: sys.ID, Key: "node/pve1", Rules: RuleSet{Stopped: pveBool(false), Mem: &Threshold{70, 1}}})
	must(&Settings{SystemID: sys.ID, Key: "qemu/100", Rules: RuleSet{CPU: &Threshold{0, 0}, Stopped: pveBool(true)}, ExpectRunning: pveBool(false)})

	r, _ := pveEffective(ctx, s, sys.ID, "qemu/100", "pve1")
	if r.CPU.Percent != 0 || !r.Stopped || r.Mem != (Threshold{70, 1}) || r.Delay != 3 || r.Disk != (Threshold{90, 0}) {
		t.Fatalf("Gast: %+v", r)
	}
	r, _ = pveEffective(ctx, s, sys.ID, "qemu/101", "pve1")
	if r.CPU != (Threshold{80, 5}) || r.Stopped || r.Mem.Percent != 70 {
		t.Fatalf("anderer Gast auf pve1: %+v", r)
	}
	r, _ = pveEffective(ctx, s, sys.ID, "qemu/101", "pve2")
	if r.CPU != (Threshold{80, 5}) || !r.Stopped || r.Mem.Percent != 95 {
		t.Fatalf("Gast auf pve2: %+v", r)
	}
	r, _ = pveEffective(ctx, s, sys.ID, "node/pve1", "pve1")
	if r.Mem.Percent != 70 || r.Stopped {
		t.Fatalf("Node: %+v", r)
	}
	r, _ = pveEffective(ctx, s, sys.ID, "", "")
	if r.CPU.Percent != 80 || r.Mem.Percent != 95 {
		t.Fatalf("System: %+v", r)
	}

	ss, _ := s.Settings(ctx, sys.ID)
	if it := ss.Item("qemu/100"); it == nil || it.ExpectRunning == nil || *it.ExpectRunning {
		t.Fatalf("ExpectRunning: %+v", it)
	}
	if ss.Name != "Lab" {
		t.Fatalf("Name: %q", ss.Name)
	}
	if err := s.ResetSettings(ctx, sys.ID, "qemu/100"); err != nil {
		t.Fatal(err)
	}
	r, _ = pveEffective(ctx, s, sys.ID, "qemu/100", "pve1")
	if r.CPU.Percent != 80 || r.Stopped {
		t.Fatalf("nach Zuruecksetzen: %+v", r)
	}

	// Validierung
	bad := 0
	var fe *FieldError
	if err := s.SaveSettings(ctx, &Settings{SystemID: sys.ID, Key: "qemu/x"}); !errors.As(err, &fe) || fe.Field != "key" {
		t.Fatalf("Key: %v", err)
	}
	if err := s.SaveSettings(ctx, &Settings{SystemID: sys.ID, Key: "lxc/1", Rules: RuleSet{Delay: &bad}}); !errors.As(err, &fe) || fe.Field != "delay" {
		t.Fatalf("Delay: %v", err)
	}
	if err := s.SaveSettings(ctx, &Settings{SystemID: sys.ID, Key: "lxc/1", Rules: RuleSet{Disk: &Threshold{101, 0}}}); !errors.As(err, &fe) || fe.Field != "disk" {
		t.Fatalf("Disk: %v", err)
	}
	if err := s.SaveSettings(ctx, &Settings{SystemID: 999, Key: "lxc/1"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unbekanntes System: %v", err)
	}
	if err := s.SaveSettings(ctx, &Settings{SystemID: sys.ID, Key: "lxc/1", Rules: RuleSet{Channels: &[]int64{3, 0}}}); !errors.As(err, &fe) || fe.Field != "channels" {
		t.Fatalf("Channels: %v", err)
	}
	// AsCheck mit Check
	must(&Settings{SystemID: sys.ID, Key: "lxc/200", AsCheck: true, CheckToken: "tok"})
	ss, _ = s.Settings(ctx, sys.ID)
	if it := ss.Item("lxc/200"); !it.AsCheck || it.CheckToken != "tok" || it.ExpectRunning != nil {
		t.Fatalf("AsCheck: %+v", it)
	}
	// Zuruecksetzen behaelt „als Check“
	must(&Settings{SystemID: sys.ID, Key: "lxc/200", AsCheck: true, CheckToken: "tok", Muted: true, Rules: RuleSet{Delay: &delay}})
	if err := s.ResetSettings(ctx, sys.ID, "lxc/200"); err != nil {
		t.Fatal(err)
	}
	ss, _ = s.Settings(ctx, sys.ID)
	if it := ss.Item("lxc/200"); !it.AsCheck || it.CheckToken != "tok" || it.Muted || it.Rules != (RuleSet{}) {
		t.Fatalf("Reset mit AsCheck: %+v", it)
	}
	if err := s.ResetSettings(ctx, sys.ID, "qemu/x"); !errors.As(err, &fe) {
		t.Fatalf("Reset Key: %v", err)
	}
}

// Gespeichertes Secret nur fuer dieselben Adressen und denselben Pin.
func TestSameEndpoint(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	a := &System{Addresses: []string{"https://pve1:8006", "pve2"}, PinSHA256: pin}
	for _, c := range []struct {
		b    System
		same bool
	}{
		{System{Addresses: []string{"pve2:8006", "PVE1"}, PinSHA256: strings.ToUpper(pin)}, true},
		{System{Addresses: []string{"pve1", "pve2", "pve2"}, PinSHA256: pin}, true},
		{System{Addresses: []string{"pve1"}, PinSHA256: pin}, false},
		{System{Addresses: []string{"pve1", "evil"}, PinSHA256: pin}, false},
		{System{Addresses: []string{"pve1", "pve2"}}, false},
		{System{Addresses: []string{"pve1", "pve2"}, PinSHA256: strings.Repeat("cd", 32)}, false},
	} {
		if got := SameEndpoint(a, &c.b); got != c.same {
			t.Errorf("%+v: %v", c.b, got)
		}
	}
}

// Kanaele: nil = erben, leere Liste = Standardkanaele, sonst diese (doppelte entfernt, sortiert); JSON-Roundtrip.
func TestRulesChannels(t *testing.T) {
	ctx := context.Background()
	s, _ := pveTestStore(t)
	sys := pveNewSystem(t, s)
	must := func(st *Settings) {
		t.Helper()
		if err := s.SaveSettings(ctx, st); err != nil {
			t.Fatal(err)
		}
	}
	eff := func(key, node string) []int64 {
		t.Helper()
		r, err := pveEffective(ctx, s, sys.ID, key, node)
		if err != nil {
			t.Fatal(err)
		}
		return r.Channels
	}
	if c := eff("qemu/100", "pve1"); c == nil || len(c) != 0 {
		t.Fatalf("Standard: %v", c)
	}
	must(&Settings{SystemID: sys.ID, Key: "", Rules: RuleSet{Channels: &[]int64{7, 3, 7}}})
	must(&Settings{SystemID: sys.ID, Key: "node/pve1", Rules: RuleSet{Channels: &[]int64{}}})
	must(&Settings{SystemID: sys.ID, Key: "qemu/101", Rules: RuleSet{Channels: &[]int64{9}}})
	must(&Settings{SystemID: sys.ID, Key: "qemu/102", Muted: true}) // ohne Kanaele: erbt
	for _, c := range []struct {
		key, node string
		want      []int64
	}{
		{"", "", []int64{3, 7}},              // System: sortiert, ohne doppelte
		{"node/pve2", "pve2", []int64{3, 7}}, // Node ohne eigene: vom System
		{"qemu/200", "pve2", []int64{3, 7}},  // Gast auf pve2: vom System
		{"node/pve1", "pve1", []int64{}},     // Node: Standardkanaele
		{"qemu/100", "pve1", []int64{}},      // Gast auf pve1: vom Node (Standardkanaele)
		{"qemu/101", "pve1", []int64{9}},     // Gast mit eigener Auswahl
		{"qemu/102", "pve2", []int64{3, 7}},  // Gast mit Einstellungen, aber ohne Kanaele
	} {
		if got := eff(c.key, c.node); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s@%s: %v, erwartet %v", c.key, c.node, got, c.want)
		}
	}
	ss, _ := s.Settings(ctx, sys.ID)
	if it := ss.Item("node/pve1"); it == nil || it.Rules.Channels == nil || len(*it.Rules.Channels) != 0 {
		t.Fatalf("leere Liste gespeichert: %+v", it)
	}
	if it := ss.Item("qemu/102"); it == nil || it.Rules.Channels != nil {
		t.Fatalf("ohne Kanaele: %+v", it)
	}
	b, _ := json.Marshal(ss.Item("node/pve1").Rules)
	if string(b) != `{"channels":[]}` {
		t.Fatalf("JSON: %s", b)
	}
	// Zuruecksetzen: wieder erben
	if err := s.ResetSettings(ctx, sys.ID, "node/pve1"); err != nil {
		t.Fatal(err)
	}
	if got := eff("qemu/100", "pve1"); !reflect.DeepEqual(got, []int64{3, 7}) {
		t.Fatalf("nach Zuruecksetzen: %v", got)
	}
}
