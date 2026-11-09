package monitor64

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/snmp"
)

// Echttest Modul + SNMP-Zugang gegen einen Agenten (z. B. net-snmp im Container), normal uebersprungen:
//
//	M64_MOD_SNMP_HOST=m64-snmpdw M64_MOD_SNMP_COMMUNITY=... [M64_MOD_SNMP_V3="user:authpass:privpass"]
//	M64_MOD_TRAP_PORT=1162 M64_MOD_TRAP_READY=/src/.trap-ready go test -run IntegrationSNMPModule
//
// Der Test fragt den Agenten ueber den Zugang ab (Verbindung testen und eine Runde), oeffnet den Trap-Empfaenger,
// meldet Bereitschaft ueber die Datei M64_MOD_TRAP_READY und erwartet vom Agenten einen linkDown (sofortige Runde)
// und einen unbekannten Trap (Dienst "traps" mit Warnung). Zugangsdaten nur ueber die Umgebung (Testwerte).
func TestIntegrationSNMPModule(t *testing.T) {
	target := os.Getenv("M64_MOD_SNMP_HOST")
	if target == "" {
		t.Skip("M64_MOD_SNMP_HOST nicht gesetzt")
	}
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if p := os.Getenv("M64_MOD_TRAP_PORT"); p != "" {
		if err := m.st.SetSetting(ctx, setTrapPort, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	h := &Host{Name: target, Address: target, Kind: "snmp", IntervalSec: 300}
	if err := m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	add := func(cfg accessConfig, sec snmp.Secret) *Access {
		t.Helper()
		raw, _ := json.Marshal(cfg)
		clean, err := cleanAccessConfig("snmp", raw)
		if err != nil {
			t.Fatal(err)
		}
		a := &Access{HostUID: h.UID, Type: "snmp", Config: clean, Secret: m.box.Encrypt(sec.String()), Enabled: true}
		if err := checkSNMPSecret(cfg, sec.String()); err != nil {
			t.Fatal(err)
		}
		return a
	}
	accs := []*Access{add(accessConfig{SNMPVersion: "2c", Traps: true}, snmp.Secret{Community: os.Getenv("M64_MOD_SNMP_COMMUNITY")})}
	if v3 := strings.Split(os.Getenv("M64_MOD_SNMP_V3"), ":"); len(v3) == 3 {
		accs = append(accs, add(accessConfig{SNMPVersion: "3", User: v3[0], Level: "authPriv", AuthProto: "SHA256", PrivProto: "AES"}, snmp.Secret{AuthPass: v3[1], PrivPass: v3[2]}))
	}
	for i, a := range accs {
		res := m.testAccess(ctx, h, *a)
		t.Logf("Zugang %d: ok=%v fehler=%q geraet=%s profile=%v version=%q warnung=%q dienste=%d", i, res.OK, res.Error, res.Device, res.Profiles, res.Version, res.Warning, len(res.Services))
		if !res.OK || len(res.Services) == 0 || res.Device == "" || len(res.Queries) == 0 {
			t.Fatalf("Zugang %d: Test fehlgeschlagen: %+v", i, res)
		}
		keys := map[string]bool{}
		for _, s := range res.Services {
			keys[s.Key] = true
		}
		for _, k := range []string{"uptime", "cpu", "mem"} {
			if !keys[k] {
				t.Errorf("Zugang %d: Dienst %s fehlt", i, k)
			}
		}
		if i == 0 && (!keys[trapSvcKey] || !strings.Contains(res.Warning, "v3")) {
			t.Errorf("v2c: Traps-Dienst bzw. Warnung fehlt: %q", res.Warning)
		}
	}
	if err := m.store.SaveAccess(ctx, accs[0], false, SystemActor); err != nil {
		t.Fatal(err)
	}
	m.ReloadHost(ctx, h.UID)
	m.rtMu.Lock()
	rt := m.rts[h.UID]
	m.rtMu.Unlock()
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	m.poll(pctx, rt)
	adoptAll(t, m, h.UID)
	m.poll(pctx, rt)
	cancel()
	v := rt.getView()
	if v == nil || len(v.Services) == 0 || !v.Accesses[0].OK {
		t.Fatalf("Runde: %+v", v)
	}
	for _, s := range v.Services {
		t.Logf("Dienst %s (%s): %v %s", s.Key, s.Kind, s.State, s.Text)
	}

	// Traps: Empfaenger offen, Bereitschaft melden, auf zwei Traps warten
	m.syncTraps(ctx)
	st := m.trapStatus(ctx)
	if !st.Running {
		t.Fatalf("Trap-Empfaenger: %+v", st)
	}
	if p := os.Getenv("M64_MOD_TRAP_READY"); p != "" {
		_ = os.WriteFile(p, []byte(strconv.Itoa(st.Port)), 0o644)
		defer os.Remove(p)
	}
	deadline := time.Now().Add(120 * time.Second)
	for {
		s := m.traps.snapshot(h.UID, true)
		if s != nil && s.Total >= 2 && s.Pending >= 1 {
			for _, e := range s.List {
				t.Logf("Trap: v%s %s %s handled=%v varbinds=%d", e.Version, e.TrapName, e.TrapOID, e.Handled, len(e.Varbinds))
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Traps nicht angekommen: %+v %+v", s, m.trapStatus(ctx))
		}
		time.Sleep(200 * time.Millisecond)
	}
	pctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	m.poll(pctx, rt)
	cancel()
	if sv := svcView(rt, trapSvcKey); sv == nil || sv.State != eval.Warn {
		t.Fatalf("Dienst traps: %+v", sv)
	}
	t.Logf("Empfaenger: %+v", m.trapStatus(ctx))
}
