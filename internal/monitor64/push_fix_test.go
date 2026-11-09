package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64agent"
	"github.com/ipv64net/node64/internal/monitor64/snmp"
	"github.com/ipv64net/node64/internal/ports"
)

// freePort liefert einen gerade freien TCP-Port auf 127.0.0.1.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

func dialOK(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// pushEnv: Modul mit Push-Lauscher auf 127.0.0.1 und einem Host mit Push-Zugang.
func pushEnv(t *testing.T) (e *testEnv, port int, hostUID string, acc *Access) {
	t.Helper()
	port = freePort(t)
	e = newEnvWith(t, func(m *Module) {
		ctx := context.Background()
		if err := errors.Join(m.st.SetSetting(ctx, setPushBind, "127.0.0.1"), m.st.SetSetting(ctx, setPushPort, strconv.Itoa(port))); err != nil {
			t.Fatal(err)
		}
	})
	rec := e.do("POST", "/api/monitor64/hosts", map[string]any{"name": "vps01", "address": "127.0.0.1", "kind": "linux-agent",
		"accesses": []map[string]any{{"type": "agent", "config": json.RawMessage(`{"mode":"push"}`)}}})
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var c struct{ UID string }
	decodeBody(t, rec.Body.Bytes(), &c)
	accs, err := e.m.store.Accesses(context.Background(), c.UID)
	if err != nil || len(accs) != 1 {
		t.Fatal(accs, err)
	}
	return e, port, c.UID, accs[0]
}

// PU5/UI7/CL1: Portwechsel oeffnet erst den neuen Port; belegter Port bzw. Konflikt im Port-Verzeichnis gehen als
// Fehler an die API, der alte Port bleibt offen und die Einstellung unveraendert. Datenbankfehler: Zustand bleibt.
func TestPushPortSwitch(t *testing.T) {
	e, p1, _, _ := pushEnv(t)
	ctx := context.Background()
	if use, err := e.m.usesPush(ctx); !use || err != nil || !dialOK(p1) {
		t.Fatalf("push listener not open: %v %v", use, err)
	}
	put := func(port int) (int, string) {
		rec := e.do("PUT", "/api/monitor64/settings", map[string]any{"interval": 60, "workers": 8, "push_port": port})
		var out struct{ Error string }
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out.Error
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if code, ec := put(busy.Addr().(*net.TCPAddr).Port); code == 200 || ec != "push_port_bind" {
		t.Fatalf("busy port: %d %q", code, ec)
	}
	if !dialOK(p1) || e.m.pushPort(ctx) != p1 {
		t.Fatal("old port closed or setting changed after a failed switch")
	}
	p2 := freePort(t)
	if code, ec := put(p2); code != 200 {
		t.Fatalf("switch: %d %q", code, ec)
	}
	if !dialOK(p2) || dialOK(p1) {
		t.Fatal("switch did not move the port")
	}
	// Port-Verzeichnis: anderer Teil belegt den Port
	reg := ports.New()
	p3 := freePort(t)
	reg.Provide("other", func(context.Context) []ports.Claim {
		return []ports.Claim{{Owner: "other", Purpose: "x", Proto: ports.TCP, Port: p3, Active: true}}
	})
	reg.Provide(Name, e.m.PushClaims)
	e.m.SetPorts(reg)
	if code, ec := put(p3); code != 400 || ec != "push_port_used" {
		t.Fatalf("conflict: %d %q", code, ec)
	}
	if cl := e.m.PushClaims(ctx); len(cl) != 1 || cl[0].Port != p2 || !cl[0].Active || cl[0].Bind != "127.0.0.1" {
		t.Fatalf("claims %+v", cl)
	}
	// Datenbank nicht lesbar (hier: abgebrochener Kontext): Lauscher bleibt
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := e.m.syncPush(cctx); err == nil || !dialOK(p2) {
		t.Fatalf("listener closed on a read error: %v", err)
	}
}

// pushAgentFor startet einen Agent im Push-Betrieb zur Node des Moduls.
func pushAgentFor(t *testing.T, m *Module, port int, token string) {
	t.Helper()
	line, err := m.PublicKeyLine(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	if err := os.WriteFile(keys, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hk, err := m64agent.LoadOrCreateHostKey(filepath.Join(dir, "hostkey"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := m64agent.New(m64agent.Config{HostKey: hk, KeysFile: keys, Collector: &fakeHost{fsUsed: 40}, Version: "1.0.0",
		PushRetryMin: 20 * time.Millisecond, PushRetryMax: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = srv.Push(m64agent.PushTarget{Token: token, Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))})
	}()
	t.Cleanup(func() { _ = srv.Close() })
}

// UI6/PU1: "Verbindung testen" eines Push-Zugangs nutzt den laufenden Client (kein zweiter Client mit dem Token, der
// beim Schliessen die Anmeldung des echten loescht); ungespeichert: erst speichern.
func TestPushAccessTestUsesRunningClient(t *testing.T) {
	e, port, _, acc := pushEnv(t)
	var cfg accessConfig
	_ = json.Unmarshal(acc.Config, &cfg)
	pushAgentFor(t, e.m, port, cfg.Token)
	for i := range 2 {
		var res testResult
		var rec = e.do("POST", "/api/monitor64/access/"+acc.UID+"/test", nil)
		if i == 1 { // Formular des gespeicherten Zugangs ueber /test mit access_uid
			rec = e.do("POST", "/api/monitor64/test", map[string]any{"address": "127.0.0.1", "access_uid": acc.UID,
				"access": map[string]any{"type": "agent", "config": acc.Config}})
		}
		decodeBody(t, rec.Body.Bytes(), &res)
		if rec.Code != 200 || !res.OK || len(res.Services) < 3 || !strings.HasPrefix(res.Fingerprint, "SHA256:") {
			t.Fatalf("test %d: %d %+v", i, rec.Code, res)
		}
	}
	e.m.mu.Lock()
	pl := e.m.push
	e.m.mu.Unlock()
	if st := pl.Stats(); st.Tokens != 1 || e.m.pool.Len() != 1 {
		t.Fatalf("after test: %+v pool %d", st, e.m.pool.Len())
	}
	c := e.m.pool.Existing(acc.UID)
	if c == nil {
		t.Fatal("production client gone")
	}
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("production client after test: %v", err)
	}
	var res testResult
	rec := e.do("POST", "/api/monitor64/test", map[string]any{"address": "127.0.0.1", "access": map[string]any{"type": "agent", "config": json.RawMessage(`{"mode":"push"}`)}})
	decodeBody(t, rec.Body.Bytes(), &res)
	if res.OK || res.Error != i18nText("monitor64.err.push_test_saved") {
		t.Fatalf("unsaved push test: %+v", res)
	}
}

// UI6: Formular eines gespeicherten Zugangs testen - Teil-Geheimnis (SNMP v3 nur Auth-Passwort neu) wird mit dem
// gespeicherten zusammengefuehrt; Zugang muss zum Host passen; geaendertes Ziel ohne neues Geheimnis: erst speichern.
func TestAccessTestStoredSecret(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := &Host{Name: "sw01", Address: "127.0.0.1", Kind: "snmp", IntervalSec: 300}
	if err := e.m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	cfg := json.RawMessage(`{"snmp_version":"3","user":"mon","level":"authPriv","auth_proto":"SHA256","priv_proto":"AES","port":` + strconv.Itoa(freePort(t)) + `}`)
	clean, err := cleanAccessConfig("snmp", cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := &Access{HostUID: h.UID, Type: "snmp", Config: clean, Secret: e.m.box.Encrypt(snmp.Secret{AuthPass: "authpass1", PrivPass: "privpass1"}.String())}
	if err := e.m.store.SaveAccess(ctx, a, false, SystemActor); err != nil {
		t.Fatal(err)
	}
	body := func(addr, typ string) map[string]any {
		return map[string]any{"address": addr, "access_uid": a.UID, "access": map[string]any{"type": typ, "config": clean,
			"secret": snmp.Secret{AuthPass: "authpass2"}.String()}}
	}
	// ohne gespeichertes Priv-Passwort waere das Geheimnis unvollstaendig (400); zusammengefuehrt laeuft der Test
	if rec := e.do("POST", "/api/monitor64/test", body("127.0.0.1", "snmp")); rec.Code != 200 {
		t.Fatalf("merged test: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/api/monitor64/test", body("192.0.2.7", "snmp")); rec.Code != 400 {
		t.Fatalf("foreign host: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/monitor64/test", body("127.0.0.1", "agent")); rec.Code != 400 {
		t.Fatalf("other type: %d", rec.Code)
	}
	// URL-Zugang: geaendertes Ziel mit gespeichertem Geheimnis -> erst speichern (nichts gesendet)
	rf := &Access{HostUID: h.UID, Type: "redfish", Config: json.RawMessage(`{"url":"https://127.0.0.1:1","user":"admin@corp.example"}`), Secret: e.m.box.Encrypt("pw")}
	if err := e.m.store.SaveAccess(ctx, rf, false, SystemActor); err != nil {
		t.Fatal(err)
	}
	var res testResult
	rec := e.do("POST", "/api/monitor64/access/"+rf.UID+"/test", map[string]any{"config": json.RawMessage(`{"url":"https://198.51.100.9","user":"admin@corp.example"}`)})
	decodeBody(t, rec.Body.Bytes(), &res)
	if rec.Code != 200 || res.Error != i18nText("monitor64.err.test_save_first") {
		t.Fatalf("changed target: %d %+v", rec.Code, res)
	}
}

// KE6: Benutzernamen je Zugangsart.
func TestAccessUserNames(t *testing.T) {
	long := strings.Repeat("a", 128)
	for _, tc := range []struct {
		typ, user string
		ok        bool
	}{
		{"ssh", "monitor64", true},
		{"ssh", "user@corp.example", false},
		{"ssh", `CORP\user`, false},
		{"redfish", "admin@corp.example", true},
		{"redfish", `CORP\admin`, true},
		{"truenas", long, true},
		{"nut", long + "a", false},
		{"prom", "a:b", false},
		{"redfish", "a b", false},
		{"redfish", "a\x01", false},
		{"snmp", strings.Repeat("u", 32), true},
		{"snmp", strings.Repeat("u", 33), false},
	} {
		raw, _ := json.Marshal(map[string]any{"user": tc.user})
		_, err := cleanAccessConfig(tc.typ, raw)
		if (err == nil) != tc.ok {
			t.Errorf("%s %q: %v", tc.typ, tc.user, err)
		}
	}
	_, err := cleanAccessConfig("ssh", json.RawMessage(`{"metrics":[{"name":"x"}]}`))
	var ae *apiError
	if !errors.As(err, &ae) || ae.code != "metrics" || len(ae.args) != 2 {
		t.Fatalf("metrics error without detail: %v", err)
	}
}
