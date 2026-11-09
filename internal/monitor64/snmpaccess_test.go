package monitor64

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/snmp"
)

func TestCleanSNMPConfig(t *testing.T) {
	cases := []struct {
		name, typ, raw string
		ok             bool
		want           map[string]any // Felder nach dem Normieren
	}{
		{"v2c minimal", "snmp", `{}`, true, map[string]any{"snmp_version": "2c"}},
		{"v2c ohne v3-Felder", "snmp", `{"snmp_version":"2c","user":"x","level":"authPriv","auth_proto":"sha","context":"c"}`, true, map[string]any{"snmp_version": "2c", "user": nil, "level": nil, "auth_proto": nil, "context": nil}},
		{"v1", "snmp", `{"snmp_version":"1","port":1161,"traps":true}`, true, map[string]any{"snmp_version": "1", "port": 1161.0, "traps": true}},
		{"v3 authPriv", "snmp", `{"snmp_version":"3","user":"mon","level":"authpriv","auth_proto":"sha512","priv_proto":"aes256"}`, true,
			map[string]any{"level": "authPriv", "auth_proto": "SHA512", "priv_proto": "AES256"}},
		{"v3 authNoPriv ohne priv", "snmp", `{"snmp_version":"3","user":"mon","level":"authNoPriv","auth_proto":"SHA","priv_proto":"DES"}`, true,
			map[string]any{"level": "authNoPriv", "auth_proto": "SHA", "priv_proto": nil}},
		{"v3 Standardstufe", "snmp", `{"snmp_version":"3","user":"mon"}`, true, map[string]any{"level": "authPriv"}},
		{"v3 Engine-ID normiert", "snmp", `{"snmp_version":"3","user":"mon","traps":true,"trap_engine_id":"0x80001F8880AABBCCDD"}`, true, map[string]any{"trap_engine_id": "80001f8880aabbccdd"}},
		{"v3 ohne Benutzer", "snmp", `{"snmp_version":"3"}`, false, nil},
		{"Version unbekannt", "snmp", `{"snmp_version":"4"}`, false, nil},
		{"Stufe unbekannt", "snmp", `{"snmp_version":"3","user":"mon","level":"secret"}`, false, nil},
		{"Auth unbekannt", "snmp", `{"snmp_version":"3","user":"mon","auth_proto":"CRC"}`, false, nil},
		{"Priv unbekannt", "snmp", `{"snmp_version":"3","user":"mon","priv_proto":"ROT13"}`, false, nil},
		{"Kontext mit Leerzeichen", "snmp", `{"snmp_version":"3","user":"mon","context":"a b"}`, false, nil},
		{"Engine-ID kaputt", "snmp", `{"snmp_version":"3","user":"mon","trap_engine_id":"xyz"}`, false, nil},
		{"Engine-ID zu kurz", "snmp", `{"snmp_version":"3","user":"mon","trap_engine_id":"8000"}`, false, nil},
		{"eigene OID ok", "snmp", `{"custom":[{"oid":"1.3.6.1.4.1.2021.10.1.5.1","name":"Load","factor":0.01,"rule":"temp.system","unit":"°C"}]}`, true, nil},
		{"eigene OID kaputt", "snmp", `{"custom":[{"oid":"kein.oid","name":"x"}]}`, false, nil},
		{"eigene OID ohne Namen", "snmp", `{"custom":[{"oid":"1.3.6.1.2.1.1.3.0","name":""}]}`, false, nil},
		{"eigene OID Regel unbekannt", "snmp", `{"custom":[{"oid":"1.3.6.1.2.1.1.3.0","name":"x","rule":"cpu.nope"}]}`, false, nil},
		{"Profil unbekannt", "snmp", `{"profiles":["gibtsnicht"]}`, false, nil},
		{"Profil bekannt", "snmp", `{"profiles":["apc"]}`, true, nil},
		{"URL bei SNMP", "snmp", `{"url":"http://10.0.0.1"}`, false, nil},
		{"Port zu gross", "snmp", `{"port":70000}`, false, nil},
		{"SNMP-Feld bei anderem Zugang", "ssh", `{"snmp_version":"2c"}`, false, nil},
		{"Traps bei anderem Zugang", "pve", `{"traps":true}`, false, nil},
		{"eigene OID bei anderem Zugang", "agent", `{"custom":[{"oid":"1.3.6.1.2.1.1.3.0","name":"x"}]}`, false, nil},
		{"unbekanntes Feld", "snmp", `{"community":"public"}`, false, nil}, // Community nie in der Konfiguration
	}
	for _, c := range cases {
		out, err := cleanAccessConfig(c.typ, json.RawMessage(c.raw))
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v", c.name, err)
			continue
		}
		if err != nil {
			continue
		}
		var got map[string]any
		_ = json.Unmarshal(out, &got)
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%s: %s = %v, want %v (%s)", c.name, k, got[k], v, out)
			}
		}
	}
}

func TestMergeSNMPSecret(t *testing.T) {
	old := snmp.Secret{Community: "c-alt", AuthPass: "auth-alt1", PrivPass: "priv-alt1"}.String()
	cases := []struct {
		in, old string
		want    snmp.Secret
		keep    bool
	}{
		{`{"community":"neu"}`, old, snmp.Secret{Community: "neu", AuthPass: "auth-alt1", PrivPass: "priv-alt1"}, false},
		{`{"priv":"priv-neu1"}`, old, snmp.Secret{Community: "c-alt", AuthPass: "auth-alt1", PrivPass: "priv-neu1"}, false},
		{`nur-community`, old, snmp.Secret{Community: "nur-community", AuthPass: "auth-alt1", PrivPass: "priv-alt1"}, false},
		{`{}`, old, snmp.Secret{}, true},
		{`{"auth":"a12345678"}`, "", snmp.Secret{AuthPass: "a12345678"}, false},
		{`{"auth":"a12345678"}`, "alte-community-als-text", snmp.Secret{Community: "alte-community-als-text", AuthPass: "a12345678"}, false},
	}
	for i, c := range cases {
		got := mergeSNMPSecret(c.in, c.old)
		if c.keep {
			if got != "" {
				t.Errorf("%d: want keep, got %q", i, got)
			}
			continue
		}
		if snmp.ParseSecret(got) != c.want {
			t.Errorf("%d: got %+v", i, snmp.ParseSecret(got))
		}
	}
}

// TestAPISNMPSecret: Geheimnis als ein verschluesseltes JSON, beim Aendern ohne neue Passwoerter bleibt es, einzelne
// Felder werden zusammengefuehrt; nie in Antworten.
func TestAPISNMPSecret(t *testing.T) {
	e := newEnv(t)
	rec := e.do("POST", "/api/monitor64/hosts", map[string]any{"name": "sw01", "address": "192.0.2.30", "kind": "snmp", "paused": true, "accesses": []map[string]any{}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create host: %d %s", rec.Code, rec.Body)
	}
	var created struct{ UID string }
	decodeBody(t, rec.Body.Bytes(), &created)
	base := "/api/monitor64/hosts/" + created.UID + "/access"
	// ohne Community: abgelehnt
	if rec := e.do("POST", base, map[string]any{"type": "snmp", "config": map[string]any{"snmp_version": "2c"}}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "snmp_secret") {
		t.Fatalf("missing community: %d %s", rec.Code, rec.Body)
	}
	rec = e.do("POST", base, map[string]any{"type": "snmp", "config": map[string]any{"snmp_version": "2c"}, "secret": `{"community":"pub-GEHEIM"}`})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create access: %d %s", rec.Code, rec.Body)
	}
	var acc accessOut
	decodeBody(t, rec.Body.Bytes(), &acc)
	if !acc.SecretSet || strings.Contains(rec.Body.String(), "pub-GEHEIM") {
		t.Fatalf("access out: %s", rec.Body)
	}
	secretOf := func() snmp.Secret {
		t.Helper()
		enc := e.col(`SELECT secret FROM m64_access WHERE uid = ?`, acc.UID)
		if strings.Contains(enc, "GEHEIM") {
			t.Fatal("secret stored in clear")
		}
		s, err := e.m.box.Decrypt(enc)
		if err != nil {
			t.Fatal(err)
		}
		return snmp.ParseSecret(s)
	}
	if s := secretOf(); s.Community != "pub-GEHEIM" {
		t.Fatalf("stored: %+v", s)
	}
	au := "/api/monitor64/access/" + acc.UID
	// Wechsel auf v3 ohne Passwoerter: abgelehnt (Passwort fehlt), gespeichertes bleibt
	v3 := map[string]any{"snmp_version": "3", "user": "mon", "level": "authPriv", "auth_proto": "SHA256", "priv_proto": "AES"}
	if rec := e.do("PUT", au, map[string]any{"config": v3}); rec.Code != http.StatusBadRequest {
		t.Fatalf("v3 without passwords: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("PUT", au, map[string]any{"config": v3, "secret": `{"auth":"kurz"}`}); rec.Code != http.StatusBadRequest {
		t.Fatalf("short auth password: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("PUT", au, map[string]any{"config": v3, "secret": `{"auth":"auth-GEHEIM-1","priv":"priv-GEHEIM-1"}`}); rec.Code != http.StatusOK {
		t.Fatalf("v3: %d %s", rec.Code, rec.Body)
	}
	if s := secretOf(); s != (snmp.Secret{AuthPass: "auth-GEHEIM-1", PrivPass: "priv-GEHEIM-1"}) { // v3: Community verworfen
		t.Fatalf("merged: %+v", s)
	}
	// nur das Verschluesselungs-Passwort neu: Authentifizierung bleibt
	if rec := e.do("PUT", au, map[string]any{"config": v3, "secret": `{"priv":"priv-GEHEIM-2"}`}); rec.Code != http.StatusOK {
		t.Fatalf("priv only: %d %s", rec.Code, rec.Body)
	}
	if s := secretOf(); s.AuthPass != "auth-GEHEIM-1" || s.PrivPass != "priv-GEHEIM-2" {
		t.Fatalf("priv only: %+v", s)
	}
	// ohne Geheimnis (z. B. nur Traps einschalten): unveraendert
	v3["traps"] = true
	if rec := e.do("PUT", au, map[string]any{"config": v3, "secret": ""}); rec.Code != http.StatusOK {
		t.Fatalf("keep: %d %s", rec.Code, rec.Body)
	}
	if s := secretOf(); s.PrivPass != "priv-GEHEIM-2" || s.Community != "" {
		t.Fatalf("keep: %+v", s)
	}
	// v3 ohne Authentifizierung: eine noch gespeicherte Community wird verworfen
	if rec := e.do("PUT", au, map[string]any{"config": map[string]any{"snmp_version": "2c"}, "secret": `{"community":"pub-GEHEIM"}`}); rec.Code != http.StatusOK {
		t.Fatalf("back to v2c: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("PUT", au, map[string]any{"config": map[string]any{"snmp_version": "3", "user": "mon", "level": "noAuthNoPriv"}, "clear_secret": false}); rec.Code != http.StatusOK {
		t.Fatalf("v3 noAuth: %d %s", rec.Code, rec.Body)
	}
	if s := secretOf(); s.Community != "" || s.AuthPass != "auth-GEHEIM-1" {
		t.Fatalf("community kept for v3 noAuth: %+v", s)
	}
	// nur Community gespeichert (v2c) und Wechsel auf v3 ohne Authentifizierung: Geheimnis ganz leer
	if rec := e.do("PUT", au, map[string]any{"config": map[string]any{"snmp_version": "2c"}, "secret": `{"community":"pub-GEHEIM"}`, "clear_secret": true}); rec.Code != http.StatusOK {
		t.Fatalf("v2c only community: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("PUT", au, map[string]any{"config": map[string]any{"snmp_version": "3", "user": "mon", "level": "noAuthNoPriv"}}); rec.Code != http.StatusOK {
		t.Fatalf("v3 noAuth: %d %s", rec.Code, rec.Body)
	}
	if enc := e.col(`SELECT secret FROM m64_access WHERE uid = ?`, acc.UID); enc != "" {
		t.Fatal("community kept for v3 noAuth")
	}
	for _, path := range []string{"/api/monitor64/hosts/" + created.UID, "/monitor64/host/" + created.UID} {
		if b := e.do("GET", path, nil).Body.String(); strings.Contains(b, "GEHEIM") {
			t.Fatalf("%s leaks the secret", path)
		}
	}
	// Test ohne Antwort: Fehler, kein Geheimnis im Text
	res := e.do("POST", "/api/monitor64/test", map[string]any{"address": "127.0.0.1", "access": map[string]any{"type": "snmp",
		"config": map[string]any{"port": 9, "snmp_version": "2c"}, "secret": `{"community":"pub-GEHEIM"}`}})
	if res.Code != http.StatusOK || strings.Contains(res.Body.String(), "GEHEIM") {
		t.Fatalf("test: %d %s", res.Code, res.Body)
	}
	var tr testResult
	decodeBody(t, res.Body.Bytes(), &tr)
	if tr.OK || tr.Error == "" {
		t.Fatalf("test against closed port: %+v", tr)
	}
}

// TestSNMPFactKinds: jeder Fact-Code des SNMP-Sammlers hat eine Zustandsregel (Standard-Tabelle, Seite Schwellen).
func TestSNMPFactKinds(t *testing.T) {
	std := eval.Defaults()
	codes := []string{snmp.FactRestarted, snmp.FactIfDown, snmp.FactIfSpeedLow, snmp.FactIfHalfDuplex, snmp.FactUPSBatteryLow, snmp.FactUPSReplace,
		snmp.FactUPSAlarm, snmp.FactPrinterError, snmp.FactPaperEmpty, snmp.FactHWFailed, snmp.FactPoEFault, factTrapReceived,
		"ups_on_battery", "bond_member_down", "lacp_mismatch", "smart_failed", "smart_sectors", "raid_degraded", "zfs_degraded", "store_inactive"}
	for _, c := range codes {
		k := factKind(c)
		if k == "" {
			t.Errorf("fact %s has no rule kind", c)
			continue
		}
		if _, ok := std[k]; !ok {
			t.Errorf("fact %s: kind %s not in defaults", c, k)
		}
		if _, ok := ruleKindOf(k); !ok {
			t.Errorf("fact %s: kind %s not on the rules page", c, k)
		}
	}
	// SNMP und NUT melden dieselben USV-Arten
	if factKind(snmp.FactUPSBatteryLow) != eval.KindUPSLowBattery || factKind(snmp.FactUPSReplace) != eval.KindUPSReplace {
		t.Error("UPS codes of SNMP and NUT differ")
	}
	for _, kind := range []string{"uptime", "ups", "printer", "supply", "tray", "poe", "wlan", "fan", "hw", "oid", "traps"} {
		if svcCategory(kind) == "other" && kind != "oid" {
			t.Errorf("service kind %s has no category", kind)
		}
		if kindOrder(kind) == kindOrder("unbekannt") {
			t.Errorf("service kind %s has no order", kind)
		}
	}
	if !slices.Contains(accessTypes, "snmp") {
		t.Error("snmp access type missing")
	}
	if k, _ := hostKindOf("snmp"); k.Soon {
		t.Error("snmp host kind still 'soon'")
	}
}

// TestSeenUpHelpers: Ports, die schon verbunden waren, kommen aus dem Laufzeitstand in den SNMP-Sammler und
// Aenderungen zurueck (andere Zugaenge: nichts).
func TestSeenUpHelpers(t *testing.T) {
	m, _, _ := newTestModule(t)
	h := &Host{Address: "192.0.2.70"}
	col, err := m.newAPICollector(&Access{Type: "snmp"}, h, accessConfig{SNMPVersion: "2c"}, snmp.Secret{Community: "c"}.String())
	if err != nil {
		t.Fatal(err)
	}
	defer col.close()
	if l, ch := seenUpChanged(col, nil); ch || l != nil {
		t.Fatalf("empty: %v %v", l, ch)
	}
	restoreSeenUp(col, []string{"if:eth1", "if:eth0"})
	l, ch := seenUpChanged(col, nil)
	if !ch || !slices.Equal(l, []string{"if:eth0", "if:eth1"}) {
		t.Fatalf("restored: %v %v", l, ch)
	}
	if _, ch := seenUpChanged(col, l); ch {
		t.Fatal("unchanged reported as changed")
	}
	if _, ch := seenUpChanged(&fakeCol{}, nil); ch {
		t.Fatal("other collector")
	}
	restoreSeenUp(&fakeCol{}, []string{"if:x"}) // kein SNMP-Sammler: nichts
}
