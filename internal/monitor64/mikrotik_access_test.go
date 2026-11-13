package monitor64

import (
	"testing"
)

// Zugang "mikrotik": nur https, Benutzer und Pin wie bei den anderen Geraete-APIs; der Sammler laesst sich bauen.
func TestMikrotikAccessConfig(t *testing.T) {
	if !validAccessType("mikrotik") || !isAPIAccess("mikrotik") || accessRank("mikrotik") != 2 {
		t.Fatal("Zugang mikrotik nicht angemeldet")
	}
	if _, ok := hostKindOf("mikrotik"); !ok {
		t.Fatal("Kachel mikrotik fehlt")
	}
	if svcCategory("routing") != "network" {
		t.Fatal("Dienste der Art routing gehoeren zum Netzwerk")
	}
	if _, err := cleanAccessConfig("mikrotik", []byte(`{"url":"https://192.0.2.1","user":"monitor64"}`)); err != nil {
		t.Fatalf("https abgelehnt: %v", err)
	}
	if _, err := cleanAccessConfig("mikrotik", []byte(`{"url":"http://192.0.2.1","user":"monitor64"}`)); err == nil {
		t.Fatal("http angenommen")
	}
	h := &Host{UID: "h1", Name: "router", Address: "192.0.2.1"}
	src, done, err := newDeviceAPI("mikrotik", h, accessConfig{User: "monitor64"}, "geheim")
	if err != nil || src == nil {
		t.Fatalf("Sammler: %v", err)
	}
	done()
	if _, _, err := newDeviceAPI("mikrotik", h, accessConfig{}, "geheim"); err == nil {
		t.Fatal("ohne Benutzer angenommen")
	}
}
