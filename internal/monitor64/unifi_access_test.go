package monitor64

import (
	"testing"
)

// Zugang "unifi": nur https, Site nur dort, Benutzer leer = API-Schluessel; der Sammler laesst sich bauen.
func TestUnifiAccessConfig(t *testing.T) {
	if !validAccessType("unifi") || !isAPIAccess("unifi") || accessRank("unifi") != 2 {
		t.Fatal("Zugang unifi nicht angemeldet")
	}
	if _, ok := hostKindOf("unifi"); !ok {
		t.Fatal("Kachel unifi fehlt")
	}
	if svcCategory("netdev") != "network" {
		t.Fatal("Dienste der Art netdev gehoeren zum Netzwerk")
	}
	out, err := cleanAccessConfig("unifi", []byte(`{"url":"https://192.0.2.1","site":" a1b2c3d4 "}`))
	if err != nil || string(out) != `{"url":"https://192.0.2.1","site":"a1b2c3d4"}` {
		t.Fatalf("Konfiguration: %s %v", out, err)
	}
	for _, bad := range []string{`{"url":"http://192.0.2.1"}`, `{"url":"https://192.0.2.1","site":"a/b"}`} {
		if _, err := cleanAccessConfig("unifi", []byte(bad)); err == nil {
			t.Errorf("%s angenommen", bad)
		}
	}
	if _, err := cleanAccessConfig("mikrotik", []byte(`{"url":"https://192.0.2.1","user":"x","site":"default"}`)); err == nil {
		t.Error("Site bei einem anderen Zugang angenommen")
	}
	h := &Host{UID: "h1", Name: "udm", Address: "192.0.2.1"}
	for _, cfg := range []accessConfig{{}, {User: "monitor64", Site: "default"}} {
		src, done, err := newDeviceAPI("unifi", h, cfg, "geheim")
		if err != nil || src == nil {
			t.Fatalf("Sammler %+v: %v", cfg, err)
		}
		done()
	}
	if _, _, err := newDeviceAPI("unifi", h, accessConfig{}, ""); err == nil {
		t.Fatal("ohne Geheimnis angenommen")
	}
}
