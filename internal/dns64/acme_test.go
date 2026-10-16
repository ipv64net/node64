package dns64

import (
	"context"
	"testing"
)

func TestACMEName(t *testing.T) {
	if acmeName(config{ACMEDomain: "home.ipv64.net", ACMEPrefix: "dns"}) != "dns.home.ipv64.net" || acmeName(config{ACMEDomain: "home.ipv64.net"}) != "home.ipv64.net" || acmeName(config{}) != "" {
		t.Fatal("acmeName")
	}
	m, _ := testModule(t)
	ctx := context.Background()
	c := m.loadConfig(ctx)
	c.CertMode, c.ACMEDomain = certACME, ""
	if err := m.saveConfig(ctx, c); err == nil {
		t.Fatal("acme without domain accepted")
	}
	c.ACMEDomain, c.ACMEPrefix = "home.ipv64.net", "_acme-challenge"
	if err := m.saveConfig(ctx, c); err == nil {
		t.Fatal("prefix with underscore accepted")
	}
	c.ACMEPrefix = "dns"
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	// ohne Zertifikat: Dienste laufen mit der eigenen CA, der Name steht mit im Zertifikat
	crt, names, err := m.serverCert(m.loadConfig(ctx))
	if err != nil || crt.Certificate == nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range names {
		found = found || n == "dns.home.ipv64.net"
	}
	if !found {
		t.Fatalf("fallback certificate names = %v", names)
	}
}
