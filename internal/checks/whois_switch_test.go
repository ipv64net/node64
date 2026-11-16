package checks

import (
	"context"
	"testing"
)

// #170: SWITCH (.ch/.li) antwortet im Blockformat; RDAP steht nicht im IANA-Bootstrap.
func TestWhoisSwitchBlockFormat(t *testing.T) {
	text := "\nDomain name:\nnic.li\n\nHolder of domain name:\nSWITCH\nWerdstrasse 2\nCH-8004 Zürich\n\nRegistrar:\nGandi SAS\nboulevard Massena 63-65\nFR-75013 Paris\nFrance\n\n" +
		"First registration date:\n2001-04-01\n\nDNSSEC:Y\n\nName servers:\nns1.switch.ch\nns2.switch.ch\t[2001:620:0:ffff::3]\n\n"
	i := parseWhoisText(text, "domain")
	if i.Name != "nic.li" || i.Registrar != "Gandi SAS" || i.Created.IsZero() || len(i.Nameservers) != 2 || i.Nameservers[1] != "ns2.switch.ch" || i.NotFound {
		t.Fatalf("SWITCH: %+v", i)
	}
	// gewohntes Format bleibt unveraendert (leeres Feld vor "Feld: Wert"-Zeilen)
	j := parseWhoisText("Domain Name: example.com\nRegistrar:\nRegistrar URL: http://x\nName Server: ns1.example.com\n", "domain")
	if j.Name != "example.com" || j.Registrar != "" || len(j.Nameservers) != 1 {
		t.Fatalf("gewohnt: %+v", j)
	}
}

func TestWhoisRDAPFallbackSwitch(t *testing.T) {
	fakeRDAP(t, map[string]string{})
	for _, q := range []string{"nic.li", "switch.ch"} {
		if base, err := rdapBase(context.Background(), "domain", q); err != nil || base != "https://rdap.nic.ch/" {
			t.Fatalf("%s: %q %v", q, base, err)
		}
	}
	if _, err := rdapBase(context.Background(), "domain", "example.zz"); err == nil {
		t.Fatal("unbekannte TLD ohne Fehler")
	}
}
