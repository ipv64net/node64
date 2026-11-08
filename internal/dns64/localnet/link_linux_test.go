//go:build linux

package localnet

import "testing"

func TestInfoKind(t *testing.T) {
	// unbekanntes Attribut (Typ 2), dann IFLA_INFO_KIND "ipvlan"
	b := []byte{8, 0, 2, 0, 'x', 0, 0, 0, 11, 0, 1, 0, 'i', 'p', 'v', 'l', 'a', 'n', 0, 0}
	if got := infoKind(b); got != "ipvlan" {
		t.Fatalf("got %q", got)
	}
	for _, bad := range [][]byte{{3, 0, 1, 0}, {8, 0, 2, 0, 'x'}, nil} {
		if got := infoKind(bad); got != "" {
			t.Fatalf("broken %v: got %q", bad, got)
		}
	}
	if k := linkKinds(); k == nil || k["lo"] != "" { // lo hat keinen Typ, Netlink geht ohne Rechte
		t.Fatalf("linkKinds: %v", k)
	}
}
