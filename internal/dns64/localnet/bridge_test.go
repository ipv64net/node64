package localnet

import "testing"

func TestInBridge(t *testing.T) {
	veth := iface{"12", "13"}
	real := iface{"2", "2"}
	for _, c := range []struct {
		name      string
		container bool
		ifs       map[string]iface
		want      bool
	}{
		{"kein Container", false, map[string]iface{"lo": {"1", "1"}, "eth0": veth}, false},
		{"Bridge", true, map[string]iface{"lo": {"1", "1"}, "eth0": veth}, true},
		{"Host-Netz (echte Karte)", true, map[string]iface{"lo": {"1", "1"}, "enp3s0": real, "veth1": veth}, false},
		{"Host-Netz (docker0)", true, map[string]iface{"lo": {"1", "1"}, "docker0": veth}, false},
		{"nur lo", true, map[string]iface{"lo": {"1", "1"}}, false},
	} {
		if got := inBridge(c.container, c.ifs); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
