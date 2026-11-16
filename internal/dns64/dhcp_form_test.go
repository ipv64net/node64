package dns64

import (
	"html/template"
	"net/netip"
	"strings"
	"testing"
)

// Formular fuer ein DHCP-Netz: Auswahl der echten Schnittstellen dieser Node (Name und Adresse, Vorschlag als
// data-Attribute), "Sonstige" fuer das Textfeld, virtuelle Schnittstellen nur ueber "Sonstige"; das Textfeld name=iface
// bleibt fuer den Betrieb ohne JavaScript, die Hinweisfelder fuer Werte ausserhalb des Netzes sind da.
func TestDHCPFormIfacePick(t *testing.T) {
	tpl, err := template.New("dhcp").Funcs(template.FuncMap{"join": strings.Join}).ParseFS(templateFS, "templates/pages/dhcp.html")
	if err != nil {
		t.Fatal(err)
	}
	sc := DHCPScope{Iface: "eth0", Subnet: "192.168.1.0/24", Start: "192.168.1.100", End: "192.168.1.199", Router: "192.168.1.1"}
	v := tview{CSRF: "c", Data: pageData{DHCP: dhcpPage{Mode: dhcpOff, Suggest: sc, Ifaces: []dhcpIface{
		{Name: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.20/24")}, Suggest: sc},
		{Name: "eth0.20", Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.20.2/24")}, Suggest: DHCPScope{Subnet: "10.0.20.0/24"}},
		{Name: "docker0", Addrs: []netip.Prefix{netip.MustParsePrefix("172.17.0.1/16")}, Virtual: true},
	}}}}
	var b strings.Builder
	if err := tpl.ExecuteTemplate(&b, "content", v); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	i, j := strings.Index(out, `id="d-iface-pick"`), strings.Index(out, `</select>`)
	if i < 0 || j < i {
		t.Fatal("no interface selection")
	}
	sel := out[i:j]
	for _, want := range []string{`value="eth0" data-subnet="192.168.1.0/24" data-start="192.168.1.100"`, `eth0 – 192.168.1.20/24`, `eth0.20 – 10.0.20.2/24`, `data-other>dns64.dhcp.iface_other`} {
		if !strings.Contains(sel, want) {
			t.Fatalf("selection lacks %q:\n%s", want, sel)
		}
	}
	if strings.Contains(sel, "docker0") {
		t.Fatal("virtual interface offered")
	}
	for _, want := range []string{`id="d-iface" name="iface"`, `data-outside="start"`, `data-outside="end"`, `data-outside="router"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("form lacks %q", want)
		}
	}
}

// virtualIface markiert die Schnittstellen, die das Formular nicht anbietet.
func TestDHCPIfaceVirtual(t *testing.T) {
	for name, want := range map[string]bool{"eth0": false, "eth0.20": false, "end0": false, "br0": false, "docker0": true, "veth12ab": true, "br-1a2b": true, "wg0": true} {
		if virtualIface(name) != want {
			t.Errorf("%s: virtual %v, want %v", name, !want, want)
		}
	}
}
