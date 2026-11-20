package cdn64

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/dns64/localnet"
)

// WE-3: Die Adresse des Docker-Gateways im Bridge-Netz ist keine Herkunft - Zugriffslisten mit privaten Netzen,
// die Ausnahme "Heimnetz" der Limits und "nur zulassen" der Laendersperre werten sie nicht als lokal; die Seite
// Proxy-Hosts zeigt einen Hinweis.
func TestDockerGatewayOrigin(t *testing.T) {
	gw := netip.MustParseAddr("172.17.0.1")
	lanOnly := &AccessList{Rules: []AccessRule{{Action: "allow", CIDR: "172.16.0.0/12"}, {Action: "allow", CIDR: "192.168.0.0/16"}, {Action: "deny", CIDR: "all"}}}
	denyOne := &AccessList{Rules: []AccessRule{{Action: "deny", CIDR: "203.0.113.9"}, {Action: "allow", CIDR: "all"}}}
	lanOnly.prepare()
	denyOne.prepare()
	l := newLimiter()
	on := Limits{Enabled: true, ExemptLAN: true}
	m := &Module{bl: newBlocklists()}
	m.bl.geo.put("DE", []netip.Prefix{netip.MustParsePrefix("5.1.0.0/16")}, time.Now())
	allow := &Advanced{GeoMode: geoAllow, GeoCountries: []string{"DE"}}
	block := &Advanced{GeoMode: geoBlock, GeoCountries: []string{"DE"}}

	// ohne Bridge-Netz: privat wie bisher (ausdruecklich gesetzt - der Test selbst kann in einem Bridge-Netz laufen)
	restore := localnet.OriginForTest(false, gw)
	if !lanOnly.ipAllowed(gw) || !l.exempted(&on, gw) || m.geoBlocked(allow, gw) {
		t.Fatal("private address without bridge network must count as home network")
	}
	restore()
	restore = localnet.OriginForTest(true, gw)
	defer restore()
	if lanOnly.ipAllowed(gw) {
		t.Fatal("access list with private networks allows the docker gateway")
	}
	if !denyOne.ipAllowed(gw) {
		t.Fatal("\"allow all\" must still match an unknown origin")
	}
	if !lanOnly.ipAllowed(netip.MustParseAddr("192.168.1.5")) {
		t.Fatal("other LAN addresses must stay allowed")
	}
	if l.exempted(&on, gw) {
		t.Fatal("docker gateway exempted from limits as home network")
	}
	// ausdrueckliche Ausnahme bzw. vertrauenswuerdiger Proxy auf dem Docker-Host gilt auch fuer das Gateway
	l.exempt.Store(&[]netip.Prefix{netip.MustParsePrefix("172.17.0.1/32")})
	if !l.exempted(&on, gw) || !l.exempted(&Limits{Enabled: true}, gw) {
		t.Fatal("explicit exemption must cover the docker gateway")
	}
	l.exempt.Store(nil)
	if !m.geoBlocked(allow, gw) || m.geoBlocked(block, gw) {
		t.Fatal("country block: unknown origin must be blocked by \"allow only\" and pass \"block\"")
	}
	// ausdruecklich freigegebenes Netz (Ausnahme, z. B. das Docker-Netz) gilt auch fuer das Gateway (Forum 5189)
	m.bl.geo.mu.Lock()
	m.bl.geo.allow = []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}
	m.bl.geo.mu.Unlock()
	if m.geoBlocked(allow, gw) {
		t.Fatal("country block \"allow only\": the docker gateway inside an allowed network must pass")
	}
	m.bl.geo.mu.Lock()
	m.bl.geo.allow = nil
	m.bl.geo.mu.Unlock()
	// Hinweis auf der Seite
	if body := renderHosts(t, listData{Kind: KindProxy}); strings.Contains(body, "cdn64.gw_masked") {
		t.Fatal("hint without gateway requests")
	}
	m.gwSeen.Store(time.Now().UnixNano())
	if !m.gwMasked() {
		t.Fatal("gwMasked after a gateway request")
	}
	if body := renderHosts(t, listData{Kind: KindProxy, GwMasked: true}); !strings.Contains(body, "cdn64.gw_masked") {
		t.Fatal("hint missing")
	}
}
