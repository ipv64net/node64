package cdn64

import (
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/geoip"
)

func init() {
	// Tests laden nie Standortdaten von ipv64.net (die Tests hier setzen eigene)
	geoDataStart = func(string, string, *slog.Logger) func() { return func() {} }
}

// geoTable legt Standortdaten wie country_ranges.txt.gz von ipv64.net an und setzt sie fuer den Test als geoLocate.
func geoTable(t testing.TB, lines string) *geoip.DB {
	t.Helper()
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "country_ranges.txt.gz"))
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	_, _ = io.WriteString(zw, "# test\n"+lines)
	_ = zw.Close()
	_ = f.Close()
	return geoLoad(t, dir)
}

func geoLoad(t testing.TB, dir string) *geoip.DB {
	t.Helper()
	d := geoip.New(dir, "http://127.0.0.1:1/", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := d.LoadCache(); err != nil {
		t.Fatal(err)
	}
	if !d.Status().Loaded {
		t.Fatal("no location data")
	}
	old := geoLocate
	geoLocate = d.Lookup
	t.Cleanup(func() { geoLocate = old })
	return d
}

// #139: Die Laendersperre entschied nur nach den Listen der Registrierungsstellen. AWS Frankfurt (3.64.0.0/12) und Azure
// Germany West Central (4.182.0.0/16) sind bei ARIN registriert und fehlen in DE.txt, 2001:ac8::/32 steht dort unter GB -
// mit "nur DE" wurden sie gesperrt, obwohl sie laut DB-IP in Deutschland stehen. Jetzt zaehlt der Standort.
func TestGeoByLocation(t *testing.T) {
	m := &Module{bl: newBlocklists()}
	// Listen nach Registrierungsland (Ausschnitt wie auf ipv64.net am 13.11.2026)
	m.bl.geo.put("DE", []netip.Prefix{netip.MustParsePrefix("2.28.0.0/14")}, time.Now())
	m.bl.geo.put("US", []netip.Prefix{netip.MustParsePrefix("3.0.0.0/9"), netip.MustParsePrefix("4.176.0.0/12")}, time.Now())
	m.bl.geo.put("GB", []netip.Prefix{netip.MustParsePrefix("2001:ac8::/32")}, time.Now())
	allowDE := &Advanced{GeoMode: geoAllow, GeoCountries: []string{"DE"}}
	blockDE := &Advanced{GeoMode: geoBlock, GeoCountries: []string{"DE"}}
	ips := []string{"3.64.10.10", "4.182.1.1", "2001:ac8:36:5e::", "2.28.6.30"}

	// vorher (ohne Standortdaten = nur Registrierungsland): drei der vier deutschen Adressen gesperrt
	var blocked []string
	for _, s := range ips {
		if m.geoBlocked(allowDE, netip.MustParseAddr(s)) {
			blocked = append(blocked, s)
		}
	}
	if strings.Join(blocked, " ") != "3.64.10.10 4.182.1.1 2001:ac8:36:5e::" {
		t.Fatalf("registry only: blocked %v", blocked)
	}

	// mit Standortdaten (Zeilen aus country_ranges.txt.gz vom 13.11.2026)
	geoTable(t, `DE 2.28.0.0 2.28.255.255
DE 3.64.0.0 3.79.255.255
DE 4.182.0.0 4.182.255.255
US 8.8.8.0 8.8.8.255
DE 2001:ac8:36:: 2001:ac8:36:ffff:ffff:ffff:ffff:ffff
GB 2001:ac8:37:: 2001:ac8:37:ffff:ffff:ffff:ffff:ffff
`)
	for _, s := range ips {
		ip := netip.MustParseAddr(s)
		if m.geoBlocked(allowDE, ip) {
			t.Errorf("allow DE: %s blocked", s)
		}
		if !m.geoBlocked(blockDE, ip) {
			t.Errorf("block DE: %s not blocked", s)
		}
		if cc, src := m.geoSource(ip); cc != "DE" || src != "location" {
			t.Errorf("source %s: %s %s", s, cc, src)
		}
	}
	if !m.geoBlocked(allowDE, netip.MustParseAddr("8.8.8.8")) || !m.geoBlocked(allowDE, netip.MustParseAddr("2001:ac8:37::1")) {
		t.Error("allow DE: other countries must be blocked")
	}
	// ohne Standort (Adresse nicht in den Daten): Rueckfall auf die Listen nach Registrierungsland
	if !m.geoBlocked(allowDE, netip.MustParseAddr("3.1.1.1")) {
		t.Error("fallback: US by registry must be blocked")
	}
	if cc, src := m.geoSource(netip.MustParseAddr("3.1.1.1")); cc != "US" || src != "registry" {
		t.Errorf("fallback source: %s %s", cc, src)
	}
	// Freigabeliste und private Netze gelten weiter vor dem Standort
	m.bl.geo.mu.Lock()
	m.bl.geo.allow = []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}
	m.bl.geo.mu.Unlock()
	if m.geoBlocked(allowDE, netip.MustParseAddr("8.8.8.8")) || m.geoBlocked(allowDE, netip.MustParseAddr("192.168.1.1")) {
		t.Error("allow list / private")
	}
}

// Standortdaten werden nur angefordert, solange ein Host oder Stream die Laendersperre nutzt.
func TestGeoDataRequested(t *testing.T) {
	starts, releases := 0, 0
	old := geoDataStart
	geoDataStart = func(dir, _ string, _ *slog.Logger) func() {
		if dir == "" {
			t.Error("no data dir")
		}
		starts++
		return func() { releases++ }
	}
	t.Cleanup(func() { geoDataStart = old })
	m := &Module{bl: newBlocklists(), dataDir: t.TempDir(), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	m.geoNeedFrom("hosts", nil)
	if starts != 0 {
		t.Fatal("started without country block")
	}
	m.geoNeedFrom("hosts", []string{"DE"})
	m.geoNeedFrom("streams", []string{"AT"})
	if starts != 1 || releases != 0 {
		t.Fatalf("start: %d %d", starts, releases)
	}
	m.geoNeedFrom("hosts", nil)
	if releases != 0 {
		t.Fatal("released while a stream uses it")
	}
	m.geoNeedFrom("streams", nil)
	if releases != 1 {
		t.Fatalf("release: %d", releases)
	}
	m.geoNeedFrom("hosts", []string{"DE"})
	m.geoData(false) // Modul-Stopp
	if starts != 2 || releases != 2 {
		t.Fatalf("restart/stop: %d %d", starts, releases)
	}
}

// Mit echten Daten (NODE64_GEO_DIR = Ordner mit country_ranges.txt.gz von ipv64.net): die Adressen aus #139.
func TestGeoRealData(t *testing.T) {
	dir := os.Getenv("NODE64_GEO_DIR")
	if dir == "" {
		t.Skip("NODE64_GEO_DIR not set")
	}
	d := geoLoad(t, dir)
	st := d.Status()
	t.Logf("ranges v4 %d, v6 %d, memory %d bytes", st.Ranges4, st.Ranges6, st.Bytes)
	m := &Module{bl: newBlocklists()}
	for _, s := range []string{"3.64.10.10", "4.182.1.1", "2001:ac8:36:5e::", "2.28.6.30"} {
		cc, src := m.geoSource(netip.MustParseAddr(s))
		t.Logf("%s -> %s (%s)", s, cc, src)
		if cc != "DE" {
			t.Errorf("%s: %s", s, cc)
		}
	}
}

// Kosten je Anfrage: Binaersuche in den Standortdaten (Groesse wie bei ipv64.net: ~370.000 IPv4- und ~380.000 IPv6-Bereiche).
func BenchmarkGeoBlocked(b *testing.B) {
	if dir := os.Getenv("NODE64_GEO_DIR"); dir != "" {
		geoLoad(b, dir)
	} else {
		var sb strings.Builder
		cc := []string{"DE", "US", "FR", "NL", "GB"}
		for i := range 370_000 {
			a := uint32(16<<24) + uint32(i)*1024
			fmt.Fprintf(&sb, "%s %d.%d.%d.%d %d.%d.%d.%d\n", cc[i%5], a>>24, a>>16&255, a>>8&255, a&255, a>>24, a>>16&255, (a+1023)>>8&255, 255)
		}
		for i := range 380_000 {
			fmt.Fprintf(&sb, "%s 2a%02x:%x:: 2a%02x:%x:ffff:ffff:ffff:ffff:ffff:ffff\n", cc[i%5], i>>16, i&0xffff, i>>16, i&0xffff)
		}
		geoTable(b, sb.String())
	}
	m := &Module{bl: newBlocklists()}
	m.bl.geo.put("DE", []netip.Prefix{netip.MustParsePrefix("2.28.0.0/14")}, time.Now())
	a := &Advanced{GeoMode: geoAllow, GeoCountries: []string{"DE", "AT", "CH"}}
	ips := []netip.Addr{netip.MustParseAddr("3.64.10.10"), netip.MustParseAddr("17.1.2.3"), netip.MustParseAddr("2a01:4f8::1"), netip.MustParseAddr("2001:ac8:36:5e::")}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		m.geoBlocked(a, ips[i&3])
	}
}
