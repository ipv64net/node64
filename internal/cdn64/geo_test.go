package cdn64

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const testIndex = `{"version":1,"lists":[
 {"id":"feodo","name":"abuse.ch Feodo Tracker","category":"botnet","description":"Botnet C2","license":"CC0","source":"https://feodotracker.abuse.ch/","files":{"all":"ipv64_blocklist_feodo.txt"}},
 {"id":"doh_servers","name":"DoH Server","category":"doh","files":{"all":"ipv64_blocklist_doh_servers.txt"}},
 {"id":"neu_liste","name":"New list","category":"attack","description":"Something new","source":"javascript:alert(1)","files":{"all":"ipv64_blocklist_neu_liste.txt"}},
 {"id":"boese","name":"x","files":{"all":"../../etc/passwd"}}],
 "combined":[{"id":"all_notor","name":"All lists without Tor","files":{"all":"ipv64_blocklist_all_notor.txt"}}],
 "countries":[{"country":"DE","name":"Germany"},{"country":"xx1","name":"bad"}]}`

func TestParseBlIndex(t *testing.T) {
	cat, cc, err := parseBlIndex([]byte(testIndex))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, b := range cat {
		ids = append(ids, b.ID)
	}
	if strings.Join(ids, ",") != "all_notor,feodo,neu_liste" {
		t.Fatalf("ids: %v", ids) // Gesamtliste zuerst, ohne DoH, ohne unsauberen Dateinamen
	}
	if cat[1].Name != "abuse.ch Feodo Tracker" || cat[1].Desc != "cdn64.bl.desc.feodo" || cat[1].License != "CC0" || cat[1].Source == "" {
		t.Fatalf("known: %+v", cat[1])
	}
	if cat[2].Desc != "" || cat[2].Text != "Something new" || cat[2].Source != "" {
		t.Fatalf("unknown: %+v", cat[2])
	}
	if len(cc) != 1 || cc[0].Code != "DE" {
		t.Fatalf("countries: %+v", cc)
	}
	if _, _, err := parseBlIndex([]byte(`{"lists":[]}`)); err == nil {
		t.Fatal("empty index")
	}
}

func TestGeoBlocked(t *testing.T) {
	m := &Module{bl: newBlocklists()}
	m.bl.geo.put("DE", []netip.Prefix{netip.MustParsePrefix("5.1.0.0/16"), netip.MustParsePrefix("2a00::/12")}, time.Now())
	de, us := netip.MustParseAddr("5.1.2.3"), netip.MustParseAddr("8.8.8.8")
	block := &Advanced{GeoMode: geoBlock, GeoCountries: []string{"DE"}}
	allow := &Advanced{GeoMode: geoAllow, GeoCountries: []string{"DE"}}
	cases := []struct {
		a    *Advanced
		ip   netip.Addr
		want bool
	}{
		{block, de, true}, {block, us, false}, {allow, de, false}, {allow, us, true},
		{block, netip.MustParseAddr("2a00:1::1"), true},
		{block, netip.MustParseAddr("::ffff:5.1.2.3"), true},                          // v4 in v6
		{allow, netip.MustParseAddr("192.168.1.5"), false},                            // privat
		{allow, netip.MustParseAddr("100.64.1.1"), false},                             // CGNAT
		{allow, netip.MustParseAddr("fd00::1"), false},                                // ULA
		{&Advanced{GeoMode: geoAllow, GeoCountries: []string{"FR"}}, us, false},       // Liste noch nicht geladen
		{&Advanced{GeoMode: geoAllow, GeoCountries: []string{"DE", "AT"}}, us, false}, // AT fehlt noch: niemanden sperren
		{&Advanced{GeoMode: geoBlock, GeoCountries: []string{"AT", "DE"}}, de, true},  // Sperre wirkt schon mit DE
		{&Advanced{}, de, false},
	}
	for i, c := range cases {
		if got := m.geoBlocked(c.a, c.ip); got != c.want {
			t.Errorf("%d %s %v: got %v", i, c.a.GeoMode, c.ip, got)
		}
	}
	m.bl.geo.mu.Lock()
	m.bl.geo.allow = []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")} // Ausnahmen der Blocklisten
	m.bl.geo.mu.Unlock()
	if m.geoBlocked(allow, us) {
		t.Fatal("exception")
	}
}

func TestGeoNormalize(t *testing.T) {
	a := Advanced{GeoMode: geoBlock, GeoCountries: []string{" de", "AT", "de", ""}}
	if err := a.normalizeGeo(); err != nil || strings.Join(a.GeoCountries, ",") != "DE,AT" {
		t.Fatalf("%v %v", err, a.GeoCountries)
	}
	for _, bad := range [][]string{{"DEU"}, {"1A"}, nil} {
		a := Advanced{GeoMode: geoAllow, GeoCountries: bad}
		if err := a.normalizeGeo(); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
	a = Advanced{GeoMode: "quatsch", GeoCountries: []string{"DE"}}
	if err := a.normalizeGeo(); err != nil || a.GeoMode != "" || a.GeoCountries != nil {
		t.Fatalf("off: %+v", a)
	}
}

// index.json und Laenderliste von einem Testserver: Auswahl erweitert, Laenderliste nur fuer genutzte Laender.
func TestIndexAndGeoLoaded(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	var pmu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pmu.Lock()
		paths = append(paths, r.URL.Path)
		pmu.Unlock()
		switch r.URL.Path {
		case "/index.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(testIndex))
		case "/countries/ipv64_blocklist_DE.txt":
			_, _ = w.Write([]byte("5.1.0.0/16\n2a00::/12\n"))
		case "/ipv64_blocklist_feodo.txt":
			_, _ = w.Write([]byte("198.51.100.7/32\n"))
		default:
			http.Error(w, "<html>404</html>", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	e.m.bl.base = srv.URL + "/"
	dir := t.TempDir()
	e.m.SetDataDir(dir)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"geo.test"}, "127.0.0.1", 9
	h.Advanced.GeoMode, h.Advanced.GeoCountries = geoBlock, []string{"de"}
	h.CertID, h.Advanced.TrustedProxies = CertNone, []string{"127.0.0.1"} // nur HTTP; echte Client-IP aus X-Forwarded-For
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	e.m.blRefresh(ctx) // laeuft auch im Modul; hier fuer einen festen Stand
	if err := e.m.blSave(ctx, []string{"feodo"}, ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100 && e.m.bl.set.Load() == nil; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if !e.m.bl.Blocked(netip.MustParseAddr("198.51.100.7")) {
		t.Fatal("feodo not active")
	}
	saved, err := e.m.host(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(saved.Advanced.GeoCountries, []string{"DE"}) {
		t.Fatalf("saved: %+v", saved.Advanced)
	}
	if !e.m.geoBlocked(&saved.Advanced, netip.MustParseAddr("5.1.9.9")) || e.m.geoBlocked(&saved.Advanced, netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("geo")
	}
	c := e.client(false) // Proxy: 403 nach der echten Client-IP, andere Laender gehen bis zum (fehlenden) Ziel
	if code, _, _ := do(t, c, "GET", "http://geo.test/", "X-Forwarded-For", "5.1.2.3"); code != http.StatusForbidden {
		t.Fatalf("geo proxy: %d", code)
	}
	if code, _, _ := do(t, c, "GET", "http://geo.test/", "X-Forwarded-For", "8.8.8.8"); code == http.StatusForbidden || code == 0 {
		t.Fatalf("other country: %d", code)
	}
	if e.m.bl.geo.blocked.Load() != 2 { // oben direkt geprueft + diese Anfrage
		t.Fatalf("counted %d", e.m.bl.geo.blocked.Load())
	}
	if st := e.m.geoStates(); len(st) != 1 || st[0].Code != "DE" || st[0].Entries != 2 {
		t.Fatalf("states: %+v", st)
	}
	pmu.Lock()
	defer pmu.Unlock()
	if slices.Contains(paths, "/countries/ipv64_blocklist_FR.txt") {
		t.Fatal("unused country loaded")
	}
	// Neustart: index.json und Laenderliste aus dem Zwischenspeicher, ohne Server
	srv.Close()
	m2 := &Module{bl: newBlocklists(), core: e.m.core, dataDir: dir, log: e.m.log}
	m2.blLoadCache(ctx)
	if !m2.bl.known("feodo") || !m2.geoBlocked(&saved.Advanced, netip.MustParseAddr("5.1.9.9")) {
		t.Fatal("cache")
	}
}

// Stream: Laendersperre gespeichert, beim Abgleich ohne Neustart uebernommen, abgewiesen nach Land.
func TestStreamGeo(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	e.m.bl.geo.put("DE", []netip.Prefix{netip.MustParsePrefix("5.1.0.0/16")}, time.Now())
	s := newStream()
	s.ListenPort, s.TargetHost, s.TargetPort = freePort(t), "127.0.0.1", echoTCP(t)
	s.GeoMode, s.GeoCountries = geoBlock, []string{"de", "DE"}
	if err := e.m.saveStream(ctx, s); err != nil {
		t.Fatal(err)
	}
	got, err := e.m.stream(ctx, s.ID)
	if err != nil || got.GeoMode != geoBlock || !slices.Equal(got.GeoCountries, []string{"DE"}) {
		t.Fatalf("saved: %+v %v", got, err)
	}
	e.m.smu.Lock()
	r := e.m.runs[s.ID]
	e.m.smu.Unlock()
	if r == nil || r.tcp == nil {
		t.Fatal("stream not running")
	}
	de, us := netip.MustParseAddr("5.1.2.3"), netip.MustParseAddr("8.8.8.8")
	if !e.m.streamGeoBlocked(r, de, "stream") || e.m.streamGeoBlocked(r, us, "stream") || e.m.streamGeoBlocked(r, netip.MustParseAddr("127.0.0.1"), "stream") {
		t.Fatal("block")
	}
	if !slices.Contains(e.m.geoNeeded(), "DE") {
		t.Fatal("DE not needed")
	}
	// auf "nur DE" umstellen: gleicher Lauf, neue Regel
	got.GeoMode = geoAllow
	if err := e.m.saveStream(ctx, got); err != nil {
		t.Fatal(err)
	}
	e.m.smu.Lock()
	r2 := e.m.runs[s.ID]
	e.m.smu.Unlock()
	if r2 != r {
		t.Fatal("stream restarted for a geo change")
	}
	if e.m.streamGeoBlocked(r, de, "stream") || !e.m.streamGeoBlocked(r, us, "stream") {
		t.Fatal("allow")
	}
	bad := *got
	bad.GeoCountries = []string{"Deutschland"}
	if err := e.m.saveStream(ctx, &bad); err == nil {
		t.Fatal("bad country accepted")
	}
}
