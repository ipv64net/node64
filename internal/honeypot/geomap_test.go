package honeypot

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/honeypot/worldmap"
	"github.com/ipv64net/node64/internal/module"
)

func TestMapLevels(t *testing.T) {
	if b := mapBounds(1); b != [MapLevels + 2]int64{0, 1, 1, 1, 1, 1, 2} || mapLevel(1, b) != MapLevels {
		t.Fatalf("bounds(1) %v", b)
	}
	b := mapBounds(100000)
	if b != [MapLevels + 2]int64{0, 1, 10, 100, 1000, 10000, 100001} {
		t.Fatalf("bounds(100000) %v", b)
	}
	for n, want := range map[int64]int{0: 0, -1: 0, 1: 1, 9: 1, 10: 2, 99: 2, 100: 3, 9999: 4, 10000: 5, 100000: 5, 200000: 5} {
		if got := mapLevel(n, b); got != want {
			t.Errorf("level(%d) = %d, want %d", n, got, want)
		}
	}
	if b := mapBounds(0); b[MapLevels+1] != 1 {
		t.Fatalf("bounds(0) %v", b)
	}
}

func TestBuildMap(t *testing.T) {
	v := BuildMap([]CountryCount{{Key: "DE", Count: 1000, Sources: 7}, {Key: "US", Count: 10, Sources: 2}, {Key: "ZZ", Count: 5}}, "de")
	if v.Max != 1000 || v.Missing != 1 || v.ViewBox != worldmap.ViewBox() || len(v.Countries) != len(worldmap.Countries()) {
		t.Fatalf("map %+v", v)
	}
	lv := map[string]MapCountry{}
	for _, c := range v.Countries {
		lv[c.Code] = c
	}
	if de := lv["DE"]; de.Level != 5 || de.Count != 1000 || de.Sources != 7 || de.Name != "Deutschland" || de.Flag == "" || de.Path == "" {
		t.Fatalf("DE %+v", de)
	}
	if lv["US"].Level != 2 || lv["FR"].Level != 0 || lv["FR"].Count != 0 {
		t.Fatalf("US %+v FR %+v", lv["US"], lv["FR"])
	}
	want := []MapStep{{1, 1, 3}, {2, 4, 15}, {3, 16, 63}, {4, 64, 251}, {5, 252, 1000}}
	if len(v.Legend) != len(want) {
		t.Fatalf("legend %+v", v.Legend)
	}
	for i := range want {
		if v.Legend[i] != want[i] {
			t.Fatalf("legend %+v, want %+v", v.Legend, want)
		}
	}
	// kleine Zahlen: leere Stufen fallen aus der Legende
	v = BuildMap([]CountryCount{{Key: "DE", Count: 3}, {Key: "FR", Count: 1}}, "en")
	if len(v.Legend) != 3 || v.Legend[0] != (MapStep{1, 1, 1}) || v.Legend[1] != (MapStep{4, 2, 2}) || v.Legend[2] != (MapStep{5, 3, 3}) {
		t.Fatalf("small legend %+v", v.Legend)
	}
	// ohne Daten: alles neutral, keine Legende
	v = BuildMap(nil, "de")
	if v.Max != 0 || len(v.Legend) != 0 || len(v.Countries) == 0 {
		t.Fatalf("empty %+v", v.Legend)
	}
	for _, c := range v.Countries {
		if c.Level != 0 {
			t.Fatalf("empty map colored: %+v", c)
		}
	}
}

func TestValidCountryAndURL(t *testing.T) {
	for in, want := range map[string]string{"DE": "DE", "de": "DE", "xK": "XK"} {
		if got, ok := validCountry(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "D", "DEU", "1A", "Ä", "d-"} {
		if _, ok := validCountry(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
	var d overviewData
	for _, c := range []struct{ rng, src, cc, want string }{
		{"24h", "", "", "/honeypot"}, {"7d", "", "", "/honeypot?range=7d"}, {"24h", "log", "DE", "/honeypot?country=DE&source=log"},
		{"7d", "", "US", "/honeypot?country=US&range=7d"},
	} {
		if got := d.URL(c.rng, c.src, c.cc); got != c.want {
			t.Errorf("URL(%q,%q,%q) = %q, want %q", c.rng, c.src, c.cc, got, c.want)
		}
	}
}

// TestEventsCountryFilter: Ereignisliste nach Land (Store, API mit country=XX, ungueltig = 400).
func TestEventsCountryFilter(t *testing.T) {
	fakeCountries(t, map[string]string{"192.0.2.0/24": "DE", "198.51.100.0/24": "NL"})
	m, _ := modTest(t, modFreePort(t))
	ctx := context.Background()
	if _, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{Service: SvcSSH, Port: modFreePort(t)}}}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	modEvents(m)
	m.sink(Event{Time: time.Now(), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: netip.MustParseAddr("192.0.2.11"), Source: SrcLog})
	_ = m.st.Flush(ctx)
	for _, c := range []struct {
		cc, source string
		want       int
	}{{"DE", "", 3}, {"NL", "", 1}, {"DE", SrcLog, 1}, {"NL", SrcLog, 0}, {"US", "", 0}, {"", "", 4}} {
		list, err := m.st.RecentIn(ctx, 50, c.source, c.cc)
		if err != nil || len(list) != c.want {
			t.Fatalf("%s/%s: %v %d, want %d", c.cc, c.source, err, len(list), c.want)
		}
		for _, e := range list {
			if c.cc != "" && countryOf(storeSrc(e.Src)) != c.cc {
				t.Fatalf("%s: wrong event %+v", c.cc, e)
			}
		}
	}
	mux := http.NewServeMux()
	m.apiRoutes(mux, m.g)
	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec.Code, rec.Body.String()
	}
	if code, body := get("/api/honeypot/events?country=nl"); code != 200 || !strings.Contains(body, "198.51.100.7") || strings.Contains(body, "192.0.2.10") {
		t.Fatalf("api country: %d %s", code, body)
	}
	if code, body := get("/api/honeypot/events?country=US"); code != 200 || strings.TrimSpace(body) != "[]" {
		t.Fatalf("api empty country: %d %s", code, body)
	}
	if code, _ := get("/api/honeypot/events?country=DEU"); code != http.StatusBadRequest {
		t.Fatalf("invalid country: %d", code)
	}
}

func cardStat(c *module.Card, key string) (module.CardStat, bool) {
	for _, s := range c.Stats {
		if s.LabelKey == key {
			return s, true
		}
	}
	return module.CardStat{}, false
}

// TestCard: Startseiten-Karte ohne Daten und mit Daten (Trend, Laender, Dienst, Fehler, Meldung).
func TestCard(t *testing.T) {
	m, _ := modTest(t, modFreePort(t))
	ctx := context.Background()
	busy, err := net.Listen("tcp", "127.0.0.1:0") // dieser Port ist belegt: Fallen-Dienst mit Fehler
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	bp := busy.Addr().(*net.TCPAddr).Port
	if _, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{Service: SvcSSH, Port: modFreePort(t)}, {Service: SvcTCP, Port: bp}}}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	c, err := m.Card(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ev, _ := cardStat(c, "honeypot.card.events"); ev.Value != 0 || ev.Note != "" {
		t.Fatalf("empty events %+v", ev)
	}
	if _, ok := cardStat(c, "honeypot.card.countries"); ok {
		t.Fatal("no countries without data")
	}
	if _, ok := cardStat(c, "honeypot.card.top_service"); ok {
		t.Fatal("no top service without data")
	}
	if s, _ := cardStat(c, "honeypot.card.services"); s.Value != 1 {
		t.Fatalf("services %+v", s)
	}
	if s, _ := cardStat(c, "honeypot.card.errors"); s.Value != 1 || s.Class != "text-danger" || !strings.Contains(s.Title, "TCP "+strconv.Itoa(bp)) || !strings.HasPrefix(c.Err, "TCP "+strconv.Itoa(bp)) {
		t.Fatalf("errors %+v / %q", s, c.Err)
	}
	if s, _ := cardStat(c, "honeypot.card.report"); s.TextKey != "honeypot.card.report_off" {
		t.Fatalf("report %+v", s)
	}
	// mit Daten: 3 Ereignisse jetzt, 2 vor 30 Stunden (Trend +50 %), Laender DE und NL
	fakeCountries(t, map[string]string{"192.0.2.0/24": "DE", "198.51.100.0/24": "NL"})
	modEvents(m)
	old := time.Now().Add(-30 * time.Hour)
	m.sink(Event{Time: old, Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: netip.MustParseAddr("192.0.2.1")})
	m.sink(Event{Time: old, Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: netip.MustParseAddr("192.0.2.1")})
	if c, err = m.Card(ctx); err != nil {
		t.Fatal(err)
	}
	if ev, _ := cardStat(c, "honeypot.card.events"); ev.Value != 3 || ev.Note != "▲ 50 %" || ev.NoteClass != "text-danger" {
		t.Fatalf("events %+v", ev)
	}
	if s, _ := cardStat(c, "honeypot.card.sources"); s.Value != 2 {
		t.Fatalf("sources %+v", s)
	}
	if s, _ := cardStat(c, "honeypot.card.countries"); s.Text != "\U0001F1E9\U0001F1EA \U0001F1F3\U0001F1F1" || s.Title != "DE 2 · NL 1" {
		t.Fatalf("countries %+v", s)
	}
	if s, _ := cardStat(c, "honeypot.card.top_service"); s.Text == "" || s.Note != "33 %" {
		t.Fatalf("top service %+v", s)
	}
	for _, c := range []struct {
		cur, prev int64
		note, cls string
	}{{0, 0, "", ""}, {5, 0, "▲", "text-danger"}, {5, 10, "▼ 50 %", "text-success"}, {7, 7, "± 0 %", "text-body-secondary"}} {
		if n, cl := cardTrend(c.cur, c.prev); n != c.note || cl != c.cls {
			t.Errorf("trend(%d,%d) = %q %q", c.cur, c.prev, n, cl)
		}
	}
	now := time.Now()
	for _, c := range []struct {
		rs  ReportStatus
		key string
		ago bool
	}{
		{ReportStatus{}, "honeypot.card.report_off", false},
		{ReportStatus{Enabled: true}, "honeypot.card.report_nokey", false},
		{ReportStatus{Enabled: true, KeySet: true, Active: true}, "honeypot.card.report_wait", false},
		{ReportStatus{Enabled: true, KeySet: true, Active: true, LastSuccess: now}, "honeypot.card.report_ok", true},
		{ReportStatus{Enabled: true, KeySet: true, Active: true, LastSuccess: now.Add(-time.Hour), LastError: "boom", LastErrorAt: now}, "honeypot.card.report_error", true},
		{ReportStatus{Enabled: true, KeySet: true, Active: true, LastSuccess: now, LastError: "old", LastErrorAt: now.Add(-time.Hour)}, "honeypot.card.report_ok", true},
	} {
		if s := cardReport(c.rs); s.TextKey != c.key || s.Ago.IsZero() == c.ago {
			t.Errorf("report %+v: %+v", c.rs, s)
		}
	}
}
