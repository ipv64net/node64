package honeypot

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/metrics"
)

// TestMain: kein Abruf der Laenderdaten von ipv64.net in Tests (Modulstart fordert sie sonst an).
func TestMain(m *testing.M) {
	geoStart = func(string, string, *slog.Logger) func() { return func() {} }
	os.Exit(m.Run())
}

// fakeCountries ersetzt das Nachschlagen: Netz -> Land.
func fakeCountries(t *testing.T, nets map[string]string) {
	t.Helper()
	old := lookupCountry
	type pc struct {
		p  netip.Prefix
		cc string
	}
	var list []pc
	for n, cc := range nets {
		list = append(list, pc{netip.MustParsePrefix(n), cc})
	}
	lookupCountry = func(a netip.Addr) (string, bool) {
		a = a.Unmap()
		for _, x := range list {
			if x.p.Contains(a) {
				return x.cc, true
			}
		}
		return "", false
	}
	t.Cleanup(func() { lookupCountry = old })
}

func TestStoreByCountryAndDecoys(t *testing.T) {
	fakeCountries(t, map[string]string{"192.0.2.0/25": "DE", "192.0.2.128/25": "US", "2001:db8::/32": "JP"})
	s := newTestStore(t)
	ctx := context.Background()
	sink := s.Sink()
	now := time.Now()
	for i := 0; i < 3; i++ {
		sink(Event{Time: now, Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("192.0.2.1")})
	}
	sink(Event{Time: now, Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("192.0.2.2")})
	sink(Event{Time: now, Service: SvcHTTP, Port: 80, Kind: KindHTTPBrute, Src: ip("192.0.2.200"), Detail: "device=fritzbox", Username: "a", Password: "b"})
	sink(Event{Time: now, Service: SvcHTTP, Port: 80, Kind: KindHTTPBrute, Src: ip("::ffff:192.0.2.201"), Detail: "foo,device=fritzbox"})
	sink(Event{Time: now, Service: SvcHTTPS, Port: 443, Kind: KindHTTPScan, Src: ip("2001:db8::5"), Page: "wp-login"})
	sink(Event{Time: now, Service: SvcTCP, Port: 23, Kind: KindProbe, Src: ip("10.1.2.3")})    // privat: kein Land
	sink(Event{Time: now, Service: SvcTCP, Port: 23, Kind: KindProbe, Src: ip("203.0.113.9")}) // unbekannt
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	st, err := s.Stats(ctx, now.Add(-time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.ByCountry) != 3 || st.ByCountry[0].Key != "DE" || st.ByCountry[0].Count != 4 || st.ByCountry[0].Sources != 2 ||
		st.ByCountry[1].Key != "US" || st.ByCountry[1].Count != 2 || st.ByCountry[1].Sources != 2 || st.ByCountry[2].Key != "JP" || st.ByCountry[0].Last.IsZero() {
		t.Fatalf("by country: %+v", st.ByCountry)
	}
	if st.CountryUnknown != 2 {
		t.Fatalf("unknown %d", st.CountryUnknown)
	}
	if st.TopSources[0].Key != "192.0.2.1" || st.TopSources[0].Country != "DE" {
		t.Fatalf("top sources: %+v", st.TopSources)
	}
	for _, c := range st.TopSources {
		if (c.Key == "10.1.2.3" || c.Key == "203.0.113.9") && c.Country != "" {
			t.Fatalf("no country expected: %+v", c)
		}
	}
	if len(st.ByDecoy) != 2 || st.ByDecoy[0].Key != "device:fritzbox" || st.ByDecoy[0].Count != 2 || st.ByDecoy[1].Key != "page:wp-login" {
		t.Fatalf("decoys: %+v", st.ByDecoy)
	}
	// JSON: by_country, country_unknown, country an top_sources
	raw, _ := json.Marshal(st)
	for _, s := range []string{`"by_country":[{"key":"DE","count":4,"sources":2`, `"country_unknown":2`, `"country":"DE"`, `"by_decoy":[{"key":"device:fritzbox"`} {
		if !strings.Contains(string(raw), s) {
			t.Errorf("json lacks %s", s)
		}
	}
	// ohne Laenderdaten: alles unbekannt, leere Liste
	lookupCountry = func(netip.Addr) (string, bool) { return "", false }
	st, err = s.Stats(ctx, now.Add(-time.Hour), 0)
	if err != nil || len(st.ByCountry) != 0 || st.CountryUnknown != 9 || st.TopSources[0].Country != "" {
		t.Fatalf("without data: %v %+v %d", err, st.ByCountry, st.CountryUnknown)
	}
	if raw, _ := json.Marshal(st); !strings.Contains(string(raw), `"by_country":[]`) {
		t.Errorf("by_country must be an empty list: %s", raw)
	}
}

func TestCountryViewAndRanks(t *testing.T) {
	v := countryView("DE", "de")
	if v.Flag != "\U0001F1E9\U0001F1EA" || v.Name != "Deutschland" || v.Code != "DE" {
		t.Fatalf("view %+v", v)
	}
	if v := countryView("US", "en"); v.Name != "United States" || v.Flag != "\U0001F1FA\U0001F1F8" {
		t.Fatalf("view %+v", v)
	}
	if v := countryView("", "de"); v.Code != "" || v.Flag != "" {
		t.Fatalf("empty %+v", v)
	}
	if v := countryView("AP", "de"); v.Flag != "" || v.Name != "AP" {
		t.Fatalf("unknown code %+v", v)
	}
	r := countryRanks([]CountryCount{{Key: "DE", Count: 30, Sources: 3}, {Key: "US", Count: 10, Sources: 1}}, "de", 1)
	if len(r) != 1 || r[0].Pct != 100 || r[0].Share != 75 || r[0].Color == "" || r[0].Name != "Deutschland" {
		t.Fatalf("ranks %+v", r)
	}
}

func TestKindGroupsAndTargets(t *testing.T) {
	for _, c := range []struct{ kind, source, want string }{
		{KindSSHBrute, SrcHoneypot, GroupLogin}, {KindMailBrute, "", GroupLogin}, {KindHTTPSQLi, SrcHoneypot, GroupExploit},
		{KindDBExploit, SrcHoneypot, GroupExploit}, {KindPortScan, SrcHoneypot, GroupScan}, {KindSIPScan, SrcHoneypot, GroupScan},
		{KindScannerResch, SrcHoneypot, GroupScan}, {KindProbe, SrcHoneypot, GroupProbe}, {KindBadUA, SrcHoneypot, GroupProbe},
		{KindSSHBrute, SrcLog, GroupLog}, {KindHTTPExploit, SrcSyslog, GroupLog},
	} {
		if g := KindGroup(c.kind, c.source); g != c.want {
			t.Errorf("%s/%s: %s, want %s", c.kind, c.source, g, c.want)
		}
	}
	tg := buildTargets([]targetRow{
		{Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Source: SrcHoneypot, Count: 6},
		{Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Source: SrcLog, Count: 2},
		{Service: SvcHTTP, Port: 80, Kind: KindHTTPRCE, Source: SrcHoneypot, Count: 3},
		{Service: SvcScan, Port: 80, Kind: KindPortScan, Source: SrcHoneypot, Count: 1},
	}, 10)
	if len(tg.Cols) != 3 || tg.Cols[0].ID != "services" || tg.Cols[1].ID != "ports" || tg.Cols[2].ID != "kinds" {
		t.Fatalf("cols %+v", tg.Cols)
	}
	svc := tg.Cols[0].Items
	if svc[0].Key != "ssh" || svc[0].Count != 8 || len(svc[0].Segs) != 2 || svc[0].Segs[0].Group != GroupLogin || svc[0].Segs[0].Pct != 75 ||
		svc[0].Segs[1].Group != GroupLog || svc[0].Segs[1].Pct != 25 {
		t.Fatalf("services %+v", svc)
	}
	ports := tg.Cols[1].Items
	if ports[0].Key != "22" || ports[0].Sub != "ssh" || ports[1].Key != "80" || ports[1].Sub != "http" || ports[1].Count != 4 {
		t.Fatalf("ports %+v", ports)
	}
	if strings.Join(tg.Groups, ",") != "login,exploit,scan,log" {
		t.Fatalf("legend %v", tg.Groups)
	}
	if (uiTargets{}).Color(GroupLogin) != "bg-danger" || (uiTargets{}).Color("x") != "bg-secondary" {
		t.Fatal("colors")
	}
	if e := buildTargets(nil, 10); len(e.Cols) != 0 {
		t.Fatal("empty targets")
	}
	d := decoyRanks([]Count{{Key: "device:fritzbox", Count: 3}, {Key: "page:wp-login", Count: 1}})
	if len(d) != 2 || d[0].Kind != "device" || d[0].Name != "fritzbox" || d[1].Kind != "page" {
		t.Fatalf("decoys %+v", d)
	}
}

func TestEventsAPICountryAndMetrics(t *testing.T) {
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
	mux := http.NewServeMux()
	m.apiRoutes(mux, m.g)
	for path, want := range map[string]string{"/api/honeypot/events": `"country":"DE"`, "/api/honeypot/stats": `"by_country":[{"key":"DE","count":2,"sources":1`} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	w := metrics.New()
	m.Metrics(ctx, w)
	var b strings.Builder
	_, _ = w.WriteTo(&b)
	for _, s := range []string{`node64_honeypot_events_by_country_total{country="DE"}`, `node64_honeypot_events_by_country_total{country="NL"}`,
		"# TYPE node64_honeypot_events_by_country_total counter"} {
		if !strings.Contains(b.String(), s) {
			t.Errorf("metrics lack %q", s)
		}
	}
}
