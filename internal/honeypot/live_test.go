package honeypot

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// Live-Karte: nur Ereignisse im Zeitraum mit bekanntem Land, Kartenpunkt und Gruppe; Ziel = Land der eigenen IPv4,
// ohne bekanntes Land die Kartenmitte.
func TestLiveEvents(t *testing.T) {
	fakeCountries(t, map[string]string{"192.0.2.0/24": "DE", "198.51.100.0/24": "US"})
	old := ownCC
	ownCC = &ownCountry{from: func(context.Context) (netip.Addr, error) { return netip.MustParseAddr("192.0.2.1"), nil }}
	t.Cleanup(func() { ownCC = old })
	m, _ := modTest(t, modFreePort(t))
	ctx := context.Background()
	if _, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{Service: SvcSSH, Port: modFreePort(t)}}}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m.sink(Event{Time: now.Add(-3 * time.Hour), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: netip.MustParseAddr("198.51.100.8")}) // zu alt
	m.sink(Event{Time: now, Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: netip.MustParseAddr("198.51.100.7")})
	m.sink(Event{Time: now, Service: SvcHTTP, Port: 80, Kind: "http:scan", Src: netip.MustParseAddr("203.0.113.9")}) // Land unbekannt
	_ = m.st.Flush(ctx)
	ev, err := m.liveEvents(ctx, 60, "de")
	if err != nil || len(ev) != 1 || ev[0].Country != "US" || ev[0].Group != GroupLogin || ev[0].X <= 0 || ev[0].IP != "198.51.100.7" || ev[0].Source != SrcHoneypot {
		t.Fatalf("events: %+v %v", ev, err)
	}
	if tg := liveTarget(ctx, "de", ""); !tg.Known || tg.Country != "DE" || tg.X <= 0 || tg.Manual {
		t.Fatalf("target: %+v", tg)
	}
	ownCC = &ownCountry{from: func(context.Context) (netip.Addr, error) { return netip.Addr{}, context.DeadlineExceeded }}
	if tg := liveTarget(ctx, "de", "SG"); !tg.Known || tg.Country != "SG" || !tg.Manual {
		t.Fatalf("eingestellter Standort: %+v", tg)
	}
	if tg := liveTarget(ctx, "de", ""); tg.Known || tg.X != 500 {
		t.Fatalf("unknown target: %+v", tg)
	}
}

// Laendernamen der Standort-Auswahl nach Sprache sortiert: Oesterreich zwischen Oman und Pakistan, nicht hinter Zypern.
func TestCountryOptionsSorted(t *testing.T) {
	pos := map[string]int{}
	for i, c := range countryOptions("de") {
		pos[c.Code] = i
	}
	if !(pos["OM"] < pos["AT"] && pos["AT"] < pos["PK"]) || !(pos["EG"] < pos["CY"]) {
		t.Fatalf("order: OM %d AT %d PK %d EG %d CY %d", pos["OM"], pos["AT"], pos["PK"], pos["EG"], pos["CY"])
	}
}

// Waehrend des Abrufs der eigenen IPv4 warten cached() und weitere get()-Aufrufe nicht (Einstellungsseite).
func TestOwnCountryNoWaitDuringFetch(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	o := &ownCountry{from: func(context.Context) (netip.Addr, error) {
		close(started)
		<-release
		return netip.Addr{}, context.DeadlineExceeded
	}}
	done := make(chan struct{})
	go func() { o.get(context.Background()); close(done) }()
	<-started
	ok := make(chan struct{})
	go func() { o.cached(); o.get(context.Background()); close(ok) }()
	select {
	case <-ok:
	case <-time.After(2 * time.Second):
		t.Fatal("cached()/get() blocked during fetch")
	}
	close(release)
	<-done
}
