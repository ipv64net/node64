package ipam64

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	nodesync "github.com/ipv64net/node64/internal/sync"
	"github.com/ipv64net/node64/internal/web"
)

// Nachstellungen der Befunde aus dem Code-Review (v1.6.0..HEAD), je Befund ein Test.

// webClient startet den echten Webserver mit eingeschaltetem IPAM64 und angemeldetem Admin; liefert get und post.
func webClient(t *testing.T, m *Module, dir string) (get func(string) (int, string), post func(string, url.Values) (int, string)) {
	t.Helper()
	logger := logging.New("error", "text", io.Discard)
	bundle, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	reg := module.NewRegistry(m.core, logger.Slog())
	reg.Register(m)
	t.Cleanup(reg.StopAll)
	s, err := web.New(web.Deps{Cfg: &config.Config{DataDir: dir, HTTPPort: 8080, LogLevel: "error"}, Store: m.core, Log: logger, I18n: bundle, Modules: reg,
		Sync: nodesync.NoOp{}, Version: "test", StartedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var tok string
	do := func(method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if method != "GET" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-CSRF-Token", tok)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	get = func(path string) (int, string) { return do("GET", path, "") }
	post = func(path string, form url.Values) (int, string) {
		form.Set("_csrf", tok)
		return do("POST", path, form.Encode())
	}
	_, body := get("/setup")
	tok = csrfRe.FindStringSubmatch(body)[1]
	if code, _ := post("/setup", url.Values{"lang": {"de"}, "username": {"admin"}, "password": {"sehr geheimes passwort"},
		"password2": {"sehr geheimes passwort"}, "timezone": {"Europe/Berlin"}, "node_name": {"pi"}}); code != http.StatusSeeOther {
		t.Fatalf("setup: %d", code)
	}
	if err := reg.Enable(context.Background(), Name); err != nil {
		t.Fatal(err)
	}
	_, body = get("/")
	tok = csrfRe.FindStringSubmatch(body)[1]
	return get, post
}

// Uebernommene Reservierung von Hand mit Namen, der kein DNS-Label ist: ohne Rechnernamen in IPAM64 ist der
// abweichende Name in DNS64 keine Abweichung (der Abgleich schreibt nicht immer wieder), ein eigener schon.
func TestReviewKeepHandReservationName(t *testing.T) {
	w := OwnedRes{Ref: "u", MAC: "02:00:00:00:00:01", IP: "192.168.1.10"}
	have := w
	have.Name = "Tablet Lea"
	if !resEqual(w, have) || !(ownedOne{res: &have}).matches(want{res: &w}) {
		t.Fatal("kept hand name counted as difference")
	}
	have.Name = "tablet" // so schreibt nur IPAM64 selbst: muss weg
	if resEqual(w, have) {
		t.Fatal("own name not cleared")
	}
	w.Name, have.Name = "nas", "Tablet Lea"
	if resEqual(w, have) {
		t.Fatal("name from IPAM64 not enforced")
	}
}

// Gesperrtes DHCP-Kaestchen (Praefix ohne DHCP-Netz): Speichern laesst die Reservierung stehen.
func TestReviewLockedDHCPKept(t *testing.T) {
	m, _, dir := modTest(t)
	ctx := context.Background()
	mustPrefix(t, m, Prefix{Prefix: "192.168.1.0/24"})
	a, err := m.SaveAddress(ctx, Address{Address: "192.168.1.10", Name: "nas", MAC: "02:00:00:00:00:0a", DHCP: true}, "t")
	if err != nil {
		t.Fatal(err)
	}
	get, post := webClient(t, m, dir)
	if code, body := get("/ipam64/address?ip=192.168.1.10"); code != 200 || !strings.Contains(body, `name="dhcp_locked"`) {
		t.Fatalf("address page: %d", code)
	}
	if code, _ := post("/ipam64/address", url.Values{"uid": {a.UID}, "address": {a.Address}, "name": {"nas"}, "mac": {a.MAC},
		"description": {"nur Text"}, "dhcp_locked": {"1"}}); code != http.StatusSeeOther {
		t.Fatalf("save: %d", code)
	}
	if cur, _ := m.AddressByIP(ctx, "192.168.1.10"); cur == nil || !cur.DHCP || cur.Description != "nur Text" {
		t.Fatalf("dhcp lost: %+v", cur)
	}
}

// Meldung nach dem Import: hoechstens zehn Fehlzeilen, dazu die Zahl der uebrigen (Cookie bleibt klein).
func TestReviewImportFlashShort(t *testing.T) {
	m, _, dir := modTest(t)
	mustPrefix(t, m, Prefix{Prefix: "10.20.0.0/24"}) // ohne Zone: dns=1 scheitert erst beim Uebernehmen
	m.SetDNS64(newFake().hooks())
	get, post := webClient(t, m, dir)
	var b strings.Builder
	b.WriteString("ip;name;dns\n")
	for i := 1; i <= 40; i++ {
		b.WriteString("10.20.0." + strconv.Itoa(i) + ";h" + strconv.Itoa(i) + ";1\n")
	}
	if code, _ := post("/ipam64/import", url.Values{"action": {"apply"}, "csv": {b.String()}}); code != http.StatusSeeOther {
		t.Fatalf("import: %d", code)
	}
	_, body := get("/ipam64")
	if !strings.Contains(body, "und 30 weitere") || strings.Contains(body, "10.20.0.11:") || !strings.Contains(body, "10.20.0.10:") {
		t.Fatalf("flash not shortened:\n%s", body)
	}
}

// Blockuebersicht: ein Feld in einem groesseren Kind-Praefix verlinkt auf dieses.
func TestReviewBlockMapLargeChild(t *testing.T) {
	p := netip.MustParsePrefix("10.80.0.0/16")
	n := Net{CIDR: p.String(), Prefix: p, Family: 4}
	s := &Snapshot{Nets: []Net{n, {CIDR: "10.80.4.0/22", Prefix: netip.MustParsePrefix("10.80.4.0/22"), Family: 4, Parent: p.String()}}, entries: map[netip.Prefix][]Entry{}}
	cells := s.blockMap(&n, 24, nil)
	for i := 4; i < 8; i++ {
		if cells[i].Level != "child" || cells[i].Child != "10.80.4.0/22" {
			t.Fatalf("cell %d: %+v", i, cells[i])
		}
	}
	if cells[8].Level != "empty" || cells[8].Child != "" {
		t.Fatalf("cell 8: %+v", cells[8])
	}
}

// Eigener CSV-Export wieder eingelesen: Leases und blosse Sichtungen werden keine festen Adressen.
func TestReviewImportOwnExport(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	m.SetNetworks(lanHint)
	csv := "prefix,ip,name,note,mac,kind,status,role,tags,sources,last_seen,state\n" +
		"192.168.1.0/24,192.168.1.10,nas,,02:00:00:00:00:0a,static,active,,,ipam,,online\n" +
		"192.168.1.0/24,192.168.1.11,drucker,,02:00:00:00:00:0b,fixed,,,,dhcp,,unknown\n" +
		"192.168.1.0/24,192.168.1.12,pi.home.lan,,,static,,,,dns,,unknown\n" +
		"192.168.1.0/24,192.168.1.13,tv,,02:00:00:00:00:0d,dhcp,active,,,ipam dhcp,,online\n" +
		"192.168.1.0/24,192.168.1.150,handy,,02:00:00:00:00:96,dhcp,,,,dhcp scan,,online\n" +
		"192.168.1.0/24,192.168.1.160,,,02:00:00:00:00:a0,static,,,,scan,,offline\n"
	rows, err := m.ParseImport(ctx, []byte(csv))
	if err != nil || len(rows) != 6 {
		t.Fatalf("parse: %+v %v", rows, err)
	}
	for i, wantSeen := range []bool{false, false, false, false, true, true} {
		if got := rows[i].Err == ErrImportSeen; got != wantSeen || (!wantSeen && rows[i].Err != nil) {
			t.Fatalf("row %s: %v", rows[i].Key, rows[i].Err)
		}
	}
	if observedOnly("", "") || !observedOnly("dhcp", "") { // ohne die Spalten (fremde Datei) wird nichts uebergangen
		t.Fatal("observedOnly without columns")
	}
}

// DHCP-Netz auf dieser Node aus (im Cluster vergibt eine andere Node): die Ausnahme der festen Adresse im Pool bleibt.
func TestReviewExcludeInDisabledScope(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	f := newFake()
	m.SetDNS64(f.hooks())
	off := false
	m.SetNetworks(func(context.Context) []NetHint {
		h := lanHint(ctx)
		h[0].Off = off
		return h
	})
	mustPrefix(t, m, Prefix{Prefix: "192.168.1.0/24"})
	cam, err := m.ApplyAddress(ctx, Address{Address: "192.168.1.150", Name: "kamera"}, "t")
	if err != nil || f.excl[cam.UID].IP != "192.168.1.150" {
		t.Fatalf("exclude: %+v %v", f.excl, err)
	}
	off = true
	m.now = func() time.Time { return time.Now().Add(settleFor + time.Minute) }
	if n, err := m.reconcile(ctx); err != nil || n != 0 || f.excl[cam.UID].IP != "192.168.1.150" {
		t.Fatalf("reconcile removed exclude of disabled scope: %d %v %+v", n, err, f.excl)
	}
	cam.Description = "neu"
	if _, err := m.ApplyAddress(ctx, cam, "t"); err != nil || f.excl[cam.UID].IP != "192.168.1.150" {
		t.Fatalf("save removed exclude: %+v %v", f.excl, err)
	}
	// das ausgeschaltete Netz erscheint nicht als DHCP-Netz
	if s, _ := m.Snapshot(ctx); s.Net("192.168.1.0/24").DHCP {
		t.Fatal("disabled scope shown as dhcp net")
	}
}

// Cluster: Tausch zweier Adressen auf einer anderen Node, der neue Stand der einen kommt vor dem der anderen an -
// keine Doppelvergabe, nichts geht verloren.
func TestReviewClusterSwapNotDouble(t *testing.T) {
	b, _, _ := modTest(t)
	ctx := context.Background()
	var got []string
	stale := map[string]bool{}
	b.SetCluster(ClusterHooks{
		Change: func(_ context.Context, item, id string, del bool) { got = append(got, id) },
		Stale:  func(_ context.Context, _, id string) bool { return stale[id] },
	})
	mustPrefix(t, b, Prefix{Prefix: "192.168.1.0/24"})
	now := time.Now().UTC().Truncate(time.Second)
	u1 := Address{UID: "00000000000000000000000000000001", Address: "192.168.1.10", Name: "eins", Status: StatusActive, PTR: true, Updated: now}
	u2 := Address{UID: "00000000000000000000000000000002", Address: "192.168.1.11", Name: "zwei", Status: StatusActive, PTR: true, Updated: now}
	for _, a := range []Address{u1, u2} {
		raw, _ := json.Marshal(a)
		if err := b.ClusterApply(ctx, ClusterItemAddresses, a.UID, raw, false); err != nil {
			t.Fatal(err)
		}
	}
	got = nil
	stale[u1.UID], stale[u2.UID] = true, true // beide stammen von der Node, die jetzt liefert
	u2.Address, u1.Address = "192.168.1.10", "192.168.1.11"
	for _, a := range []Address{u2, u1} {
		raw, _ := json.Marshal(a)
		if err := b.ClusterApply(ctx, ClusterItemAddresses, a.UID, raw, false); err != nil {
			t.Fatal(err)
		}
	}
	x, _ := b.AddressByIP(ctx, "192.168.1.10")
	y, _ := b.AddressByIP(ctx, "192.168.1.11")
	if x == nil || x.UID != u2.UID || y == nil || y.UID != u1.UID || len(got) != 0 || len(b.doubleFindings()) != 0 {
		t.Fatalf("swap: %+v %+v changes %v", x, y, got)
	}
}

// Gedaechtnis der Sichtungen waechst nicht ohne Grenze.
func TestReviewSeenMemoryPruned(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	now := time.Now()
	if err := m.saveSeen(ctx, []seenRow{{IP: ip("192.168.1.50"), MAC: "02:00:00:00:00:50", Last: now.Add(-seenKeep - time.Hour)},
		{IP: ip("192.168.1.51"), MAC: "02:00:00:00:00:51", Last: now}}); err != nil {
		t.Fatal(err)
	}
	m.pruneSeen(ctx, now)
	if len(m.seenAt) != 1 {
		t.Fatalf("seenAt: %v", m.seenAt)
	}
}

// Die Router-Adresse des DHCP-Netzes ist nie die naechste freie Adresse (auch nicht in der Lueckenliste).
func TestReviewRouterNotFree(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	m.SetNetworks(func(context.Context) []NetHint {
		return []NetHint{{Subnet: netip.MustParsePrefix("10.0.0.0/24"), Router: ip("10.0.0.1"), Start: ip("10.0.0.100"), End: ip("10.0.0.199")}}
	})
	mustPrefix(t, m, Prefix{Prefix: "10.0.0.0/24"})
	if got, _ := m.Available(ctx, "10.0.0.0/24", "", 1); len(got) != 1 || got[0].String() != "10.0.0.2" {
		t.Fatalf("free: %v", got)
	}
	s, _ := m.Snapshot(ctx)
	if b := s.FreeBlocks(s.Net("10.0.0.0/24")); len(b) == 0 || b[0].First.String() != "10.0.0.2" {
		t.Fatalf("blocks: %+v", b)
	}
}

// Abgelaufene Lease eines gegangenen Clients: kein Hinweis "unbekanntes Geraet im Pool", keine Meldung "neues Geraet".
func TestReviewGoneClientNotUnknown(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	m.SetNetworks(lanHint)
	mustPrefix(t, m, Prefix{Prefix: "192.168.1.0/24"})
	if err := m.saveSeen(ctx, []seenRow{{IP: ip("192.168.1.150"), MAC: "02:00:00:00:00:96", Last: time.Now().Add(-25 * time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	found, err := m.Findings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range found {
		if x.Kind == "pool" {
			t.Fatalf("pool hint for gone client: %+v", x)
		}
	}
	var sent []notify.Alert
	m.SetNotifier(func(a notify.Alert) { sent = append(sent, a) })
	m.started = time.Now().Add(-48 * time.Hour)
	if err := m.SetNotifyFlags(ctx, true, true); err != nil {
		t.Fatal(err)
	}
	m.notifyCheck(ctx)
	if len(sent) != 0 {
		t.Fatalf("gone client reported as new device: %+v", sent)
	}
	// ein gerade gesehenes unbekanntes Geraet im Pool bleibt ein Hinweis
	if err := m.saveSeen(ctx, []seenRow{{IP: ip("192.168.1.160"), MAC: "02:00:00:00:00:a0", Last: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	m.invalidate()
	found, _ = m.Findings(ctx)
	pool := 0
	for _, x := range found {
		if x.Kind == "pool" && x.IP == "192.168.1.160" {
			pool++
		}
	}
	if pool != 1 {
		t.Fatalf("pool hint missing: %+v", found)
	}
}

// Rueckkehr zu einer frueher gesehenen MAC (VIP-Failover) ist keine Doppelvergabe: es zaehlt die aktuelle Anwesenheit,
// nicht die allererste Sichtung.
func TestReviewReturnedMACNotDup(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	mustPrefix(t, m, Prefix{Prefix: "192.168.1.0/24"})
	now := time.Now()
	vip := ip("192.168.1.5")
	for _, s := range []seenRow{
		{IP: vip, MAC: "02:00:00:00:00:aa", Last: now.Add(-48 * time.Hour)},
		{IP: vip, MAC: "02:00:00:00:00:bb", Last: now.Add(-30 * time.Minute)},
		{IP: vip, MAC: "02:00:00:00:00:bb", Last: now.Add(-20 * time.Minute)},
		{IP: vip, MAC: "02:00:00:00:00:bb", Last: now.Add(-12 * time.Minute)},
		{IP: vip, MAC: "02:00:00:00:00:aa", Last: now.Add(-10 * time.Minute)},
		{IP: vip, MAC: "02:00:00:00:00:aa", Last: now},
	} {
		if err := m.saveSeen(ctx, []seenRow{s}); err != nil {
			t.Fatal(err)
		}
	}
	s, err := m.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if e := s.Entry(vip); e == nil || e.Conflict != "" || e.First.After(now.Add(-47*time.Hour)) {
		t.Fatalf("failover back: %+v", e)
	}
	// echte Doppelvergabe (beide gleichzeitig da) bleibt ein Konflikt
	for _, s := range []seenRow{
		{IP: ip("192.168.1.6"), MAC: "02:00:00:00:00:cc", Last: now.Add(-14 * time.Minute)},
		{IP: ip("192.168.1.6"), MAC: "02:00:00:00:00:dd", Last: now.Add(-13 * time.Minute)},
		{IP: ip("192.168.1.6"), MAC: "02:00:00:00:00:cc", Last: now.Add(-6 * time.Minute)},
		{IP: ip("192.168.1.6"), MAC: "02:00:00:00:00:dd", Last: now},
		{IP: ip("192.168.1.6"), MAC: "02:00:00:00:00:cc", Last: now.Add(-time.Second)},
	} {
		if err := m.saveSeen(ctx, []seenRow{s}); err != nil {
			t.Fatal(err)
		}
	}
	m.invalidate()
	s, _ = m.Snapshot(ctx)
	if e := s.Entry(ip("192.168.1.6")); e == nil || e.Conflict != "dup" {
		t.Fatalf("real dup: %+v", e)
	}
}

// Lueckenliste nach den Regeln der freien Adressen: an den Pool-Grenzen geteilt, ohne Kind-Praefix und reservierten
// Bereich.
func TestReviewFreeBlocksRules(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	m.SetNetworks(func(context.Context) []NetHint {
		return []NetHint{{Subnet: netip.MustParsePrefix("10.1.0.0/24"), Start: ip("10.1.0.100"), End: ip("10.1.0.200")}}
	})
	m.SetSource(SrcDHCP, func(context.Context) []Sighting {
		return []Sighting{{Addr: "10.1.0.110", MAC: "02:00:00:00:01:10", Kind: KindDHCP}}
	})
	mustPrefix(t, m, Prefix{Prefix: "10.1.0.0/24"})
	mustPrefix(t, m, Prefix{Prefix: "10.1.0.0/28"})
	if _, err := m.SaveRange(ctx, Range{Start: "10.1.0.20", End: "10.1.0.29", Kind: RangeReserved}, "t"); err != nil {
		t.Fatal(err)
	}
	s, _ := m.Snapshot(ctx)
	var got []string
	for _, b := range s.FreeBlocks(s.Net("10.1.0.0/24")) {
		g := b.First.String() + "-" + b.Last.String()
		if b.Pool {
			g += "p"
		}
		got = append(got, g)
	}
	want := "10.1.0.16-10.1.0.19 10.1.0.30-10.1.0.99 10.1.0.100-10.1.0.109p 10.1.0.111-10.1.0.200p 10.1.0.201-10.1.0.254"
	if strings.Join(got, " ") != want {
		t.Fatalf("blocks:\n%s\nwant\n%s", strings.Join(got, " "), want)
	}
}
