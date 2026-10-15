package dyndns

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ipv64net/node64/internal/notify"
)

// fakeUpdate bildet update.php nach und merkt sich jede Anfrage.
type fakeUpdate struct {
	mu    sync.Mutex
	calls []string // Query je Aufruf
	auth  []string
	reply func(q string) (int, string)
}

func (f *fakeUpdate) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.URL.RawQuery)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	reply := f.reply
	f.mu.Unlock()
	code, body := http.StatusOK, `{"status":"success","info":"good"}`
	if reply != nil {
		code, body = reply(r.URL.RawQuery)
	}
	w.WriteHeader(code)
	_, _ = io.WriteString(w, body)
}

func (f *fakeUpdate) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeUpdate) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func setupUpdater(t *testing.T) (*Module, *fakeUpdate, *dnsView) {
	t.Helper()
	callGap = 0
	t.Cleanup(func() { callGap = defaultGap })
	m, _ := newTargetModule(t, true)
	f := &fakeUpdate{}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	m.updateURL = srv.URL + "/update.php"
	dns := &dnsView{Known: true}
	m.dnsLookup = func(context.Context, *Target) dnsView { return *dns }
	m.local = func() []ifAddr { return nil }
	m.stMu.Lock()
	m.fam[0] = famState{IP: netip.MustParseAddr("93.184.216.34")}
	m.fam[1] = famState{IP: netip.MustParseAddr("2a01:4f8:1:2:aaaa:bbbb:cccc:dddd")}
	m.stMu.Unlock()
	return m, f, dns
}

var defaultGap = callGap

func addTarget(t *testing.T, m *Module, host, mode4, mode6, suffix string) *Target {
	tg := &Target{Domain: "home.ipv64.net", Host: host, TokenKind: "record", Token: tokA, Mode4: mode4, Mode6: mode6, Suffix6: suffix, Enabled: true}
	if err := m.InsertTarget(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	return tg
}

func reload(t *testing.T, m *Module, id int64) *Target {
	tg, err := m.Target(context.Background(), id)
	if err != nil || tg == nil {
		t.Fatal(err)
	}
	return tg
}

// Nur bei Abweichung aufrufen, Token im Header, nur die geaenderte Familie, IP-Wechsel erkannt.
func TestUpdaterOnlyOnChange(t *testing.T) {
	ctx := context.Background()
	m, f, dns := setupUpdater(t)
	tg := addTarget(t, m, "nas", Mode4Auto, Mode6Off, "")

	m.runUpdates(ctx) // DNS leer -> Update
	if f.n() != 1 || !strings.Contains(f.last(), "ipv4=93.184.216.34") || strings.Contains(f.last(), "ipv6=") || !strings.Contains(f.last(), "praefix=nas") || strings.Contains(f.last(), tokA) {
		t.Fatalf("call 1: %v", f.calls)
	}
	if f.auth[0] != "Bearer "+tokA {
		t.Fatalf("token must go in the header: %q", f.auth[0])
	}
	got := reload(t, m, tg.ID)
	if got.LastIP4 != "93.184.216.34" || got.LastOKAt.IsZero() || got.LastError != "" {
		t.Fatalf("runtime: %+v", got)
	}
	dns.A = []string{"93.184.216.34"}
	m.runUpdates(ctx) // stimmt -> kein Aufruf
	if f.n() != 1 || reload(t, m, tg.ID).DNSState != 1 {
		t.Fatalf("no call expected, calls %d", f.n())
	}
	m.stMu.Lock()
	m.fam[0].IP = netip.MustParseAddr("93.184.216.35")
	m.stMu.Unlock()
	m.runUpdates(ctx) // neue Adresse
	if f.n() != 2 || !strings.Contains(f.last(), "ipv4=93.184.216.35") {
		t.Fatalf("call 2: %v", f.calls)
	}
	var rows, ok int
	_ = m.core.Reader().QueryRow(`SELECT count(*), sum(ok) FROM dyn_updates WHERE target_id = ?`, tg.ID).Scan(&rows, &ok)
	if rows != 2 || ok != 2 {
		t.Fatalf("history rows %d ok %d", rows, ok)
	}
}

// Praefix-Modus: nur ipv6prefix + onlyprefix; Antwort ohne status gilt als Erfolg. Interface-ID: volle Adresse.
func TestUpdaterPrefixAndSuffix(t *testing.T) {
	ctx := context.Background()
	m, f, _ := setupUpdater(t)
	f.reply = func(q string) (int, string) {
		if strings.Contains(q, "onlyprefix") {
			return http.StatusOK, `{"info":"good","ipv6prefix":"2a01:4f8:1:2::/64","updated_ipv6prefix_ips":2}`
		}
		return http.StatusOK, `{"status":"success","info":"good"}`
	}
	p := addTarget(t, m, "lan", Mode4Off, Mode6Prefix, "")
	m.runUpdates(ctx)
	if f.n() != 1 || !strings.Contains(f.last(), "ipv6prefix=2a01%3A4f8%3A1%3A2%3A%3A%2F64") || !strings.Contains(f.last(), "onlyprefix=1") {
		t.Fatalf("prefix call: %v", f.calls)
	}
	if got := reload(t, m, p.ID); got.LastPrefix != "2a01:4f8:1:2::/64" || got.LastError != "" {
		t.Fatalf("prefix runtime: %+v", got)
	}
	m.runUpdates(ctx) // Praefix unveraendert -> nichts
	if f.n() != 1 {
		t.Fatalf("prefix repeated: %v", f.calls)
	}
	s := addTarget(t, m, "pc", Mode4Off, Mode6Suffix, "::1a2b:3c4d:5e6f:7a8b")
	m.runUpdates(ctx)
	if f.n() != 2 || !strings.Contains(f.last(), "ipv6=2a01%3A4f8%3A1%3A2%3A1a2b%3A3c4d%3A5e6f%3A7a8b") {
		t.Fatalf("suffix call: %v", f.calls)
	}
	_ = s
}

// Von aussen staendig anders gesetzt: nach flapMax Mal pausieren statt Limit zu verbrennen.
func TestUpdaterFlapping(t *testing.T) {
	ctx := context.Background()
	m, f, dns := setupUpdater(t)
	tg := addTarget(t, m, "nas", Mode4Auto, Mode6Off, "")
	dns.A = []string{"1.1.1.1"} // jemand anderes
	for i := 0; i < 5; i++ {
		m.runUpdates(ctx)
		// naechste Runde nach der Schonfrist (die Nameserver zeigen weiter die fremde Adresse)
		_, _ = m.core.Writer().Exec(`UPDATE dyn_targets SET last_ok_at = '2000-01-01T00:00:00Z' WHERE id = ?`, tg.ID)
	}
	got := reload(t, m, tg.ID)
	// erste Runde meldet, danach zaehlt "von aussen" erst ab der zweiten Runde in Folge: flapMax+1 Aufrufe
	if got.Paused != PauseFlapping || f.n() != flapMax+1 {
		t.Fatalf("paused %q after %d calls", got.Paused, f.n())
	}
	m.runUpdates(ctx) // pausiert -> nichts mehr
	if f.n() != flapMax+1 {
		t.Fatal("paused target must not be updated")
	}
}

// badauth pausiert das Ziel; Cooldown haelt alle Aufrufe an; "Jetzt aktualisieren" erzwingt.
func TestUpdaterErrors(t *testing.T) {
	ctx := context.Background()
	m, f, dns := setupUpdater(t)
	f.reply = func(string) (int, string) {
		return http.StatusUnauthorized, `{"status":"401 Unauthorized","info":"badauth"}`
	}
	bad := addTarget(t, m, "bad", Mode4Auto, Mode6Off, "")
	m.runUpdates(ctx)
	if got := reload(t, m, bad.ID); got.Paused != PauseBadAuth || got.LastError == "" {
		t.Fatalf("badauth: %+v", got)
	}
	_ = m.DeleteTarget(ctx, bad.ID)

	f.reply = func(string) (int, string) {
		return http.StatusTooManyRequests, `{"status":"429 Too Many Requests","info":"Update Cooldown - 10sec"}`
	}
	a := addTarget(t, m, "a", Mode4Auto, Mode6Off, "")
	addTarget(t, m, "b", Mode4Auto, Mode6Off, "")
	before := f.n()
	m.runUpdates(ctx)
	if f.n() != before+1 { // nach dem 429 kein zweiter Aufruf in dieser Runde
		t.Fatalf("cooldown: %d calls", f.n()-before)
	}
	m.runUpdates(ctx)
	if f.n() != before+1 {
		t.Fatal("backoff must hold further calls")
	}
	f.reply = nil
	dns.A = []string{"93.184.216.34"}
	m.UpdateNow(ctx, reload(t, m, a.ID))
	if f.n() != before+2 || !strings.Contains(f.last(), "praefix=a") {
		t.Fatalf("manual update: %v", f.calls)
	}
}

// ipv64 meldet success, ignoriert aber IPv4 (Domain-Einstellung): Ziel pausieren statt erneut zu senden.
func TestUpdaterIgnored(t *testing.T) {
	ctx := context.Background()
	m, f, dns := setupUpdater(t)
	f.reply = func(string) (int, string) {
		return http.StatusOK, `{"status":"success","info":"","ip":{"ipv4":"ignore","ipv6":""}}`
	}
	dns.A = []string{"212.132.105.130"}
	tg := addTarget(t, m, "blog", Mode4Auto, Mode6Off, "")
	m.runUpdates(ctx)
	m.runUpdates(ctx)
	got := reload(t, m, tg.ID)
	if f.n() != 1 || got.Paused != PauseIgnored || got.LastIP4 != "" || got.Status() != "paused" {
		t.Fatalf("calls %d, target %+v", f.n(), got)
	}
}

// Kurz nach dem Update liefern die Nameserver noch den alten Stand: kein zweiter Aufruf, kein Flattern.
func TestUpdaterDNSGrace(t *testing.T) {
	ctx := context.Background()
	m, f, dns := setupUpdater(t)
	dns.A = []string{"1.2.3.4"}
	tg := addTarget(t, m, "test", Mode4Auto, Mode6Off, "")
	for i := 0; i < 4; i++ {
		m.runUpdates(ctx)
	}
	got := reload(t, m, tg.ID)
	if f.n() != 1 || got.Paused != "" || got.Status() != "pending" {
		t.Fatalf("calls %d, status %s, paused %q", f.n(), got.Status(), got.Paused)
	}
	// nach der Schonfrist noch immer alt: dann wieder melden
	_, _ = m.core.Writer().Exec(`UPDATE dyn_targets SET last_ok_at = '2000-01-01T00:00:00Z' WHERE id = ?`, tg.ID)
	m.runUpdates(ctx)
	if f.n() != 2 {
		t.Fatalf("after grace: %d calls", f.n())
	}
}

// Meldungen: Adresswechsel, erster Fehler (nicht jede Wiederholung), ausgeschaltet = keine.
func TestUpdaterNotifications(t *testing.T) {
	ctx := context.Background()
	m, f, _ := setupUpdater(t)
	var mu sync.Mutex
	var got []notify.Alert
	m.notifier = func(a notify.Alert) { mu.Lock(); got = append(got, a); mu.Unlock() }
	count := func(k notify.Kind) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, a := range got {
			if a.Kind == k && a.Check.Local {
				n++
			}
		}
		return n
	}
	f.reply = func(string) (int, string) {
		return http.StatusBadRequest, `{"status":"400 Bad Request","info":"No correct IP transmitted"}`
	}
	addTarget(t, m, "x", Mode4Auto, Mode6Off, "")
	m.runUpdates(ctx)
	m.runUpdates(ctx) // gleicher Fehler erneut: keine zweite Meldung
	if count(notify.KindDynFail) != 1 {
		t.Fatalf("fail alerts: %d", count(notify.KindDynFail))
	}
	list, _ := m.Targets(ctx)
	list[0].LastError = "" // wie nach einem Erfolg
	m.UpdateNow(ctx, list[0])
	if count(notify.KindDynFail) != 1 {
		t.Fatal("manual update must not notify")
	}
	_ = m.core.SetSetting(ctx, SetNotifyIP, "0")
	m.fetch = func(context.Context, int, string) (netip.Addr, error) {
		return netip.MustParseAddr("93.184.216.99"), nil
	}
	m.probe = func(fam int) bool { return fam == 4 }
	m.checkFamily(ctx, 4)
	if count(notify.KindDynIP) != 0 {
		t.Fatal("ip alert although switched off")
	}
	_ = m.core.SetSetting(ctx, SetNotifyIP, "1")
	m.fetch = func(context.Context, int, string) (netip.Addr, error) {
		return netip.MustParseAddr("93.184.216.100"), nil
	}
	m.checkFamily(ctx, 4)
	if count(notify.KindDynIP) != 1 {
		t.Fatalf("ip alerts: %d", count(notify.KindDynIP))
	}
}

// Letzte IPv6-Pruefung fehlgeschlagen (z. B. IPv6 ausgefallen): die alte Adresse nicht melden.
func TestUpdaterSkipsStaleAddress(t *testing.T) {
	ctx := context.Background()
	m, f, _ := setupUpdater(t)
	m.stMu.Lock()
	m.fam[1].Err = "timeout" // IP noch als "zuletzt bekannt" im Stand
	m.stMu.Unlock()
	addTarget(t, m, "v6", Mode4Off, Mode6Host, "")
	addTarget(t, m, "pfx", Mode4Off, Mode6Prefix, "")
	addTarget(t, m, "both", Mode4Auto, Mode6Host, "")
	m.runUpdates(ctx)
	if f.n() != 1 || strings.Contains(f.last(), "ipv6=") || !strings.Contains(f.last(), "praefix=both") {
		t.Fatalf("only the IPv4 of 'both' may be sent: %v", f.calls)
	}
}

// Review 2026-10-14: mehrere A-Records, Rueckhalt nach Serverfehler, Wiederaufnahme, UpdateNow besetzt,
// temporaere IPv6, onlyprefix ohne JSON, Meldungen einmal und nach manuellem Fehler.
func TestUpdaterReviewFixes(t *testing.T) {
	ctx := context.Background()
	m, f, dns := setupUpdater(t)
	var mu sync.Mutex
	var alerts []notify.Alert
	m.notifier = func(a notify.Alert) { mu.Lock(); alerts = append(alerts, a); mu.Unlock() }
	fails := func() int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, a := range alerts {
			if a.Kind == notify.KindDynFail {
				n++
			}
		}
		return n
	}

	// zwei A-Records (Round-Robin), einer ist unsere Adresse: kein Update
	dns.A = []string{"10.9.9.9", "93.184.216.34"}
	rr := addTarget(t, m, "rr", Mode4Auto, Mode6Off, "")
	_, _ = m.core.Writer().Exec(`UPDATE dyn_targets SET last_ip4 = '93.184.216.34' WHERE id = ?`, rr.ID)
	m.runUpdates(ctx)
	if f.n() != 0 {
		t.Fatalf("round-robin must not trigger an update: %v", f.calls)
	}
	_ = m.DeleteTarget(ctx, rr.ID)

	// Serverfehler: Meldung einmal, danach Rueckhalt statt Aufruf in jeder Runde
	dns.A = nil
	f.reply = func(string) (int, string) { return http.StatusInternalServerError, "oops" }
	se := addTarget(t, m, "se", Mode4Auto, Mode6Off, "")
	m.runUpdates(ctx)
	m.runUpdates(ctx)
	if f.n() != 1 || fails() != 1 {
		t.Fatalf("server error: calls %d alerts %d", f.n(), fails())
	}
	// "Jetzt aktualisieren" scheitert ebenfalls: keine Meldung, blockiert aber spaetere automatische nicht
	m.upd.mu.Lock()
	delete(m.upd.tback, se.ID)
	delete(m.upd.alerted, se.ID)
	m.upd.mu.Unlock()
	if res, err := m.UpdateNow(ctx, reload(t, m, se.ID)); err != nil || res != NowSent || fails() != 1 {
		t.Fatalf("manual: %s %v alerts %d", res, err, fails())
	}
	m.upd.mu.Lock()
	delete(m.upd.tback, se.ID) // Rueckhalt nach dem manuellen Fehler abgelaufen
	m.upd.mu.Unlock()
	m.runUpdates(ctx)
	if fails() != 2 {
		t.Fatalf("auto failure after a manual one must be reported: %d", fails())
	}
	_ = m.DeleteTarget(ctx, se.ID)

	// UpdateNow waehrend einer Runde: sofort "besetzt" statt warten
	m.upd.run.Lock()
	if _, err := m.UpdateNow(ctx, reload(t, m, addTarget(t, m, "busy", Mode4Auto, Mode6Off, "").ID)); !errors.Is(err, ErrBusy) {
		t.Fatalf("want ErrBusy, got %v", err)
	}
	m.upd.run.Unlock()

	// nohost: pausiert, nach 6 h erneut versucht
	f.reply = func(string) (int, string) { return http.StatusNotFound, `{"status":"404 Not Found","info":"nohost"}` }
	nh := addTarget(t, m, "nh", Mode4Auto, Mode6Off, "")
	before := f.n()
	m.runUpdates(ctx)
	if got := reload(t, m, nh.ID); got.Paused != PauseNoHost {
		t.Fatalf("nohost: %+v", got)
	}
	m.runUpdates(ctx)
	_, _ = m.core.Writer().Exec(`UPDATE dyn_targets SET last_err_at = '2000-01-01T00:00:00Z' WHERE id = ?`, nh.ID)
	f.reply = nil
	m.runUpdates(ctx)
	if got := reload(t, m, nh.ID); got.Paused != "" || got.LastOKAt.IsZero() {
		t.Fatalf("nohost not resumed: %+v (calls %d)", got, f.n()-before)
	}

	// onlyprefix: 200 ohne JSON ist kein Erfolg
	r := m.doCallFor(t, `<html>maintenance</html>`)
	if r.OK {
		t.Fatal("html answer must not count as success")
	}
}

// doCallFor wertet eine feste Antwort im Praefix-Modus aus (Hilfe fuer den Test).
func (m *Module) doCallFor(t *testing.T, body string) updResult {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
	defer srv.Close()
	old := m.updateURL
	m.updateURL = srv.URL
	defer func() { m.updateURL = old }()
	return m.doCall(context.Background(), url.Values{"ipv6prefix": {"2a01::/64"}, "onlyprefix": {"1"}}, tokA)
}

// Host-Modus: temporaere Privacy-Adresse wird durch die stabile aus demselben /64 ersetzt.
func TestUpdaterStableIPv6(t *testing.T) {
	m, _, _ := setupUpdater(t)
	temp := netip.MustParseAddr("2a01:4f8:1:2:aaaa:bbbb:cccc:dddd")
	stable := netip.MustParseAddr("2a01:4f8:1:2::10")
	m.local = func() []ifAddr {
		return []ifAddr{{Iface: "eth0", Addr: temp, Temporary: true}, {Iface: "eth0", Addr: stable}}
	}
	if p := m.planFor(&Target{Mode4: Mode4Off, Mode6: Mode6Host}); p.IP6 != stable.String() {
		t.Fatalf("want stable address, got %q", p.IP6)
	}
}

// Nach einer gemeldeten Stoerung kommt beim naechsten Erfolg genau eine Entwarnung.
func TestUpdaterRecoveryAlert(t *testing.T) {
	ctx := context.Background()
	m, f, _ := setupUpdater(t)
	var mu sync.Mutex
	kinds := map[notify.Kind]int{}
	m.notifier = func(a notify.Alert) { mu.Lock(); kinds[a.Kind]++; mu.Unlock() }
	f.reply = func(string) (int, string) {
		return http.StatusBadRequest, `{"status":"400 Bad Request","info":"No correct IP transmitted"}`
	}
	tg := addTarget(t, m, "rec", Mode4Auto, Mode6Off, "")
	m.runUpdates(ctx)
	m.upd.mu.Lock()
	delete(m.upd.tback, tg.ID)
	m.upd.mu.Unlock()
	f.reply = nil
	m.runUpdates(ctx)
	m.runUpdates(ctx)
	mu.Lock()
	defer mu.Unlock()
	if kinds[notify.KindDynFail] != 1 || kinds[notify.KindDynOK] != 1 {
		t.Fatalf("alerts: %v", kinds)
	}
}
