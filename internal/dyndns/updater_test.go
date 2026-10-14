package dyndns

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
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
	}
	got := reload(t, m, tg.ID)
	if got.Paused != PauseFlapping || f.n() != flapMax {
		t.Fatalf("paused %q after %d calls", got.Paused, f.n())
	}
	m.runUpdates(ctx) // pausiert -> nichts mehr
	if f.n() != flapMax {
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
