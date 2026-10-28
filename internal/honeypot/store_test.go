package honeypot

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	cm, _ := store.CoreMigrations()
	if err := core.Migrate(context.Background(), "core", cm); err != nil {
		t.Fatal(err)
	}
	if err := core.Migrate(context.Background(), Name, Migrations()); err != nil {
		t.Fatal(err)
	}
	return NewStore(core, log)
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestStoreStats(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sink := s.Sink()
	now := time.Now()
	for i := 0; i < 3; i++ {
		sink(Event{Time: now.Add(-time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("192.0.2.1"), Username: "root", Password: "123456", Client: "SSH-2.0-Go"})
	}
	sink(Event{Time: now.Add(-2 * time.Hour), Service: SvcSSH, Port: 2222, Kind: KindSSHBrute, Src: ip("::ffff:192.0.2.2"), Username: "admin", Password: "admin"})
	sink(Event{Service: SvcHTTP, Port: 80, Kind: KindHTTPScan, Src: ip("2001:db8::1"), Method: "GET", Path: "/.env", UA: "curl/8"})
	sink(Event{Service: SvcTCP, Port: 3389, Kind: KindProbe, Src: ip("192.0.2.1"), Payload: []byte{1, 2, 3}})
	sink(Event{Time: now.Add(-30 * 24 * time.Hour), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("198.51.100.9"), Username: "old"}) // ausserhalb der Aufbewahrung
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if s.Buffered() != 0 {
		t.Fatalf("buffered %d", s.Buffered())
	}

	st, err := s.Stats(ctx, now.Add(-24*time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if st.Events != 6 || st.Sources != 3 || st.Logins != 4 {
		t.Fatalf("events=%d sources=%d logins=%d", st.Events, st.Sources, st.Logins)
	}
	if len(st.ByService) != 3 || st.ByService[0].Key != SvcSSH || st.ByService[0].Count != 4 {
		t.Fatalf("by service %+v", st.ByService)
	}
	if len(st.ByPort) != 4 || st.ByPort[0].Key != "22" || st.ByPort[0].Count != 3 {
		t.Fatalf("by port %+v", st.ByPort)
	}
	if st.TopSources[0].Key != "192.0.2.1" || st.TopSources[0].Count != 4 || st.TopSources[0].Last.IsZero() {
		t.Fatalf("top sources %+v", st.TopSources)
	}
	found := false
	for _, c := range st.TopSources {
		if c.Key == "192.0.2.2" { // IPv4-mapped wird als IPv4 gespeichert
			found = true
		}
	}
	if !found {
		t.Fatalf("mapped address missing %+v", st.TopSources)
	}
	if st.TopCreds[0].Key != "root:123456" || st.TopCreds[0].Count != 3 || len(st.TopCreds) != 2 {
		t.Fatalf("top creds %+v", st.TopCreds)
	}
	if st.TopUsers[0].Key != "root" || st.TopPass[0].Key != "123456" {
		t.Fatalf("users %+v pass %+v", st.TopUsers, st.TopPass)
	}
	if len(st.TopPaths) != 1 || st.TopPaths[0].Key != "/.env" || len(st.TopUAs) != 1 || st.TopUAs[0].Key != "curl/8" {
		t.Fatalf("paths %+v uas %+v", st.TopPaths, st.TopUAs)
	}
	// Verlauf je Stunde, luckenlos
	if n := len(st.Timeline); n < 24 || n > 26 {
		t.Fatalf("timeline len %d", n)
	}
	var sum int64
	for i, p := range st.Timeline {
		sum += p.Events
		if i > 0 && p.Time.Sub(st.Timeline[i-1].Time) != time.Hour {
			t.Fatalf("timeline step at %d", i)
		}
	}
	if sum != 6 {
		t.Fatalf("timeline sum %d", sum)
	}

	// Ranglisten-Grenze
	st, err = s.Stats(ctx, now.Add(-24*time.Hour), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.TopSources) != 1 || len(st.ByService) != 3 {
		t.Fatalf("limit: sources %d services %d", len(st.TopSources), len(st.ByService))
	}

	// 7 Tage: je Tag, alte Ereignisse (30 Tage) fallen durch die Aufbewahrung heraus
	st, err = s.Stats(ctx, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if st.Events != 6 {
		t.Fatalf("7d events %d", st.Events)
	}
	if n := len(st.Timeline); n < 7 || n > 8 {
		t.Fatalf("daily timeline len %d", n)
	}
	if d := st.Timeline[1].Time.Sub(st.Timeline[0].Time); d != 24*time.Hour {
		t.Fatalf("daily step %v", d)
	}
}

func TestStoreSanitizeAndRecent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	payload := make([]byte, 1000)
	for i := range payload {
		payload[i] = byte(i)
	}
	long := strings.Repeat("ä", MaxText) // 2 Bytes je Zeichen
	s.Sink()(Event{Service: SvcHTTP, Port: 8080, Kind: KindHTTPBrute, Src: ip("fe80::1%eth0"), SrcPort: 4711,
		Username: long, Password: "pw\xff", Path: strings.Repeat("/a", MaxPath), Page: "wp-login", Payload: payload, Detail: "x"})
	payload[0] = 99 // Sensor verwendet seinen Puffer weiter
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	evs, err := s.Recent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("recent %d", len(evs))
	}
	e := evs[0]
	if len(e.Username) > MaxText || !strings.HasPrefix(long, e.Username) || len(e.Username) != MaxText {
		t.Fatalf("username len %d", len(e.Username))
	}
	if e.Password != "pw�" {
		t.Fatalf("password %q", e.Password)
	}
	if len(e.Path) != MaxPath || len(e.Payload) != MaxPayload || e.Payload[0] != 0 || e.Payload[255] != 255 {
		t.Fatalf("path %d payload %d first %d", len(e.Path), len(e.Payload), e.Payload[0])
	}
	if e.Src != ip("fe80::1") || e.SrcPort != 4711 || e.Port != 8080 || e.Page != "wp-login" || e.Time.IsZero() {
		t.Fatalf("event %+v", e)
	}
}

func TestStoreDropped(t *testing.T) {
	s := newTestStore(t)
	sink := s.Sink()
	for i := 0; i < sinkBuffer+5; i++ {
		sink(Event{Service: SvcTCP, Port: 21, Kind: KindProbe, Src: ip("192.0.2.1")})
	}
	if s.Dropped() != 5 {
		t.Fatalf("dropped %d", s.Dropped())
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, err := s.Stats(context.Background(), time.Now().Add(-time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if st.Events != sinkBuffer {
		t.Fatalf("events %d", st.Events)
	}
}

func TestStorePurge(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sink := s.Sink()
	now := time.Now()
	sink(Event{Time: now.Add(-8 * 24 * time.Hour), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("192.0.2.1")})
	for i := 0; i < 10; i++ {
		sink(Event{Time: now.Add(time.Duration(i-10) * time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("192.0.2.2"), Detail: string(rune('a' + i))})
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	n, err := s.Purge(ctx)
	if err != nil || n != 1 {
		t.Fatalf("purge retention n=%d err=%v", n, err)
	}
	s.SetLimits(0, 4)
	n, err = s.Purge(ctx)
	if err != nil || n != 6 {
		t.Fatalf("purge max rows n=%d err=%v", n, err)
	}
	evs, err := s.Recent(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 4 || evs[0].Detail != "j" || evs[3].Detail != "g" {
		t.Fatalf("kept %+v", evs)
	}
}

// Die Obergrenze loescht einzelne Ereignisse, die Zahlen (Zaehler je Minute, Quell-IPs) bleiben vollstaendig;
// Capped meldet das aelteste noch gespeicherte Ereignis (Issue #7: Zahlen sanken nach dem Aufraeumen).
func TestStoreTotalsSurviveCap(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sink := s.Sink()
	now := time.Now()
	for i := 0; i < 10; i++ {
		sink(Event{Time: now.Add(time.Duration(i-30) * time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("192.0.2." + strconv.Itoa(i+1))})
	}
	sink(Event{Time: now.Add(-3 * time.Hour), Service: SvcHTTP, Port: 80, Kind: KindHTTPScan, Src: ip("192.0.2.1")})
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, capped, err := s.Capped(ctx, now.Add(-24*time.Hour)); err != nil || capped {
		t.Fatalf("not capped yet: %v %v", capped, err)
	}
	s.SetLimits(0, 4)
	if n, err := s.Purge(ctx); err != nil || n != 7 {
		t.Fatalf("purge n=%d err=%v", n, err)
	}
	ev, src, logins, err := s.Totals(ctx, now.Add(-24*time.Hour))
	if err != nil || ev != 11 || src != 10 || logins != 10 {
		t.Fatalf("totals after cap: events=%d sources=%d logins=%d err=%v", ev, src, logins, err)
	}
	if ev, src, _, _ = s.Totals(ctx, now.Add(-time.Hour)); ev != 10 || src != 10 {
		t.Fatalf("totals 1h: events=%d sources=%d", ev, src)
	}
	if n, _ := s.CountBetween(ctx, now.Add(-4*time.Hour), now.Add(-2*time.Hour)); n != 1 {
		t.Fatalf("count between: %d", n)
	}
	st, err := s.Stats(ctx, now.Add(-24*time.Hour), 10)
	if err != nil || st.Events != 11 {
		t.Fatalf("stats events %+v %v", st, err)
	}
	var sum int64
	for _, p := range st.Timeline {
		sum += p.Events
	}
	if sum != 11 {
		t.Fatalf("timeline sum %d", sum)
	}
	oldest, capped, err := s.Capped(ctx, now.Add(-24*time.Hour))
	if err != nil || !capped || !oldest.After(now.Add(-25*time.Minute)) {
		t.Fatalf("capped %v %v %v", oldest, capped, err)
	}
}

func TestStoreRunWritesRest(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	sink := s.Sink()
	for i := 0; i < 1200; i++ { // mehr als ein Stapel: Run schreibt sofort
		sink(Event{Service: SvcTelnet, Port: 23, Kind: KindTelnetBrute, Src: ip("192.0.2.3"), Username: "u", Password: "p"})
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.Buffered() > flushBatch && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	sink(Event{Service: SvcTelnet, Port: 23, Kind: KindTelnetBrute, Src: ip("192.0.2.4")})
	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not end")
	}
	st, err := s.Stats(context.Background(), time.Now().Add(-time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if st.Events != 1201 || st.Logins != 1201 || st.Sources != 2 {
		t.Fatalf("events=%d logins=%d sources=%d", st.Events, st.Logins, st.Sources)
	}
}

func TestStoreNewSources(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sink := s.Sink()
	now := time.Now()
	sink(Event{Time: now.Add(-3 * time.Hour), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("192.0.2.1")})
	sink(Event{Time: now.Add(-10 * time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("192.0.2.1")})
	sink(Event{Time: now.Add(-5 * time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("192.0.2.9")})
	sink(Event{Time: now.Add(-4 * time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("192.0.2.9")})
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	cs, err := s.NewSources(ctx, now.Add(-time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cs[0].Key != "192.0.2.9" || cs[0].Count != 2 {
		t.Fatalf("new sources %+v", cs)
	}
}

// TestStoreSourceRule: Quelle und Regel werden gespeichert (leer = honeypot); Ereignisse aus echten Logs behalten
// keine Inhalte, auch wenn eine Regel sie faelschlich setzt (H5).
func TestStoreSourceRule(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sink := s.Sink()
	now := time.Now()
	sink(Event{Time: now, Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("192.0.2.1"), Username: "root", Password: "toor"})
	sink(Event{Time: now, Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("192.0.2.2"), Source: SrcLog, Rule: "sshd/bruteforce@1",
		Username: "alice", Password: "geheim", Method: "GET", Path: "/intern", Host: "h", UA: "ua", Client: "c", Page: "p", Payload: []byte("x"), Detail: "sshd/bruteforce"})
	sink(Event{Time: now, Service: SvcVPN, Port: 1194, Kind: KindVPNBrute, Src: ip("192.0.2.3"), Source: SrcSyslog, Rule: "opnsense/openvpn@1", Username: "bob"})
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	all, err := s.Recent(ctx, 10)
	if err != nil || len(all) != 3 {
		t.Fatalf("recent: %v %d", err, len(all))
	}
	bySrc := map[string]Event{}
	for _, e := range all {
		bySrc[e.Src.String()] = e
	}
	if e := bySrc["192.0.2.1"]; e.Source != SrcHoneypot || e.Rule != "" || e.Username != "root" || e.Password != "toor" {
		t.Fatalf("honeypot event: %+v", e)
	}
	e := bySrc["192.0.2.2"]
	if e.Source != SrcLog || e.Rule != "sshd/bruteforce@1" || e.Detail != "sshd/bruteforce" {
		t.Fatalf("log event: %+v", e)
	}
	if e.Username != "" || e.Password != "" || e.Method != "" || e.Path != "" || e.Host != "" || e.UA != "" || e.Client != "" || e.Page != "" || len(e.Payload) != 0 {
		t.Fatalf("log event must not keep contents: %+v", e)
	}
	if e := bySrc["192.0.2.3"]; e.Source != SrcSyslog || e.Username != "" {
		t.Fatalf("syslog event: %+v", e)
	}
	// Filter nach Quelle
	for src, n := range map[string]int{SrcHoneypot: 1, SrcLog: 1, SrcSyslog: 1, "": 3, "other": 0} {
		list, err := s.RecentBy(ctx, 10, src)
		if err != nil || len(list) != n {
			t.Errorf("RecentBy(%q): %v %d", src, err, len(list))
		}
	}
	st, err := s.Stats(ctx, time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, c := range st.BySource {
		got[c.Key] = c.Count
	}
	if len(got) != 3 || got[SrcHoneypot] != 1 || got[SrcLog] != 1 || got[SrcSyslog] != 1 {
		t.Fatalf("by_source: %+v", st.BySource)
	}
	// Zugangsdaten nur aus dem Honeypot in der Statistik
	if len(st.TopUsers) != 1 || st.TopUsers[0].Key != "root" {
		t.Fatalf("top users: %+v", st.TopUsers)
	}
}
