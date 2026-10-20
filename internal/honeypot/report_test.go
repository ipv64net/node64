package honeypot

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
)

var repNow = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// repWrite schreibt Ereignisse direkt (ohne Sink-Puffer, der bei grossen Mengen verwirft).
func repWrite(t *testing.T, s *Store, evs ...Event) {
	t.Helper()
	for i := 0; i < len(evs); i += flushBatch {
		j := min(i+flushBatch, len(evs))
		batch := make([]Event, 0, j-i)
		for _, e := range evs[i:j] {
			batch = append(batch, storeSanitize(e))
		}
		if err := s.write(context.Background(), batch); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReportable(t *testing.T) {
	for s, want := range map[string]bool{"45.83.64.1": true, "2a01:4f8::1": true, "::ffff:45.83.64.1": true, "8.8.8.8": true,
		"10.1.2.3": false, "172.16.5.4": false, "192.168.1.1": false, "100.64.0.1": false, "100.127.255.255": false, "127.0.0.1": false,
		"169.254.1.1": false, "fe80::1": false, "fd00::1": false, "::1": false, "::": false, "0.0.0.0": false, "192.0.2.7": false,
		"198.51.100.1": false, "203.0.113.9": false, "2001:db8::1": false, "224.0.0.1": false, "255.255.255.255": false, "198.18.0.1": false,
		"::ffff:192.168.1.1": false} {
		if got := reportable(ip(s)); got != want {
			t.Errorf("%s: %v, want %v", s, got, want)
		}
	}
}

func TestBuildReport(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	start, end := repNow.Add(-10*time.Minute), repNow
	at := func(d time.Duration) time.Time { return start.Add(d) }
	long := strings.Repeat("x", 300)
	repWrite(t, s,
		// A: SSH-Logins (3x, zwei Paare), dazu einmal mit langem Detail
		Event{Time: at(time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("45.83.64.1"), Username: "root", Password: "123456"},
		Event{Time: at(2 * time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("45.83.64.1"), Username: "root", Password: "123456", Detail: long},
		Event{Time: at(3 * time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("45.83.64.1"), Username: "admin", Password: "admin"},
		// B: HTTP mit Pfad, UA und Body
		Event{Time: at(4 * time.Minute), Service: SvcHTTP, Port: 80, Kind: KindHTTPScan, Src: ip("2a01:4f8::1"), Method: "GET", Path: "/.env", UA: "zgrab/0.x"},
		Event{Time: at(5 * time.Minute), Service: SvcHTTP, Port: 80, Kind: KindHTTPRCE, Src: ip("2a01:4f8::1"), Method: "POST", Path: "/cgi-bin/x", UA: "zgrab/0.x", Payload: []byte("cmd=id")},
		// C: TCP mit Payload und (unsinnigem) Benutzernamen: keine Zugangsdaten-Probe
		Event{Time: at(6 * time.Minute), Service: SvcTCP, Port: 3389, Kind: KindProbe, Src: ip("8.8.4.4"), Payload: []byte{0x03, 0x00, 0x00, 0x13}, Username: "mstshash"},
		// genau am Anfang: dabei
		Event{Time: start, Service: SvcTelnet, Port: 23, Kind: KindTelnetBrute, Src: ip("8.8.4.4"), Password: "xc3511"},
		// ausserhalb: vorher, genau am Ende
		Event{Time: start.Add(-time.Millisecond), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("9.9.9.9"), Username: "old", Password: "old"},
		Event{Time: end, Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("9.9.9.9"), Username: "late", Password: "late"},
		// private/reservierte Quellen: lokal, nicht gemeldet (auch keine Proben)
		Event{Time: at(time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("192.168.1.50"), Username: "localtest", Password: "secret"},
		Event{Time: at(time.Minute), Service: SvcHTTP, Port: 80, Kind: KindHTTPScan, Src: ip("100.64.1.1"), Path: "/internal-scan", UA: "nmap"},
		Event{Time: at(time.Minute), Service: SvcTCP, Port: 23, Kind: KindProbe, Src: ip("fd00::5"), Payload: []byte("local")},
		Event{Time: at(time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("192.0.2.9"), Username: "doc", Password: "doc"},
		// ohne Quelle: nicht gemeldet
		Event{Time: at(time.Minute), Service: SvcTCP, Port: 25, Kind: KindProbe, Path: "/nosrc"},
	)
	rep, err := s.BuildReport(ctx, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Schema != ReportSchema || !rep.Period.Start.Equal(start) || !rep.Period.End.Equal(end) || rep.Dropped != 0 {
		t.Fatalf("head: %+v", rep)
	}
	type key struct {
		ip, kind, svc string
		port          int
	}
	got := map[key]ReportSource{}
	for _, x := range rep.Sources {
		got[key{x.IP, x.Kind, x.Service, x.Port}] = x
	}
	if len(rep.Sources) != 5 {
		t.Fatalf("sources: %+v", rep.Sources)
	}
	a := got[key{"45.83.64.1", KindSSHBrute, SvcSSH, 22}]
	if a.Count != 3 || !a.First.Equal(at(time.Minute)) || !a.Last.Equal(at(3*time.Minute)) || a.Source != "honeypot" || a.Rule != "honeypot/ssh@1" ||
		len(a.Detail) != reportDetailMax {
		t.Fatalf("source A: %+v", a)
	}
	if rep.Sources[0].IP != "45.83.64.1" { // haeufigste zuerst
		t.Fatalf("order: %+v", rep.Sources[0])
	}
	if x := got[key{"2a01:4f8::1", KindHTTPRCE, SvcHTTP, 80}]; x.Count != 1 || x.Rule != "honeypot/http@1" {
		t.Fatalf("source B: %+v", x)
	}
	if x := got[key{"8.8.4.4", KindTelnetBrute, SvcTelnet, 23}]; x.Count != 1 || !x.First.Equal(start) {
		t.Fatalf("event at start missing: %+v", got)
	}
	for k := range got {
		if k.ip == "9.9.9.9" || !reportable(ip(k.ip)) {
			t.Fatalf("not reportable or outside the period: %v", k)
		}
	}
	// Proben
	c := rep.Samples.Credentials
	if len(c) != 3 || c[0] != (ReportCred{Service: SvcSSH, User: "root", Pass: "123456", Count: 2}) {
		t.Fatalf("credentials: %+v", c)
	}
	for _, x := range c {
		if x.Service == SvcTCP || x.User == "localtest" || x.User == "doc" || x.User == "old" || x.User == "late" {
			t.Fatalf("credential must not be reported: %+v", x)
		}
	}
	if p := rep.Samples.Paths; len(p) != 2 || p[0].Key != "/.env" && p[0].Key != "/cgi-bin/x" {
		t.Fatalf("paths: %+v", p)
	}
	if u := rep.Samples.UserAgents; len(u) != 1 || u[0] != (ReportKey{Key: "zgrab/0.x", Count: 2}) {
		t.Fatalf("user agents: %+v", u)
	}
	if len(rep.Samples.Payloads) != 2 {
		t.Fatalf("payloads: %+v", rep.Samples.Payloads)
	}
	for _, p := range rep.Samples.Payloads {
		raw, _ := base64.StdEncoding.DecodeString(p.Head)
		sum := sha256.Sum256(raw)
		if p.SHA256 != hex.EncodeToString(sum[:]) || p.Count != 1 || string(raw) == "local" {
			t.Fatalf("payload: %+v", p)
		}
		if p.Service == SvcTCP && (p.Port != 3389 || string(raw) != "\x03\x00\x00\x13") {
			t.Fatalf("tcp payload: %+v", p)
		}
	}

	// nur private Quellen bzw. nichts: leere Meldung (Lebenszeichen), Quellen als [] im JSON
	for _, from := range []time.Time{end.Add(time.Hour), start.Add(-time.Hour)} {
		rep, err = s.BuildReport(ctx, from, from.Add(10*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(rep)
		if len(rep.Sources) != 0 || !strings.Contains(string(raw), `"sources":[]`) || strings.Contains(string(raw), `"samples":{"`) {
			t.Fatalf("empty: %s", raw)
		}
	}
	repWrite(t, s, Event{Time: end.Add(time.Hour), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("10.0.0.1"), Username: "a", Password: "b"})
	if rep, err = s.BuildReport(ctx, end.Add(time.Hour), end.Add(2*time.Hour)); err != nil || len(rep.Sources) != 0 || len(rep.Samples.Credentials) != 0 {
		t.Fatalf("private only: %+v %v", rep, err)
	}
}

func TestBuildReportLimits(t *testing.T) {
	s := newTestStore(t)
	start := repNow.Add(-time.Hour)
	var evs []Event
	for i := 0; i < ReportMaxSources+3; i++ {
		e := Event{Time: start.Add(time.Second), Service: SvcHTTP, Port: 80, Kind: KindHTTPScan, Src: ip("11.0." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250+1))}
		if i < ReportMaxSamples+2 {
			e.Path = "/p" + strconv.Itoa(i)
		}
		evs = append(evs, e)
	}
	// ein Pfad haeufiger: steht zuerst
	evs = append(evs, Event{Time: start.Add(2 * time.Second), Service: SvcHTTP, Port: 80, Kind: KindHTTPScan, Src: ip("11.0.0.1"), Path: "/p499"})
	repWrite(t, s, evs...)
	rep, err := s.BuildReport(context.Background(), start, repNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Sources) != ReportMaxSources || len(rep.Samples.Paths) != ReportMaxSamples || rep.Dropped != 3+2 {
		t.Fatalf("limits: %d sources, %d paths, dropped %d", len(rep.Sources), len(rep.Samples.Paths), rep.Dropped)
	}
	if rep.Samples.Paths[0] != (ReportKey{Key: "/p499", Count: 2}) || rep.Sources[0].Count != 2 {
		t.Fatalf("most frequent first: %+v %+v", rep.Samples.Paths[0], rep.Sources[0])
	}
	// zu gross: halbiert, bis es passt
	big := &Report{Schema: 1, Sources: make([]ReportSource, 6000)}
	for i := range big.Sources {
		big.Sources[i] = ReportSource{IP: "11.0.0.1", Detail: strings.Repeat("y", reportDetailMax), Kind: KindHTTPScan}
	}
	for i := 0; i < ReportMaxSamples; i++ {
		big.Samples.Paths = append(big.Samples.Paths, ReportKey{Key: strings.Repeat("/z", MaxPath/2), Count: 1})
	}
	gz, err := encodeReport(big)
	if err != nil {
		t.Fatal(err)
	}
	zr, _ := gzip.NewReader(strings.NewReader(string(gz)))
	raw, _ := io.ReadAll(zr)
	if len(raw) > reportMaxBody || big.Dropped == 0 || len(big.Sources) == 6000 {
		t.Fatalf("not shrunk: %d bytes, dropped %d", len(raw), big.Dropped)
	}
}

// repServer ist ein Ersatz fuer ipv64: nimmt Meldungen an und antwortet mit den Codes aus answers (leer = 202).
type repServer struct {
	mu      sync.Mutex
	srv     *httptest.Server
	answers []int
	retry   string
	got     []Report
	auth    []string
	enc     []string
}

func newRepServer(t *testing.T) *repServer {
	rs := &repServer{}
	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/honeypot/reports" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("not gzip: %v", err)
			w.WriteHeader(400)
			return
		}
		var rep Report
		if err := json.NewDecoder(zr).Decode(&rep); err != nil {
			t.Errorf("json: %v", err)
		}
		rs.mu.Lock()
		rs.got = append(rs.got, rep)
		rs.auth = append(rs.auth, r.Header.Get("Authorization"))
		rs.enc = append(rs.enc, r.Header.Get("Content-Encoding"))
		code := http.StatusAccepted
		if len(rs.answers) > 0 {
			code, rs.answers = rs.answers[0], rs.answers[1:]
		}
		retry := rs.retry
		rs.mu.Unlock()
		if retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		w.WriteHeader(code)
		switch code {
		case http.StatusAccepted:
			_, _ = io.WriteString(w, `{"data":{"accepted":`+strconv.Itoa(len(rep.Sources))+`,"rejected":1,"rejected_reasons":{"not_public":1},"report_id":"`+rep.ReportID+`"}}`)
		case http.StatusOK:
			_, _ = io.WriteString(w, `{"data":{"duplicate":true,"report_id":"`+rep.ReportID+`"}}`)
		default:
			_, _ = io.WriteString(w, `{"error":"code `+strconv.Itoa(code)+`"}`)
		}
	}))
	t.Cleanup(rs.srv.Close)
	return rs
}

func (rs *repServer) reports() []Report {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return append([]Report(nil), rs.got...)
}

const repKey = "Key0123456789abcdefXYZ"

type repFixture struct {
	s       *Store
	r       *Reporter
	srv     *repServer
	state   ReportStateStore
	now     time.Time
	enabled bool
	key     string
}

func newRepFixture(t *testing.T) *repFixture {
	t.Helper()
	f := &repFixture{s: newTestStore(t), srv: newRepServer(t), state: FileReportState(t.TempDir()), now: repNow, enabled: true, key: repKey}
	client := ipv64api.NewClient(f.srv.srv.URL+"/api/v2", "node64/test")
	f.r = NewReporter(ReporterConfig{Store: f.s, State: f.state, Mode: "headless", Version: "0.11.200", Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		API:      func(context.Context) (*ipv64api.Client, string) { return client, f.key },
		Enabled:  func(context.Context) bool { return f.enabled },
		Profile:  func(context.Context) string { return "standard" },
		SensorID: func(context.Context) (string, error) { return "0b9e7c1a-1111-4222-8333-444455556666", nil }})
	f.r.now = func() time.Time { return f.now }
	return f
}

func (f *repFixture) lastEnd(t *testing.T) time.Time {
	t.Helper()
	st, err := f.state.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return st.LastEnd
}

func (f *repFixture) setLastEnd(t *testing.T, at time.Time) {
	t.Helper()
	if err := f.state.Save(context.Background(), ReportState{LastEnd: at}); err != nil {
		t.Fatal(err)
	}
}

func TestReporterSend(t *testing.T) {
	f := newRepFixture(t)
	ctx := context.Background()
	start := repNow.Add(-10 * time.Minute)
	f.setLastEnd(t, start)
	repWrite(t, f.s,
		Event{Time: start.Add(time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("45.83.64.1"), Username: "root", Password: "x"},
		Event{Time: start.Add(2 * time.Minute), Service: SvcHTTP, Port: 80, Kind: KindHTTPScan, Src: ip("45.83.64.2"), Path: "/.env"},
		Event{Time: start.Add(2 * time.Minute), Service: SvcHTTP, Port: 80, Kind: KindHTTPScan, Src: ip("192.168.1.2"), Path: "/lan"})

	// 202: angenommen, last_end rueckt vor
	d := f.r.RunOnce(ctx)
	if d < ReportEvery-reportJitter || d > ReportEvery+reportJitter {
		t.Fatalf("delay %v", d)
	}
	reps := f.srv.reports()
	if len(reps) != 1 {
		t.Fatalf("reports: %d", len(reps))
	}
	rep := reps[0]
	end := repNow.Add(-reportGrace).Truncate(time.Second)
	if rep.Schema != 1 || rep.ReportID != "0b9e7c1a-1111-4222-8333-444455556666-"+strconv.FormatInt(start.Unix(), 10) ||
		rep.Sensor != (ReportSensor{ID: "0b9e7c1a-1111-4222-8333-444455556666", Version: "0.11.200", Profile: "standard", Mode: "headless"}) ||
		!rep.Period.Start.Equal(start) || !rep.Period.End.Equal(end) || len(rep.Sources) != 2 {
		t.Fatalf("report: %+v", rep)
	}
	if f.srv.auth[0] != "Bearer "+repKey || f.srv.enc[0] != "gzip" {
		t.Fatalf("headers: %q %q", f.srv.auth[0], f.srv.enc[0])
	}
	if !f.lastEnd(t).Equal(end) {
		t.Fatalf("last_end %v, want %v", f.lastEnd(t), end)
	}
	st := f.r.Status(ctx)
	if !st.Active || st.SourcesToday != 2 || st.SourcesTotal != 2 || st.Errors != 0 || !st.LastSuccess.Equal(repNow) || st.SensorID == "" ||
		st.LastRejected != 1 || st.RejectedText() != "not_public 1" {
		t.Fatalf("status: %+v", st)
	}

	// leerer Zeitraum: Lebenszeichen ohne Quellen
	f.now = f.now.Add(10 * time.Minute)
	f.r.RunOnce(ctx)
	if reps = f.srv.reports(); len(reps) != 2 || len(reps[1].Sources) != 0 || !reps[1].Period.Start.Equal(end) {
		t.Fatalf("heartbeat: %+v", reps)
	}

	// 200 (schon bekannt) zaehlt als Erfolg
	f.srv.answers = []int{http.StatusOK}
	f.now = f.now.Add(10 * time.Minute)
	f.r.RunOnce(ctx)
	if want := f.now.Add(-reportGrace).Truncate(time.Second); !f.lastEnd(t).Equal(want) || f.r.Status(ctx).Errors != 0 {
		t.Fatalf("duplicate: last_end %v want %v", f.lastEnd(t), want)
	}

	// 422: verwerfen, vorruecken, Fehler zaehlen
	f.srv.answers = []int{http.StatusUnprocessableEntity}
	f.now = f.now.Add(10 * time.Minute)
	if d := f.r.RunOnce(ctx); d < ReportEvery-reportJitter {
		t.Fatalf("422 delay %v", d)
	}
	st = f.r.Status(ctx)
	if want := f.now.Add(-reportGrace).Truncate(time.Second); !f.lastEnd(t).Equal(want) || st.Errors != 1 || !strings.Contains(st.LastError, "422") {
		t.Fatalf("422: last_end %v, status %+v", f.lastEnd(t), st)
	}
}

func TestReporterRetry(t *testing.T) {
	f := newRepFixture(t)
	ctx := context.Background()
	start := repNow.Add(-10 * time.Minute)
	f.setLastEnd(t, start)
	repWrite(t, f.s, Event{Time: start.Add(time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("45.83.64.1")})

	// 429 mit Retry-After: nicht vorruecken, so lange warten
	f.srv.answers, f.srv.retry = []int{http.StatusTooManyRequests}, "300"
	if d := f.r.RunOnce(ctx); d != 300*time.Second {
		t.Fatalf("429 delay %v", d)
	}
	if !f.lastEnd(t).Equal(start) || f.r.Status(ctx).Errors != 1 {
		t.Fatal("429 must not advance")
	}
	// 500: Backoff verdoppelt sich (1 min, 2 min …), Retry-After weg
	f.srv.retry = ""
	f.srv.answers = []int{http.StatusInternalServerError}
	f.now = f.now.Add(5 * time.Minute)
	if d := f.r.RunOnce(ctx); d != 2*reportBackoff {
		t.Fatalf("500 delay %v", d)
	}
	f.srv.answers = []int{http.StatusBadGateway}
	f.now = f.now.Add(2 * time.Minute)
	if d := f.r.RunOnce(ctx); d != 4*reportBackoff || !f.lastEnd(t).Equal(start) {
		t.Fatalf("502 delay %v", d)
	}
	// Wiederholung: genau derselbe Zeitraum (gleiche report_id, gleiches Ende), der Rest nach der Sperrzeit von ipv64
	f.now = f.now.Add(4 * time.Minute)
	if d := f.r.RunOnce(ctx); d != reportMinGap {
		t.Fatalf("rest delay %v", d)
	}
	f.r.RunOnce(ctx)
	reps := f.srv.reports()
	if len(reps) != 5 {
		t.Fatalf("reports: %d", len(reps))
	}
	first, retry, rest := reps[0], reps[3], reps[4]
	if retry.ReportID != first.ReportID || !retry.Period.End.Equal(first.Period.End) || !rest.Period.Start.Equal(first.Period.End) {
		t.Fatalf("retry: %+v / %+v / %+v", first.Period, retry.Period, rest.Period)
	}
	if want := f.now.Add(-reportGrace).Truncate(time.Second); !f.lastEnd(t).Equal(want) {
		t.Fatalf("last_end %v want %v", f.lastEnd(t), want)
	}
	// 401: frühestens im Takt
	f.srv.answers = []int{http.StatusUnauthorized}
	f.now = f.now.Add(10 * time.Minute)
	if d := f.r.RunOnce(ctx); d < ReportEvery {
		t.Fatalf("401 delay %v", d)
	}
}

func TestReporterChunksAndLimits(t *testing.T) {
	f := newRepFixture(t)
	ctx := context.Background()
	// 3,5 Stunden mit Ereignissen: Stuecke zu je 1 Stunde, lueckenlos; je Durchlauf eine angenommene Meldung
	// (Rate-Limit bei ipv64), schon bekannte (200) zaehlen nicht und es geht gleich weiter
	start := repNow.Add(-3*time.Hour - 30*time.Minute)
	f.setLastEnd(t, start)
	repWrite(t, f.s, Event{Time: start.Add(190 * time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("45.83.64.1")})
	f.srv.answers = []int{http.StatusOK}
	if d := f.r.RunOnce(ctx); d != reportMinGap || len(f.srv.reports()) != 2 {
		t.Fatalf("first run: %v %d", d, len(f.srv.reports()))
	}
	for f.r.RunOnce(ctx) == reportMinGap {
	}
	reps := f.srv.reports()
	if len(reps) != 4 {
		t.Fatalf("chunks: %d", len(reps))
	}
	prev := start
	for i, r := range reps {
		if !r.Period.Start.Equal(prev) || r.Period.End.Sub(r.Period.Start) > reportChunk || r.ReportID != "0b9e7c1a-1111-4222-8333-444455556666-"+strconv.FormatInt(prev.Unix(), 10) {
			t.Fatalf("chunk %d: %+v %s", i, r.Period, r.ReportID)
		}
		prev = r.Period.End
	}
	end := repNow.Add(-reportGrace).Truncate(time.Second)
	if len(reps[3].Sources) != 1 || len(reps[0].Sources) != 0 || !f.lastEnd(t).Equal(end) {
		t.Fatal("event in the wrong chunk")
	}
	// mehr als 7 Tage: nur die letzten 7 Tage; ohne Ereignisse ein einziges Lebenszeichen
	f2 := newRepFixture(t)
	f2.setLastEnd(t, repNow.Add(-10*24*time.Hour))
	f2.r.RunOnce(ctx)
	reps = f2.srv.reports()
	if len(reps) != 1 || !reps[0].Period.Start.Equal(end.Add(-ReportMaxBack)) || !reps[0].Period.End.Equal(end) {
		t.Fatalf("backlog: %+v", reps)
	}
	// mehr als ein Tag nachzuholen: zuerst Stuecke zu 6 Stunden, dann zu 1 Stunde
	f3 := newRepFixture(t)
	f3.setLastEnd(t, repNow.Add(-30*time.Hour))
	repWrite(t, f3.s, Event{Time: repNow.Add(-time.Hour), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("45.83.64.1")})
	for i := 0; f3.r.RunOnce(ctx) == reportMinGap; i++ {
		if i > 100 {
			t.Fatal("no end")
		}
	}
	reps = f3.srv.reports()
	if len(reps) != 25 || reps[0].Period.End.Sub(reps[0].Period.Start) != reportChunkBig || reps[1].Period.End.Sub(reps[1].Period.Start) != reportChunk ||
		!f3.lastEnd(t).Equal(end) {
		t.Fatalf("catch up: %d reports, last_end %v", len(reps), f3.lastEnd(t))
	}
}

func TestReporterOptIn(t *testing.T) {
	f := newRepFixture(t)
	ctx := context.Background()
	f.setLastEnd(t, repNow.Add(-10*time.Minute))
	repWrite(t, f.s, Event{Time: repNow.Add(-time.Minute), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: ip("45.83.64.1")})
	// aus: nichts
	f.enabled = false
	f.r.RunOnce(ctx)
	if st := f.r.Status(ctx); len(f.srv.reports()) != 0 || st.Active || !st.NextAttempt.IsZero() {
		t.Fatalf("opt-in off: %d %+v", len(f.srv.reports()), st)
	}
	// an, aber kein Key: nichts
	f.enabled, f.key = true, ""
	f.r.RunOnce(ctx)
	if st := f.r.Status(ctx); len(f.srv.reports()) != 0 || st.KeySet || st.Active {
		t.Fatalf("no key: %+v", st)
	}
	// Einschalten: Zeitraum beginnt jetzt (nichts von vorher)
	f.key = repKey
	if err := f.r.ResetWindow(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.lastEnd(t).Equal(repNow) {
		t.Fatalf("reset: %v", f.lastEnd(t))
	}
	// erster Durchlauf ohne Stand: nur Startpunkt setzen
	f2 := newRepFixture(t)
	f2.r.RunOnce(ctx)
	if len(f2.srv.reports()) != 0 || !f2.lastEnd(t).Equal(repNow.Add(-reportGrace).Truncate(time.Second)) {
		t.Fatalf("first run: %d %v", len(f2.srv.reports()), f2.lastEnd(t))
	}
}

func TestReporterRunStops(t *testing.T) {
	f := newRepFixture(t)
	f.r.first = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.r.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestSensorIDAndState(t *testing.T) {
	dir := t.TempDir()
	a, err := SensorIDFromFile(dir)
	if err != nil || !validSensorID(a) || len(a) != 36 || a[14] != '4' {
		t.Fatalf("id %q %v", a, err)
	}
	if b, _ := SensorIDFromFile(dir); b != a {
		t.Fatal("sensor id must stay the same")
	}
	core, _ := modCore(t)
	ctx := context.Background()
	x, err := SensorIDFromSettings(ctx, core)
	if y, _ := SensorIDFromSettings(ctx, core); err != nil || x != y || x == a {
		t.Fatalf("settings id %q %q %v", x, y, err)
	}
	for _, ss := range []ReportStateStore{FileReportState(dir), SettingsReportState(core)} {
		want := ReportState{LastEnd: repNow, LastSuccess: repNow.Add(time.Second)}
		if err := ss.Save(ctx, want); err != nil {
			t.Fatal(err)
		}
		if got, err := ss.Load(ctx); err != nil || !got.LastEnd.Equal(want.LastEnd) || !got.LastSuccess.Equal(want.LastSuccess) {
			t.Fatalf("state %+v %v", got, err)
		}
	}
}

func TestModuleReportOptIn(t *testing.T) {
	m, _ := modTest(t, modFreePort(t))
	ctx := context.Background()
	c := m.loadConfig(ctx)
	if c.Report {
		t.Fatal("report must be off by default")
	}
	// ohne Key: Einschalten abgelehnt
	c.Report = true
	_, err := m.SaveConfig(ctx, c)
	var fe FieldErrors
	if !errors.As(err, &fe) || fe["report"] != "honeypot.err.report_key" {
		t.Fatalf("without key: %v", err)
	}
	if st := m.rep.Status(ctx); st.Enabled || st.KeySet {
		t.Fatalf("status: %+v", st)
	}
	// mit Key: an, Zeitraum beginnt jetzt
	if err := m.core.SetSetting(ctx, ipv64api.SetKey, repKey); err != nil {
		t.Fatal(err)
	}
	m.SetKey(ipv64api.NewKey(m.core, nil, ipv64api.NewClient("http://127.0.0.1:1/api/v2", "test"), m.log))
	before := time.Now().Add(-time.Second)
	if _, err := m.SaveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	st, _ := SettingsReportState(m.core).Load(ctx)
	if st.LastEnd.Before(before) {
		t.Fatalf("window not reset: %v", st.LastEnd)
	}
	rs := m.rep.Status(ctx)
	if !rs.Active || rs.SensorID == "" {
		t.Fatalf("status: %+v", rs)
	}
	if id, _ := SensorIDFromSettings(ctx, m.core); id != rs.SensorID {
		t.Fatal("sensor id differs")
	}
	// Export/Import behaelt den Schalter (Key vorhanden)
	raw, _ := json.Marshal(m.loadConfig(ctx))
	if !strings.Contains(string(raw), `"report":true`) {
		t.Fatalf("export: %s", raw)
	}
}
