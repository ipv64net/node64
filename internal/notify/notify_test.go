package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(context.Background(), filepath.Join(dir, "a.db"), filepath.Join(dir, "b"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	ms, _ := Migrations()
	if err := core.Migrate(context.Background(), "notify", ms); err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.Load(filepath.Join(dir, "secret.key"))
	return NewStore(core, box)
}

func TestChannelStoreEncryptsSecrets(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	c := &Channel{Type: TypeTelegram, Name: "tg", Config: map[string]string{"bot_token": "123:ABC", "chat_id": "42"}, Enabled: true, Default: true, NotifyDown: true, NotifyUp: true}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := st.Insert(ctx, c); err != nil {
		t.Fatal(err)
	}
	var raw string
	st.r.QueryRow(`SELECT config FROM nf_channels WHERE id = ?`, c.ID).Scan(&raw)
	if strings.Contains(raw, "123:ABC") || !strings.Contains(raw, "enc:v1:") {
		t.Fatalf("token stored in plaintext: %s", raw)
	}
	got, err := st.Channel(ctx, c.ID)
	if err != nil || got.Config["bot_token"] != "123:ABC" || got.Config["chat_id"] != "42" || !got.Default {
		t.Fatalf("read back: %+v %v", got, err)
	}
	if m := got.Masked(); m["bot_token"] == "123:ABC" || m["chat_id"] != "42" {
		t.Fatalf("masked: %v", m)
	}
	bad := &Channel{Type: TypeSMTP, Name: "m", Config: map[string]string{"host": "mail", "from": "a@b", "to": "nope"}}
	if err := bad.Validate(); err == nil {
		t.Fatal("invalid recipient must fail")
	}
	bad = &Channel{Type: TypeGotify, Name: "g", Config: map[string]string{"server": "gotify.local", "app_token": "x"}}
	if err := bad.Validate(); err == nil {
		t.Fatal("url without scheme must fail")
	}
}

func TestSendersHTTP(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got[r.URL.Path] = r.Method + "|" + r.Header.Get("Title") + "|" + r.Header.Get("Authorization") + "|" + r.Header.Get("X-Gotify-Key") + "|" + r.Header.Get("X-Custom") + "|" + string(b)
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/fail") {
			w.WriteHeader(500)
			w.Write([]byte("boom"))
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	ctx := context.Background()
	s := Senders("test")
	m := Message{Kind: KindDown, Title: "T", Text: "body", Time: time.Now(), URL: "http://a/x", Check: CheckInfo{Name: "N", Token: "tok"}, Payload: map[string]any{"status": "down", "reason": "timeout", "message": "msg"}}

	if err := s[TypeDiscord].Send(ctx, &Channel{Type: TypeDiscord, Config: map[string]string{"webhook_url": srv.URL + "/discord", "username": "bot"}}, m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got["/discord"], `"embeds"`) || !strings.Contains(got["/discord"], `"username":"bot"`) {
		t.Fatalf("discord: %s", got["/discord"])
	}
	if err := s[TypeNtfy].Send(ctx, &Channel{Type: TypeNtfy, Config: map[string]string{"server": srv.URL, "topic": "t1", "token": "tk", "priority_down": "5"}}, m); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got["/t1"], "POST|T|Bearer tk|") || !strings.HasSuffix(got["/t1"], "|body") {
		t.Fatalf("ntfy: %s", got["/t1"])
	}
	if err := s[TypeGotify].Send(ctx, &Channel{Type: TypeGotify, Config: map[string]string{"server": srv.URL, "app_token": "gk", "priority": "7"}}, m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got["/message"], "|gk|") || !strings.Contains(got["/message"], `"priority":7`) {
		t.Fatalf("gotify: %s", got["/message"])
	}
	wh := &Channel{Type: TypeWebhook, Config: map[string]string{"url": srv.URL + "/hook", "method": "POST", "headers": "X-Custom: yes\nAuthorization: Bearer abc"}}
	if err := s[TypeWebhook].Send(ctx, wh, m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got["/hook"], "|Bearer abc||yes|") || !strings.Contains(got["/hook"], `"status":"down"`) {
		t.Fatalf("webhook: %s", got["/hook"])
	}
	wh.Config["body"] = `{"text":"{{name}} is {{status}}: {{reason}}"}`
	wh.Config["url"] = srv.URL + "/tpl"
	if err := s[TypeWebhook].Send(ctx, wh, m); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got["/tpl"], `{"text":"N is down: timeout"}`) {
		t.Fatalf("template: %s", got["/tpl"])
	}
	wh.Config["url"] = srv.URL + "/fail"
	if err := s[TypeWebhook].Send(ctx, wh, m); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected HTTP 500 error, got %v", err)
	}
}

// fakeSMTP ist ein minimaler SMTP-Server ohne TLS fuer den Test.
func fakeSMTP(t *testing.T) (string, *strings.Builder) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var data strings.Builder
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		w := bufio.NewWriter(c)
		r := bufio.NewReader(c)
		say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }
		say("220 fake ESMTP")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					say("250 ok")
					continue
				}
				data.WriteString(line + "\n")
				continue
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				say("250-fake")
				say("250 OK")
			case strings.HasPrefix(line, "DATA"):
				inData = true
				say("354 go")
			case strings.HasPrefix(line, "QUIT"):
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().String(), &data
}

func TestSMTP(t *testing.T) {
	addr, data := fakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	ch := &Channel{Type: TypeSMTP, Config: map[string]string{"host": host, "port": port, "security": "none", "from": "node@example.com", "to": "a@example.com, b@example.com"}}
	m := Message{Kind: KindDown, Title: "Störung: Test", Text: "Zeile 1\nZeile 2", Time: time.Now(), URL: "http://node/x", EventID: "e1"}
	if err := Senders("test")[TypeSMTP].Send(context.Background(), ch, m); err != nil {
		t.Fatal(err)
	}
	got := data.String()
	if !strings.Contains(got, "To: a@example.com, b@example.com") || !strings.Contains(got, "Subject: =?utf-8?q?") || !strings.Contains(got, "Zeile 2") || !strings.Contains(got, "http://node/x") {
		t.Fatalf("mail content:\n%s", got)
	}
}

// recorder sammelt gesendete Nachrichten.
type recorder struct {
	mu   sync.Mutex
	msgs []Message
	fail bool
}

func (r *recorder) Send(_ context.Context, ch *Channel, m Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return io.ErrUnexpectedEOF
	}
	m.Check.Target = ch.Name // Kanalname merken
	r.msgs = append(r.msgs, m)
	return nil
}

func (r *recorder) list() []Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Message{}, r.msgs...)
}

func testDispatcher(t *testing.T, settings map[string]string) (*Dispatcher, *Store, *recorder) {
	t.Helper()
	st := testStore(t)
	bundle, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	if settings == nil {
		settings = map[string]string{}
	}
	if _, ok := settings[SetBatchWindow]; !ok {
		settings[SetBatchWindow] = "0"
	}
	get := func(key, def string) string {
		if v, ok := settings[key]; ok {
			return v
		}
		return def
	}
	d := NewDispatcher(st, map[Type]Sender{TypeWebhook: rec, TypeTelegram: rec}, bundle, get, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.Start(context.Background())
	t.Cleanup(d.Stop)
	return d, st, rec
}

func addChannel(t *testing.T, st *Store, name string, def bool) *Channel {
	t.Helper()
	c := &Channel{Type: TypeWebhook, Name: name, Config: map[string]string{"url": "http://x/", "method": "POST"}, Enabled: true, Default: def, NotifyDown: true, NotifyUp: true, Lang: "de"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := st.Insert(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c
}

func waitMsgs(t *testing.T, rec *recorder, n int) []Message {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(rec.list()) >= n {
			return rec.list()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d messages, got %d: %+v", n, len(rec.list()), rec.list())
	return nil
}

func TestDispatchDefaultsAndFlags(t *testing.T) {
	d, st, rec := testDispatcher(t, nil)
	def := addChannel(t, st, "default", true)
	other := addChannel(t, st, "other", false)
	chk := CheckInfo{Token: "t1", Name: "Web", Type: "http", Target: "https://x/", NotifyDown: true, NotifyUp: true}
	d.Dispatch(Alert{EventID: "e1", Kind: KindDown, Check: chk, Reason: "timeout", Message: "timeout after 10s"})
	msgs := waitMsgs(t, rec, 1)
	if msgs[0].Check.Target != "default" || !strings.Contains(msgs[0].Title, "Web") || !strings.Contains(msgs[0].Text, "timeout after 10s") {
		t.Fatalf("default delivery: %+v", msgs[0])
	}
	// Eigene Kanalwahl des Checks
	chk.Channels = []int64{other.ID}
	d.Dispatch(Alert{EventID: "e2", Kind: KindUp, Check: chk, Duration: 90 * time.Second})
	msgs = waitMsgs(t, rec, 2)
	if msgs[1].Check.Target != "other" || msgs[1].Kind != KindUp || !strings.Contains(msgs[1].Text, "1 min") {
		t.Fatalf("explicit channel: %+v", msgs[1])
	}
	// notify_up am Check aus: keine Erholungsmeldung
	chk.Channels = nil
	chk.NotifyUp = false
	d.Dispatch(Alert{EventID: "e3", Kind: KindUp, Check: chk})
	d.Dispatch(Alert{EventID: "e4", Kind: KindDown, Check: chk})
	msgs = waitMsgs(t, rec, 3)
	if msgs[2].EventID != "e4" {
		t.Fatalf("up should have been suppressed: %+v", msgs)
	}
	// Zustellprotokoll
	dl, _ := st.Deliveries(context.Background(), 10, 0, 0)
	if len(dl) != 3 || !dl[0].OK || dl[0].Channel != "default" {
		t.Fatalf("deliveries: %+v", dl)
	}
	_ = def
}

func TestQuietHoursAndCritical(t *testing.T) {
	now := time.Date(2026, 1, 7, 23, 30, 0, 0, time.UTC) // Mittwoch
	d, st, rec := testDispatcher(t, map[string]string{SetQuietEnabled: "1", SetQuietFrom: "22:00", SetQuietTo: "07:00", SetQuietDays: "1,2,3,4,5,6,7", SetQuietTZ: "UTC"})
	d.now = func() time.Time { return now }
	addChannel(t, st, "default", true)
	chk := CheckInfo{Token: "t", Name: "A", NotifyDown: true, NotifyUp: true}
	d.Dispatch(Alert{EventID: "q1", Kind: KindDown, Check: chk})
	chk.Critical = true
	d.Dispatch(Alert{EventID: "q2", Kind: KindDown, Check: chk})
	msgs := waitMsgs(t, rec, 1)
	time.Sleep(50 * time.Millisecond)
	if len(rec.list()) != 1 || msgs[0].EventID != "q2" {
		t.Fatalf("only the critical alert may pass quiet hours: %+v", rec.list())
	}
	// Fenster ueber Mitternacht: 02:00 am Folgetag liegt drin, 08:00 nicht
	if !d.inQuietHours(0, time.Date(2026, 1, 8, 2, 0, 0, 0, time.UTC)) || d.inQuietHours(0, time.Date(2026, 1, 8, 8, 0, 0, 0, time.UTC)) {
		t.Fatal("quiet window across midnight wrong")
	}
}

func TestSummaryAndRateLimit(t *testing.T) {
	d, st, rec := testDispatcher(t, map[string]string{SetBatchWindow: "1", SetBatchThreshold: "3", SetRatePerHour: "2"})
	addChannel(t, st, "default", true)
	for i, n := range []string{"a", "b", "c", "d"} {
		d.Dispatch(Alert{EventID: "s" + n, Kind: KindDown, Check: CheckInfo{Token: n, Name: "Check " + n, NotifyDown: true, NotifyUp: true}, Message: "down " + string(rune('0'+i))})
	}
	msgs := waitMsgs(t, rec, 1)
	time.Sleep(100 * time.Millisecond)
	msgs = rec.list()
	if len(msgs) != 1 || msgs[0].Kind != KindSummary || !strings.Contains(msgs[0].Title, "4") || !strings.Contains(msgs[0].Text, "Check d") {
		t.Fatalf("expected one summary, got %+v", msgs)
	}
	// Ratelimit: 2 pro Stunde, eine ist verbraucht; die naechste geht, die uebernaechste nicht
	d.Dispatch(Alert{EventID: "r1", Kind: KindUp, Check: CheckInfo{Token: "a", Name: "Check a", NotifyDown: true, NotifyUp: true}})
	time.Sleep(1200 * time.Millisecond)
	d.Dispatch(Alert{EventID: "r2", Kind: KindUp, Check: CheckInfo{Token: "b", Name: "Check b", NotifyDown: true, NotifyUp: true}})
	time.Sleep(1200 * time.Millisecond)
	if n := len(rec.list()); n != 2 {
		t.Fatalf("rate limit: expected 2 sent, got %d", n)
	}
	dl, _ := st.Deliveries(context.Background(), 10, 0, 0)
	if len(dl) != 3 || dl[0].OK || !strings.Contains(dl[0].Error, "rate limited") {
		t.Fatalf("rate limited delivery must be logged: %+v", dl)
	}
}

func TestTestMessage(t *testing.T) {
	d, st, rec := testDispatcher(t, nil)
	ch := addChannel(t, st, "tg", false)
	if err := d.Test(context.Background(), ch); err != nil {
		t.Fatal(err)
	}
	if msgs := rec.list(); len(msgs) != 1 || msgs[0].Kind != KindTest || !strings.Contains(msgs[0].Text, "tg") {
		t.Fatalf("test message: %+v", msgs)
	}
	rec.fail = true
	if err := d.Test(context.Background(), ch); err == nil {
		t.Fatal("failure must be reported")
	}
	got, _ := st.Channel(context.Background(), ch.ID)
	if got.LastError == "" || got.LastUsedAt.IsZero() {
		t.Fatalf("channel should carry last error: %+v", got)
	}
	var e string
	_ = json.Unmarshal([]byte(`"x"`), &e)
}
