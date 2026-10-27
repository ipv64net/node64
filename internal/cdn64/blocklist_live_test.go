package cdn64

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/secrets"
)

const testHoneypotIndex = `{"version":1,"lists":[
 {"id":"v64","name":"v64 blocklist","category":"honeypot","description":"Attackers seen by ipv64 Honeypot64 sensors","license":"ipv64","files":{"all":"ipv64_blocklist_v64.txt"}},
 {"id":"v64_ssh","name":"v64 SSH","category":"honeypot","description":"SSH attackers","files":{"all":"ipv64_blocklist_v64_ssh.txt"}},
 {"id":"v64_neu","name":"v64 new","category":"honeypot","description":"Something new","files":{"all":"ipv64_blocklist_v64_neu.txt"}},
 {"id":"feodo","name":"abuse.ch Feodo Tracker","category":"botnet","files":{"all":"ipv64_blocklist_feodo.txt"}}],
 "combined":[{"id":"all","name":"All","files":{"all":"ipv64_blocklist_all.txt"}}]}`

const (
	tokLive   = "LiveToken0123456789abcdefABCDEFx" // 32 Zeichen, berechtigt
	tokDaily  = "DailyToken123456789abcdefABCDEFx" // gueltig, aber Klasse Standard: Tagesstand mit Kopfzeile
	tokDenied = "DeniedToken23456789abcdefABCDEFx" // widerrufen: 403
	tokBusy   = "BusyToken0123456789abcdefABCDEFx" // gedrosselt: 429
)

// Katalog: Kategorie honeypot mit eigenen Namen/Uebersetzungen fuer bekannte IDs, Text aus index.json fuer neue.
func TestParseBlIndexHoneypot(t *testing.T) {
	cat, _, err := parseBlIndex([]byte(testHoneypotIndex))
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]BlocklistInfo{}
	for _, b := range cat {
		by[b.ID] = b
	}
	if v := by["v64"]; v.Category != blCatHoneypot || v.Name != "v64 Blocklist" || v.Desc != "cdn64.bl.desc.v64" || v.Text == "" {
		t.Fatalf("v64: %+v", v)
	}
	if v := by["v64_ssh"]; v.Name != "v64 SSH" || v.Desc != "" || v.Text != "SSH attackers" { // keine eigene Uebersetzung mehr
		t.Fatalf("v64_ssh: %+v", v)
	}
	if v := by["v64_neu"]; v.Category != blCatHoneypot || v.Desc != "" || v.Text != "Something new" || v.Name != "v64 new" {
		t.Fatalf("v64_neu: %+v", v)
	}
	if blKnown["v64"] == "" || blKnown["v64_ssh"] != "" {
		t.Error("blKnown: only v64 of the v64 lists")
	}
}

// syncBuf: Log-Ziel fuer Tests (die Schleife loggt nebenher).
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// Listen-Token: verschluesselt gespeichert, Live-URL mit Token, Kopfzeile daily erkannt, Rueckfall bei 403, Token
// nie in Fehlern, Log, API oder Export.
func TestBlocklistLiveToken(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, _ := secrets.New(key)
	e.m.SetSecrets(box)
	logs := &syncBuf{}
	e.m.log = slog.New(slog.NewTextHandler(logs, nil))
	var paths sync.Map
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		paths.Store(r.URL.Path, true)
		w.Header().Set("Content-Type", "text/plain")
		switch r.URL.Path {
		case "/index.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(testHoneypotIndex))
		case "/ipv64_blocklist_v64.txt":
			_, _ = w.Write([]byte("198.51.100.1\n"))
		case "/live/" + tokLive + "/ipv64_blocklist_v64.txt":
			w.Header().Set("X-IPv64-List", "live")
			_, _ = w.Write([]byte("198.51.100.1\n198.51.100.2\n203.0.113.0/24\n"))
		case "/live/" + tokDaily + "/ipv64_blocklist_v64.txt":
			w.Header().Set("X-IPv64-List", "daily")
			_, _ = w.Write([]byte("198.51.100.1\n"))
		case "/live/" + tokBusy + "/ipv64_blocklist_v64.txt":
			w.Header().Set("Retry-After", "120")
			http.Error(w, "too many", http.StatusTooManyRequests)
		default:
			http.Error(w, "forbidden", http.StatusForbidden)
		}
	}))
	defer srv.Close()
	e.m.bl.base = srv.URL + "/"
	e.m.SetDataDir(t.TempDir())
	if err := e.m.blFetchIndex(ctx); err != nil {
		t.Fatal(err)
	}
	state := func() BlocklistState {
		e.m.bl.mu.Lock()
		defer e.m.bl.mu.Unlock()
		return *e.m.bl.stateOf("v64")
	}

	// ohne Token: Tagesstand
	if err := e.m.blFetch(ctx, "v64"); err != nil {
		t.Fatal(err)
	}
	if st := state(); st.Edition != "daily" || st.Entries != 1 || st.LiveDenied || st.LiveError != "" {
		t.Fatalf("daily: %+v", st)
	}

	// Format
	for _, bad := range []string{"kurz", tokLive + "x", strings.Repeat("a", 31) + "/", "../" + tokLive[3:]} {
		if err := e.m.blSetToken(ctx, bad); err == nil {
			t.Fatalf("token %q accepted", bad)
		}
	}

	// mit Token: live, verschluesselt gespeichert
	if err := e.m.blSetToken(ctx, " "+tokLive+" "); err != nil {
		t.Fatal(err)
	}
	if v := e.m.core.SettingOr(ctx, setBlockToken, ""); !strings.HasPrefix(v, "enc:v1:") || strings.Contains(v, tokLive) {
		t.Fatalf("token not encrypted: %q", v)
	}
	if e.m.blToken(ctx) != tokLive {
		t.Fatal("token not readable")
	}
	if err := e.m.blFetch(ctx, "v64"); err != nil {
		t.Fatal(err)
	}
	if _, ok := paths.Load("/live/" + tokLive + "/ipv64_blocklist_v64.txt"); !ok {
		t.Fatal("live url not used")
	}
	if st := state(); st.Edition != "live" || st.Entries != 3 || st.LiveDenied || st.LiveError != "" || st.Error != "" {
		t.Fatalf("live: %+v", st)
	}

	// Token ohne Berechtigung: ipv64 liefert den Tagesstand mit X-IPv64-List: daily
	if err := e.m.blSetToken(ctx, tokDaily); err != nil {
		t.Fatal(err)
	}
	if err := e.m.blFetch(ctx, "v64"); err != nil {
		t.Fatal(err)
	}
	if st := state(); st.Edition != "daily" || !st.LiveDenied || st.Entries != 1 {
		t.Fatalf("daily header: %+v", st)
	}

	// gedrosselt (429, Token gilt fuer alle Nodes): vorhandener Stand bleibt, kein Fehler
	if err := e.m.blSetToken(ctx, tokBusy); err != nil {
		t.Fatal(err)
	}
	if err := e.m.blFetch(ctx, "v64"); err != nil {
		t.Fatal(err)
	}
	if st := state(); st.Edition != "daily" || st.Entries != 1 || st.Error != "" || st.LiveError != "" {
		t.Fatalf("throttled with list: %+v", st)
	}

	// widerrufenes Token: 403 -> Tagesstand, Fehler sichtbar
	if err := e.m.blSetToken(ctx, tokDenied); err != nil {
		t.Fatal(err)
	}
	if err := e.m.blFetch(ctx, "v64"); err != nil {
		t.Fatal(err)
	}
	if st := state(); st.Edition != "daily" || st.LiveDenied || st.LiveError != "live: HTTP 403" || st.Entries != 1 || st.Error != "" {
		t.Fatalf("fallback: %+v", st)
	}

	// andere Listen bleiben beim Tagesstand-Pfad
	if _, ok := paths.Load("/live/" + tokDenied + "/ipv64_blocklist_feodo.txt"); ok {
		t.Fatal("non-honeypot list loaded live")
	}

	// Netzfehler mit Token: Token nicht in Fehler, Zustand oder Log
	if err := e.m.blSetToken(ctx, tokLive); err != nil {
		t.Fatal(err)
	}
	// fruehere Teillisten der v64 Blocklist gelten als die Hauptliste (keine Luecke im Schutz)
	if err := e.m.core.SetSetting(ctx, setBlocklists, "v64_ssh,v64_web"); err != nil {
		t.Fatal(err)
	}
	if got := e.m.blEnabled(ctx); len(got) != 1 || got[0] != "v64" {
		t.Fatalf("old sub-lists: %v", got)
	}
	if err := e.m.core.SetSetting(ctx, setBlocklists, "v64"); err != nil {
		t.Fatal(err)
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	e.m.bl.base = dead.URL + "/"
	err := e.m.blFetch(ctx, "v64")
	if err == nil || strings.Contains(err.Error(), tokLive) || !strings.Contains(err.Error(), "***") {
		t.Fatalf("masked error: %v", err)
	}
	e.m.blRefresh(ctx)
	if st := state(); st.Error == "" || strings.Contains(st.Error, tokLive) {
		t.Fatalf("state error: %+v", st)
	}
	for _, tok := range []string{tokLive, tokDaily, tokDenied} {
		if strings.Contains(logs.String(), tok) {
			t.Fatalf("token in log: %s", logs.String())
		}
	}
	if !strings.Contains(logs.String(), "blocklist not loaded") {
		t.Fatalf("no warning logged: %s", logs.String())
	}
	e.m.bl.base = srv.URL + "/"

	// Export: kein Token
	e.enable(t)
	exp, err := e.m.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(exp)
	if strings.Contains(string(raw), setBlockToken) || strings.Contains(string(raw), tokLive) || strings.Contains(string(raw), "enc:v1:") {
		t.Fatalf("token exported: %s", raw)
	}
	b := newEnv(t)
	b.enable(t)
	if _, err := b.m.Import(ctx, json.RawMessage(`{"settings":{"cdn64.blocklist_token":"`+tokLive+`"}}`)); err != nil {
		t.Fatal(err)
	}
	if b.m.core.SettingOr(ctx, setBlockToken, "") != "" {
		t.Fatal("token imported")
	}

	// API: token_set, Token nie in der Antwort; PUT nur token laesst die Listen
	api := func(method, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, httptest.NewRequest(method, "/api/cdn64/blocklists", strings.NewReader(body)))
		return rec
	}
	rec := api("GET", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"token_set":true`) || strings.Contains(rec.Body.String(), tokLive) {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	if rec := api("PUT", `{"token":"zu-kurz"}`); rec.Code != 422 {
		t.Fatalf("bad token: %d %s", rec.Code, rec.Body)
	}
	rec = api("PUT", `{"token":"`+tokDaily+`"}`)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), tokDaily) || !strings.Contains(rec.Body.String(), `"token_set":true`) {
		t.Fatalf("put token: %d %s", rec.Code, rec.Body)
	}
	if e.m.blToken(ctx) != tokDaily || e.m.core.SettingOr(ctx, setBlocklists, "") != "v64" {
		t.Fatal("put token: token not set or lists changed")
	}
	rec = api("PUT", `{"token":""}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"token_set":false`) || e.m.core.SettingOr(ctx, setBlocklists, "") != "v64" {
		t.Fatalf("delete token: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(logs.String(), tokDaily) {
		t.Fatal("token in log")
	}
}

// tokenAPI: ipv64 mit zentralem API-Key, liefert das Listen-Token (OnlineAPI eingebettet: andere Aufrufe nicht noetig).
type tokenAPI struct {
	OnlineAPI
	tok   string
	calls atomic.Int64
}

func (a *tokenAPI) Ready(context.Context) bool { return true }
func (a *tokenAPI) ListToken(context.Context) (*ipv64api.ListToken, error) {
	a.calls.Add(1)
	return &ipv64api.ListToken{Token: a.tok, Live: true}, nil
}

// Ohne Token von Hand holt PROXY64 das Listen-Token ueber den API-Key (nur mit eingeschalteter Honeypot-Liste, nur
// einmal), laedt damit die Live-Fassung; ein Token von Hand geht vor; 404 verwirft das geholte Token.
func TestBlocklistAutoToken(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, _ := secrets.New(key)
	e.m.SetSecrets(box)
	gone := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(testHoneypotIndex))
		case "/ipv64_blocklist_v64.txt", "/ipv64_blocklist_feodo.txt":
			_, _ = w.Write([]byte("198.51.100.1\n"))
		case "/live/" + tokLive + "/ipv64_blocklist_v64.txt":
			if gone.Load() {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("X-IPv64-List", "live")
			_, _ = w.Write([]byte("198.51.100.1\n198.51.100.2\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	e.m.bl.base = srv.URL + "/"
	e.m.SetDataDir(t.TempDir())
	api := &tokenAPI{tok: tokLive}
	e.m.SetOnlineAPI(api)
	state := func() BlocklistState {
		e.m.bl.mu.Lock()
		defer e.m.bl.mu.Unlock()
		return *e.m.bl.stateOf("v64")
	}

	// nur feodo eingeschaltet: kein Token holen (legt sonst bei ipv64 ohne Bedarf eins an)
	if err := e.m.core.SetSetting(ctx, setBlocklists, "feodo"); err != nil {
		t.Fatal(err)
	}
	e.m.blRefresh(ctx)
	if api.calls.Load() != 0 || e.m.blToken(ctx) != "" {
		t.Fatalf("token fetched without honeypot list: %d", api.calls.Load())
	}

	// v64 eingeschaltet: Token geholt, verschluesselt gemerkt, Live-Fassung; zweiter Lauf fragt nicht noch einmal
	if err := e.m.core.SetSetting(ctx, setBlocklists, "v64"); err != nil {
		t.Fatal(err)
	}
	e.m.blRefresh(ctx)
	e.m.blRefresh(ctx)
	if api.calls.Load() != 1 || e.m.blToken(ctx) != tokLive {
		t.Fatalf("auto token: calls %d", api.calls.Load())
	}
	if v := e.m.core.SettingOr(ctx, setBlockTokenAuto, ""); !strings.HasPrefix(v, "enc:v1:") || strings.Contains(v, tokLive) {
		t.Fatalf("auto token not encrypted: %q", v)
	}
	if st := state(); st.Edition != "live" || st.Entries != 2 {
		t.Fatalf("live: %+v", st)
	}
	if v := e.m.blView(httptest.NewRequest(http.MethodGet, "/", nil)); v.TokenSet || !v.TokenAuto {
		t.Fatalf("view: set %v auto %v", v.TokenSet, v.TokenAuto)
	}

	// Token bei ipv64 unbekannt (404): verworfen, Tagesstand, beim naechsten Lauf neu geholt
	gone.Store(true)
	e.m.blRefresh(ctx)
	if e.m.core.SettingOr(ctx, setBlockTokenAuto, "") != "" || state().Edition != "daily" {
		t.Fatalf("404 keeps auto token: %+v", state())
	}
	gone.Store(false)
	e.m.blRefresh(ctx)
	if api.calls.Load() != 2 || state().Edition != "live" {
		t.Fatalf("refetch: calls %d %+v", api.calls.Load(), state())
	}

	// Token von Hand geht vor
	if err := e.m.blSetToken(ctx, tokDaily); err != nil {
		t.Fatal(err)
	}
	if e.m.blToken(ctx) != tokDaily {
		t.Fatal("manual token must win")
	}
}

// Reihenfolge: Gesamtlisten vorne, die v64 Blocklist direkt dahinter (in index.json steht sie am Ende).
func TestParseBlIndexV64First(t *testing.T) {
	raw := `{"lists":[{"id":"spamhaus_drop","files":{"all":"ipv64_blocklist_spamhaus_drop.txt"}},
	 {"id":"feodo","files":{"all":"ipv64_blocklist_feodo.txt"}},
	 {"id":"v64","category":"honeypot","files":{"all":"ipv64_blocklist_v64.txt"}}],
	 "combined":[{"id":"all","files":{"all":"ipv64_blocklist_all.txt"}},{"id":"all_notor","files":{"all":"ipv64_blocklist_all_notor.txt"}}]}`
	cat, _, err := parseBlIndex([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, b := range cat {
		ids = append(ids, b.ID)
	}
	if strings.Join(ids, ",") != "all,all_notor,v64,spamhaus_drop,feodo" {
		t.Fatalf("order: %v", ids)
	}
}
