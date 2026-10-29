package cdn64

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testAIList: wie ipv64_ai_useragents.json (Auszug); "OpenAI" steht drin, damit "openai.com" im User-Agent von
// ChatGPT-User nicht trifft, wenn Nutzer-Abrufe erlaubt sind.
func testAIList(extra ...string) []byte {
	type bot struct {
		Name string `json:"name"`
		User bool   `json:"user"`
	}
	bots := []bot{{"GPTBot", false}, {"ChatGPT-User", true}, {"Perplexity-User", true}, {"PerplexityBot", false}, {"CCBot", false},
		{"ClaudeBot", false}, {"Spider", false}, {"OpenAI", false}, {"meta-externalagent", false}, {"Meta-ExternalAgent", false},
		{"iaskspider/2.0", false}, {"ChatGPT Agent", true}, {"bad\x01token", false}, {strings.Repeat("x", 81), false}, {"ab", false}}
	for _, e := range extra {
		bots = append(bots, bot{e, false})
	}
	raw, _ := json.Marshal(map[string]any{"count": len(bots), "bots": bots})
	return raw
}

func TestParseAIBotsAndMatch(t *testing.T) {
	l, err := parseAIBots(testAIList())
	if err != nil {
		t.Fatal(err)
	}
	if l.count != 12 || l.users != 3 || len(l.all) != 11 || len(l.crawl) != 8 { // ungueltige weg, Gross/klein doppelt nur einmal
		t.Fatalf("count %d users %d all %v crawl %v", l.count, l.users, l.all, l.crawl)
	}
	a := &aiBots{}
	a.put(l, time.Now())
	cases := []struct {
		ua          string
		user, crawl bool // gesperrt mit bzw. ohne Nutzer-Abrufe
	}{
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)", true, true},
		{"gptbot", true, true}, // Gross/klein egal
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot", true, false},
		{"Mozilla/5.0 (compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)", true, false},
		{"Mozilla/5.0 (compatible) ChatGPT Agent", true, false},
		{"CCBot/2.0 (https://commoncrawl.org/faq/)", true, true},
		{"meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)", true, true},
		{"Mozilla/5.0 (compatible; iaskspider/2.0; +https://iask.ai)", true, true},
		{"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)", false, false}, // "Spider" nur als Wort
		{"Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)", true, true},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36", false, false},
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		if got := a.match(c.ua, true); got != c.user {
			t.Errorf("user on: %q = %v", c.ua, got)
		}
		if got := a.match(c.ua, false); got != c.crawl {
			t.Errorf("user off: %q = %v", c.ua, got)
		}
	}
	if r := a.robots(true); !strings.Contains(r, "User-agent: GPTBot\n") || !strings.Contains(r, "User-agent: ChatGPT-User\n") || !strings.HasSuffix(r, "Disallow: /\n") {
		t.Fatalf("robots: %q", r)
	}
	if r := a.robots(false); strings.Contains(r, "ChatGPT-User") || !strings.Contains(r, "User-agent: CCBot\n") {
		t.Fatalf("robots without user fetchers: %q", r)
	}
	for _, bad := range []string{`{"bots":[{"name":"GPTBot"}]}`, `nope`, `{"bots":"x"}`} {
		if _, err := parseAIBots([]byte(bad)); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
	if (&aiBots{}).match("GPTBot/1.0", true) {
		t.Fatal("no list loaded: nothing is blocked")
	}
}

// Laden von ipv64.net nur mit Bedarf, ETag/304, bei Fehler und Unsinn bleibt die alte Liste, Zwischenspeicher beim Start.
func TestAIBotsFetchCacheFallback(t *testing.T) {
	ctx := context.Background()
	var mode atomic.Int32 // 0 = Liste, 1 = Fehler 500, 2 = zu wenige Kennungen
	var gets atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		if r.URL.Path != "/"+aiUAFile {
			http.NotFound(w, r)
			return
		}
		switch mode.Load() {
		case 1:
			http.Error(w, "down", http.StatusInternalServerError)
			return
		case 2:
			w.Header().Set("ETag", `"v2"`)
			_, _ = w.Write([]byte(`{"bots":[{"name":"GPTBot"}]}`))
			return
		}
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(testAIList())
	}))
	defer srv.Close()
	dir := t.TempDir()
	mk := func() *Module {
		m := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, "test")
		m.SetDataDir(dir)
		m.bl.base = srv.URL + "/"
		return m
	}
	m := mk()
	m.aiRefresh(ctx)
	if gets.Load() != 0 {
		t.Fatal("no host uses the list: nothing loaded")
	}
	m.aiNeed([]*Host{{Kind: KindProxy, Advanced: Advanced{AIBots: true}}})
	m.aiRefresh(ctx)
	st := m.aiState()
	if !st.Needed || st.Entries != 12 || st.Users != 3 || st.Error != "" || st.Updated.IsZero() || !m.bl.ai.match("GPTBot/1.0", true) {
		t.Fatalf("loaded: %+v", st)
	}
	m.aiRefresh(ctx) // 304
	if st := m.aiState(); st.Error != "" || st.Entries != 12 {
		t.Fatalf("not modified: %+v", st)
	}
	mode.Store(1)
	m.aiRefresh(ctx)
	if st := m.aiState(); st.Error == "" || st.Entries != 12 || !m.bl.ai.match("GPTBot/1.0", true) {
		t.Fatalf("download failed, old list must stay: %+v", st)
	}
	mode.Store(2)
	m.aiRefresh(ctx)
	if st := m.aiState(); st.Error == "" || st.Entries != 12 {
		t.Fatalf("invalid list, old list must stay: %+v", st)
	}
	// Neustart ohne ipv64: Liste aus dem Zwischenspeicher
	m2 := mk()
	m2.bl.base = "http://127.0.0.1:1/"
	m2.aiLoadCache()
	if st := m2.aiState(); st.Entries != 12 || !m2.bl.ai.match("ClaudeBot", false) {
		t.Fatalf("cache: %+v", st)
	}
	m2.aiNeed(nil)
	if m2.aiState().Needed {
		t.Fatal("no host: not needed")
	}
}

// 403 fuer KI-Bots am Host, Nutzer-Abrufe je Host erlaubbar, /robots.txt bleibt erreichbar und kommt mit KI-Sperre,
// wenn das Ziel keine hat; eine eigene robots.txt des Ziels bleibt unberuehrt.
func TestAIBotsProxy(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	var ownRobots atomic.Bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			if ownRobots.Load() {
				_, _ = io.WriteString(w, "User-agent: *\nAllow: /\n")
				return
			}
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)
	bport, _ := strconv.Atoi(bu.Port())
	l, err := parseAIBots(testAIList())
	if err != nil {
		t.Fatal(err)
	}
	e.m.bl.ai.put(l, time.Now())
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"app.test"}, "127.0.0.1", bport
	h.Advanced.AIBots, h.Advanced.AIRobots = true, true
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	st := &hostStats{}
	do := func(path, ua string) (int, string) {
		req := httptest.NewRequest("GET", "http://app.test"+path, nil)
		req.RemoteAddr = "203.0.113.7:4242"
		req.Header.Set("User-Agent", ua)
		rec := httptest.NewRecorder()
		e.m.handlerFor(h, st).ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	const gpt, chat, browser = "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)", "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
	if code, body := do("/", gpt); code != 403 || strings.Contains(body, "GPTBot") {
		t.Fatalf("crawler: %d %q", code, body)
	}
	if code, _ := do("/", chat); code != 403 {
		t.Fatalf("user fetcher (default blocked): %d", code)
	}
	if code, body := do("/", browser); code != 200 || body != "ok" {
		t.Fatalf("browser: %d %q", code, body)
	}
	if st.blocked.Load() != 2 || e.m.aiState().Blocked != 2 {
		t.Fatalf("counted: host %d list %d", st.blocked.Load(), e.m.aiState().Blocked)
	}
	code, body := do("/robots.txt", gpt)
	if code != 200 || !strings.Contains(body, "User-agent: GPTBot\n") || !strings.Contains(body, "User-agent: ChatGPT-User\n") || !strings.Contains(body, "Disallow: /") {
		t.Fatalf("robots.txt: %d %q", code, body)
	}
	ownRobots.Store(true)
	if code, body := do("/robots.txt", browser); code != 200 || body != "User-agent: *\nAllow: /\n" {
		t.Fatalf("own robots.txt of the target: %d %q", code, body)
	}
	ownRobots.Store(false)
	h.Advanced.AIBotsAllowUser = true
	if code, _ := do("/", chat); code != 200 {
		t.Fatalf("user fetcher allowed: %d", code)
	}
	if code, _ := do("/", gpt); code != 403 {
		t.Fatalf("crawler still blocked: %d", code)
	}
	if _, body := do("/robots.txt", browser); strings.Contains(body, "ChatGPT-User") || !strings.Contains(body, "GPTBot") {
		t.Fatalf("robots.txt without user fetchers: %q", body)
	}
	h.Advanced.AIBots, h.Advanced.AIRobots = false, false
	if code, _ := do("/", gpt); code != 200 {
		t.Fatalf("switched off: %d", code)
	}
	if code, _ := do("/robots.txt", gpt); code != 404 {
		t.Fatalf("robots.txt off: %d", code)
	}
}

// Einstellungen je Host: speichern, Formular (Haken "Nutzer-Abrufe auch sperren" umgekehrt), Bereinigung je Art, Export/Import.
func TestAIBotsSettingsExport(t *testing.T) {
	ctx := context.Background()
	a := newEnv(t)
	a.enable(t)
	h := newHost()
	form := url.Values{"names": {"ki.test"}, "scheme": {"http"}, "target_host": {"192.168.1.10"}, "target_port": {"8080"}, "enabled": {"on"},
		"has_ai": {"1"}, "ai_bots": {"on"}, "ai_robots": {"on"}} // ai_bots_user fehlt = Nutzer-Abrufe erlauben
	req := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()
	hostFromForm(req, h)
	if !h.Advanced.AIBots || !h.Advanced.AIBotsAllowUser || !h.Advanced.AIRobots {
		t.Fatalf("form: %+v", h.Advanced)
	}
	if err := a.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	got, err := a.m.host(ctx, h.ID)
	if err != nil || !got.Advanced.AIBots || !got.Advanced.AIBotsAllowUser || !got.Advanced.AIRobots {
		t.Fatalf("stored: %+v %v", got, err)
	}
	if !a.m.aiState().Needed {
		t.Fatal("enabled host with ai_bots: list needed")
	}
	for kind, want := range map[string][3]bool{KindRedirect: {true, true, false}, KindDead: {false, false, false}, KindPass: {false, false, false}} {
		adv := Advanced{AIBots: true, AIBotsAllowUser: true, AIRobots: true}
		adv.normalizeAI(kind)
		if [3]bool{adv.AIBots, adv.AIBotsAllowUser, adv.AIRobots} != want {
			t.Errorf("%s: %+v", kind, adv)
		}
	}
	exp, err := a.m.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(exp)
	if !strings.Contains(string(raw), `"ai_bots":true`) || !strings.Contains(string(raw), `"ai_robots":true`) {
		t.Fatalf("export: %s", raw)
	}
	b := newEnv(t)
	b.enable(t)
	if _, err := b.m.Import(ctx, raw); err != nil {
		t.Fatal(err)
	}
	list, err := b.m.hosts(ctx)
	if err != nil || len(list) != 1 || !list[0].Advanced.AIBots || !list[0].Advanced.AIBotsAllowUser || !list[0].Advanced.AIRobots {
		t.Fatalf("import: %+v %v", list, err)
	}
}

// Die IP-Liste der KI-Bots kommt aus index.json in die Auswahl (Kategorie ai); Eintraege unter "data" sind keine IP-Listen.
func TestAIBotsIndex(t *testing.T) {
	raw := fmt.Sprintf(`{"lists":[{"id":"ai_bots","name":"v64 AI Bots (IP)","category":"ai","files":{"all":"ipv64_blocklist_ai_bots.txt","sources":"ipv64_blocklist_ai_bots_sources.txt"},"sources":[{"id":"openai_gptbot"}]}],
	 "data":[{"id":"ai_useragents","category":"ai","files":{"txt":"ipv64_ai_useragents.txt","json":"%s"}}]}`, aiUAFile)
	cat, _, err := parseBlIndex([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(cat) != 1 || cat[0].ID != "ai_bots" || cat[0].Category != "ai" || cat[0].Name != "v64 KI-Bots (IP)" || cat[0].Desc != "cdn64.bl.desc.ai_bots" {
		t.Fatalf("catalog: %+v", cat)
	}
}

// Vorlagen: Schalter im Host-Formular (je Art), Stand der Liste und Kategorie auf dem Reiter Zugriffslisten.
func TestAIBotsTemplates(t *testing.T) {
	named := func(h *Host) *Host { h.Names = []string{"x.test"}; return h }
	h := named(newHost())
	h.Advanced.AIBots, h.Advanced.AIBotsAllowUser = true, true
	body := aiRender(t, "host_form.html", formData{Host: h, Errors: map[string]string{}})
	for _, want := range []string{`name="has_ai"`, `name="ai_bots" id="ai_bots" checked`, `name="ai_robots"`, "cdn64.f.ai_hint"} {
		if !strings.Contains(body, want) {
			t.Fatalf("form misses %q", want)
		}
	}
	if strings.Contains(body, `id="ai_bots_user" checked`) {
		t.Fatal("user fetchers allowed: box must be unchecked")
	}
	r := named(newHostKind(KindRedirect))
	if body := aiRender(t, "host_form.html", formData{Host: r, Errors: map[string]string{}}); !strings.Contains(body, `name="ai_bots"`) || strings.Contains(body, `name="ai_robots"`) {
		t.Fatal("redirect: ai_bots without robots.txt")
	}
	if body := aiRender(t, "host_form.html", formData{Host: named(newHostKind(KindPass)), Errors: map[string]string{}}); strings.Contains(body, `name="has_ai"`) {
		t.Fatal("passthrough: no ai options")
	}
	v := blocklistsView{Lists: []BlocklistState{{BlocklistInfo: BlocklistInfo{ID: "ai_bots", Name: "v64 KI-Bots (IP)", Category: "ai", Desc: "cdn64.bl.desc.ai_bots"}}},
		AIBots: AIBotsState{Needed: true, Entries: 193, Users: 53, Updated: time.Now(), Blocked: 7}}
	body = aiRender(t, "access.html", aclsData{BL: v})
	for _, want := range []string{"cdn64.bl.cat.ai", "cdn64.ai.list", "cdn64.ai.entries"} {
		if !strings.Contains(body, want) {
			t.Fatalf("access page misses %q", want)
		}
	}
}

// aiRender wie renderPage, mit den Funktionen, die host_form.html braucht.
func aiRender(t *testing.T, file string, d any) string {
	t.Helper()
	tp, err := template.New(file).Funcs(template.FuncMap{"join": strings.Join, "split": strings.Fields, "dict": tplDict}).ParseFS(templateFS, "templates/partials/*.html", "templates/pages/"+file)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := tp.ExecuteTemplate(&buf, "content", tplView{Data: d}); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
