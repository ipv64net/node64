package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type chatReq struct {
	Method, Path, Auth string
	Body               map[string]any
}

func chatServer(t *testing.T, status int, extra func(w http.ResponseWriter, r *http.Request) bool) (*httptest.Server, func() []chatReq) {
	var mu sync.Mutex
	var got []chatReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if extra != nil && extra(w, r) {
			return
		}
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(b, &body)
		mu.Lock()
		got = append(got, chatReq{r.Method, r.URL.EscapedPath(), r.Header.Get("Authorization"), body})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []chatReq { mu.Lock(); defer mu.Unlock(); return append([]chatReq(nil), got...) }
}

func chatMsg(k Kind) Message {
	return Message{Kind: k, Title: "Shop <Web> ist gestört", Text: "Grund: Zeitüberschreitung\n\nZeitpunkt: 10:00", URL: "https://node.example/healthchecks/x", Time: time.Now(), EventID: "e1", Language: "de"}
}

func TestMatrixSender(t *testing.T) {
	srv, reqs := chatServer(t, 200, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/directory/room/") { // Alias aufloesen
			if r.URL.EscapedPath() != "/_matrix/client/v3/directory/room/%23alerts:example.org" || r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"errcode":"M_NOT_FOUND","error":"Room alias not found"}`))
				return true
			}
			_, _ = w.Write([]byte(`{"room_id":"!abc:example.org"}`))
			return true
		}
		return false
	})
	ch := &Channel{ID: 3, Type: TypeMatrix, Config: map[string]string{"server": srv.URL, "token": "tok", "room": "#alerts:example.org"}}
	if err := (matrixSender{"t"}).Send(context.Background(), ch, chatMsg(KindDown)); err != nil {
		t.Fatal(err)
	}
	r := reqs()
	if len(r) != 1 || r[0].Method != "PUT" || !strings.HasPrefix(r[0].Path, "/_matrix/client/v3/rooms/%21abc:example.org/send/m.room.message/node64-") || r[0].Auth != "Bearer tok" {
		t.Fatalf("request: %+v", r)
	}
	b := r[0].Body
	if b["msgtype"] != "m.notice" || !strings.Contains(b["body"].(string), "Grund: Zeitüberschreitung") ||
		!strings.Contains(b["formatted_body"].(string), `data-mx-color="#d63939"`) || !strings.Contains(b["formatted_body"].(string), "Shop &lt;Web&gt;") ||
		!strings.Contains(b["formatted_body"].(string), `<a href="https://node.example/healthchecks/x">`) {
		t.Fatalf("body: %+v", b)
	}
	// Fehler von Matrix lesbar
	ch.Config["room"] = "#nix:example.org"
	if err := (matrixSender{"t"}).Send(context.Background(), ch, chatMsg(KindUp)); err == nil || !strings.Contains(err.Error(), "M_NOT_FOUND") {
		t.Fatalf("error: %v", err)
	}
}

func TestSlackSender(t *testing.T) {
	srv, reqs := chatServer(t, 200, nil)
	ch := &Channel{Type: TypeSlack, Config: map[string]string{"webhook_url": srv.URL + "/services/T/B/x"}}
	if err := (slackSender{"t"}).Send(context.Background(), ch, chatMsg(KindUp)); err != nil {
		t.Fatal(err)
	}
	r := reqs()
	raw, _ := json.Marshal(r[0].Body)
	s := string(raw)
	if len(r) != 1 || r[0].Path != "/services/T/B/x" || r[0].Body["text"] != "Shop <Web> ist gestört" || !strings.Contains(s, `"color":"#2fb344"`) ||
		!strings.Contains(slackText(r[0].Body), "*Shop &lt;Web&gt; ist gestört*"+"\n"+"Grund") || !strings.Contains(s, `"url":"https://node.example/healthchecks/x"`) {
		t.Fatalf("slack: %s", s)
	}
	srv2, _ := chatServer(t, 404, nil)
	ch.Config["webhook_url"] = srv2.URL
	if err := (slackSender{"t"}).Send(context.Background(), ch, chatMsg(KindUp)); err == nil || !strings.Contains(err.Error(), "slack: HTTP 404") {
		t.Fatalf("error: %v", err)
	}
}

func TestTeamsSender(t *testing.T) {
	srv, reqs := chatServer(t, 202, nil)
	ch := &Channel{Type: TypeTeams, Config: map[string]string{"webhook_url": srv.URL + "/workflows/x"}}
	if err := (teamsSender{"t"}).Send(context.Background(), ch, chatMsg(KindQuota)); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(reqs()[0].Body)
	s := string(raw)
	if !strings.Contains(s, `"type":"message"`) || !strings.Contains(s, `"contentType":"application/vnd.microsoft.card.adaptive"`) ||
		!strings.Contains(s, `"type":"AdaptiveCard"`) || !strings.Contains(s, `"color":"warning"`) || !strings.Contains(s, `"type":"Action.OpenUrl"`) ||
		!strings.Contains(s, `"text":"Grund: Zeitüberschreitung"`) {
		t.Fatalf("teams: %s", s)
	}
}

// Formular: Raum und https-Webhooks werden geprueft, Server ohne Schraegstrich am Ende.
func TestChatChannelValidate(t *testing.T) {
	ok := []*Channel{
		{Name: "m", Type: TypeMatrix, Config: map[string]string{"server": "https://matrix.example.org/", "token": "x", "room": "!abc:example.org"}},
		{Name: "m", Type: TypeMatrix, Config: map[string]string{"token": "x", "room": "#alerts:example.org"}},
		{Name: "s", Type: TypeSlack, Config: map[string]string{"webhook_url": "https://hooks.slack.com/services/T/B/x"}},
		{Name: "t", Type: TypeTeams, Config: map[string]string{"webhook_url": "https://prod-01.westeurope.logic.azure.com/workflows/x"}},
	}
	for _, c := range ok {
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: %v", c.Type, err)
		}
	}
	if ok[0].Config["server"] != "https://matrix.example.org" || ok[1].Config["server"] != "https://matrix.org" {
		t.Fatalf("server: %q %q", ok[0].Config["server"], ok[1].Config["server"])
	}
	bad := []*Channel{
		{Name: "m", Type: TypeMatrix, Config: map[string]string{"token": "x", "room": "alerts"}},
		{Name: "s", Type: TypeSlack, Config: map[string]string{"webhook_url": "http://hooks.slack.com/x"}},
		{Name: "t", Type: TypeTeams, Config: map[string]string{"webhook_url": ""}},
	}
	for _, c := range bad {
		if err := c.Validate(); err == nil {
			t.Fatalf("%s: accepted %+v", c.Type, c.Config)
		}
	}
	if !IsSecret(TypeMatrix, "token") || !IsSecret(TypeSlack, "webhook_url") || !IsSecret(TypeTeams, "webhook_url") || IsSecret(TypeMatrix, "room") {
		t.Fatal("secrets")
	}
}

// slackText: mrkdwn-Text des ersten Abschnitts der ersten Anlage.
func slackText(b map[string]any) string {
	defer func() { _ = recover() }()
	att := b["attachments"].([]any)[0].(map[string]any)
	return att["blocks"].([]any)[0].(map[string]any)["text"].(map[string]any)["text"].(string)
}
