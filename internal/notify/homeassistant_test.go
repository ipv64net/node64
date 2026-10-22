package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHomeAssistantSender(t *testing.T) {
	const id = "node64-Secret_42"
	var path, ctype string
	var got map[string]any
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, ctype = r.URL.Path, r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		got = nil
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(status)
		_, _ = w.Write([]byte("echo " + r.URL.Path)) // Body mit der ID: darf nicht im Fehler landen
	}))
	defer srv.Close()

	ch := &Channel{Type: TypeHomeAssistant, Name: "HA", Config: map[string]string{"url": srv.URL + "/", "webhook_id": id}}
	if err := ch.Validate(); err != nil {
		t.Fatal(err)
	}
	if ch.Config["url"] != srv.URL || ch.Config["verify_tls"] != "true" {
		t.Fatalf("config: %v", ch.Config)
	}
	m := Message{Kind: KindDown, Title: "Down: web", Text: "Check web", Priority: 5, URL: "http://node/healthchecks/abc", EventID: "ev1",
		Time: time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC), Check: CheckInfo{Token: "abc", Name: "web", Type: "http", Target: "https://x"},
		Payload: map[string]any{"status": "down", "node": map[string]any{"name": "Keller", "location": ""}}}
	s := homeAssistantSender{"node64/test"}
	if err := s.Send(context.Background(), ch, m); err != nil {
		t.Fatal(err)
	}
	if path != "/api/webhook/"+id || ctype != "application/json" {
		t.Fatalf("path %q ctype %q", path, ctype)
	}
	ck, _ := got["check"].(map[string]any)
	if got["source"] != "node64" || got["kind"] != "down" || got["state"] != "down" || got["title"] != "Down: web" || got["message"] != "Check web" ||
		got["url"] != m.URL || got["time"] != "2026-10-22T08:00:00Z" || got["priority"] != float64(5) || got["event_id"] != "ev1" || got["node"] != "Keller" ||
		ck["name"] != "web" || ck["token"] != "abc" || ck["type"] != "http" || ck["target"] != "https://x" {
		t.Fatalf("body: %v", got)
	}

	// Test: state "test", kein Check; Modul-Hinweis ohne Status: info
	if err := s.Send(context.Background(), ch, Message{Kind: KindTest, Check: CheckInfo{Name: "HA"}, Payload: map[string]any{"node": "Node64"}}); err != nil {
		t.Fatal(err)
	}
	if ck, _ := got["check"].(map[string]any); got["state"] != "test" || ck["name"] != "" || got["node"] != "Node64" {
		t.Fatalf("test body: %v", got)
	}
	if st := haState(Message{Kind: KindHoneypotNew}); st != "info" {
		t.Fatalf("honeypot state %q", st)
	}
	if st := haState(Message{Kind: KindDynOK}); st != "up" {
		t.Fatalf("dyndns ok state %q", st)
	}

	// Fehler 500: voruebergehend, ohne Webhook-ID im Text
	status = 500
	err := s.Send(context.Background(), ch, m)
	if err == nil || !IsTemporary(err) || !strings.Contains(err.Error(), "HTTP 500") || strings.Contains(err.Error(), id) {
		t.Fatalf("500: %v", err)
	}
	status = 404
	if err := s.Send(context.Background(), ch, m); err == nil || IsTemporary(err) || strings.Contains(err.Error(), id) {
		t.Fatalf("404: %v", err)
	}

	// nicht erreichbar: Fehler von net/http enthaelt die URL, die ID muss geschwaerzt sein
	srv.Close()
	if err := s.Send(context.Background(), ch, m); err == nil || strings.Contains(err.Error(), id) {
		t.Fatalf("down: %v", err)
	}
}

func TestHomeAssistantValidate(t *testing.T) {
	ok := &Channel{Type: TypeHomeAssistant, Name: "HA", Config: map[string]string{"url": "https://ha.example.de", "webhook_id": "abc_DEF-123", "verify_tls": "false"}}
	if err := ok.Validate(); err != nil || ok.Config["verify_tls"] != "false" {
		t.Fatalf("valid: %v %v", err, ok.Config)
	}
	for name, cfg := range map[string]map[string]string{
		"no url":       {"webhook_id": "abc"},
		"ftp":          {"url": "ftp://ha.local", "webhook_id": "abc"},
		"no scheme":    {"url": "homeassistant.local:8123", "webhook_id": "abc"},
		"query":        {"url": "http://ha.local:8123/?x=1", "webhook_id": "abc"},
		"no id":        {"url": "http://ha.local:8123"},
		"slash in id":  {"url": "http://ha.local:8123", "webhook_id": "a/b"},
		"space in id":  {"url": "http://ha.local:8123", "webhook_id": "a b"},
		"umlaut in id": {"url": "http://ha.local:8123", "webhook_id": "kühl"},
		"too long":     {"url": "http://ha.local:8123", "webhook_id": strings.Repeat("a", 129)},
	} {
		ch := &Channel{Type: TypeHomeAssistant, Name: "HA", Config: cfg}
		if err := ch.Validate(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if !IsSecret(TypeHomeAssistant, "webhook_id") || IsSecret(TypeHomeAssistant, "url") {
		t.Fatal("webhook_id must be secret")
	}
	if m := (&Channel{Type: TypeHomeAssistant, Config: map[string]string{"url": "http://ha", "webhook_id": "geheim-id-123"}}).Masked(); strings.Contains(m["webhook_id"], "geheim-id-123") {
		t.Fatalf("masked: %v", m)
	}
}
