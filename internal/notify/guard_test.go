package notify

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Mit PublicOnly (hub) erreichen Kanaele keine internen Adressen; Serverfehler sind voruebergehend, Antworttexte gekuerzt.
func TestSendersPublicOnlyAndTemporary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/busy" {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(strings.Repeat("ä", 500)))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	ctx := context.Background()
	m := Message{Kind: KindTest, Title: "t", Text: "x"}
	hook := func(path string) *Channel {
		return &Channel{Type: TypeWebhook, Config: map[string]string{"url": srv.URL + path, "method": "POST"}}
	}
	err := Senders("test")[TypeWebhook].Send(ctx, hook("/busy"), m)
	if err == nil || !IsTemporary(err) || len(err.Error()) > 230 {
		t.Fatalf("503 must be temporary and short: %v", err)
	}
	if err := Senders("test")[TypeWebhook].Send(ctx, hook("/bad"), m); err == nil || IsTemporary(err) {
		t.Fatalf("400 must be final: %v", err)
	}
	err = SendersPublicOnly("test")[TypeWebhook].Send(ctx, hook("/busy"), m)
	if !errors.Is(err, ErrPrivateTarget) || IsTemporary(err) {
		t.Fatalf("loopback must be blocked: %v", err)
	}
	// SMTP ebenso
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	smtpCh := &Channel{Type: TypeSMTP, Config: map[string]string{"host": host, "port": port, "security": "none", "from": "a@example.com", "to": "b@example.com"}}
	if err := SendersPublicOnly("test")[TypeSMTP].Send(ctx, smtpCh, m); !errors.Is(err, ErrPrivateTarget) {
		t.Fatalf("smtp loopback must be blocked: %v", err)
	}
	// Verbindung abgelehnt: voruebergehend
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	if err := Senders("test")[TypeWebhook].Send(ctx, &Channel{Type: TypeWebhook, Config: map[string]string{"url": "http://" + addr + "/", "method": "POST"}}, m); !IsTemporary(err) {
		t.Fatalf("refused must be temporary: %v", err)
	}
}
