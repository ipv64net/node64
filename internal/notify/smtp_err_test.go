package notify

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// SMTP-Fehler nennen Schritt und Server; Zeitueberschreitung als "timeout", Hinweis bei TLS gegen Klartext.
func TestSMTPErrorTexts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	greet := make(chan bool, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if <-greet {
				_, _ = c.Write([]byte("220 test ESMTP\r\n"))
			}
			go func() { time.Sleep(3 * time.Second); c.Close() }()
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	send := func(security string, greeting bool) string {
		greet <- greeting
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		ch := &Channel{Type: "smtp", Config: map[string]string{"host": host, "port": port, "security": security, "from": "a@example.org", "to": "b@example.org"}}
		err := smtpSender{}.send(ctx, ch, Message{})
		if err == nil {
			t.Fatalf("%s: kein Fehler", security)
		}
		return err.Error()
	}
	// Server schweigt (wie Port 465 mit STARTTLS eingestellt)
	if e := send("starttls", false); !strings.HasPrefix(e, "greeting "+ln.Addr().String()+": timeout") {
		t.Fatalf("starttls ohne Begruessung: %s", e)
	}
	// TLS eingestellt, Server spricht Klartext
	if e := send("tls", true); !strings.Contains(e, ln.Addr().String()) || !strings.Contains(e, "STARTTLS") {
		t.Fatalf("tls gegen Klartext: %s", e)
	}
	// TLS eingestellt, Server schweigt: Handschlag laeuft in die Zeit
	if e := send("tls", false); !strings.HasPrefix(e, "connect "+ln.Addr().String()+": timeout (TLS handshake") {
		t.Fatalf("tls ohne Antwort: %s", e)
	}
	// Port 465 mit STARTTLS: Hinweis auf TLS
	if e := smtpErr("greeting", "mail.example.org:465", "starttls", context.DeadlineExceeded).Error(); !strings.Contains(e, "port 465 expects TLS") {
		t.Fatalf("465: %s", e)
	}
}
