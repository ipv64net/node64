package notify

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// #209: Absender mit Anzeigenamen ("Monitoring <monitoring@example.com>") - EHLO und MAIL FROM bekommen nur die
// Adresse (vorher "EHLO example.com>" -> 501 Invalid domain name), die Mail zeigt den Namen.
func TestSMTPFromDisplayName(t *testing.T) {
	for _, c := range []struct{ raw, name, addr string }{
		{"monitoring@example.com", "Node64", "monitoring@example.com"},
		{"Monitoring <monitoring@example.com>", "Monitoring", "monitoring@example.com"},
		{`"Node64 Keller" <keller@example.com>`, "Node64 Keller", "keller@example.com"},
		{"  <x@example.com> ", "Node64", "x@example.com"},
		{"kaputt", "Node64", "kaputt"},
	} {
		if n, a := smtpFrom(c.raw); n != c.name || a != c.addr {
			t.Errorf("smtpFrom(%q) = %q, %q", c.raw, n, a)
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	type seen struct{ ehlo, mailFrom, header string }
	got := make(chan seen, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		w := bufio.NewWriter(c)
		r := bufio.NewReader(c)
		say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }
		read := func() string {
			line, _ := r.ReadString('\n')
			return strings.TrimRight(line, "\r\n")
		}
		var s seen
		say("220 fake ESMTP")
		for {
			line := read()
			if line == "" {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				s.ehlo = strings.TrimPrefix(line, "EHLO ")
				if strings.ContainsAny(s.ehlo, "<>") {
					say("501 5.5.4 Invalid domain name")
					continue
				}
				say("250 fake")
			case strings.HasPrefix(line, "MAIL FROM:"):
				s.mailFrom = strings.TrimPrefix(line, "MAIL FROM:")
				say("250 ok")
			case strings.HasPrefix(line, "DATA"):
				say("354 go")
				for {
					raw, err := r.ReadString('\n')
					if err != nil {
						return
					}
					l := strings.TrimRight(raw, "\r\n")
					if l == "." {
						break
					}
					if strings.HasPrefix(l, "From: ") {
						s.header = strings.TrimPrefix(l, "From: ")
					}
				}
				say("250 ok")
			case strings.HasPrefix(line, "QUIT"):
				got <- s
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	ch := &Channel{Type: TypeSMTP, Config: map[string]string{"host": host, "port": port, "security": "none",
		"from": "Monitoring <monitoring@example.com>", "to": "a@example.com"}}
	m := Message{Kind: KindDown, Title: "Test", Text: "x", Time: time.Now(), EventID: "e1"}
	if err := Senders("test")[TypeSMTP].Send(context.Background(), ch, m); err != nil {
		t.Fatal(err)
	}
	s := <-got
	if strings.ContainsAny(s.ehlo, "<>") || !strings.Contains(s.mailFrom, "<monitoring@example.com>") || strings.Contains(s.mailFrom, "Monitoring") {
		t.Fatalf("EHLO %q, MAIL FROM %q", s.ehlo, s.mailFrom)
	}
	if !strings.Contains(s.header, "Monitoring") || !strings.Contains(s.header, "<monitoring@example.com>") {
		t.Fatalf("From header %q", s.header)
	}
}
