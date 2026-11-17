package notify

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"
)

// #205: Server, die nur AUTH LOGIN (und NTLM) anbieten (z. B. Hosted Exchange), lehnten PLAIN mit
// "5.7.4 Unrecognized authentication type" ab. Node64 meldet sich dort jetzt mit LOGIN an.
func TestSMTPAuthLogin(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan string, 1)
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
		say("220 fake ESMTP")
		authed := ""
		for {
			line := read()
			if line == "" {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				say("250-fake")
				say("250 AUTH LOGIN NTLM")
			case strings.HasPrefix(line, "AUTH LOGIN"):
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
				u, _ := base64.StdEncoding.DecodeString(read())
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
				p, _ := base64.StdEncoding.DecodeString(read())
				authed = string(u) + "/" + string(p)
				say("235 2.7.0 Authentication successful")
			case strings.HasPrefix(line, "AUTH"):
				say("504 5.7.4 Unrecognized authentication type")
			case strings.HasPrefix(line, "MAIL") && authed == "":
				say("530 5.7.57 Client not authenticated")
			case strings.HasPrefix(line, "DATA"):
				say("354 go")
				for read() != "." {
				}
				say("250 ok")
			case strings.HasPrefix(line, "QUIT"):
				got <- authed
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	ch := &Channel{Type: TypeSMTP, Config: map[string]string{"host": host, "port": port, "security": "none", "user": "mail@example.com",
		"password": "geheim", "from": "mail@example.com", "to": "a@example.com"}}
	m := Message{Kind: KindDown, Title: "Test", Text: "x", Time: time.Now(), EventID: "e1"}
	if err := Senders("test")[TypeSMTP].Send(context.Background(), ch, m); err != nil {
		t.Fatal(err)
	}
	if a := <-got; a != "mail@example.com/geheim" {
		t.Fatalf("AUTH LOGIN credentials: %q", a)
	}
}

// LOGIN schickt das Passwort wie PLAIN nur verschluesselt (ausser an localhost).
func TestLoginAuthRefusesPlaintext(t *testing.T) {
	a := &loginAuth{user: "u", password: "p", host: "mail.example.com"}
	if _, _, err := a.Start(&smtp.ServerInfo{Name: "mail.example.com", TLS: false, Auth: []string{"LOGIN"}}); err == nil {
		t.Fatal("LOGIN over an unencrypted connection to a remote host")
	}
	if mech, _, err := a.Start(&smtp.ServerInfo{Name: "mail.example.com", TLS: true, Auth: []string{"LOGIN"}}); err != nil || mech != "LOGIN" {
		t.Fatalf("LOGIN over TLS: %q %v", mech, err)
	}
}
