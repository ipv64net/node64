package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Kind der Nachricht.
type Kind string

const (
	KindDown          Kind = "down"
	KindUp            Kind = "up"
	KindFlappingStart Kind = "flapping_start"
	KindFlappingEnd   Kind = "flapping_end"
	KindDegraded      Kind = "degraded" // teilweise gestoert (mehrere Messstellen)
	KindDegradedEnd   Kind = "degraded_end"
	KindReminder      Kind = "reminder"
	KindSummary       Kind = "summary"
	KindTest          Kind = "test"
)

// CheckInfo sind die Angaben zum Check, die in Nachrichten erscheinen.
type CheckInfo struct {
	UserID         int64 // Account auf dem Server; im Node 0
	Token          string
	Name           string
	Type           string
	Target         string
	Critical       bool
	Channels       []int64 // leer = Standardkanaele
	NotifyDown     bool
	NotifyUp       bool
	NotifyDegraded bool
}

// Message ist die fertig formulierte Nachricht fuer einen Sender.
type Message struct {
	Kind     Kind
	Title    string
	Text     string
	Priority int // 1 niedrig ... 5 hoch
	URL      string
	Time     time.Time
	Check    CheckInfo
	EventID  string
	Payload  map[string]any // fuer Webhooks
	Language string
}

// Sender verschickt eine Nachricht ueber einen Kanal.
type Sender interface {
	Send(ctx context.Context, ch *Channel, m Message) error
}

var httpClient = &http.Client{Timeout: 20 * time.Second}

// Senders liefert die eingebauten Sender je Typ.
func Senders(version string) map[Type]Sender {
	ua := "node64/" + version
	return map[Type]Sender{
		TypeSMTP: smtpSender{}, TypeTelegram: telegramSender{ua}, TypeDiscord: discordSender{ua},
		TypeNtfy: ntfySender{ua}, TypeGotify: gotifySender{ua}, TypeWebhook: webhookSender{ua}, TypePushover: pushoverSender{ua},
	}
}

// ---------------------------------------------------------------- Pushover

type pushoverSender struct{ ua string }

func (p pushoverSender) Send(ctx context.Context, ch *Channel, m Message) error {
	prio := ch.Config["priority_up"]
	if m.Kind == KindDown || m.Kind == KindReminder || m.Kind == KindFlappingStart || m.Kind == KindSummary || m.Kind == KindDegraded {
		prio = ch.Config["priority_down"]
	}
	if prio == "" {
		prio = "0"
	}
	form := url.Values{"token": {ch.Config["app_token"]}, "user": {ch.Config["user_key"]}, "title": {m.Title}, "message": {m.Text}, "priority": {prio}}
	if m.URL != "" {
		form.Set("url", m.URL)
	}
	if ch.Config["device"] != "" {
		form.Set("device", ch.Config["device"])
	}
	if prio == "2" { // Notfall: Pushover verlangt Wiederholung und Ablauf
		form.Set("retry", "60")
		form.Set("expire", "3600")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.pushover.net/1/messages.json", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", p.ua)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != 200 {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(rb, &e)
		if len(e.Errors) > 0 {
			return fmt.Errorf("pushover: %s", strings.Join(e.Errors, "; "))
		}
		return httpErr(resp.StatusCode, rb)
	}
	return nil
}

func postJSON(ctx context.Context, ua, u string, body any, headers map[string]string) ([]byte, int, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ua)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return rb, resp.StatusCode, nil
}

func httpErr(status int, body []byte) error {
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		s = s[:200]
	}
	return fmt.Errorf("HTTP %d: %s", status, s)
}

// ---------------------------------------------------------------- Telegram

type telegramSender struct{ ua string }

func (t telegramSender) Send(ctx context.Context, ch *Channel, m Message) error {
	text := "<b>" + html.EscapeString(m.Title) + "</b>\n" + html.EscapeString(m.Text)
	if m.URL != "" {
		text += "\n<a href=\"" + html.EscapeString(m.URL) + "\">Details</a>"
	}
	body := map[string]any{"chat_id": ch.Config["chat_id"], "text": text, "parse_mode": "HTML", "disable_web_page_preview": true,
		"disable_notification": ch.Config["silent"] == "true"}
	rb, status, err := postJSON(ctx, t.ua, "https://api.telegram.org/bot"+url.PathEscape(ch.Config["bot_token"])+"/sendMessage", body, nil)
	if err != nil {
		return err
	}
	if status != 200 {
		var e struct {
			Description string `json:"description"`
		}
		_ = json.Unmarshal(rb, &e)
		if e.Description != "" {
			return fmt.Errorf("telegram: %s", e.Description)
		}
		return httpErr(status, rb)
	}
	return nil
}

// ---------------------------------------------------------------- Discord

type discordSender struct{ ua string }

func (d discordSender) Send(ctx context.Context, ch *Channel, m Message) error {
	color := 0x6c757d
	switch m.Kind {
	case KindDown, KindReminder, KindSummary:
		color = 0xdc3545
	case KindUp, KindFlappingEnd:
		color = 0x28a745
	case KindFlappingStart:
		color = 0xffc107
	}
	embed := map[string]any{"title": m.Title, "description": m.Text, "color": color, "timestamp": m.Time.UTC().Format(time.RFC3339)}
	if m.URL != "" {
		embed["url"] = m.URL
	}
	body := map[string]any{"embeds": []any{embed}}
	if u := ch.Config["username"]; u != "" {
		body["username"] = u
	}
	rb, status, err := postJSON(ctx, d.ua, ch.Config["webhook_url"], body, nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return httpErr(status, rb)
	}
	return nil
}

// ---------------------------------------------------------------- ntfy

type ntfySender struct{ ua string }

func (n ntfySender) Send(ctx context.Context, ch *Channel, m Message) error {
	u := strings.TrimRight(ch.Config["server"], "/") + "/" + url.PathEscape(ch.Config["topic"])
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(m.Text))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", n.ua)
	req.Header.Set("Title", m.Title)
	prio := ch.Config["priority_up"]
	tags := "green_circle"
	switch m.Kind {
	case KindDown, KindReminder, KindSummary:
		prio, tags = ch.Config["priority_down"], "red_circle"
	case KindFlappingStart:
		tags = "orange_circle"
	case KindTest:
		tags = "white_check_mark"
	}
	if prio == "" {
		prio = "3"
	}
	req.Header.Set("Priority", prio)
	req.Header.Set("Tags", tags)
	if m.URL != "" {
		req.Header.Set("Click", m.URL)
	}
	if tok := ch.Config["token"]; tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	} else if ch.Config["user"] != "" {
		req.SetBasicAuth(ch.Config["user"], ch.Config["password"])
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return httpErr(resp.StatusCode, rb)
	}
	return nil
}

// ---------------------------------------------------------------- Gotify

type gotifySender struct{ ua string }

func (g gotifySender) Send(ctx context.Context, ch *Channel, m Message) error {
	prio, _ := strconv.Atoi(ch.Config["priority"])
	if prio == 0 {
		prio = 5
	}
	if m.Kind == KindUp || m.Kind == KindFlappingEnd {
		prio = max(1, prio-2)
	}
	body := map[string]any{"title": m.Title, "message": m.Text, "priority": prio}
	if m.URL != "" {
		body["extras"] = map[string]any{"client::notification": map[string]any{"click": map[string]any{"url": m.URL}}}
	}
	u := strings.TrimRight(ch.Config["server"], "/") + "/message"
	rb, status, err := postJSON(ctx, g.ua, u, body, map[string]string{"X-Gotify-Key": ch.Config["app_token"]})
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return httpErr(status, rb)
	}
	return nil
}

// ---------------------------------------------------------------- Webhook

type webhookSender struct{ ua string }

func (w webhookSender) Send(ctx context.Context, ch *Channel, m Message) error {
	method := strings.ToUpper(ch.Config["method"])
	if method == "" {
		method = http.MethodPost
	}
	var body io.Reader
	ctype := "application/json"
	if tpl := ch.Config["body"]; strings.TrimSpace(tpl) != "" {
		body = strings.NewReader(fillTemplate(tpl, m))
		if !strings.HasPrefix(strings.TrimSpace(tpl), "{") {
			ctype = "text/plain; charset=utf-8"
		}
	} else if method != http.MethodGet {
		b, _ := json.Marshal(m.Payload)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, ch.Config["url"], body)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", w.ua)
	if body != nil {
		req.Header.Set("Content-Type", ctype)
	}
	for _, line := range strings.Split(ch.Config["headers"], "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) != "" {
			req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	client := httpClient
	if ch.Config["insecure_tls"] == "true" {
		client = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // bewusst per Option
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return httpErr(resp.StatusCode, rb)
	}
	return nil
}

// fillTemplate ersetzt {{feld}} in eigenen Webhook-Bodys.
func fillTemplate(tpl string, m Message) string {
	q := func(s string) string {
		b, _ := json.Marshal(s)
		return strings.Trim(string(b), `"`)
	}
	r := strings.NewReplacer(
		"{{title}}", q(m.Title), "{{text}}", q(m.Text), "{{kind}}", string(m.Kind), "{{event_id}}", m.EventID,
		"{{name}}", q(m.Check.Name), "{{token}}", m.Check.Token, "{{type}}", m.Check.Type, "{{target}}", q(m.Check.Target),
		"{{url}}", m.URL, "{{time}}", m.Time.UTC().Format(time.RFC3339),
		"{{status}}", fmt.Sprint(m.Payload["status"]), "{{reason}}", q(fmt.Sprint(m.Payload["reason"])), "{{message}}", q(fmt.Sprint(m.Payload["message"])),
	)
	return r.Replace(tpl)
}

// ---------------------------------------------------------------- SMTP

type smtpSender struct{}

func (smtpSender) Send(ctx context.Context, ch *Channel, m Message) error {
	host := ch.Config["host"]
	port := ch.Config["port"]
	if port == "" {
		port = "587"
	}
	addr := net.JoinHostPort(host, port)
	security := ch.Config["security"]
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, Deadline: deadline}
	var conn net.Conn
	var err error
	if security == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	_ = conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if security == "starttls" {
		if okTLS, _ := c.Extension("STARTTLS"); !okTLS {
			return errors.New("server does not offer STARTTLS")
		}
		if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if user := ch.Config["user"]; user != "" {
		var auth smtp.Auth
		if okAuth, kinds := c.Extension("AUTH"); okAuth && strings.Contains(kinds, "CRAM-MD5") && security == "none" {
			auth = smtp.CRAMMD5Auth(user, ch.Config["password"])
		} else {
			auth = smtp.PlainAuth("", user, ch.Config["password"], host)
		}
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	from := ch.Config["from"]
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("from: %w", err)
	}
	tos := splitList(ch.Config["to"])
	for _, to := range tos {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("to %s: %w", to, err)
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", from)
	fmt.Fprintf(&buf, "To: %s\r\n", strings.Join(tos, ", "))
	fmt.Fprintf(&buf, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", m.Title))
	fmt.Fprintf(&buf, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "Message-ID: <%s.%d@node64>\r\n", m.EventID, time.Now().UnixNano())
	buf.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\nX-Mailer: node64\r\n\r\n")
	text := m.Text
	if m.URL != "" {
		text += "\n\n" + m.URL
	}
	buf.WriteString(strings.ReplaceAll(text, "\n", "\r\n"))
	buf.WriteString("\r\n")
	if _, err := wc.Write(buf.Bytes()); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}
