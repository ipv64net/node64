package notify

import (
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMailContentAndMIME(t *testing.T) {
	m := Message{Kind: KindDown, Title: "🔴 <Router> ist gestört", Language: "de", URL: "https://ipv64.net/healthchecks2/check.php?token=abc",
		Check: CheckInfo{Token: "abc", Name: "<Router>"}, Time: time.Now(),
		Text: "Check: <Router> (Ping)\nZiel: 192.168.10.1\nGrund: Zeitüberschreitung\nZeit: 12.10.2026 16:00\nNode: Pi im Keller"}
	subject, text, html := MailContent(m, MailBrand{Name: "IPv64.net Healthchecks", ManageURL: "https://ipv64.net/notifications.php"})
	if subject != "<Router> ist gestört" {
		t.Fatalf("subject without emoji: %q", subject)
	}
	if strings.Contains(html, "<Router>") || !strings.Contains(html, "&lt;Router&gt;") {
		t.Fatal("check name must be escaped in HTML")
	}
	for _, bad := range []string{"<script", "<img", "<link", "http://", "@import"} {
		if strings.Contains(html, bad) {
			t.Fatalf("HTML must not contain %q", bad)
		}
	}
	if !strings.Contains(text, "Ziel: 192.168.10.1") || !strings.Contains(text, "Check öffnen: https://ipv64.net/") || !strings.Contains(text, "Benachrichtigungen verwalten") {
		t.Fatalf("text part:\n%s", text)
	}
	raw := string(BuildMail(mail.Address{Name: "IPv64.net Healthchecks", Address: "no-reply@ipv64.net"}, []string{"a@example.com"}, subject, text, html))
	for _, h := range []string{"Auto-Submitted: auto-generated", "MIME-Version: 1.0", "multipart/alternative", "Content-Type: text/plain; charset=utf-8", "Content-Type: text/html; charset=utf-8", "@ipv64.net>", "Date: "} {
		if !strings.Contains(raw, h) {
			t.Fatalf("missing %q in\n%s", h, raw[:600])
		}
	}
	for _, line := range strings.Split(raw, "\r\n") {
		if len(line) > 78 && !strings.HasPrefix(line, "Content-Type") && !strings.HasPrefix(line, "Subject") {
			t.Fatalf("line too long (%d): %q", len(line), line)
		}
	}
	if strings.Contains(strings.ReplaceAll(raw, "\r\n", ""), "\n") {
		t.Fatal("bare LF in message")
	}
	if dir := os.Getenv("MAIL_SAMPLES"); dir != "" {
		samples := map[string]Message{
			"down": m,
			"up": {Kind: KindUp, Title: "🟢 Router wieder OK", Language: "de", URL: m.URL, Check: CheckInfo{Token: "abc"},
				Text: "Check: Router (Ping)\nZiel: 192.168.10.1\nDauer: 4 Minuten\nZeit: 12.10.2026 16:04\nNode: Pi im Keller"},
			"summary": {Kind: KindSummary, Title: "🔴 3 Checks gestört", Language: "de", URL: "https://ipv64.net/healthchecks2/index.php?state=down",
				Text: "• Router: Zeitüberschreitung\n• Webserver: HTTP 502\n• NAS: Port 445 geschlossen\nNode: Pi im Keller"},
			"code": {Kind: KindTest, Title: "IPv64.net: Bestätigungscode", Language: "de", URL: "https://ipv64.net/notifications.php",
				Text: "Dein Code zur Bestätigung des Benachrichtigungskanals \"Dennis Mail\": 482913\nGültig 15 Minuten."},
		}
		for name, s := range samples {
			_, _, h := MailContent(s, MailBrand{Name: "IPv64.net Healthchecks", ManageURL: "https://ipv64.net/notifications.php"})
			_ = os.WriteFile(filepath.Join(dir, "mail_"+name+".html"), []byte(h), 0o644)
		}
		_ = os.WriteFile(filepath.Join(dir, "mail_down.eml"), []byte(raw), 0o644)
	}
}
