package notify

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"
	"unicode"
)

// MailBrand bestimmt Absendername und Links einer Benachrichtigungs-Mail.
type MailBrand struct {
	Name      string // z. B. "IPv64.net Healthchecks" oder "Node64"
	ManageURL string // Seite der Benachrichtigungs-Einstellungen (Fusszeile)
}

// mailLabels: feste Texte der Mail-Vorlage (die Nachricht selbst ist schon uebersetzt).
var mailLabels = map[string]map[string]string{
	"de": {"open": "Check öffnen", "list": "Übersicht öffnen", "auto": "Automatische Benachrichtigung von %s.", "manage": "Benachrichtigungen verwalten",
		"down": "Störung", "up": "Wieder OK", "warn": "Teilweise gestört", "attention": "Achtung", "info": "Information"},
	"en": {"open": "Open check", "list": "Open overview", "auto": "Automatic notification from %s.", "manage": "Manage notifications",
		"down": "Down", "up": "Recovered", "warn": "Partially down", "attention": "Warning", "info": "Information"},
}

// mailStatus liefert Farbe und Bezeichnung des Statusbalkens.
func mailStatus(k Kind, lang string) (color, label string) {
	l := mailLabels[lang]
	if l == nil {
		l = mailLabels["de"]
	}
	switch k { // Balken passend zum Betreff (auch Modul-Meldungen: Proxmox/Docker, DynDNS, DNS64, Zertifikate, CDN64, Cluster)
	case KindDown, KindReminder, KindSummary, KindProxmoxDown, KindDynFail, KindDNS64Down, KindDNS64Lists, KindDNS64Cert, KindCertFail,
		KindCDNOnlineDown, KindCDNOnlineBlocked, KindClusterDown, KindHoneypotWatch, KindHoneypotLogin, KindUpdateFailed:
		return "#d63939", l["down"]
	case KindUp, KindFlappingEnd, KindDegradedEnd, KindSummaryUp, KindRechecked, KindProxmoxUp, KindProxmoxThresholdOK, KindDynOK, KindDNS64Up,
		KindCertOK, KindCDNOnlineUp, KindClusterUp, KindUpdateOK:
		return "#2fb344", l["up"]
	case KindDegraded:
		return "#f59f00", l["warn"]
	case KindFlappingStart, KindQuota, KindProxmoxThreshold, KindCertExpiry, KindDynLimit, KindUnchecked:
		return "#f59f00", l["attention"]
	}
	return "#17bebb", l["info"]
}

// MailSubject: Betreff ohne Emoji und Symbole am Anfang (Spamfilter werten sie ab, die Farbe zeigt der Balken).
func MailSubject(title string) string {
	return strings.TrimLeftFunc(title, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.Is(unicode.So, r) || unicode.Is(unicode.Sk, r) || r == 0xFE0F || r == 0x200D
	})
}

// MailContent baut Betreff, Textteil und HTML-Teil einer Benachrichtigung. Das HTML kommt ohne externe
// Bilder, Skripte oder Stylesheets aus (alle Stile inline) und entspricht inhaltlich dem Textteil.
func MailContent(m Message, b MailBrand) (subject, text, htmlBody string) {
	lang := m.Language
	if mailLabels[lang] == nil {
		lang = "de"
	}
	l := mailLabels[lang]
	subject = MailSubject(m.Title)
	color, status := mailStatus(m.Kind, lang)
	button := l["open"]
	if m.Check.Token == "" {
		button = l["list"]
	}

	// Textteil
	var t strings.Builder
	t.WriteString(subject + "\n\n" + strings.TrimSpace(m.Text) + "\n")
	if m.URL != "" {
		t.WriteString("\n" + button + ": " + m.URL + "\n")
	}
	t.WriteString("\n-- \n" + fmt.Sprintf(l["auto"], b.Name) + "\n")
	if b.ManageURL != "" {
		t.WriteString(l["manage"] + ": " + b.ManageURL + "\n")
	}
	text = t.String()

	// HTML-Teil: Zeilen "Bezeichnung: Wert" als Tabelle, uebrige als Absatz
	esc := html.EscapeString
	var rows, paras strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(m.Text), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if k, v, ok := strings.Cut(line, ": "); ok && !strings.HasPrefix(line, "•") && len([]rune(k)) <= 24 {
			fmt.Fprintf(&rows, `<tr><td style="padding:6px 12px 6px 0;color:#667382;white-space:nowrap;vertical-align:top">%s</td><td style="padding:6px 0;color:#1d273b;word-break:break-word">%s</td></tr>`, esc(k), esc(v))
			continue
		}
		fmt.Fprintf(&paras, `<p style="margin:0 0 8px 0;color:#1d273b">%s</p>`, esc(line))
	}
	var h strings.Builder
	fmt.Fprintf(&h, `<!DOCTYPE html><html lang="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title></head>`, lang, esc(subject))
	h.WriteString(`<body style="margin:0;padding:0;background:#f1f1f1;font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.5">`)
	h.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f1f1"><tr><td align="center" style="padding:24px 12px">`)
	h.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;background:#ffffff;border-radius:8px;overflow:hidden">`)
	fmt.Fprintf(&h, `<tr><td style="padding:18px 24px;border-bottom:1px solid #e6e7e9;font-size:18px;font-weight:bold;color:#17bebb">%s</td></tr>`, esc(b.Name))
	fmt.Fprintf(&h, `<tr><td style="padding:10px 24px;background:%s;color:#ffffff;font-weight:bold;letter-spacing:.3px">%s</td></tr>`, color, esc(status))
	fmt.Fprintf(&h, `<tr><td style="padding:20px 24px 8px 24px"><h1 style="margin:0 0 12px 0;font-size:20px;line-height:1.3;color:#1d273b">%s</h1>`, esc(subject))
	h.WriteString(paras.String())
	if rows.Len() > 0 {
		h.WriteString(`<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;font-size:14px">` + rows.String() + `</table>`)
	}
	h.WriteString(`</td></tr>`)
	if m.URL != "" {
		fmt.Fprintf(&h, `<tr><td style="padding:12px 24px 24px 24px"><a href="%s" style="display:inline-block;padding:10px 18px;background:#17bebb;color:#ffffff;text-decoration:none;border-radius:6px;font-weight:bold">%s</a></td></tr>`, esc(m.URL), esc(button))
	}
	fmt.Fprintf(&h, `<tr><td style="padding:14px 24px;border-top:1px solid #e6e7e9;font-size:12px;color:#667382">%s`, esc(fmt.Sprintf(l["auto"], b.Name)))
	if b.ManageURL != "" {
		fmt.Fprintf(&h, ` <a href="%s" style="color:#667382">%s</a>`, esc(b.ManageURL), esc(l["manage"]))
	}
	h.WriteString(`</td></tr></table></td></tr></table></body></html>`)
	return subject, text, h.String()
}

// BuildMail erzeugt eine vollstaendige MIME-Nachricht (multipart/alternative, quoted-printable, CRLF)
// mit den Kopfzeilen, die Spamfilter bei automatischen Mails erwarten.
func BuildMail(from mail.Address, to []string, subject, text, htmlBody string) []byte {
	var buf bytes.Buffer
	boundary := randomHex(12)
	domain := "localhost"
	if i := strings.LastIndex(from.Address, "@"); i >= 0 {
		domain = from.Address[i+1:]
	}
	hdr := func(k, v string) { fmt.Fprintf(&buf, "%s: %s\r\n", k, v) }
	hdr("From", from.String())
	hdr("To", strings.Join(to, ", "))
	hdr("Subject", mime.QEncoding.Encode("utf-8", subject))
	hdr("Date", time.Now().Format(time.RFC1123Z))
	hdr("Message-ID", "<"+randomHex(16)+"@"+domain+">")
	hdr("MIME-Version", "1.0")
	hdr("Auto-Submitted", "auto-generated")
	hdr("X-Auto-Response-Suppress", "All")
	hdr("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	buf.WriteString("\r\n")
	part := func(ctype, body string) {
		fmt.Fprintf(&buf, "--%s\r\nContent-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", boundary, ctype)
		qp := quotedprintable.NewWriter(&buf)
		_, _ = qp.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")))
		_ = qp.Close()
		buf.WriteString("\r\n")
	}
	part("text/plain", text)
	part("text/html", htmlBody)
	fmt.Fprintf(&buf, "--%s--\r\n", boundary)
	return buf.Bytes()
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
