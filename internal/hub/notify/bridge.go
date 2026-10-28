package hubnotify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/notify"
)

// Bridge ruft die PHP-Bruecke des Portals (hc2_send.php) auf, die Mail, SMS
// und App-Push ueber die vorhandene Infrastruktur verschickt. Anfragen sind
// mit HMAC-SHA256 ueber den Body signiert; der Zeitstempel verhindert Replay.
type Bridge struct {
	URL    string
	Secret []byte
	UA     string
	client *http.Client
}

// NewBridge erzeugt die Bruecke.
func NewBridge(url string, secret []byte, ua string) *Bridge {
	return &Bridge{URL: url, Secret: secret, UA: ua, client: &http.Client{Timeout: 20 * time.Second}}
}

type bridgeRequest struct {
	Type    string `json:"type"` // mail, sms, app
	To      string `json:"to"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`
	UpDown  string `json:"updown"` // "0" down, "1" up, "" neutral
	UserID  int64  `json:"userid"`
	TS      int64  `json:"ts"`
	EventID string `json:"event_id"`
}

// Send schickt eine Anfrage an die Bruecke.
func (b *Bridge) Send(ctx context.Context, req bridgeRequest) error {
	if b == nil || b.URL == "" {
		return errors.New("bridge not configured")
	}
	req.TS = time.Now().Unix()
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, b.Secret)
	mac.Write(body)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, b.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", b.UA)
	r.Header.Set("X-HC2-Signature", hex.EncodeToString(mac.Sum(nil)))
	resp, err := b.client.Do(r)
	if err != nil {
		return notify.Temporary(err) // Netzwerk oder Zeitueberschreitung: spaeter erneut
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rb, &out)
	if resp.StatusCode != 200 || !out.OK {
		msg := strings.TrimSpace(out.Error)
		if msg == "" {
			msg = strings.TrimSpace(string(rb))
			if len(msg) > 200 {
				msg = msg[:200]
			}
		}
		err := fmt.Errorf("bridge HTTP %d: %s", resp.StatusCode, msg)
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout {
			return notify.Temporary(err) // Portal ueberlastet oder gestoert: spaeter erneut
		}
		return err
	}
	return nil
}

func updown(k notify.Kind) string {
	switch k {
	case notify.KindDown, notify.KindReminder, notify.KindFlappingStart, notify.KindSummary, notify.KindDegraded, notify.KindUnchecked:
		return "0"
	case notify.KindUp, notify.KindFlappingEnd, notify.KindDegradedEnd, notify.KindRechecked:
		return "1"
	}
	return ""
}

// mailSender: ipv64_mail (Account- oder verifizierte Adresse, Versand ueber ipv64).
type mailSender struct{ b *Bridge }

func (m mailSender) Send(ctx context.Context, ch *notify.Channel, msg notify.Message) error {
	to := strings.TrimSpace(ch.Config["email"])
	if to == "" {
		return errors.New("ipv64_mail: no address")
	}
	// vollstaendige Mail (Betreff, Textteil, HTML im ipv64-Design); das Portal verschickt sie unveraendert
	subject, text, htmlBody := notify.MailContent(msg, notify.MailBrand{Name: "IPv64.net Healthchecks", ManageURL: "https://ipv64.net/notifications.php"})
	return m.b.Send(ctx, bridgeRequest{Type: "mail", To: to, Subject: subject, Text: text, HTML: htmlBody, UpDown: updown(msg.Kind), UserID: ch.UserID, EventID: msg.EventID})
}

// smsSender: ipv64_sms mit Tageslimit.
type smsSender struct {
	b  *Bridge
	st *Store
}

func (s smsSender) Send(ctx context.Context, ch *notify.Channel, msg notify.Message) error {
	num, err := notify.SMSNumber(ch.Config["number"])
	if err != nil {
		return errors.New("ipv64_sms: " + err.Error())
	}
	ok, err := s.st.SMSAllowed(ctx, ch.UserID)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("ipv64_sms: daily limit reached")
	}
	text := msg.Title
	if first := strings.SplitN(msg.Text, "\n", 3); len(first) > 1 {
		text += " - " + first[1]
	}
	text = truncRunes(smsText(text), 300) // zeichengenau, sonst zerschneidet es Umlaute
	return s.b.Send(ctx, bridgeRequest{Type: "sms", To: num, Text: text, UpDown: updown(msg.Kind), UserID: ch.UserID, EventID: msg.EventID})
}

// appSender: Push an die ipv64-App (Firebase) ueber die Bruecke.
type appSender struct{ b *Bridge }

func (a appSender) Send(ctx context.Context, ch *notify.Channel, msg notify.Message) error {
	tok := strings.TrimSpace(ch.Config["device_token"])
	if tok == "" {
		return errors.New("app: no device token")
	}
	return a.b.Send(ctx, bridgeRequest{Type: "app", To: tok, Subject: msg.Title, Text: msg.Check.Name, UpDown: updown(msg.Kind), UserID: ch.UserID, EventID: msg.EventID})
}

// relaySender: Node-Kanaele (Execution "node") werden als Sendeauftrag an die
// Node gegeben, alle anderen direkt gesendet.
type relaySender struct {
	inner notify.Sender
	st    *Store
}

func (r relaySender) Send(ctx context.Context, ch *notify.Channel, m notify.Message) error {
	if ch.Execution == "node" {
		nodeID := r.st.NodeOfChannel(ch.ID)
		if nodeID == "" {
			return errors.New("node channel without node")
		}
		return r.st.AddSendOrder(ctx, nodeID, ch, m)
	}
	if r.inner == nil {
		return errors.New("no sender for type " + string(ch.Type))
	}
	return r.inner.Send(ctx, ch, m)
}

// Senders liefert alle Sender des Servers: die der Node plus Bruecken-Typen;
// Node-Kanaele werden weitergereicht.
func Senders(version string, b *Bridge, st *Store) map[notify.Type]notify.Sender {
	// Nur oeffentliche Ziele: die Kanal-Adressen (Webhook, ntfy, Gotify, SMTP, Matrix ...) bestimmt der Nutzer,
	// der hub verbindet sich nie mit Loopback, privaten Netzen, Link-Local, ULA oder Metadaten-Adressen
	m := notify.SendersPublicOnly(version)
	m[notify.TypeIPv64Mail] = mailSender{b}
	m[notify.TypeIPv64SMS] = smsSender{b, st}
	m[notify.TypeApp] = appSender{b}
	// Browser-Kanaele gibt es nur an der Node; der hub reicht sie als Sendeauftrag weiter
	m[notify.TypeBrowser] = nodeOnlySender{}
	// Home Assistant steht im LAN der Node: der hub ruft keine solchen Adressen auf
	m[notify.TypeHomeAssistant] = nodeOnlySender{}
	out := map[notify.Type]notify.Sender{}
	for t, snd := range m {
		out[t] = relaySender{inner: snd, st: st}
	}
	return out
}

// nodeOnlySender: Typen, die nur eine Node selbst ausliefern kann (z. B. Browser).
type nodeOnlySender struct{}

func (nodeOnlySender) Send(context.Context, *notify.Channel, notify.Message) error {
	return errors.New("this channel type can only be delivered by its node")
}

// smsText entfernt Emoji und Bildzeichen, die viele SMS-Gateways nicht uebertragen.
func smsText(in string) string {
	var b strings.Builder
	for _, r := range in {
		if r > 0xFFFF || unicode.Is(unicode.So, r) || r == 0xFE0F || r == 0x200D {
			continue
		}
		b.WriteRune(r)
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// truncRunes kuerzt auf hoechstens max Bytes, ohne ein UTF-8-Zeichen zu zerschneiden.
func truncRunes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
}
