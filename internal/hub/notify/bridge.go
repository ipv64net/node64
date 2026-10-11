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
	"html"
	"io"
	"net/http"
	"strings"
	"time"

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
		return err
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
		return fmt.Errorf("bridge HTTP %d: %s", resp.StatusCode, msg)
	}
	return nil
}

func updown(k notify.Kind) string {
	switch k {
	case notify.KindDown, notify.KindReminder, notify.KindFlappingStart, notify.KindSummary, notify.KindDegraded:
		return "0"
	case notify.KindUp, notify.KindFlappingEnd, notify.KindDegradedEnd:
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
	htmlBody := "<p><strong>" + html.EscapeString(msg.Title) + "</strong></p><p>" + strings.ReplaceAll(html.EscapeString(msg.Text), "\n", "<br>") + "</p>"
	if msg.URL != "" {
		htmlBody += "<p><a href=\"" + html.EscapeString(msg.URL) + "\">" + html.EscapeString(msg.URL) + "</a></p>"
	}
	return m.b.Send(ctx, bridgeRequest{Type: "mail", To: to, Subject: msg.Title, Text: msg.Text, HTML: htmlBody, UpDown: updown(msg.Kind), UserID: ch.UserID, EventID: msg.EventID})
}

// smsSender: ipv64_sms mit Tageslimit.
type smsSender struct {
	b  *Bridge
	st *Store
}

func (s smsSender) Send(ctx context.Context, ch *notify.Channel, msg notify.Message) error {
	num := strings.TrimSpace(ch.Config["number"])
	if num == "" {
		return errors.New("ipv64_sms: no number")
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
	if len(text) > 300 {
		text = text[:300]
	}
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
	m := notify.Senders(version)
	m[notify.TypeIPv64Mail] = mailSender{b}
	m[notify.TypeIPv64SMS] = smsSender{b, st}
	m[notify.TypeApp] = appSender{b}
	out := map[notify.Type]notify.Sender{}
	for t, snd := range m {
		out[t] = relaySender{inner: snd, st: st}
	}
	return out
}
