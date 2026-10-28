package notify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Chat-Kanaele: Matrix (Client-Server-API mit Zugriffstoken), Slack (Incoming Webhook) und Microsoft Teams
// (Workflows-Webhook „Wenn eine Teams-Webhookanforderung empfangen wird“, Adaptive Card). Die Farbe folgt dem
// Statusbalken der Mails (rot Stoerung, gruen Entwarnung, orange Achtung, sonst Hinweis).

// matrixRoom: Raum-ID (!abc:server) oder Alias (#raum:server).
var matrixRoom = regexp.MustCompile(`^[!#][^:\s]+:[^\s]+$`)

// chatLines: Titel und Text als Zeilen (leere Zeilen weg).
func chatLines(text string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(text), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// ---------------------------------------------------------------- Matrix

type matrixSender struct{ ua string }

func (s matrixSender) Send(ctx context.Context, ch *Channel, m Message) error {
	server := strings.TrimRight(ch.Config["server"], "/")
	token := ch.Config["token"]
	room := strings.TrimSpace(ch.Config["room"])
	if strings.HasPrefix(room, "#") { // Alias: Raum-ID beim Server nachschlagen
		var out struct {
			RoomID string `json:"room_id"`
		}
		if err := s.call(ctx, http.MethodGet, server+"/_matrix/client/v3/directory/room/"+url.PathEscape(room), token, nil, &out); err != nil {
			return err
		}
		if out.RoomID == "" {
			return fmt.Errorf("matrix: alias %s not found", room)
		}
		room = out.RoomID
	}
	plain := m.Title + "\n" + m.Text
	color, _ := mailStatus(m.Kind, m.Language)
	formatted := `<b><span data-mx-color="` + color + `">` + html.EscapeString(m.Title) + `</span></b>`
	for _, l := range chatLines(m.Text) {
		formatted += "<br>" + html.EscapeString(l)
	}
	if m.URL != "" {
		plain += "\n" + m.URL
		formatted += `<br><a href="` + html.EscapeString(m.URL) + `">Details</a>`
	}
	// m.notice: Bots antworten nicht auf Hinweise (keine Schleifen); Transaktions-ID je Ereignis und Kanal
	sum := sha256.Sum256([]byte(m.EventID + "|" + strconv.FormatInt(ch.ID, 10) + "|" + m.Title + "|" + strconv.FormatInt(time.Now().UnixNano(), 10)))
	txn := "node64-" + hex.EncodeToString(sum[:12])
	body := map[string]any{"msgtype": "m.notice", "body": plain, "format": "org.matrix.custom.html", "formatted_body": formatted}
	return s.call(ctx, http.MethodPut, server+"/_matrix/client/v3/rooms/"+url.PathEscape(room)+"/send/m.room.message/"+txn, token, body, nil)
}

func (s matrixSender) call(ctx context.Context, method, u, token string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", s.ua)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return netErr(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Code  string `json:"errcode"`
			Error string `json:"error"`
		}
		if json.Unmarshal(rb, &e) == nil && e.Code != "" {
			return statusErr(resp.StatusCode, fmt.Errorf("matrix: %s %s", e.Code, excerpt(e.Error)))
		}
		return httpErr(resp.StatusCode, rb)
	}
	if out != nil {
		return json.Unmarshal(rb, out)
	}
	return nil
}

// ---------------------------------------------------------------- Slack

type slackSender struct{ ua string }

// slackEsc: Steuerzeichen von mrkdwn (&, <, >) maskieren.
func slackEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func (s slackSender) Send(ctx context.Context, ch *Channel, m Message) error {
	color, _ := mailStatus(m.Kind, m.Language)
	text := "*" + slackEsc(m.Title) + "*"
	for _, l := range chatLines(m.Text) {
		text += "\n" + slackEsc(l)
	}
	blocks := []any{map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": text}}}
	if m.URL != "" {
		blocks = append(blocks, map[string]any{"type": "actions", "elements": []any{map[string]any{"type": "button",
			"text": map[string]any{"type": "plain_text", "text": "Details"}, "url": m.URL}}})
	}
	// text = Vorschau in der Benachrichtigung; die Farbe als Leiste der Anlage
	body := map[string]any{"text": m.Title, "attachments": []any{map[string]any{"color": color, "blocks": blocks}}}
	rb, status, err := postJSON(ctx, s.ua, ch.Config["webhook_url"], body, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("slack: %w", httpErr(status, rb))
	}
	return nil
}

// ---------------------------------------------------------------- Microsoft Teams

type teamsSender struct{ ua string }

func (s teamsSender) Send(ctx context.Context, ch *Channel, m Message) error {
	style := "accent" // Adaptive-Card-Farben: attention (rot), good (gruen), warning (orange)
	switch color, _ := mailStatus(m.Kind, m.Language); color {
	case "#d63939":
		style = "attention"
	case "#2fb344":
		style = "good"
	case "#f59f00":
		style = "warning"
	}
	items := []any{map[string]any{"type": "TextBlock", "text": m.Title, "weight": "Bolder", "size": "Medium", "color": style, "wrap": true}}
	for _, l := range chatLines(m.Text) {
		items = append(items, map[string]any{"type": "TextBlock", "text": l, "wrap": true, "spacing": "Small"})
	}
	card := map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": items}
	if m.URL != "" {
		card["actions"] = []any{map[string]any{"type": "Action.OpenUrl", "title": "Details", "url": m.URL}}
	}
	body := map[string]any{"type": "message", "attachments": []any{map[string]any{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": nil, "content": card}}}
	rb, status, err := postJSON(ctx, s.ua, ch.Config["webhook_url"], body, nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 { // Workflows antwortet mit 202 Accepted
		return fmt.Errorf("teams: %w", httpErr(status, rb))
	}
	return nil
}
