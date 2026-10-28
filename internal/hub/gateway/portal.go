package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/hub/store"
	"github.com/ipv64net/node64/internal/notify"
)

// Portal -> hub: signierte Aufrufe aus den PHP-Seiten (gleiches Geheimnis wie die Versand-Bruecke,
// HMAC-SHA256 ueber den rohen Body im Header X-HC2-Signature, Zeitstempel ts hoechstens 5 Minuten alt).
//
//	POST /v1/portal/channel-test  {ts, userid, channel_id, kind: test|verify, code?, lang?}
//	  -> {"ok":true} | {"ok":false,"error":"..."}; Node-Kanaele werden als Sendeauftrag an die Node gegeben ("queued").

// SetTrusted setzt IPs ohne Ratenlimit (nur fuer Lasttests gedacht).
func (g *Gateway) SetTrusted(ips []string) {
	g.trusted = map[string]bool{}
	for _, ip := range ips {
		g.trusted[ip] = true
	}
}

// SetPortalSecret aktiviert die Portal-Endpunkte.
func (g *Gateway) SetPortalSecret(secret []byte) { g.portalSecret = secret }

// RegisterPortal haengt die Portal-Routen an den Multiplexer.
func (g *Gateway) RegisterPortal(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/portal/channel-test", g.portalChannelTest)
	mux.HandleFunc("POST /v1/portal/push", g.portalPush)
}

// portalPush nimmt einen Heartbeat von health.php an: Messpunkt, last_push_at und Weitergabe an die
// messenden Nodes an einer Stelle (PushIn). Erreicht PHP keinen hub, speichert es selbst ohne Weitergabe.
//
//	POST /v1/portal/push {ts, token, down, msg, from} -> {"ok":true|false}
func (g *Gateway) portalPush(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TS    int64  `json:"ts"`
		Token string `json:"token"`
		Down  bool   `json:"down"`
		Msg   string `json:"msg"`
		From  string `json:"from"`
	}
	if !g.portalAuth(w, r, &in) {
		return
	}
	if d := time.Since(time.Unix(in.TS, 0)); d > 5*time.Minute || d < -5*time.Minute {
		writeErr(w, http.StatusBadRequest, "stale request")
		return
	}
	if len(in.Token) < 20 || len(in.Token) > 50 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false})
		return
	}
	if !g.limiter.allow("push:"+in.Token, 60, time.Minute) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "limited": true}) // wie am HTTP-Eingang: verworfen
		return
	}
	ok, err := g.st.PushIn(r.Context(), in.Token, in.Down, in.Msg, in.From)
	if errors.Is(err, store.ErrDailyLimit) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "daily_limit": true})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok})
}

type portalReq struct {
	TS        int64  `json:"ts"`
	UserID    int64  `json:"userid"`
	ChannelID int64  `json:"channel_id"`
	Kind      string `json:"kind"`
	Code      string `json:"code"`
	Lang      string `json:"lang"`
}

func (g *Gateway) portalAuth(w http.ResponseWriter, r *http.Request, v any) bool {
	if len(g.portalSecret) == 0 {
		writeErr(w, http.StatusServiceUnavailable, "portal endpoint not configured")
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil || len(body) == 0 {
		writeErr(w, http.StatusBadRequest, "body required")
		return false
	}
	mac := hmac.New(sha256.New, g.portalSecret)
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(r.Header.Get("X-HC2-Signature"))) {
		writeErr(w, http.StatusForbidden, "signature")
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return false
	}
	return true
}

func (g *Gateway) portalChannelTest(w http.ResponseWriter, r *http.Request) {
	var in portalReq
	if !g.portalAuth(w, r, &in) {
		return
	}
	if d := time.Since(time.Unix(in.TS, 0)); d > 5*time.Minute || d < -5*time.Minute {
		writeErr(w, http.StatusBadRequest, "stale request")
		return
	}
	ctx := r.Context()
	list, err := g.nf.ChannelsFor(ctx, in.UserID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	var ch *notify.Channel
	for _, c := range list {
		if c.ID == in.ChannelID {
			ch = c
		}
	}
	if ch == nil {
		writeErr(w, http.StatusNotFound, "channel not found")
		return
	}
	errText, queued, code := g.sendChannelTest(ctx, ch, in.UserID, in.Kind, in.Code, in.Lang)
	if code != 0 {
		writeErr(w, code, errText)
		return
	}
	if errText != "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": errText})
		return
	}
	out := map[string]any{"ok": true}
	if queued {
		out["queued"] = true // die Node schickt selbst (Sendeauftrag)
	}
	writeJSON(w, http.StatusOK, out)
}

// sendChannelTest schickt eine Test- oder Bestaetigungsnachricht ueber einen Kanal (Portal und Node).
// Liefert den Fehlertext des Versands, ob eine Node selbst zustellt, und einen HTTP-Code bei Aufruffehlern.
func (g *Gateway) sendChannelTest(ctx context.Context, ch *notify.Channel, userID int64, kind, code, lang string) (string, bool, int) {
	if lang != "en" {
		lang = "de"
	}
	m := notify.Message{Kind: notify.KindTest, Time: time.Now().UTC(), Language: lang, Priority: 3,
		Check: notify.CheckInfo{UserID: userID, Name: ch.Name}, EventID: "portal-" + strconv.FormatInt(time.Now().UnixNano(), 36),
		URL: "https://ipv64.net/notifications.php"}
	switch kind {
	case "verify": // Code auch im Titel: die SMS besteht nur aus Titel und zweiter Textzeile
		if lang == "en" {
			m.Title, m.Text = "IPv64.net: confirmation code "+code, "Your code to confirm the notification channel \""+ch.Name+"\": "+code+"\nValid for 15 minutes."
		} else {
			m.Title, m.Text = "IPv64.net: Bestätigungscode "+code, "Dein Code zur Bestätigung des Benachrichtigungskanals \""+ch.Name+"\": "+code+"\nGültig 15 Minuten."
		}
	default:
		if lang == "en" {
			m.Title, m.Text = "✅ IPv64.net test notification", "This is a test for channel \""+ch.Name+"\". If you read this, the channel works."
		} else {
			m.Title, m.Text = "✅ IPv64.net Testbenachrichtigung", "Dies ist ein Test für den Kanal \""+ch.Name+"\". Wenn du das liest, funktioniert der Kanal."
		}
	}
	m.Payload = map[string]any{"kind": string(m.Kind), "title": m.Title, "text": m.Text, "time": m.Time.Format(time.RFC3339), "channel": ch.Name}
	s, ok := g.senders[ch.Type]
	if !ok {
		return "no sender for type " + string(ch.Type), false, http.StatusUnprocessableEntity
	}
	sctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	err := s.Send(sctx, ch, m)
	errText := publicError(ch.Type, err) // auch im Protokoll: das sieht der Nutzer im Portal
	if err != nil && errText != err.Error() {
		g.log.Info("channel test failed", "channel", ch.ID, "type", ch.Type, "err", err)
	}
	// Zustellprotokoll und last_used/last_error wie beim Dispatcher
	_ = g.nf.AddDelivery(ctx, notify.Delivery{Time: m.Time, EventID: m.EventID, ChannelID: ch.ID, Channel: ch.Name, Kind: string(m.Kind), OK: err == nil, Error: errText})
	_ = g.nf.Touch(ctx, ch.ID, errText)
	return errText, err == nil && ch.Execution == "node", 0
}

// Kanaltypen, deren Ziel fest ist (ipv64-Bruecke, feste Anbieter-Adresse) oder die der hub gar nicht selbst
// aufruft: deren Fehlertexte gehen unveraendert an Portal und Node.
var fixedTarget = map[notify.Type]bool{notify.TypeIPv64Mail: true, notify.TypeIPv64SMS: true, notify.TypeApp: true,
	notify.TypeBrowser: true, notify.TypeHomeAssistant: true, notify.TypeTelegram: true, notify.TypePushover: true}

var statusRe = regexp.MustCompile(`(?:HTTP|status) (\d{3})`)

// publicError fasst Versandfehler grob zusammen. Bei Kanaelen mit frei waehlbarer Adresse (Webhook, ntfy,
// Gotify, SMTP, Matrix ...) keine Antworttexte des Ziels weitergeben: sonst liesse sich der hub als
// Abfragewerkzeug fuer fremde oder interne Adressen nutzen. Der volle Fehler steht nur im hub-Log.
func publicError(t notify.Type, err error) string {
	if err == nil {
		return ""
	}
	if fixedTarget[t] {
		return err.Error()
	}
	var dns *net.DNSError
	var op *net.OpError
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return "delivery failed: timeout"
	case errors.As(err, &dns):
		return "delivery failed: host not found"
	case errors.As(err, &op):
		return "delivery failed: connection failed"
	}
	if m := statusRe.FindStringSubmatch(err.Error()); m != nil {
		return "delivery failed: HTTP " + m[1]
	}
	return "delivery failed"
}
