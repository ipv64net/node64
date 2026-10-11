package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/notify"
)

// Portal -> hub: signierte Aufrufe aus den PHP-Seiten (gleiches Geheimnis wie die Versand-Bruecke,
// HMAC-SHA256 ueber den rohen Body im Header X-HC2-Signature, Zeitstempel ts hoechstens 5 Minuten alt).
//
//	POST /v1/portal/channel-test  {ts, userid, channel_id, kind: test|verify, code?, lang?}
//	  -> {"ok":true} | {"ok":false,"error":"..."}; Node-Kanaele werden als Sendeauftrag an die Node gegeben ("queued").

// SetPortalSecret aktiviert die Portal-Endpunkte.
func (g *Gateway) SetPortalSecret(secret []byte) { g.portalSecret = secret }

// RegisterPortal haengt die Portal-Routen an den Multiplexer.
func (g *Gateway) RegisterPortal(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/portal/channel-test", g.portalChannelTest)
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
	lang := in.Lang
	if lang != "en" {
		lang = "de"
	}
	m := notify.Message{Kind: notify.KindTest, Time: time.Now().UTC(), Language: lang, Priority: 3,
		Check: notify.CheckInfo{UserID: in.UserID, Name: ch.Name}, EventID: "portal-" + strconv.FormatInt(time.Now().UnixNano(), 36),
		URL: "https://ipv64.net/notifications.php"}
	switch in.Kind {
	case "verify":
		if lang == "en" {
			m.Title, m.Text = "IPv64.net: confirmation code", "Your code to confirm the notification channel \""+ch.Name+"\": "+in.Code+"\nValid for 15 minutes."
		} else {
			m.Title, m.Text = "IPv64.net: Bestätigungscode", "Dein Code zur Bestätigung des Benachrichtigungskanals \""+ch.Name+"\": "+in.Code+"\nGültig 15 Minuten."
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
		writeErr(w, http.StatusUnprocessableEntity, "no sender for type "+string(ch.Type))
		return
	}
	sctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if err := s.Send(sctx, ch, m); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	out := map[string]any{"ok": true}
	if ch.Execution == "node" {
		out["queued"] = true // die Node schickt selbst (Sendeauftrag)
	}
	writeJSON(w, http.StatusOK, out)
}
