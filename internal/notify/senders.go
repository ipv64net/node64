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
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/checks"
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
	KindUnchecked     Kind = "unchecked" // keine Messstelle meldet mehr (z. B. einzige messende Node offline)
	KindRechecked     Kind = "rechecked" // nach "unchecked" wieder gemessen
	KindReminder      Kind = "reminder"
	KindSummary       Kind = "summary"
	KindSummaryUp     Kind = "summary_up" // gesammelte Entwarnungen
	KindTest          Kind = "test"
	// DynDNS-Modul (kein Check; laeuft immer ueber die lokalen Kanaele)
	KindDynIP    Kind = "dyndns_ip"    // oeffentliche Adresse gewechselt
	KindDynFail  Kind = "dyndns_fail"  // Update fehlgeschlagen bzw. Ziel pausiert
	KindDynLimit Kind = "dyndns_limit" // Update-Limit des Accounts fast oder ganz erreicht
	KindDynOK    Kind = "dyndns_ok"    // Entwarnung: Update bzw. IP-Ermittlung klappt wieder
	// DNS64-Modul (ebenfalls nur lokal)
	KindDNS64Down  Kind = "dns64_upstream"    // Upstream-Server gestoert
	KindDNS64Up    Kind = "dns64_upstream_ok" // Upstream-Server antwortet wieder
	KindDNS64Lists Kind = "dns64_lists"       // Blockliste laesst sich nicht aktualisieren
	KindDNS64Cert  Kind = "dns64_cert"        // Zertifikat (Let's Encrypt) laesst sich nicht holen/verlaengern
	// Zertifikatsverwaltung des Kerns (ebenfalls nur lokal)
	KindCertFail   Kind = "cert_fail"   // Zertifikat laesst sich nicht holen bzw. verlaengern
	KindCertExpiry Kind = "cert_expiry" // Zertifikat laeuft bald ab
	KindCertOK     Kind = "cert_ok"     // Entwarnung: Zertifikat wieder geholt
	// CDN64 online (ebenfalls nur lokal)
	KindCDNOnlineDown    Kind = "cdn64_online_down"    // Tunnel zu keinem Server mehr (Namen eingeschaltet)
	KindCDNOnlineUp      Kind = "cdn64_online_up"      // Tunnel wieder verbunden
	KindCDNOnlineBlocked Kind = "cdn64_online_blocked" // Namen bei ipv64 gesperrt (z. B. Traffic aufgebraucht)

	KindClusterDown Kind = "cluster_down" // Node des Clusters laenger nicht erreichbar oder ausgesetzt
	KindClusterUp   Kind = "cluster_up"   // Node des Clusters wieder erreichbar

	KindHoneypotNew   Kind = "honeypot_new"   // Honeypot64: neue Angreifer (gebuendelt, hoechstens stuendlich)
	KindHoneypotWatch Kind = "honeypot_watch" // Honeypot64-Fruehwarnung: eigenes Netz bzw. DynDNS-IP als Angreifer aufgefallen
	KindHoneypotLogin Kind = "honeypot_login" // Honeypot64: viele Fehlversuche an der Anmeldung von Node64 (Regel node64/login)

	// Proxmox VE (Healthchecks, ohne Check; Gaeste „als Check“ melden ihren Zustand ueber den Check)
	KindProxmoxDown        Kind = "proxmox_down"         // System nicht erreichbar, Node offline, Gast gestoppt/angehalten/abgestuerzt
	KindProxmoxUp          Kind = "proxmox_up"           // Entwarnung
	KindProxmoxThreshold   Kind = "proxmox_threshold"    // CPU/RAM/Disk ueber der Schwelle
	KindProxmoxThresholdOK Kind = "proxmox_threshold_ok" // wieder unter der Schwelle
	KindProxmoxRestarted   Kind = "proxmox_restarted"    // Gast bzw. Node neu gestartet (Hinweis)

	KindQuota Kind = "quota" // Tageskontingent der Online-Checks erreicht (Account, vom hub)

	KindUpdateOK     Kind = "update_ok"     // Node64 hat sich selbst aktualisiert (neue Version laeuft stabil)
	KindUpdateFailed Kind = "update_failed" // Selbst-Update fehlgeschlagen, zurueck auf die vorige Version
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
	Local          bool // immer ueber die lokalen Kanaele senden (der hub kennt den Anlass nicht, z. B. DynDNS)
	// Direct (Node): Check, den nur diese Node misst. Kann der hub das (SetHubDirect), sendet die Node die
	// ipv64-Kanaele ueber die API und ihre eigenen Kanaele selbst, die uebrigen Portal-Kanaele der hub.
	Direct bool
	// DirectNode (hub): diese Node sendet die ipv64-Kanaele und ihre eigenen Kanaele selbst (Direct), der hub
	// nur die uebrigen Portal-Kanaele und die Kanaele anderer Nodes.
	DirectNode string
}

// IsDynDNS: Meldung des DynDNS-Moduls.
func IsDynDNS(k Kind) bool {
	return k == KindDynIP || k == KindDynFail || k == KindDynLimit || k == KindDynOK
}

// IsDNS64: Meldung des DNS64-Moduls.
func IsDNS64(k Kind) bool {
	return k == KindDNS64Down || k == KindDNS64Up || k == KindDNS64Lists || k == KindDNS64Cert
}

// IsCert: Meldung der Zertifikatsverwaltung.
func IsCert(k Kind) bool { return k == KindCertFail || k == KindCertExpiry || k == KindCertOK }

// IsCDN64: Meldung von CDN64 online.
func IsCDN64(k Kind) bool {
	return k == KindCDNOnlineDown || k == KindCDNOnlineUp || k == KindCDNOnlineBlocked
}

// IsCluster: Meldung des Clusters.
func IsCluster(k Kind) bool { return k == KindClusterDown || k == KindClusterUp }

// IsHoneypot: Meldung von Honeypot64.
func IsHoneypot(k Kind) bool {
	return k == KindHoneypotNew || k == KindHoneypotWatch || k == KindHoneypotLogin
}

// IsProxmox: Meldung der Proxmox-VE-Ueberwachung.
func IsProxmox(k Kind) bool {
	return k == KindProxmoxDown || k == KindProxmoxUp || k == KindProxmoxThreshold || k == KindProxmoxThresholdOK || k == KindProxmoxRestarted
}

// IsUpdate: Meldung des Selbst-Updates.
func IsUpdate(k Kind) bool { return k == KindUpdateOK || k == KindUpdateFailed }

// IsModule: Meldung eines Moduls ohne Check (DynDNS, DNS64, Zertifikate, CDN64 online, Cluster, Honeypot64, Proxmox VE,
// Selbst-Update).
func IsModule(k Kind) bool {
	return IsDynDNS(k) || IsDNS64(k) || IsCert(k) || IsCDN64(k) || IsCluster(k) || IsHoneypot(k) || IsProxmox(k) || IsUpdate(k)
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

var (
	httpClient         = &http.Client{Timeout: 20 * time.Second, Transport: newTransport(false)}
	insecureHTTPClient = &http.Client{Timeout: 20 * time.Second, Transport: newTransport(true)}
)

// Sperre fuer interne Ziele (hub): Kanaele der Nutzer duerfen von den ipv64-Servern aus nur oeffentliche Adressen
// erreichen. Geprueft wird die tatsaechlich gewaehlte Adresse beim Verbindungsaufbau, damit auch Hostnamen auf interne
// Adressen und Weiterleitungen dorthin gesperrt sind (jede Verbindung, auch nach einem Redirect, laeuft hier durch).

// ErrPrivateTarget: Ziel eines Kanals liegt im privaten oder reservierten Adressbereich (nur mit PublicOnly).
var ErrPrivateTarget = errors.New("target resolves to a private or reserved address")

type publicOnlyKey struct{}

// WithPublicOnly markiert den Kontext eines Versands: nur oeffentliche Ziele.
func WithPublicOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, publicOnlyKey{}, true)
}

func publicOnly(ctx context.Context) bool { v, _ := ctx.Value(publicOnlyKey{}).(bool); return v }

// dialer liefert den Dialer fuer einen Versand (mit Adresspruefung bei PublicOnly).
func dialer(ctx context.Context, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	if publicOnly(ctx) {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !checks.PublicAddr(ap.Addr()) {
				return ErrPrivateTarget
			}
			return nil
		}
	}
	return d
}

// newTransport: gemeinsamer Transport der HTTP-Sender (einer je TLS-Einstellung, keine Verbindungen je Aufruf).
// Versand mit PublicOnly laeuft ueber einen eigenen Transport mit eigenen Verbindungen, damit keine ungepruefte
// Keep-Alive-Verbindung (z. B. eines Node-Kanals im selben Prozess) wiederverwendet wird.
func newTransport(insecure bool) http.RoundTripper {
	base := func(public bool) *http.Transport {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if public {
				ctx = WithPublicOnly(ctx)
			}
			return dialer(ctx, 15*time.Second).DialContext(ctx, network, addr)
		}
		if public {
			tr.Proxy = nil // ueber einen Proxy liesse sich die Adresspruefung umgehen
		}
		if insecure {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // bewusst per Option
		}
		return tr
	}
	return guardTransport{open: base(false), public: base(true)}
}

// guardTransport waehlt den Transport nach dem Kontext der Anfrage (auch fuer Weiterleitungen).
type guardTransport struct{ open, public *http.Transport }

func (g guardTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if publicOnly(r.Context()) {
		return g.public.RoundTrip(r)
	}
	return g.open.RoundTrip(r)
}

// publicOnlySender setzt die Sperre fuer interne Ziele in den Kontext des Versands.
type publicOnlySender struct{ inner Sender }

func (p publicOnlySender) Send(ctx context.Context, ch *Channel, m Message) error {
	return p.inner.Send(WithPublicOnly(ctx), ch, m)
}

// SendersPublicOnly liefert die Sender wie Senders, die aber nur oeffentliche Adressen erreichen (ipv64-hub:
// Kanaele der Nutzer, kein Zugriff auf interne Dienste der Server).
func SendersPublicOnly(version string) map[Type]Sender {
	out := map[Type]Sender{}
	for t, s := range Senders(version) {
		out[t] = publicOnlySender{s}
	}
	return out
}

// netErr kennzeichnet Netzwerkfehler (Zeitueberschreitung, Verbindung abgelehnt oder abgebrochen, DNS voruebergehend)
// als voruebergehend; gesperrte Ziele, Zertifikats- und Adressfehler bleiben endgueltig.
func netErr(err error) error {
	if err == nil || errors.Is(err, ErrPrivateTarget) || IsTemporary(err) {
		return err
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		if de.IsTemporary || de.IsTimeout {
			return Temporary(err)
		}
		return err
	}
	var ne net.Error
	var oe *net.OpError
	if errors.As(err, &ne) && ne.Timeout() || errors.As(err, &oe) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) {
		return Temporary(err)
	}
	return err
}

// statusErr: Serverfehler (5xx) und 429 sind voruebergehend.
func statusErr(status int, err error) error {
	if status >= 500 || status == http.StatusTooManyRequests {
		return Temporary(err)
	}
	return err
}

// Senders liefert die eingebauten Sender je Typ.
func Senders(version string) map[Type]Sender {
	ua := "node64/" + version
	return map[Type]Sender{
		TypeSMTP: smtpSender{}, TypeTelegram: telegramSender{ua}, TypeDiscord: discordSender{ua},
		TypeNtfy: ntfySender{ua}, TypeGotify: gotifySender{ua}, TypeIGotify: gotifySender{ua}, TypeWebhook: webhookSender{ua}, TypePushover: pushoverSender{ua},
		TypeBrowser: browserSender{}, TypeHomeAssistant: homeAssistantSender{ua},
		TypeSlack: slackSender{ua}, TypeTeams: teamsSender{ua}, TypeMatrix: matrixSender{ua}, TypeApp: secntfySender{ua},
		TypeSecNtfy: secntfySender{ua}, // alter Name der IPv64 App (Portal-Kanaele bis zur Umstellung)
	}
}

// ---------------------------------------------------------------- Pushover

type pushoverSender struct{ ua string }

func (p pushoverSender) Send(ctx context.Context, ch *Channel, m Message) error {
	prio := ch.Config["priority_up"]
	if m.Kind == KindDown || m.Kind == KindReminder || m.Kind == KindFlappingStart || m.Kind == KindSummary || m.Kind == KindDegraded || m.Kind == KindUnchecked {
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
		return netErr(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != 200 {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(rb, &e)
		if len(e.Errors) > 0 {
			return statusErr(resp.StatusCode, fmt.Errorf("pushover: %s", excerpt(strings.Join(e.Errors, "; "))))
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
		return nil, 0, netErr(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return rb, resp.StatusCode, nil
}

func httpErr(status int, body []byte) error {
	return statusErr(status, fmt.Errorf("HTTP %d: %s", status, excerpt(string(body))))
}

// excerpt kuerzt Antworttexte fremder Server fuer Fehlermeldungen (hoechstens 200 Bytes, eine Zeile, gueltiges UTF-8).
func excerpt(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
		s += "..."
	}
	return s
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
			return statusErr(status, fmt.Errorf("telegram: %s", excerpt(e.Description)))
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
		return netErr(err)
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
		client = insecureHTTPClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return netErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return httpErr(resp.StatusCode, rb)
	}
	return nil
}

// ---------------------------------------------------------------- Home Assistant

// homeAssistantSender ruft den Webhook-Ausloeser einer HA-Automation auf: POST <url>/api/webhook/<id> mit festem
// JSON (siehe haBody). Die Webhook-ID ist das Geheimnis und erscheint nie in Fehlertexten.
type homeAssistantSender struct{ ua string }

func (h homeAssistantSender) Send(ctx context.Context, ch *Channel, m Message) error {
	id := ch.Config["webhook_id"]
	if !haWebhookID.MatchString(id) {
		return errors.New("home assistant: invalid webhook_id")
	}
	b, err := json.Marshal(haBody(m))
	if err != nil {
		return err
	}
	u := strings.TrimRight(ch.Config["url"], "/") + "/api/webhook/" + url.PathEscape(id)
	// ohne ID im Text: URL auf Schema und Host kuerzen, Reste (z. B. Echo im Body) ersetzen
	redact := func(s string) string { return strings.ReplaceAll(RedactURLs(s), id, "***") }
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return errors.New(redact(err.Error()))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", h.ua)
	client := httpClient
	if ch.Config["verify_tls"] == "false" { // selbst signiertes Zertifikat im LAN
		client = insecureHTTPClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return Temporary(fmt.Errorf("home assistant: %s", redact(err.Error()))) // HA startet z. B. gerade neu
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return statusErr(resp.StatusCode, fmt.Errorf("home assistant: %s", redact(httpErr(resp.StatusCode, rb).Error())))
	}
	return nil
}

// haBody ist das JSON fuer Home Assistant (in Automationen als trigger.json.<feld>). Felder bleiben stabil:
// source, kind, state, title, message, url, time, priority, event_id, check {name, token, type, target, critical}, node.
func haBody(m Message) map[string]any {
	t := m.Time
	if t.IsZero() {
		t = time.Now()
	}
	check := map[string]any{"name": m.Check.Name, "token": m.Check.Token, "type": m.Check.Type, "target": m.Check.Target, "critical": m.Check.Critical}
	if m.Kind == KindTest { // beim Test steht hier der Kanalname, kein Check
		check = map[string]any{"name": "", "token": "", "type": "", "target": "", "critical": false}
	}
	node := ""
	switch v := m.Payload["node"].(type) {
	case string:
		node = v
	case map[string]any:
		node, _ = v["name"].(string)
	}
	return map[string]any{"source": "node64", "kind": string(m.Kind), "state": haState(m), "title": m.Title, "message": m.Text, "url": m.URL,
		"time": t.UTC().Format(time.RFC3339), "priority": m.Priority, "event_id": m.EventID, "check": check, "node": node}
}

// haState: down, up, degraded, unchecked (wie "status" im Webhook), test oder info (Hinweis ohne Stoerung).
func haState(m Message) string {
	if s, ok := m.Payload["status"].(string); ok && s != "" {
		return s
	}
	switch {
	case m.Kind == KindTest:
		return "test"
	case isDownKind(m.Kind):
		return "down"
	}
	switch m.Kind {
	case KindUp, KindFlappingEnd, KindDegradedEnd, KindRechecked, KindSummaryUp, KindDynOK, KindDNS64Up, KindCertOK, KindCDNOnlineUp,
		KindClusterUp, KindProxmoxUp, KindProxmoxThresholdOK:
		return "up"
	}
	return "info"
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

// heloName: voller Rechnername, sonst die Domain der Absenderadresse.
func heloName(from string) string {
	if h, err := os.Hostname(); err == nil && strings.Contains(h, ".") {
		return h
	}
	if i := strings.LastIndex(from, "@"); i >= 0 && i < len(from)-1 {
		return from[i+1:]
	}
	return "localhost"
}

// manageURL: Seite der Benachrichtigungen des Nodes (aus dem Link der Nachricht abgeleitet).
func manageURL(u string) string {
	if i := strings.Index(u, "/healthchecks"); i > 0 {
		return u[:i] + "/notifications"
	}
	return ""
}

type smtpSender struct{}

// Send: Netzwerkfehler und SMTP-Antworten 4xx sind voruebergehend.
func (s smtpSender) Send(ctx context.Context, ch *Channel, m Message) error {
	err := s.send(ctx, ch, m)
	var te *textproto.Error
	if errors.As(err, &te) {
		if te.Code >= 400 && te.Code < 500 {
			return Temporary(err)
		}
		return err
	}
	return netErr(err)
}

func (smtpSender) send(ctx context.Context, ch *Channel, m Message) error {
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
	d := dialer(ctx, 15*time.Second)
	d.Deadline = deadline
	var conn net.Conn
	var err error
	if security == "tls" {
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
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
	// EHLO mit einem richtigen Namen statt "localhost" (Spamfilter pruefen den HELO-Namen)
	if err := c.Hello(heloName(ch.Config["from"])); err != nil {
		return fmt.Errorf("ehlo: %w", err)
	}
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
	subject, text, htmlBody := MailContent(m, MailBrand{Name: "Node64", ManageURL: manageURL(m.URL)})
	buf := bytes.NewBuffer(BuildMail(mail.Address{Name: "Node64", Address: from}, tos, subject, text, htmlBody))
	if _, err := wc.Write(buf.Bytes()); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}
