package cdnedge

import (
	"bytes"
	_ "embed"
	"fmt"
	"html"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Fehlerseite der CDN64-Server im Stil von ipv64: klein, ohne externe Quellen (Logo eingebettet), hell/dunkel, Deutsch
// und Englisch nach Accept-Language. Sie erscheint fuer Fehler des Servers selbst (Node bzw. Ziel nicht erreichbar,
// gesperrt, Liste) und - nur fuer Browser (Accept: text/html) - statt einer 5xx-Antwort des Ziels bzw. der Node
// (Modus 2/3). APIs behalten die Antwort des Ziels; ein Ziel kann die Seite mit dem Antwort-Header
// "CDN64-Error-Page: off" abschalten. Modus 1 (TLS beim Kunden) sieht die Antworten nicht: dort gibt es die Seite nur
// auf Port 80, wenn die Node nicht verbunden ist.

//go:embed errorpage_logo.svg
var errorLogo string

const ipv64URL = "https://ipv64.net"

// pageTitle: Ueberschrift je Status.
func pageTitle(code int, de bool) string {
	switch {
	case code == http.StatusForbidden:
		return pick(de, "Kein Zugriff", "Access denied")
	case code == http.StatusServiceUnavailable:
		return pick(de, "Vorübergehend nicht verfügbar", "Temporarily unavailable")
	case code >= 500:
		return pick(de, "Gerade nicht erreichbar", "Currently not reachable")
	}
	return pick(de, "Fehler", "Error")
}

func pick(de bool, a, b string) string {
	if de {
		return a
	}
	return b
}

// errorPageHTML baut die Seite (lang "de" oder "en").
func errorPageHTML(de bool, code int, host, text string) []byte {
	lang := pick(de, "de", "en")
	title := pageTitle(code, de)
	note := pick(de, "Diese Adresse wird über das IPv64 CDN ausgeliefert. Danke für deine Geduld!",
		"This address is delivered by the IPv64 CDN. Thank you for your patience!")
	var b bytes.Buffer
	fmt.Fprintf(&b, `<!doctype html><html lang="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>%d · %s</title><style>
:root{color-scheme:light dark;--fg:#212529;--mut:#6c757d;--bg:#f4f5f7;--card:#fff;--line:#dee2e6;--brand:#f59c1a}
@media(prefers-color-scheme:dark){:root{--fg:#e9ecef;--mut:#9aa0a6;--bg:#16181b;--card:#202327;--line:#30343a}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{width:100%%;max-width:34rem;background:var(--card);border:1px solid var(--line);border-top:4px solid var(--brand);border-radius:.75rem;padding:2rem 1.5rem;text-align:center}
.logo{height:44px;width:auto;margin-bottom:1.25rem}.logo .cls-1{fill:var(--brand)}.logo .cls-2{fill:currentColor}
.code{font-size:3rem;font-weight:700;line-height:1;color:var(--brand)}h1{font-size:1.35rem;margin:.5rem 0 .75rem}p{margin:0 0 1rem}
.mut{color:var(--mut);font-size:.9rem}a.btn{display:inline-block;padding:.5rem 1.2rem;border-radius:.5rem;background:var(--brand);color:#fff;text-decoration:none;font-weight:600}
footer{margin-top:1.5rem;font-size:.75rem;color:var(--mut);overflow-wrap:anywhere}
</style></head><body><main>%s<div class="code">%d</div><h1>%s</h1><p>%s</p><p class="mut">%s</p><a class="btn" href="%s">ipv64.net</a>
<footer>%s · IPv64 CDN · %s</footer></main></body></html>`,
		lang, code, html.EscapeString(title), errorLogo, code, html.EscapeString(title), html.EscapeString(text), html.EscapeString(note), ipv64URL,
		html.EscapeString(host), time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
	return b.Bytes()
}

// termPage: Fehlerseite als Antwort des Servers selbst.
func termPage(w http.ResponseWriter, r *http.Request, code int, host, de, en string) {
	isDE := prefersGerman(r.Header.Get("Accept-Language"))
	body := errorPageHTML(isDE, code, host, pick(isDE, de, en))
	setPageHeader(w.Header(), isDE, len(body))
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func setPageHeader(h http.Header, de bool, n int) {
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Language", pick(de, "de", "en"))
	h.Set("Content-Length", strconv.Itoa(n))
	h.Set("Vary", "Accept-Language")
	h.Set("Cache-Control", "no-store")
}

// wantsHTML: Seitenaufruf eines Browsers (GET/HEAD mit text/html im Accept) - nicht fetch/XHR oder APIs.
func wantsHTML(r *http.Request) bool {
	return r != nil && (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.Contains(r.Header.Get("Accept"), "text/html")
}

// originErrorPage (ModifyResponse): 5xx des Ziels bzw. der Node fuer Browser durch die Fehlerseite ersetzen (Status
// bleibt, Retry-After auch).
func originErrorPage(resp *http.Response) error {
	if resp.StatusCode < 500 || resp.StatusCode > 599 || !wantsHTML(resp.Request) ||
		strings.EqualFold(strings.TrimSpace(resp.Header.Get("CDN64-Error-Page")), "off") {
		return nil
	}
	isDE := prefersGerman(resp.Request.Header.Get("Accept-Language"))
	text := pick(isDE, "Der Server hinter dieser Adresse antwortet gerade mit einem Fehler. Bitte später noch einmal versuchen.",
		"The server behind this address is answering with an error right now. Please try again later.")
	body := errorPageHTML(isDE, resp.StatusCode, hostOnly(resp.Request.Host), text)
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)) // kleine Antworten lesen, damit die Verbindung bleiben kann
	_ = resp.Body.Close()
	h := http.Header{}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		h.Set("Retry-After", ra)
	}
	setPageHeader(h, isDE, len(body))
	resp.Header, resp.Body, resp.ContentLength, resp.TransferEncoding = h, io.NopCloser(bytes.NewReader(body)), int64(len(body)), nil
	if resp.Request.Method == http.MethodHead {
		resp.Body = http.NoBody
	}
	return nil
}

// rawPage: Fehlerseite direkt auf eine rohe HTTP-Verbindung (Modus 1, Port 80); Sprache aus den ersten Bytes der
// Anfrage, sonst Englisch.
func rawPage(c io.Writer, req []byte, code int, host, de, en string) {
	isDE := prefersGerman(rawHeader(req, "accept-language"))
	body := errorPageHTML(isDE, code, host, pick(isDE, de, en))
	h := http.Header{}
	setPageHeader(h, isDE, len(body))
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	_ = h.Write(&b)
	b.WriteString("Connection: close\r\n\r\n")
	if !bytes.HasPrefix(req, []byte("HEAD ")) {
		b.Write(body)
	}
	_, _ = c.Write(b.Bytes())
}

// rawHeader: Wert eines Headers aus den ersten Bytes einer HTTP/1-Anfrage ("" = nicht enthalten).
func rawHeader(req []byte, name string) string {
	for _, line := range strings.Split(string(req), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
		if strings.TrimSpace(line) == "" { // Ende der Header
			break
		}
	}
	return ""
}
