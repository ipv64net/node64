package httpapi

import (
	"embed"
	"html/template"
	"net/http"
	"time"
)

// Kurze Infoseite unter / (statt 404), im Node64-Design. Keine Interna, nur Standort und Version.

//go:embed static/logo.svg static/logo_dark.svg
var static embed.FS

var infoTmpl = template.Must(template.New("info").Parse(`<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>ipv64 hub · {{.Name}}</title>
<style>
:root{--bg:#f6f7f8;--card:#fff;--text:#272828;--muted:#6b6f72;--accent:#f59c1a;--line:#e3e5e7}
@media (prefers-color-scheme:dark){:root{--bg:#1b1c1c;--card:#272828;--text:#f1f1f1;--muted:#a3a7aa;--line:#3a3c3c}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:16px}
main{max-width:560px;width:100%;background:var(--card);border:1px solid var(--line);border-top:4px solid var(--accent);border-radius:10px;padding:28px 28px 22px}
.logo{height:44px;display:block;margin-bottom:18px}
.logo.dark{display:none}
@media (prefers-color-scheme:dark){.logo.light{display:none}.logo.dark{display:block}}
h1{font-size:1.25rem;margin:0 0 6px}
p{margin:0 0 14px;color:var(--muted)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0 0 18px;font-size:.95rem}
dt{color:var(--muted)}dd{margin:0}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:#28a745;margin-right:6px;vertical-align:middle}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
footer{border-top:1px solid var(--line);padding-top:12px;font-size:.85rem;color:var(--muted)}
</style>
</head>
<body>
<main>
<img class="logo light" src="/static/logo.svg" alt="Node64">
<img class="logo dark" src="/static/logo_dark.svg" alt="Node64">
<h1>ipv64 hub – {{.Name}}</h1>
<p>Dieser Server gehört zu <a href="https://ipv64.net/">ipv64.net</a>. Er prüft Healthchecks von außen und verbindet die Node64-Container der Nutzer mit ihrem Account. Eine Weboberfläche gibt es hier nicht.</p>
<dl>
<dt>Status</dt><dd><span class="dot"></span>in Betrieb</dd>
<dt>Standort</dt><dd>{{.Location}}</dd>
<dt>Version</dt><dd>{{.Version}}</dd>
<dt>Zeit (UTC)</dt><dd>{{.Now}}</dd>
</dl>
<footer>Healthchecks und Node64 verwalten: <a href="https://ipv64.net/">ipv64.net</a> · Kontakt und Impressum: <a href="https://ipv64.net/">ipv64.net</a></footer>
</main>
</body>
</html>`))

// Info bestimmt, was die Seite zeigt.
type Info struct {
	Name, Location, Version string
}

// RegisterInfo haengt die Infoseite und das Logo an.
func (s *Server) RegisterInfo(info Info) {
	mux := s.Mux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_ = infoTmpl.Execute(w, map[string]string{"Name": info.Name, "Location": info.Location, "Version": info.Version, "Now": time.Now().UTC().Format("02.01.2006 15:04")})
	})
	mux.Handle("GET /static/", http.StripPrefix("/", http.FileServerFS(static)))
}
