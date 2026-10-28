package main

// Mini-Status (nur mit SONAR64_STATUS): GET /status (JSON), GET /health, GET / (schlichte Seite, laedt /status alle
// 5 s). Nur lesen, keine Geheimnisse, keine Ziel-Adressen (Recent liefert nur Target-IDs).

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ipv64net/node64/internal/sonar"
)

// recentN ist die Zahl der letzten Messungen im Mini-Status (Vertrag Abschnitt 8).
const recentN = 50

// statusSource ist der Teil des Runners, den der Mini-Status braucht (Tests ersetzen ihn).
type statusSource interface {
	Status() sonar.Status
	Recent(n int) ([]sonar.Result, []sonar.Inbound)
}

// statusDoc ist die Antwort von GET /status.
type statusDoc struct {
	Version string          `json:"version"`
	Running bool            `json:"running"`
	Status  sonar.Status    `json:"status"`
	Recent  []sonar.Result  `json:"recent"`
	Inbound []sonar.Inbound `json:"inbound"`
}

func newStatusServer(addr string, src statusSource, running func() bool) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           statusHandler(src, running),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}

func statusHandler(src statusSource, running func() bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		res, in := src.Recent(recentN)
		if res == nil {
			res = []sonar.Result{}
		}
		if in == nil {
			in = []sonar.Inbound{}
		}
		writeJSON(w, http.StatusOK, statusDoc{Version: Version, Running: running(), Status: src.Status(), Recent: res, Inbound: in})
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		st := src.Status()
		ok := running() && st.Registered
		code := http.StatusOK
		if !ok {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, map[string]any{"ok": ok, "registered": st.Registered, "paused": st.Paused})
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", pageCSP)
		h.Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(pageHTML))
	})
	return secure(mux)
}

// secure setzt die Kopfzeilen fuer alle Antworten.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if h.Get("Content-Security-Policy") == "" {
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// pageScript zeigt den Zustand an (nur textContent, kein innerHTML mit Daten).
const pageScript = `(function(){
var de=(navigator.language||"").toLowerCase().indexOf("de")===0;
var L=de?{st:"Zustand",out:"Pings von mir",inb:"Pings gegen mich (UDP 6464)",t:"Ziel",m:"Weg",ms:"ms",loss:"Verlust",at:"Zeit",from:"von",n:"Anzahl",none:"noch nichts",err:"nicht erreichbar"}
:{st:"State",out:"My pings",inb:"Pings to me (UDP 6464)",t:"Target",m:"Path",ms:"ms",loss:"Loss",at:"Time",from:"from",n:"Count",none:"nothing yet",err:"unreachable"};
function el(t,txt){var e=document.createElement(t);if(txt!==undefined)e.textContent=String(txt);return e}
function tm(s){var d=new Date(s);return isNaN(d)?"":d.toLocaleTimeString()}
function table(head,rows){var tb=el("table"),tr=el("tr");head.forEach(function(h){tr.appendChild(el("th",h))});tb.appendChild(tr);
if(!rows.length){var r=el("tr"),c=el("td",L.none);c.colSpan=head.length;r.appendChild(c);tb.appendChild(r)}
rows.forEach(function(row){var r=el("tr");row.forEach(function(v){r.appendChild(el("td",v))});tb.appendChild(r)});return tb}
function show(d){var s=d.status||{},b=document.getElementById("app");b.replaceChildren();
var kv=[["node",s.node_id||"-"],["version",d.version],["mode",s.mode],["measured",s.measured],["budget",s.budget],
["responder",s.responder],["registered",s.registered],["anchors_only",s.anchors_only],["paused",s.paused||"-"],
["sent_today",s.sent_today],["buffered",s.buffered],["last_report",tm(s.last_report)],["last_error",s.last_error||"-"]];
b.appendChild(el("h2",L.st));b.appendChild(table(["",""],kv));
b.appendChild(el("h2",L.out));b.appendChild(table([L.t,L.m,L.ms,L.loss,L.at],(d.recent||[]).map(function(x){
var loss=x.sent?Math.round(100*(x.sent-x.recv)/x.sent)+" %":"";return [x.target+" (IPv"+x.fam+")",x.method,x.recv?Number(x.avg||0).toFixed(1):(x.err||"-"),loss,tm(x.at)]})));
b.appendChild(el("h2",L.inb));b.appendChild(table([L.from,L.n,L.at],(d.inbound||[]).map(function(x){return [x.from+" (IPv"+x.fam+")",x.count,tm(x.at)]})))}
function load(){fetch("status",{cache:"no-store"}).then(function(r){return r.json()}).then(show).catch(function(){var b=document.getElementById("app");b.replaceChildren(el("p",L.err))})}
load();setInterval(load,5000)})();`

var pageCSP = "default-src 'none'; script-src 'sha256-" + scriptHash() + "'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

var pageHTML = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sonar64</title><style>body{font:14px system-ui,sans-serif;margin:16px;color:#222;background:#fff}h1{font-size:20px}
h2{font-size:16px;margin-top:20px}table{border-collapse:collapse;width:100%;max-width:900px}td,th{border-bottom:1px solid #ddd;padding:4px 8px;text-align:left}
@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}td,th{border-color:#333}}</style></head>
<body><h1>Sonar64</h1><div id="app"></div><script>` + pageScript + `</script></body></html>`

func scriptHash() string {
	h := sha256.Sum256([]byte(pageScript))
	return base64.StdEncoding.EncodeToString(h[:])
}
