package honeypot

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// HTTP-Profile (sensor_persona.go): Webserver (nginx, Apache) beantworten Pfade mit den neutralen Koedern wie bisher;
// Anwendungen (Proxmox VE, Webmin, Home Assistant, Grafana, NAS, Elasticsearch) antworten mit Kopfzeilen, Status und
// API-Format wie das Original, wenn man nicht angemeldet ist. Seiten nur schlicht (Titel und neutrales Formular,
// keine Logos, kein nachgebautes JavaScript). Erfasst wird unabhaengig davon in serveHTTP.

// sensorWebServer: Webserver-Profil (Koeder je Pfad, Geraete-Endpunkte ohne eigenes Profil).
func sensorWebServer(persona string) bool { return persona == PersonaNginx || persona == PersonaApache }

// sensorPersonaPage: Koeder-Name fuer die Statistik, wenn eine Anwendung ihre Startseite bzw. Anmeldung zeigt.
var sensorPersonaPage = map[string]string{PersonaPVE: "pve", PersonaWebmin: "webmin", PersonaHA: "homeassistant", PersonaGrafana: "grafana",
	PersonaNAS: "nas", PersonaElastic: "elastic"}

// sensorHTTPHeaders setzt die Kopfzeilen des Profils, die jede Antwort traegt.
func sensorHTTPHeaders(h http.Header, persona string, id *sensorIdent) {
	switch persona {
	case PersonaNginx:
		h.Set("Server", id.nginxServer())
		if v := id.poweredBy(); v != "" {
			h.Set("X-Powered-By", v)
		}
	case PersonaApache:
		h.Set("Server", id.apacheServer())
		if v := id.poweredBy(); v != "" {
			h.Set("X-Powered-By", v)
		}
	case PersonaNAS:
		h.Set("Server", "nginx")
	case PersonaPVE:
		h.Set("Server", "pve-api-daemon/3.0")
		h.Set("Cache-Control", "max-age=0")
		h.Set("Pragma", "no-cache")
	case PersonaWebmin:
		h.Set("Server", "MiniServ/"+id.webminVersion())
	case PersonaHA:
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "SAMEORIGIN")
	case PersonaGrafana:
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "deny")
		h.Set("X-Xss-Protection", "1; mode=block")
	case PersonaElastic:
		h["X-elastic-product"] = []string{"Elasticsearch"} // Schreibweise wie das Original
	}
}

// sensorHTTPAppMain: Pfad zeigt die Startseite bzw. Anmeldung einer Anwendung (fuer Page im Ereignis).
func sensorHTTPAppMain(persona, path string) bool {
	p := strings.ToLower(path)
	switch persona {
	case PersonaPVE, PersonaNAS, PersonaElastic:
		return p == "/"
	case PersonaWebmin:
		return true // jede Seite zeigt ohne Anmeldung das Login
	case PersonaHA:
		return p == "/" || strings.HasPrefix(p, "/auth/authorize") || p == "/onboarding.html"
	case PersonaGrafana:
		return p == "/login"
	}
	return false
}

// sensorHTTPApp schreibt die Antwort einer Anwendung (nicht angemeldet). failed = Login-Versuch erkannt.
func sensorHTTPApp(w http.ResponseWriter, r *http.Request, persona string, id *sensorIdent, failed bool) {
	h := w.Header()
	p := strings.ToLower(r.URL.Path)
	switch persona {
	case PersonaPVE:
		switch {
		case strings.HasPrefix(p, "/api2/"):
			sensorHTTPWrite(w, http.StatusUnauthorized, "application/json;charset=UTF-8", `{"data":null}`)
		case p == "/":
			sensorHTTPWrite(w, http.StatusOK, "text/html; charset=utf-8", sensorLoginHTML(id.host+" - Proxmox Virtual Environment", "Login",
				"/api2/json/access/ticket", "username", "password", `<input type="hidden" name="realm" value="pam">`, failed))
		default:
			sensorHTTPWrite(w, http.StatusNotImplemented, "text/plain; charset=utf-8", "")
		}
	case PersonaWebmin:
		h.Set("Auth-type", "auth-required=1")
		ck := "testing=1; path=/"
		if r.TLS != nil {
			ck += "; secure"
		}
		h.Add("Set-Cookie", ck)
		sensorHTTPWrite(w, http.StatusOK, "text/html; Charset=utf-8", sensorLoginHTML("Login to Webmin", "Sign in", "/session_login.cgi",
			"user", "pass", `<input type="hidden" name="save" value="1">`, failed))
	case PersonaHA:
		switch {
		case p == "/api" || strings.HasPrefix(p, "/api/"):
			sensorHTTPWrite(w, http.StatusUnauthorized, "text/plain; charset=utf-8", "401: Unauthorized")
		case p == "/auth/providers":
			sensorHTTPWrite(w, http.StatusOK, "application/json", `[{"name":"Home Assistant Local","id":null,"type":"homeassistant"}]`)
		case sensorHTTPAppMain(persona, p):
			sensorHTTPWrite(w, http.StatusOK, "text/html; charset=utf-8", sensorLoginHTML("Home Assistant", "Log in", "/auth/login_flow",
				"username", "password", "", failed))
		default:
			sensorHTTPWrite(w, http.StatusNotFound, "text/plain; charset=utf-8", "404: Not Found")
		}
	case PersonaGrafana:
		switch {
		case p == "/api/health":
			ver := id.grafanaVersion()
			sensorHTTPWrite(w, http.StatusOK, "application/json", "{\n  \"commit\": \""+sensorStableHex("grafana-"+ver, 40)+
				"\",\n  \"database\": \"ok\",\n  \"version\": \""+ver+"\"\n}")
		case p == "/login" && r.Method == http.MethodPost:
			sensorHTTPWrite(w, http.StatusUnauthorized, "application/json", `{"message":"Invalid username or password"}`)
		case p == "/login":
			sensorHTTPWrite(w, http.StatusOK, "text/html; charset=UTF-8", sensorLoginHTML("Grafana", "Log in", "/login", "user", "password", "", failed))
		case strings.HasPrefix(p, "/api/"):
			sensorHTTPWrite(w, http.StatusUnauthorized, "application/json", `{"message":"Unauthorized"}`)
		case strings.HasPrefix(p, "/public/"):
			sensorHTTPWrite(w, http.StatusNotFound, "text/plain; charset=utf-8", "404 page not found\n")
		default:
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	case PersonaNAS:
		switch {
		case p == "/webapi/query.cgi":
			sensorHTTPWrite(w, http.StatusOK, "application/json; charset=\"UTF-8\"",
				`{"data":{"SYNO.API.Auth":{"maxVersion":7,"minVersion":1,"path":"entry.cgi"}},"success":true}`)
		case strings.HasPrefix(p, "/webapi/"):
			sensorHTTPWrite(w, http.StatusOK, "application/json; charset=\"UTF-8\"", `{"error":{"code":102},"success":false}`)
		case p == "/":
			sensorHTTPWrite(w, http.StatusOK, "text/html; charset=UTF-8", sensorLoginHTML(id.host, "Sign In", "/webapi/entry.cgi", "account", "passwd",
				`<input type="hidden" name="api" value="SYNO.API.Auth">`, failed))
		default:
			sensorHTTPError(w, r, persona, id, 0, http.StatusNotFound)
		}
	case PersonaElastic:
		sensorElastic(w, r, id)
	}
}

// sensorElastic: Elasticsearch 7.17 ohne Anmeldung (wie offen im Netz stehende Knoten). Knotenname = Hostname.
func sensorElastic(w http.ResponseWriter, r *http.Request, id *sensorIdent) {
	const ct = "application/json; charset=UTF-8"
	p := r.URL.Path
	switch {
	case p == "/":
		ver := "7.17." + id.choose("elastic", "22", "24", "25", "26", "28")
		u := id.sum("es-uuid")
		uuid := base64.RawURLEncoding.EncodeToString(u[:16])
		sensorHTTPWrite(w, http.StatusOK, ct, "{\n"+
			"  \"name\" : \""+id.host+"\",\n"+
			"  \"cluster_name\" : \"elasticsearch\",\n"+
			"  \"cluster_uuid\" : \""+uuid+"\",\n"+
			"  \"version\" : {\n"+
			"    \"number\" : \""+ver+"\",\n"+
			"    \"build_flavor\" : \"default\",\n"+
			"    \"build_type\" : \""+id.choose("es-build", "docker", "deb", "rpm")+"\",\n"+
			"    \"build_hash\" : \""+sensorStableHex("es-"+ver, 40)+"\",\n"+
			"    \"build_date\" : \""+sensorElasticDate(ver)+"\",\n"+
			"    \"build_snapshot\" : false,\n"+
			"    \"lucene_version\" : \"8.11.3\",\n"+
			"    \"minimum_wire_compatibility_version\" : \"6.8.0\",\n"+
			"    \"minimum_index_compatibility_version\" : \"6.0.0-beta1\"\n"+
			"  },\n"+
			"  \"tagline\" : \"You Know, for Search\"\n"+
			"}\n")
	case p == "/_cluster/health":
		sensorHTTPWrite(w, http.StatusOK, ct, `{"cluster_name":"elasticsearch","status":"green","timed_out":false,"number_of_nodes":1,`+
			`"number_of_data_nodes":1,"active_primary_shards":0,"active_shards":0,"relocating_shards":0,"initializing_shards":0,`+
			`"unassigned_shards":0,"delayed_unassigned_shards":0,"number_of_pending_tasks":0,"number_of_in_flight_fetch":0,`+
			`"task_max_waiting_in_queue_millis":0,"active_shards_percent_as_number":100.0}`)
	case p == "/_cat/indices" || strings.HasPrefix(p, "/_cat/indices/"):
		sensorHTTPWrite(w, http.StatusOK, "text/plain; charset=UTF-8", "")
	case strings.HasPrefix(p, "/_"):
		b, _ := json.Marshal(map[string]string{"error": "no handler found for uri [" + p + "] and method [" + r.Method + "]"})
		sensorHTTPWrite(w, http.StatusBadRequest, ct, string(b))
	default:
		idx, _, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
		q, _ := json.Marshal(idx)
		reason, _ := json.Marshal("no such index [" + idx + "]")
		e := `{"type":"index_not_found_exception","reason":` + string(reason) + `,"resource.type":"index_or_alias","resource.id":` + string(q) +
			`,"index_uuid":"_na_","index":` + string(q) + `}`
		sensorHTTPWrite(w, http.StatusNotFound, ct, `{"error":{"root_cause":[`+e+`],`+strings.TrimPrefix(e, "{")+`,"status":404}`)
	}
}

// sensorElasticDate: plausibles Build-Datum je Version (fest, nicht je Sensor).
func sensorElasticDate(ver string) string {
	switch ver {
	case "7.17.22":
		return "2024-06-06T07:35:17.876121680Z"
	case "7.17.24":
		return "2024-09-05T07:24:39.123975417Z"
	case "7.17.25":
		return "2024-10-16T16:06:17.465813404Z"
	case "7.17.26":
		return "2024-11-26T09:58:17.893493574Z"
	}
	return "2025-02-20T10:13:08.215718367Z"
}

// sensorStableHex: Hex-Wert, der nur vom Text abhaengt (gleich auf allen Sensoren, z. B. Commit einer Version).
func sensorStableHex(text string, n int) string { return (&sensorIdent{seed: "node64"}).hex(text, n) }

// sensorHTTPWrite schreibt Status, Typ und Body (kein Body bei HEAD; net/http laesst ihn dann weg).
func sensorHTTPWrite(w http.ResponseWriter, code int, ctype, body string) {
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(code)
	_, _ = io.WriteString(w, body)
}

// sensorHTTPError schreibt eine Fehlerseite wie der Webserver des Profils (nginx, Apache; Anwendungen: schlicht).
// port = lokaler Port (Apache nennt ihn in der Fusszeile).
func sensorHTTPError(w http.ResponseWriter, r *http.Request, persona string, id *sensorIdent, port, code int) {
	st := fmt.Sprintf("%d %s", code, http.StatusText(code))
	switch persona {
	case PersonaApache:
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		msg := "The requested URL was not found on this server."
		if code == http.StatusForbidden {
			msg = "You don't have permission to access this resource."
		}
		sensorHTTPWrite(w, code, "text/html; charset=iso-8859-1", "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>"+st+
			"</title>\n</head><body>\n<h1>"+http.StatusText(code)+"</h1>\n<p>"+msg+"</p>\n<hr>\n<address>"+id.apacheServer()+" Server at "+
			html.EscapeString(host)+" Port "+strconv.Itoa(port)+"</address>\n</body></html>\n")
	case PersonaNginx, PersonaNAS:
		srv := "nginx"
		if persona == PersonaNginx {
			srv = id.nginxServer()
		}
		sensorHTTPWrite(w, code, "text/html", "<html>\r\n<head><title>"+st+"</title></head>\r\n<body>\r\n<center><h1>"+st+
			"</h1></center>\r\n<hr><center>"+srv+"</center>\r\n</body>\r\n</html>\r\n")
	default:
		sensorHTTPWrite(w, code, "text/plain; charset=utf-8", st+"\n")
	}
}
