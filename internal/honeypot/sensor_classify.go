package honeypot

import (
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Einordnung von HTTP-Anfragen an die Koeder. Kleine, mitgelieferte Musterliste, angelehnt an die Kategorien des
// OWASP Core Rule Set (SQLi, XSS, Path Traversal/LFI, RCE, Log4Shell/JNDI, SSRF, Upload/Web-Shell), dazu bekannte
// Exploit-Pfade und User-Agents von Scannern. Zweck ist nur die Bewertung der Quelle (Plan Abschnitt 3), keine WAF.

// sensorOWASP in der Reihenfolge der Wichtigkeit: die erste Kategorie bestimmt die Art.
var sensorOWASP = []struct {
	tag, kind string
	re        *regexp.Regexp
}{
	{"jndi", KindHTTPJNDI, regexp.MustCompile(`(?i)\$\{\s*(?:jndi|\$\{|(?:lower|upper|env|sys|date|base64|main|java|ctx)\s*:|::-)`)},
	{"rce", KindHTTPRCE, regexp.MustCompile(`(?i)(?:[;|&]|&&|\|\|)\s*(?:wget|curl|tftp|ftpget|sh|bash|busybox|nc|ncat|chmod|rm|cd|cat|id|uname|whoami|echo|perl|python3?|php)(?:\s|$|;|\|)` +
		"|`[^`\\n]{1,80}`" +
		`|\$\([^)\n]{1,80}\)|\$\{ifs\}|/bin/(?:ba|z|da)?sh\b|\bcmd(?:\.exe)?\s*/c\b|powershell|\b(?:shell_exec|passthru|proc_open|popen|system|exec|eval|assert|base64_decode|call_user_func_array)\s*\(` +
		`|invokefunction|allow_url_include|auto_prepend_file|php://input|\b(?:wget|curl)\s+(?:-\S+\s+)*https?://`)},
	{"upload", KindHTTPUpload, regexp.MustCompile(`(?i)filename\s*=\s*"?[^"\r\n]*\.(?:php\d?|phtml|phar|jsp|jspx|asp|aspx|ashx|cer|cgi|sh)\b|<\?php|<%@?\s*(?:page|eval|response)` +
		`|/(?:c99|r57|wso|b374k|alfa(?:-?rex)?|shell|cmd|webshell|uploader|up|xleet|indoxploit|sh3ll|bypass|gecko|f0x|marijuana|chosen|wp-?shell|ws\d*|mini)\.(?:php\d?|phtml|jsp|aspx?)\b` +
		`|/(?:kcfinder|elfinder|fckeditor|ckfinder)/\S*(?:upload|connector)`)},
	{"traversal", KindHTTPTrav, regexp.MustCompile(`(?i)\.\.[/\\]|\.\.;/|/etc/(?:passwd|shadow|hosts|group)\b|win\.ini|boot\.ini|/proc/self/|\b(?:php|file|expect|zip|phar|glob)://|data://text|/windows/system32`)},
	{"sqli", KindHTTPSQLi, regexp.MustCompile(`(?i)\bunion\b(?:\s|/\*.*?\*/|\()+(?:all\s+|distinct\s+)?select\b|\bselect\b[^\n]{1,100}?\bfrom\b` +
		`|\b(?:and|or|xor)\b\s+['"(]?\d+['")]?\s*(?:=|<|>|like)\s*['"(]?\d+|'\s*(?:or|and)\s+'?[\w']*'?\s*=` +
		`|\b(?:sleep|benchmark|pg_sleep|extractvalue|updatexml|load_file|group_concat)\s*\(|waitfor\s+delay|information_schema|\binto\s+(?:out|dump)file\b` +
		`|'\s*(?:--|#)|;\s*(?:drop|insert|update|delete|create|alter|exec)\s`)},
	{"ssrf", KindHTTPSSRF, regexp.MustCompile(`(?i)169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|\b(?:gopher|dict|ldap|tftp)://` +
		`|=\s*https?://(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1?\]|10\.\d+\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)`)},
	{"xss", KindHTTPXSS, regexp.MustCompile(`(?i)<\s*script|javascript\s*:|vbscript\s*:|\bon(?:error|load|mouseover|focus|click|toggle|animationstart)\s*=` +
		`|<\s*(?:iframe|svg|object|embed)\b|\b(?:alert|prompt|confirm)\s*\(|document\.(?:cookie|location|write)|string\.fromcharcode`)},
}

// sensorExploitPaths: bekannte Exploit- und Lecksuche-Pfade (im dekodierten, kleingeschriebenen Pfad enthalten).
var sensorExploitPaths = []string{
	"/.env", "/.git/", "/.git/config", "/.aws/", "/.ssh/", "/.svn/", "/.hg/", "/.ds_store", "/.htaccess", "/.htpasswd",
	"/.vscode/", "/.docker", "wp-config.php", "/cgi-bin/", "/boaform/", "/hnap1", "/vendor/phpunit/", "eval-stdin.php",
	"/actuator", "/wp-content/plugins/", "/xmlrpc.php", "/solr/", "/manager/html", "/autodiscover/autodiscover.json",
	"/owa/auth/", "/ecp/", "/remote/fgt_lang", "/remote/logincheck", "/dana-na/", "/vpns/", "/+cscoe+/",
	"/global-protect/", "/setup.cgi", "/goform/", "/gponform/", "/tmui/", "/mgmt/tm/", "/api/jsonws", "/_ignition/",
	"/telescope/requests", "/druid/", "/server-status", "/console/", "/device.rsp", "/geoserver/", "/webtools/control/",
	"/developmentserver/metadatauploader", "/mifs/", "/cgi-mod/", "/invoker/", "/jmx-console/", "/web-console/",
	"/ws/v1/cluster/apps", "/containers/json", "/php-cgi/", "/shell?", "/debug/default/view", "/cgi/",
}

// sensorResearch: User-Agents von Forschungs- und Suchmaschinen-Scannern (Teilstring -> Name).
var sensorResearch = [][2]string{
	{"shodan", "shodan"}, {"censys", "censys"}, {"binaryedge", "binaryedge"}, {"stretchoid", "stretchoid"},
	{"internett", "internettl"}, {"internet-measurement", "driftnet"}, {"expanse", "paloalto-expanse"},
	{"palo alto networks", "paloalto-expanse"}, {"leakix", "leakix"}, {"l9explore", "leakix"}, {"l9tcpid", "leakix"},
	{"l9scan", "leakix"}, {"onyphe", "onyphe"}, {"shadowserver", "shadowserver"}, {"criminalip", "criminalip"},
	{"netcraft", "netcraft"}, {"recyber", "recyber"}, {"modat", "modat"}, {"cypex", "cypex"},
	{"researchscan", "researchscan"}, {"netsystemsresearch", "netsystemsresearch"}, {"zoomeye", "zoomeye"},
	{"project sonar", "rapid7-sonar"}, {"bitsight", "bitsight"},
}

// sensorBadUAs: User-Agents von Scan- und Angriffswerkzeugen (Teilstring -> Name).
var sensorBadUAs = [][2]string{
	{"zgrab", "zgrab"}, {"masscan", "masscan"}, {"nmap", "nmap"}, {"zmap", "zmap"}, {"sqlmap", "sqlmap"},
	{"nikto", "nikto"}, {"nuclei", "nuclei"}, {"gobuster", "gobuster"}, {"dirbuster", "dirbuster"}, {"dirb/", "dirb"},
	{"wfuzz", "wfuzz"}, {"fuzz faster u fool", "ffuf"}, {"ffuf", "ffuf"}, {"feroxbuster", "feroxbuster"},
	{"hydra", "hydra"}, {"medusa", "medusa"}, {"wpscan", "wpscan"}, {"whatweb", "whatweb"}, {"acunetix", "acunetix"},
	{"netsparker", "netsparker"}, {"openvas", "openvas"}, {"nessus", "nessus"}, {"zmeu", "zmeu"}, {"jorgee", "jorgee"},
	{"morfeus", "morfeus"}, {"libwww-perl", "libwww-perl"}, {"fscan", "fscan"}, {"hello, world", "hello-world"},
	{"hello world", "hello-world"}, {"custom-asynchttpclient", "asynchttpclient"},
}

// sensorClassify ordnet eine Anfrage ein. Art: OWASP-Kategorie > Forschungs-Scanner > Exploit-Pfad > Scanner-UA,
// sonst "" (der Aufrufer entscheidet zwischen Login-Versuch und http:scan). tags nennt alle Treffer (Detail).
func sensorClassify(r *http.Request, body []byte) (kind string, tags []string) {
	target := r.RequestURI
	if target == "" {
		target = r.URL.RequestURI()
	}
	dt := sensorUnescape(sensorUnescape(target))
	var sb strings.Builder
	sb.WriteString(dt)
	sb.WriteByte('\n')
	sb.WriteString(sensorUnescape(string(body)))
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range r.Header[k] {
			sb.WriteByte('\n')
			sb.WriteString(v)
		}
	}
	hay := sb.String()
	for _, o := range sensorOWASP {
		if o.re.MatchString(hay) {
			tags = append(tags, o.tag)
			if kind == "" {
				kind = o.kind
			}
		}
	}
	ua := strings.ToLower(r.UserAgent())
	if name := sensorMatch(ua, sensorResearch); name != "" {
		tags = append(tags, "research:"+name)
		if kind == "" {
			kind = KindScannerResch
		}
	}
	path := strings.ToLower(dt)
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	for _, p := range sensorExploitPaths {
		if strings.Contains(path, p) {
			tags = append(tags, "path:"+p)
			if kind == "" {
				kind = KindHTTPExploit
			}
			break
		}
	}
	if name := sensorMatch(ua, sensorBadUAs); name != "" {
		tags = append(tags, "ua:"+name)
		if kind == "" {
			kind = KindBadUA
		}
	}
	if r.Method == http.MethodConnect || strings.HasPrefix(strings.ToLower(target), "http") {
		tags = append(tags, "proxy")
	}
	return kind, tags
}

func sensorMatch(s string, list [][2]string) string {
	if s == "" {
		return ""
	}
	for _, x := range list {
		if strings.Contains(s, x[0]) {
			return x[1]
		}
	}
	return ""
}

// sensorUnescape dekodiert %xx und '+' so weit moeglich (fehlerhafte Folgen bleiben stehen).
func sensorUnescape(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) && sensorIsHex(s[i+1]) && sensorIsHex(s[i+2]) {
			d, _ := url.QueryUnescape(s[i : i+3])
			b.WriteString(d)
			i += 2
			continue
		}
		if c == '+' {
			c = ' '
		}
		b.WriteByte(c)
	}
	return b.String()
}

func sensorIsHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}
