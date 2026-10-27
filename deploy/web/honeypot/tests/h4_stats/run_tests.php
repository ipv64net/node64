<?php
/**
 * Pruefung Honeypot64 H4 (Statistik + Listen) in der Testumgebung hp4a-* (run_agentbox.sh): Zaehlung je Account in
 * api_v2_honeypot.php, Schwelle, bots/honeypot_lists.php (Dateien, index.json, Aufraeumen), Haken in
 * create_blocklists_v2.php, honeypot/stats.php (oeffentlich vs. Klasse, Suche, CSV, Cache), GET /threat/stats.
 *
 *   HP4ATEST=1 php run_tests.php http://127.0.0.1:8080 /var/www/clients/client1/web58/web
 *   HP4ATEST=1 php run_tests.php --nginx http://hp4a-nginx      (nach dem Start von hp4a-nginx mit den Dateien aus /w/nginx)
 */
if(php_sapi_name() !== 'cli' OR getenv('HP4ATEST') !== '1') { exit; }
$pass = 0; $failed = 0;

function check(string $name, bool $ok, $info = ''): void {
	global $pass, $failed;
	if($ok) { $pass++; echo "  ok    $name\n"; }
	else { $failed++; echo "  FEHLER $name " . substr(is_string($info) ? $info : json_encode($info, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), 0, 800) . "\n"; }
}
/** HTTP-Anfrage; $o: ip (X-Forwarded-For), key, ua, body (JSON) */
function req(string $method, string $url, array $o = array()): array {
	$h = array('X-Forwarded-For: ' . ($o['ip'] ?? '84.200.9.9'));
	if(isset($o['key'])) { $h[] = 'Authorization: Bearer ' . $o['key']; }
	if(isset($o['ua'])) { $h[] = 'User-Agent: ' . $o['ua']; }
	if(isset($o['body'])) { $h[] = 'Content-Type: application/json'; }
	$ctx = stream_context_create(array('http' => array('method' => $method, 'header' => implode("\r\n", $h), 'content' => $o['body'] ?? '', 'ignore_errors' => true, 'timeout' => 60)));
	$raw = @file_get_contents($url, false, $ctx);
	$code = 0; $hdr = array();
	foreach($http_response_header ?? array() as $l) {
		if(preg_match('#^HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; }
		elseif(str_contains($l, ':')) { [$k, $v] = explode(':', $l, 2); $hdr[strtolower(trim($k))] = trim($v); }
	}
	return array('code' => $code, 'h' => $hdr, 'j' => json_decode((string)$raw, true), 'raw' => (string)$raw);
}

// ---------------------------------------------------------------- nginx (zweiter Aufruf)
if(($argv[1] ?? '') === '--nginx') {
	$N = rtrim($argv[2] ?? 'http://hp4a-nginx', '/');
	$browser = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36';
	foreach(array('zgrab/0.x', 'ZGRAB/0.X', 'Evil "quote" \\back\\slash', '~tilde-agent', 'default', 'Agent$var{x};', '\\start-backslash', 'tab\\tliteral') as $ua) {
		check("UA gesperrt: $ua", req('GET', "$N/", array('ua' => $ua))['code'] === 403);
	}
	foreach(array($browser, 'zgrab/0.y', 'Evil "quote" \\back', 'tilde-agent', 'tab	literal') as $ua) {
		check("UA erlaubt: $ua", req('GET', "$N/", array('ua' => $ua))['code'] === 200);
	}
	foreach(array('/.env', '/wp-login.php', '/cgi-bin/luci/;stok=/locale', '/legacy-path', "/it's(1)+x") as $p) {
		check("Pfad gesperrt: $p", req('GET', $N . $p, array('ua' => $browser))['code'] === 403);
	}
	foreach(array('/', '/index.html', '/.envx', '/x/.env', '/robots.txt', '/solo-path', '/cgi-bin/luci/') as $p) {
		check("Pfad erlaubt: $p", req('GET', $N . $p, array('ua' => $browser))['code'] === 200);
	}
	echo "\nnginx: $pass ok, $failed Fehler\n";
	exit($failed > 0 ? 1 : 0);
}

$BASE = rtrim($argv[1] ?? 'http://127.0.0.1:8080', '/');
$WEB = rtrim($argv[2] ?? '/var/www/clients/client1/web58/web', '/');
$PUB = "$WEB/blocklists";
$db = new PDO('mysql:host=hp4a-db;dbname=ipv64', 'root', 'hp4atest', array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8mb4'"));

function x(string $sql, array $p = array()) { global $db; $st = $db->prepare($sql); $st->execute($p); return $st; }
function one(string $sql, array $p = array()) { return x($sql, $p)->fetch(PDO::FETCH_ASSOC); }
function col(string $sql, array $p = array()): array { return x($sql, $p)->fetchAll(PDO::FETCH_COLUMN); }
function key_of(int $u): string { return sprintf('TestKeyHp4a%021d', $u); }
function cli(string $cmd): string { global $WEB; return (string)shell_exec("cd $WEB && $cmd 2>&1"); }
function lists_cron(string $args = ''): string { global $WEB; return cli("php $WEB/bots/honeypot_lists.php $args"); }
function gen(string $args = ''): string { global $WEB; return cli("php $WEB/bots/blocklist/create_blocklists_v2.php $args"); }
function lines(string $f): array { global $PUB; return is_file("$PUB/$f") ? explode("\n", rtrim((string)file_get_contents("$PUB/$f"), "\n")) : array('(fehlt)'); }
function page(string $q = ''): array { global $BASE; return req('GET', "$BASE/honeypot/stats.php" . ($q !== '' ? "?$q" : '')); }
function api_stats(array $o = array()): array { global $BASE; return req('GET', "$BASE/api_v2.php/threat/stats", $o); }
function cache(): array { return json_decode((string)one("SELECT data FROM hp_stats_cache WHERE name = 'overview'")['data'], true) ?: array(); }
function topvals(string $kind): array { return col("SELECT `text` FROM hp_sample_top WHERE kind = ? ORDER BY pos", array($kind)); }

$sensorNo = 0;
/** Meldung eines Accounts ueber die API (neuer Sensor je Meldung, wegen der 2-Minuten-Grenze je Sensor). */
function report(int $u, array $creds = array(), array $paths = array(), array $uas = array(), array $payloads = array()): array {
	global $BASE, $sensorNo;
	$sensorNo++;
	$sid = sprintf('00000000-0000-4000-8000-%06d%06d', $u, $sensorNo);
	$end = time() - 5; $start = $end - 600;
	$r = array('schema' => 1, 'report_id' => "$sid-$start", 'sensor' => array('id' => $sid, 'version' => '0.12.0', 'profile' => 'standard', 'mode' => 'headless'),
		'period' => array('start' => gmdate('Y-m-d\TH:i:s\Z', $start), 'end' => gmdate('Y-m-d\TH:i:s\Z', $end)),
		'sources' => array(array('ip' => "45.1.$u.$sensorNo", 'kind' => 'ssh:bruteforce', 'service' => 'ssh', 'port' => 22, 'count' => 3,
			'first' => gmdate('Y-m-d\TH:i:s\Z', $start + 10), 'last' => gmdate('Y-m-d\TH:i:s\Z', $start + 20), 'source' => 'honeypot')),
		'samples' => array(
			'credentials' => array_map(fn($c) => array('service' => 'ssh', 'user' => $c[0], 'pass' => $c[1], 'count' => $c[2] ?? 1), $creds),
			'paths' => array_map(fn($p) => array('key' => is_array($p) ? $p[0] : $p, 'count' => is_array($p) ? $p[1] : 1), $paths),
			'user_agents' => array_map(fn($a) => array('key' => $a, 'count' => 1), $uas),
			'payloads' => $payloads),
		'dropped' => 0);
	return req('POST', "$BASE/api_v2.php/honeypot/reports", array('key' => key_of($u), 'ip' => "84.200.$u." . ($sensorNo % 250 + 1),
		'body' => json_encode($r, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)));
}

// ---------------------------------------------------------------- Testdaten: Accounts 1-25, 2 = VIP, Rest Standard
for($u = 1; $u <= 25; $u++) {
	x("INSERT INTO users (id, email, apikey, user_class) VALUES (?, ?, ?, ?)", array($u, "u$u@test.invalid", key_of($u), $u === 2 ? 2 : 1));
}

echo "SQL\n";
$t = col("SHOW TABLES LIKE 'hp\\_sample%'");
check('Tabellen hp_sample_contrib, hp_sample_top, hp_stats_cache', in_array('hp_sample_contrib', $t, true) AND in_array('hp_sample_top', $t, true) AND (bool)one("SHOW TABLES LIKE 'hp_stats_cache'"), $t);
$leg = x("SELECT kind, userid, cnt FROM hp_sample_contrib ORDER BY kind, cnt")->fetchAll(PDO::FETCH_ASSOC);
check('Altbestand 30 Tage als Account 0 (zweimal eingespielt, ohne Doppel; 40 Tage alt nicht)', count($leg) === 5 AND count(array_filter($leg, fn($r) => (int)$r['userid'] === 0)) === 5
	AND (int)one("SELECT cnt FROM hp_sample_contrib WHERE kind = 'payload'")['cnt'] === 5, $leg);
check('Index key_day auf hp_samples_paths', (bool)one("SHOW INDEX FROM hp_samples_paths WHERE Key_name = 'key_day'"));

// ---------------------------------------------------------------- Meldungen
echo "Annahme: Zaehlung je Account\n";
$pw = array(); for($i = 1; $i <= 12; $i++) { $pw[] = array('user' . $i, sprintf('pw-%02d', $i), 1); }
$shared = array_merge(array(
	array('root', 'shared-pass', 7), array('Root', 'shared-pass', 1), array('admin@example.com', 'shared-pass', 1), array('+49 170 1234567', 'x1', 1),
	array('a1b2c3d4e5f6a7b8c9d0', 'x2', 1), array("bidi\u{202E}user", 'x3', 1), array("ctrl\u{1}user", 'x4', 1),
	array('svc', "=cmd|' /C calc'!A0", 1), array('svc', 'Xk9fQ2mZ7pL4vB8nR3tW6yH1', 1), array('svc', 'mail me@example.org now', 1)), $pw);
$sharedPaths = array('/.env', '/wp-login.php', '/', '/<script>alert(1)</script>', '/cgi-bin/luci/;stok=/locale?form=country', '/x/../etc/passwd', '/legacy-path',
	"/it's(1)+x", '/.well-known/acme-challenge/abc', '/q?token=4f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c');
$sharedUas = array('zgrab/0.x', 'ZGRAB/0.X', 'Evil "quote" \\back\\slash', '~tilde-agent', 'default', 'Agent$var{x};', '\\start-backslash', 'tab\\tliteral',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
	'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'Scanner (+abuse@example.net)', "line\u{2028}break");
$r1 = report(1, array_merge($shared, array(array('poison', 'Poison-Only-1', 1000000), array('cap', 'capped-pass', 1000000))), array_merge($sharedPaths, array(array('/solo-path', 99999))), $sharedUas,
	array(array('sha256' => str_repeat('b', 64), 'head' => base64_encode('GET / HTTP/1.0'), 'service' => 'tcp', 'port' => 23, 'count' => 2)));
check('Meldung Account 1: 202', $r1['code'] === 202, $r1['code'] . ' ' . $r1['raw']);
$r3 = report(3, array_merge($shared, array(array('cap', 'capped-pass', 5))), $sharedPaths, $sharedUas);
check('Meldung Account 3: 202', $r3['code'] === 202, $r3['code'] . ' ' . $r3['raw']);
$r4 = report(4, array(array('legacyuser', 'legacy-pass', 1), array('legacyuser', 'legacy-only-2', 1)));
check('Meldung Account 4: 202', $r4['code'] === 202, $r4['code'] . ' ' . $r4['raw']);
$c1 = one("SELECT COUNT(*) n, SUM(kind = 'cred') c, SUM(kind = 'path') p, SUM(kind = 'ua') a, SUM(kind = 'payload') l FROM hp_sample_contrib WHERE userid = 1");
check('Beitrag Account 1 je Art (cred/path/ua/payload)', (int)$c1['c'] === count($shared) + 2 AND (int)$c1['p'] === count($sharedPaths) + 1 AND (int)$c1['a'] === count($sharedUas) AND (int)$c1['l'] === 1, $c1);
check('cnt = Anzahl der Probe', (int)one("SELECT k.cnt FROM hp_sample_contrib k JOIN hp_samples_creds c ON c.day = k.day AND c.key_hash = k.key_hash WHERE k.userid = 1 AND c.password = 'Poison-Only-1'")['cnt'] === 1000000);
$r1b = report(1, array(array('poison', 'Poison-Only-1', 5)));
check('zweite Meldung desselben Accounts: addiert, keine zweite Zeile', $r1b['code'] === 202 AND (int)one("SELECT COUNT(*) n, MAX(k.cnt) m FROM hp_sample_contrib k JOIN hp_samples_creds c ON c.day = k.day AND c.key_hash = k.key_hash WHERE c.password = 'Poison-Only-1'")['m'] === 1000005
	AND (int)one("SELECT COUNT(*) n FROM hp_sample_contrib k JOIN hp_samples_creds c ON c.day = k.day AND c.key_hash = k.key_hash WHERE c.password = 'Poison-Only-1'")['n'] === 1);

// neu gelistete IP heute (Stub-Zeile in hp_scores) und eine von gestern
x("INSERT INTO hp_scores (ip_bin, ip, family, score, accounts, sensors, events, kinds, lists, first_seen, last_seen, listed, listed_since, reason, updated_at) VALUES
	(INET6_ATON('45.9.9.9'), '45.9.9.9', 4, 77, 3, 3, 30, 'ssh:bruteforce', 'v64,ssh', UTC_TIMESTAMP(), UTC_TIMESTAMP(), 1, UTC_TIMESTAMP(), 'threshold', UTC_TIMESTAMP()),
	(INET6_ATON('45.9.9.8'), '45.9.9.8', 4, 60, 2, 2, 20, 'http:scan', 'v64,web', UTC_TIMESTAMP() - INTERVAL 2 DAY, UTC_TIMESTAMP(), 1, UTC_TIMESTAMP() - INTERVAL 2 DAY, 'threshold', UTC_TIMESTAMP())");
// Beitrag vor 40 und 20 Tagen (Aufraeumen nach 35 Tagen)
x("INSERT INTO hp_sample_contrib (kind, day, key_hash, userid, cnt) VALUES ('cred', UTC_DATE() - INTERVAL 40 DAY, UNHEX(SHA2('alt', 256)), 9, 1), ('cred', UTC_DATE() - INTERVAL 20 DAY, UNHEX(SHA2('mittel', 256)), 9, 1)");

// ---------------------------------------------------------------- Listen-Cron
echo "Listen-Cron (Schwelle 2 unter 20 aktiven Accounts)\n";
$out = lists_cron();
check('Cron laeuft durch', str_contains($out, 'Fertig') AND str_contains($out, 'Schwelle: 2'), $out);
check('index.json fehlt: Hinweis statt Fehler', str_contains($out, 'index.json fehlt'), $out);
$P = lines('ipv64_passwords.txt');
check('Passwoerter: gemeinsame drin', in_array('shared-pass', $P, true) AND in_array('pw-01', $P, true) AND in_array('pw-12', $P, true) AND in_array('capped-pass', $P, true), $P);
check('Passwoerter: Altbestand + ein Account = 2 Accounts', in_array('legacy-pass', $P, true), $P);
check('Einzelaccount drueckt nichts in die Liste (Poison-Only-1, 1 000 005 Versuche)', !in_array('Poison-Only-1', $P, true), $P);
check('nur Altbestand bzw. nur ein Account: nicht drin', !in_array('legacy-only', $P, true) AND !in_array('legacy-only-2', $P, true) AND !in_array('too-old', $P, true), $P);
check('zufaellige Strings und E-Mail-Adressen nicht drin', !in_array('Xk9fQ2mZ7pL4vB8nR3tW6yH1', $P, true) AND !in_array('mail me@example.org now', $P, true), $P);
check('Formel-Passwort im Klartext (Textliste)', in_array("=cmd|' /C calc'!A0", $P, true));
check('Reihenfolge: haeufigste zuerst (capped-pass 10 005, legacy-pass 51, shared-pass 18, pw-01 2)', $P[0] === 'capped-pass' AND $P[1] === 'legacy-pass' AND $P[2] === 'shared-pass' AND array_search('pw-01', $P, true) > 2, array_slice($P, 0, 6));
check('Kappung je Account und Tag: capped-pass 10 005', (int)one("SELECT events FROM hp_sample_top WHERE kind = 'pass' AND `text` = 'capped-pass'")['events'] === 10005);
$S = lines('ipv64_passwords_sha1.txt');
$sorted = $S; sort($sorted, SORT_STRING);
check('SHA-1: 40 Hex gross, sortiert, gleiche Anzahl', count($S) === count($P) AND $S === $sorted AND count(preg_grep('/^[0-9A-F]{40}$/', $S)) === count($S) AND in_array(strtoupper(sha1('shared-pass')), $S, true), $S);
$U = lines('ipv64_usernames.txt');
check('Benutzernamen: root und Root getrennt, Altbestand-Account', in_array('root', $U, true) AND in_array('Root', $U, true) AND in_array('legacyuser', $U, true), $U);
check('Benutzernamen: keine E-Mail, Telefonnummer, Zufall, Bidi, Steuerzeichen', !array_filter($U, fn($x) => str_contains($x, '@') OR str_contains($x, '170 123') OR str_contains($x, 'a1b2c3d4e5') OR str_contains($x, 'user') && $x !== 'legacyuser' && !preg_match('/^user\d+$/', $x)), $U);
$A = lines('ipv64_bad_useragents.txt');
check('User-Agents: Werkzeuge und Sonderfaelle drin', count(array_intersect(array('zgrab/0.x', 'ZGRAB/0.X', 'Evil "quote" \\back\\slash', '~tilde-agent', 'default', 'Agent$var{x};', '\\start-backslash', 'tab\\tliteral'), $A)) === 8, $A);
check('User-Agents: kein Browser, kein Googlebot, keine E-Mail, kein Zeilentrenner, kein Altbestand-only', !array_filter($A, fn($x) => str_contains($x, 'Chrome/') OR str_contains($x, 'Googlebot') OR str_contains($x, '@') OR str_contains($x, 'line') OR str_contains($x, 'legacy')), $A);
$T = lines('ipv64_attack_paths.txt');
check('Pfade: Angriffe drin (auch mit Abfrage, Altbestand + 2 Accounts)', count(array_intersect(array('/.env', '/wp-login.php', '/<script>alert(1)</script>', '/cgi-bin/luci/;stok=/locale?form=country', '/x/../etc/passwd', '/legacy-path', "/it's(1)+x"), $T)) === 7, $T);
check('Pfade: kein /, kein .well-known, kein Einzelaccount, kein Token', !in_array('/', $T, true) AND !in_array('/solo-path', $T, true) AND !array_filter($T, fn($x) => str_contains($x, 'well-known') OR str_contains($x, 'token=')), $T);
$bad = '/[\x00-\x09\x0B-\x1F\x7F]|\xC2[\x80-\x9F]|\xE2\x80[\x8B-\x8F\xA8-\xAE]|\xE2\x81[\xA0-\xAF]|\xEF\xBB\xBF/';
foreach(array('ipv64_passwords.txt', 'ipv64_passwords_sha1.txt', 'ipv64_usernames.txt', 'ipv64_bad_useragents.txt', 'ipv64_bad_useragents.nginx.map', 'ipv64_attack_paths.txt', 'ipv64_attack_paths.nginx.conf') as $f) {
	$c = (string)@file_get_contents("$PUB/$f");
	check("$f: vorhanden, gueltiges UTF-8, keine Steuer-/Bidi-Zeichen, keine E-Mail, 0644", $c !== '' AND mb_check_encoding($c, 'UTF-8') AND !preg_match(str_replace('\x09', '\x08', $bad), $c)
		AND !preg_match('/[^\s@"]+@[^\s@"]+\.[a-z]{2,}/i', $c) AND (fileperms("$PUB/$f") & 0777) === 0644, $f);
}
check('keine Temp-Dateien uebrig', !glob("$PUB/*.tmp.*"));
$map = (string)file_get_contents("$PUB/ipv64_bad_useragents.nginx.map");
check('map: Kopf, default, Ende', str_contains($map, "map \$http_user_agent \$ipv64_bad_ua {\n\tdefault 0;\n") AND str_ends_with($map, "}\n") AND str_contains($map, 'CC BY 4.0'), $map);
check('map: Maskierung " und \\', str_contains($map, "\t\"Evil \\\"quote\\\" \\\\back\\\\slash\" 1;\n") AND str_contains($map, "\t\"tab\\\\tliteral\" 1;\n"), $map);
check('map: ~, \\ und Sonderwort mit fuehrendem \\', str_contains($map, "\t\"\\\\~tilde-agent\" 1;\n") AND str_contains($map, "\t\"\\\\default\" 1;\n") AND str_contains($map, "\t\"\\\\\\\\start-backslash\" 1;\n"), $map);
check('map: Gross-/Kleinschreibung nur einmal (nginx vergleicht ohne)', substr_count(strtolower($map), '"zgrab/0.x"') === 1, $map);
$conf = (string)file_get_contents("$PUB/ipv64_attack_paths.nginx.conf");
check('location: regex mit exaktem Vergleich, return 403', preg_match('/^location ~ "\^\(\?:.*\)\$" \{ return 403; \}$/m', $conf) === 1 AND str_contains($conf, '\\\\.env'), $conf);
check('location: nur sichere Pfade (kein <script>, kein .., kein /)', !str_contains($conf, 'script') AND !str_contains($conf, '\\\\.\\\\./') AND !str_contains($conf, '|\\\\/|'), $conf);
check('Beitraege aelter als 35 Tage geloescht, 20 Tage bleiben', !one("SELECT 1 FROM hp_sample_contrib WHERE day < UTC_DATE() - INTERVAL 35 DAY") AND (bool)one("SELECT 1 FROM hp_sample_contrib WHERE userid = 9 AND day = UTC_DATE() - INTERVAL 20 DAY"));
@mkdir('/w/nginx', 0755, true);
foreach(array('ipv64_bad_useragents.nginx.map', 'ipv64_attack_paths.nginx.conf') as $f) { copy("$PUB/$f", "/w/nginx/$f"); }

echo "index.json\n";
$g = gen();
$ix = json_decode((string)@file_get_contents("$PUB/index.json"), true);
$ids = array_column($ix['data'] ?? array(), 'id');
check('voller Generator-Lauf: Text-Listen unter "data"', $ids === array('honeypot_passwords', 'honeypot_usernames', 'honeypot_bad_useragents', 'honeypot_attack_paths'), $g . json_encode($ix['data'] ?? null));
$d0 = $ix['data'][0] ?? array();
check('Eintrag: Kategorie, Lizenz, Anzahl, Dateien', ($d0['category'] ?? '') === 'honeypot-data' AND ($d0['license'] ?? '') === 'CC BY 4.0 (IPv64.net Honeypot64), provided as is without warranty'
	AND ($d0['count'] ?? 0) === count($P) AND ($d0['files'] ?? null) === array('txt' => 'ipv64_passwords.txt', 'sha1' => 'ipv64_passwords_sha1.txt') AND ($d0['in_all'] ?? true) === false, $d0);
check('nicht unter "lists" (dort waeren es IP-Listen fuer Node64)', !array_filter($ix['lists'] ?? array(), fn($e) => ($e['category'] ?? '') === 'honeypot-data' OR str_contains(json_encode($e), 'passwords')));
$out = lists_cron();
$ix2 = json_decode((string)@file_get_contents("$PUB/index.json"), true);
check('Cron ersetzt nur "data", Rest bleibt', str_contains($out, '4 Text-Listen') AND count($ix2['data'] ?? array()) === 4 AND ($ix2['lists'] ?? null) === ($ix['lists'] ?? 1) AND ($ix2['countries'] ?? null) === ($ix['countries'] ?? 1), $out);
gen('--only=v64');
$ix3 = json_decode((string)@file_get_contents("$PUB/index.json"), true);
check('Generator --only=v64 laesst "data" stehen', array_column($ix3['data'] ?? array(), 'id') === $ids);
check('Cron --dry schreibt nichts', (function() use ($PUB) { $m = filemtime("$PUB/ipv64_passwords.txt"); clearstatcache(); sleep(1); $o = lists_cron('--dry'); clearstatcache(); return str_contains($o, 'nichts geschrieben') AND filemtime("$PUB/ipv64_passwords.txt") === $m; })());

// ---------------------------------------------------------------- Statistikseite
echo "Statistikseite\n";
$pub = page();
$b = $pub['raw'];
check('oeffentlich 200, Ueberblick', $pub['code'] === 200 AND str_contains($b, 'Überblick') AND str_contains($b, 'Honeypot64'), $pub['code'] . substr($b, 0, 300));
check('oeffentlich: Top 10, gemeinsame Eintraege, kein Einzelaccount', str_contains($b, 'shared-pass') AND !str_contains($b, 'Poison-Only-1') AND !str_contains($b, 'solo-path') AND count(array_filter(range(1, 12), fn($i) => str_contains($b, sprintf('pw-%02d', $i)))) < 12, '');
check('oeffentlich: keine Suche, kein Export, keine neuen IPs', !str_contains($b, 'name="q"') AND !str_contains($b, 'export=') AND !str_contains($b, '45.9.9.9') AND !str_contains($b, 'Neu gelistet heute'));
check('HTML maskiert (<script> aus einem Pfad)', !str_contains($b, '<script>alert(1)</script>') AND str_contains($b, '&lt;script&gt;alert(1)&lt;/script&gt;'));
check('Chart.js aus dem Portal, Verlauf 30 Tage', str_contains($b, '/js/chartjs/dist/chart.min.js') AND str_contains($b, 'hssTimeline') AND substr_count(json_encode(cache()['timeline'] ?? array()), '"day"') === 30);
check('Verweis auf /honeypot/ und Groesse der Listen', str_contains($b, 'href="/honeypot/"') AND str_contains($b, 'ipv64_passwords.txt') AND str_contains($b, 'v64 Blocklist'));
check('Herkunft nach Land ohne Daten: Hinweis statt Tabelle (seit H7)', str_contains($b, 'Herkunft nach Land') AND str_contains($b, 'Noch keine Daten.') AND !str_contains($b, '<th>Land</th>'));
$std = page('as=1')['raw'];
check('Klasse Standard eingeloggt: Ueberblick, Beitragender-Hinweis', !str_contains($std, 'name="q"') AND !str_contains($std, '45.9.9.9') AND str_contains($std, 'Danke für deinen Beitrag'));
$vip = page('as=2');
$v = $vip['raw'];
check('VIP: volle Ansicht mit Suche, Export, Top 100', $vip['code'] === 200 AND str_contains($v, 'volle Ansicht') AND str_contains($v, 'name="q"') AND str_contains($v, 'export=pass')
	AND count(array_filter(range(1, 12), fn($i) => str_contains($v, sprintf('pw-%02d', $i)))) === 12, substr($v, 0, 300));
check('VIP: neu gelistet heute (nur heute)', str_contains($v, '45.9.9.9') AND !str_contains($v, '45.9.9.8') AND str_contains($v, 'ip.php?ip=45.9.9.9'));
$np = array_column(cache()['new_paths_today'] ?? array(), 'value');
check('neue Pfade heute: /.env ja, /legacy-path (gestern schon gesehen) nein, Einzelaccount nein', in_array('/.env', $np, true) AND !in_array('/legacy-path', $np, true) AND !in_array('/solo-path', $np, true), $np);
$sr = page('as=2&k=pass&q=SHARED')['raw'];
check('Suche (ohne Gross-/Kleinschreibung)', str_contains($sr, 'shared-pass') AND str_contains($sr, 'value="SHARED"'));
check('Suche findet Einzelaccount-Eintraege nicht', str_contains(page('as=2&k=pass&q=Poison')['raw'], 'Nichts gefunden'));
check('Suche: % und _ wortwoertlich', str_contains(page('as=2&k=pass&q=' . rawurlencode('%'))['raw'], 'Nichts gefunden'));
check('Suche oeffentlich ignoriert', !str_contains(page('k=pass&q=shared')['raw'], 'Nichts gefunden') AND !str_contains(page('k=pass&q=shared')['raw'], 'name="q"'));
$csv = page('as=2&export=pass');
check('CSV fuer VIP: text/csv, Kopfzeile, Inhalt', $csv['code'] === 200 AND str_starts_with($csv['h']['content-type'] ?? '', 'text/csv') AND str_starts_with($csv['raw'], "rank,value,events,accounts,last_seen_utc\n")
	AND str_contains($csv['raw'], ',shared-pass,') AND !str_contains($csv['raw'], '<html'), $csv['h']);
check('CSV: Formel-Injektion entschaerft', str_contains($csv['raw'], "\"'=cmd|' /C calc'!A0\"") OR str_contains($csv['raw'], ",'=cmd|"), $csv['raw']);
foreach(array('user', 'path', 'ua', 'ports', 'kinds', 'timeline', 'new_ips', 'new_paths') as $e) {
	$r = page("as=2&export=$e");
	check("CSV $e", $r['code'] === 200 AND str_starts_with($r['h']['content-type'] ?? '', 'text/csv') AND substr_count($r['raw'], "\n") >= 2, $r['raw']);
}
$pc = page('export=pass');
check('CSV oeffentlich/Standard: kein Export', !str_starts_with($pc['h']['content-type'] ?? 'text/html', 'text/csv') AND str_contains($pc['raw'], 'Der Export gehört') AND !str_starts_with(page('as=1&export=pass')['h']['content-type'] ?? '', 'text/csv'));
check('Englisch', str_contains(page('lang=en')['raw'], 'Statistics') AND str_contains(page('lang=en&as=2')['raw'], 'full view'));

echo "Cache\n";
$at = one("SELECT updated_at FROM hp_stats_cache WHERE name = 'overview'")['updated_at'];
report(6, array(array('fresh', 'fresh-pass', 3))); report(7, array(array('fresh', 'fresh-pass', 3)));
check('neue Daten: Seite bleibt beim Cache-Stand (< 10 min)', !str_contains(page()['raw'], 'fresh-pass') AND one("SELECT updated_at FROM hp_stats_cache WHERE name = 'overview'")['updated_at'] === $at);
x("UPDATE hp_stats_cache SET updated_at = updated_at - INTERVAL 11 MINUTE");
check('nach 10 min neu gerechnet', str_contains(page()['raw'], 'fresh-pass') AND one("SELECT updated_at FROM hp_stats_cache WHERE name = 'overview'")['updated_at'] > $at);

// ---------------------------------------------------------------- API
echo "API GET /threat/stats\n";
$r = api_stats(array('ip' => '84.201.0.1'));
$d = $r['j']['data'] ?? array();
check('ohne Key 200', $r['code'] === 200 AND isset($d['generated_at'], $d['attacks_24h'], $d['timeline'], $d['top'], $d['lists'], $d['threshold']), $r['code'] . ' ' . $r['raw']);
check('Top 10, ab Schwelle', count($d['top']['passwords'] ?? array()) === 10 AND in_array('shared-pass', array_column($d['top']['passwords'], 'value'), true)
	AND !str_contains($r['raw'], 'Poison') AND ($d['threshold']['accounts'] ?? 0) === 2 AND count($d['timeline']) === 30, $d['top']['passwords'] ?? null);
check('keine Interna (neue IPs, Accounts, Sensoren)', !isset($d['new_ips_today']) AND !isset($d['new_paths_today']) AND !str_contains($r['raw'], '45.9.9.9') AND !str_contains($r['raw'], '84.200.') AND !str_contains($r['raw'], 'userid'));
check('Groesse der Listen', ($d['lists']['honeypot_passwords'] ?? -1) === count($P) AND ($d['lists']['v64'] ?? -1) === 2, $d['lists'] ?? null);
check('aus dem Cache (gleicher Stand wie die Seite)', ($d['generated_at'] ?? '') === (cache()['generated_at'] ?? 'x'));
check('RateLimit-Kopfzeilen wie /threat/ip', ($r['h']['ratelimit-limit'] ?? '') === '10', $r['h']);
$codes = array();
for($i = 0; $i < 10; $i++) { $codes[] = api_stats(array('ip' => '84.201.0.1'))['code']; }
check('ohne Key: 10 erlaubt, 11. -> 429', count(array_filter(array_slice($codes, 0, 9), fn($c) => $c === 200)) === 9 AND $codes[9] === 429, $codes);
check('andere IP nicht betroffen', api_stats(array('ip' => '84.201.0.2'))['code'] === 200);
$rk = api_stats(array('ip' => '84.201.0.1', 'key' => key_of(5)));
check('mit API-Key 200 (eigener Topf)', $rk['code'] === 200 AND ($rk['h']['ratelimit-limit'] ?? '') === '120', $rk['code'] . ' ' . json_encode($rk['h']));
check('ungueltiger Key 401', api_stats(array('ip' => '84.201.0.3', 'key' => 'FalscherKey00000000000000000000x'))['code'] === 401);

// ---------------------------------------------------------------- Schwelle 3 ab 20 aktiven Accounts
echo "Schwelle 3 ab 20 aktiven Accounts\n";
for($u = 6; $u <= 25; $u++) {
	$sid = sprintf('00000000-0000-4000-9000-%012d', $u);
	x("INSERT INTO hp_sensors (sensor_id, userid, first_seen, last_seen) VALUES (?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())", array($sid, $u));
	x("INSERT INTO hp_reports (day, report_id, sensor_id, userid, period_start, period_end, received_at) VALUES (UTC_DATE(), ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP())", array("$sid-1", $sid, $u));
}
$out = lists_cron();
$P = lines('ipv64_passwords.txt');
check('Schwelle 3 (mind. 20 aktive Accounts)', str_contains($out, 'Schwelle: 3') AND (cache()['threshold']['accounts'] ?? 0) === 3, $out);
check('2 Accounts reichen nicht mehr (shared-pass, legacy-pass)', !in_array('shared-pass', $P, true) AND !in_array('legacy-pass', $P, true), $P);
report(5, array(array('root', 'shared-pass', 1)));
lists_cron();
$P = lines('ipv64_passwords.txt');
check('dritter Account: wieder drin', in_array('shared-pass', $P, true) AND !in_array('legacy-pass', $P, true), $P);

echo "\n$pass ok, $failed Fehler\n";
exit($failed > 0 ? 1 : 0);
