<?php
/**
 * Pruefung von api_v2_honeypot.php, honeypot/index.php und bots/honeypot_cleanup.php in der Testumgebung hp2test-*
 * (run_agentbox.sh). Spricht die API ueber den PHP-Builtin-Server an und prueft die Tabellen direkt.
 *
 *   HP2TEST=1 php run_tests.php http://127.0.0.1:8080 /w/web
 */
if(php_sapi_name() !== 'cli' OR getenv('HP2TEST') !== '1') { exit; }
require __DIR__ . '/fresh_report.php';

$BASE = rtrim($argv[1] ?? 'http://127.0.0.1:8080', '/');
$WEB = $argv[2] ?? '/w/web';
const K1 = 'TestKeyAccountOne000000000000001';   // users.apikey, Account 1
const K2 = 'TestKeyApiKeysTwo000000000000002';   // api_keys, Account 2
const K3 = 'TestKeyAccountThree0000000000003';   // Account 3
const SENSOR_IP = '84.200.1.1';                  // oeffentliche IP des Sensors (X-Forwarded-For, REMOTE_ADDR ist privat)

$db = new PDO('mysql:host=hp2test-db;dbname=ipv64', 'root', 'hp2test', array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8mb4'"));
$pass = 0; $failed = 0;

function check(string $name, bool $ok, $info = ''): void {
	global $pass, $failed;
	if($ok) { $pass++; echo "  ok    $name\n"; }
	else { $failed++; echo "  FEHLER $name " . (is_string($info) ? $info : json_encode($info, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) . "\n"; }
}

function req(string $method, string $path, ?string $body = null, array $headers = array(), ?string $key = K1, string $ip = SENSOR_IP): array {
	global $BASE;
	$h = array('X-Forwarded-For: ' . $ip);
	if($key !== null) { $h[] = 'Authorization: Bearer ' . $key; }
	if($body !== null AND !preg_grep('/^Content-Type:/i', $headers)) { $h[] = 'Content-Type: application/json'; }
	$ctx = stream_context_create(array('http' => array('method' => $method, 'header' => implode("\r\n", array_merge($h, $headers)), 'content' => $body ?? '',
		'ignore_errors' => true, 'timeout' => 60)));
	$t = microtime(true);
	$raw = @file_get_contents($BASE . $path, false, $ctx);
	$ms = (int)((microtime(true) - $t) * 1000);
	$code = 0; $hdr = array();
	foreach($http_response_header ?? array() as $l) {
		if(preg_match('#^HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; }
		elseif(str_contains($l, ':')) { [$k, $v] = explode(':', $l, 2); $hdr[strtolower(trim($k))] = trim($v); }
	}
	return array('code' => $code, 'h' => $hdr, 'j' => json_decode((string)$raw, true), 'raw' => (string)$raw, 'ms' => $ms);
}

function report(?string $sensor = null, int $end = 0, ?callable $mod = null): array {
	$r = json_decode(file_get_contents(__DIR__ . '/sample_report.json'), true);
	$r = hp_fresh($r, $end ?: time() - 5, $sensor);
	if($mod !== null) { $r = $mod($r); }
	return $r;
}
function post(array $r, ?string $key = K1, array $headers = array(), bool $gzip = false): array {
	$b = json_encode($r, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	if($gzip) { $b = gzencode($b); $headers[] = 'Content-Encoding: gzip'; }
	return req('POST', '/api_v2.php/honeypot/reports', $b, $headers, $key);
}
function one(string $sql, array $p = array()) { global $db; $st = $db->prepare($sql); $st->execute($p); return $st->fetch(PDO::FETCH_ASSOC); }
function all(string $sql, array $p = array()): array { global $db; $st = $db->prepare($sql); $st->execute($p); return $st->fetchAll(PDO::FETCH_ASSOC); }
function code(array $res): string { return $res['code'] . ' ' . substr($res['raw'], 0, 300); }

// ---------------------------------------------------------------- Anmeldung
echo "Anmeldung\n";
$r = req('GET', '/api_v2.php/honeypot/stats', null, array(), null);
check('ohne Key 401', $r['code'] === 401, code($r));
$r = req('GET', '/api_v2.php/honeypot/stats', null, array(), 'FalscherKey00000000000000000000x');
check('falscher Key 401', $r['code'] === 401, code($r));

// ---------------------------------------------------------------- gueltige Meldung
echo "Gueltige Meldung\n";
$A = hp_uuid();
$repA = report($A, 0, function($r) {
	$r['sources'][] = array('ip' => SENSOR_IP, 'kind' => 'ssh:bruteforce', 'service' => 'ssh', 'port' => 22, 'count' => 2, 'first' => $r['period']['start'], 'last' => $r['period']['start'], 'source' => 'honeypot');
	foreach(array('10.1.2.3', '100.64.1.1', '127.0.0.1', '::1', 'fe80::1', '::ffff:9.9.9.9', '2001:db8::1', '224.0.0.1', '172.16.5.5') as $ip) {
		$r['sources'][] = array('ip' => $ip, 'kind' => 'ssh:bruteforce', 'service' => 'ssh', 'port' => 22, 'count' => 1, 'first' => $r['period']['start'], 'last' => $r['period']['start'], 'source' => 'honeypot');
	}
	$r['sources'][] = array('ip' => '1.0.0.1', 'kind' => '9future:thing', 'service' => 'ssh', 'port' => 22, 'count' => 1, 'first' => $r['period']['start'], 'last' => $r['period']['start'], 'source' => 'honeypot');
	$r['sources'][] = array('ip' => '1.0.0.2', 'kind' => 'ssh:bruteforce', 'service' => '9gopher', 'port' => 70, 'count' => 1, 'first' => $r['period']['start'], 'last' => $r['period']['start'], 'source' => 'honeypot');
	$r['samples']['credentials'][] = array('service' => 'ssh', 'user' => 'pi', 'pass' => "raspberry\u{1F600}", 'count' => 2);
	$r['samples']['credentials'][] = array('service' => 'ssh', 'user' => 'root', 'pass' => '123456', 'count' => 1); // gleicher Schluessel: wird addiert
	return $r;
});
$r = post($repA);
check('202 angenommen', $r['code'] === 202, code($r));
$d = $r['j']['data'] ?? array();
check('accepted = 3 (9.9.9.9 x2, 2620:fe::fe)', ($d['accepted'] ?? null) === 3, $d);
check('report_id zurueck', ($d['report_id'] ?? '') === $repA['report_id'], $d);
$rr = (array)($d['rejected_reasons'] ?? array());
check('verworfen: 10 nicht oeffentlich (inkl. 192.0.2.10)', ($rr['not_public'] ?? 0) === 10, $rr);
check('verworfen: eigene IP', ($rr['own_ip'] ?? 0) === 1, $rr);
check('verworfen: Art/Dienst ausserhalb des Musters', ($rr['unknown_kind'] ?? 0) === 1 AND ($rr['unknown_service'] ?? 0) === 1, $rr);
check('Antwort in 1 s', $r['ms'] < 1000, $r['ms'] . ' ms');

$sen = one("SELECT * FROM hp_sensors WHERE sensor_id = ?", array($A));
check('Sensor angelegt mit last_ip', $sen AND $sen['last_ip'] === SENSOR_IP AND (int)$sen['reports'] === 1 AND $sen['profile'] === 'standard' AND $sen['mode'] === 'headless', $sen);
check('ohne sensor.country: Standort automatisch (NULL)', $sen AND $sen['country'] === null, $sen);
$rep = one("SELECT * FROM hp_reports WHERE report_id = ?", array($repA['report_id']));
check('hp_reports: sources 3, rejected 13, ip', $rep AND (int)$rep['sources'] === 3 AND (int)$rep['rejected'] === 13 AND $rep['ip'] === SENSOR_IP, $rep);
$src = all("SELECT ip, LENGTH(ip_bin) l, HEX(ip_bin) h, kind, service, port, `count`, detail FROM hp_report_sources WHERE report_ref = ? ORDER BY id", array($rep['id']));
check('hp_report_sources 3 Zeilen', count($src) === 3, $src);
check('ip_bin IPv4 4 Byte / IPv6 16 Byte', $src[0]['l'] == 4 AND $src[0]['h'] === '09090909' AND $src[2]['l'] == 16 AND $src[2]['ip'] === '2620:fe::fe', $src);
$daily = all("SELECT kind, service, port, events, sources FROM hp_daily WHERE sensor_id = ? ORDER BY kind", array($A));
check('hp_daily je Art/Port', count($daily) === 3 AND (int)$daily[0]['events'] === 1 AND (int)$daily[2]['events'] === 17, $daily);
$cr = one("SELECT `count`, password, pass_sha1 FROM hp_samples_creds WHERE service = 'ssh' AND username = 'root' AND password = '123456'");
check('Zugangsdaten zusammengefasst (9 + 1)', $cr AND (int)$cr['count'] === 10 AND $cr['pass_sha1'] === sha1('123456'), $cr);
$cr = one("SELECT password FROM hp_samples_creds WHERE username = 'pi'");
check('4-Byte-Zeichen ersetzt', $cr AND $cr['password'] === "raspberry\u{FFFD}", $cr);
$pl = one("SELECT * FROM hp_samples_payloads WHERE port = 3389");
check('Payload gespeichert', $pl AND (int)$pl['count'] === 2 AND $pl['head_b64'] === 'R0VUIC8gSFRUUC8xLjANCg0K', $pl);

// ---------------------------------------------------------------- doppelt, Rate-Limit, gzip
echo "Doppelt, Rate-Limit, gzip\n";
$r = post($repA);
check('doppelte report_id 200 duplicate', $r['code'] === 200 AND ($r['j']['data']['duplicate'] ?? false) === true, code($r));
check('doppelt: nichts doppelt gezaehlt', (int)one("SELECT reports FROM hp_sensors WHERE sensor_id = ?", array($A))['reports'] === 1);
$r = post(report($A, time() - 1));
check('zweite Meldung sofort 429', $r['code'] === 429, code($r));
check('Retry-After gesetzt', isset($r['h']['retry-after']) AND (int)$r['h']['retry-after'] > 0 AND (int)$r['h']['retry-after'] <= 120, $r['h']);
$db->prepare("UPDATE hp_sensors SET last_seen = last_seen - INTERVAL 3 MINUTE WHERE sensor_id = ?")->execute(array($A));
$repA2 = report($A, time() - 1, function($r) { $r['period']['start'] = gmdate('Y-m-d\TH:i:s\Z', strtotime($r['period']['start']) + 1); $r['report_id'] = $r['sensor']['id'] . '-' . strtotime($r['period']['start']); $r['sensor']['country'] = 'SG'; return $r; });
$r = post($repA2, K1, array(), true);
check('gzip 202', $r['code'] === 202 AND ($r['j']['data']['accepted'] ?? 0) === 3, code($r));
$cr = one("SELECT `count` FROM hp_samples_creds WHERE service = 'ssh' AND username = 'root' AND password = '123456'");
check('Tagessumme Zugangsdaten addiert (10 + 9)', (int)$cr['count'] === 19, $cr);
$dl = one("SELECT SUM(events) e FROM hp_daily WHERE sensor_id = ? AND kind = 'ssh:bruteforce'", array($A));
check('Tagessumme hp_daily addiert (17 + 17)', (int)$dl['e'] === 34, $dl);
check('Ueberlappung vermerkt', (int)one("SELECT overlap FROM hp_reports WHERE report_id = ?", array($repA2['report_id']))['overlap'] === 1);
check('sensor.country SG gespeichert (Live-Karte)', one("SELECT country FROM hp_sensors WHERE sensor_id = ?", array($A))['country'] === 'SG');

// ---------------------------------------------------------------- Zeitformate
echo "Zeitformate\n";
$B = hp_uuid();
$r = post(report($B, time() - 30, function($r) {
	$s = strtotime($r['period']['start']); $e = strtotime($r['period']['end']);
	$r['period']['start'] = gmdate('Y-m-d\TH:i:s', $s) . '.987654321Z';
	$loc = (new DateTime('@' . $e))->setTimezone(new DateTimeZone('Europe/Berlin'));
	$r['period']['end'] = $loc->format('Y-m-d\TH:i:s') . '.5' . $loc->format('P'); // Ortszeit mit Versatz
	return $r;
}));
check('Nanosekunden und Zeitzonen-Versatz 202', $r['code'] === 202, code($r));

// ---------------------------------------------------------------- ungueltig
echo "Ungueltige Meldungen\n";
$C = hp_uuid();
$cases = array(
	'schema 2' => array(fn($r) => array_merge($r, array('schema' => 2)), 422),
	'schema als Text' => array(fn($r) => array_merge($r, array('schema' => '1')), 422),
	'report_id falsch' => array(fn($r) => array_merge($r, array('report_id' => 'abc')), 422),
	'report_id anderer Start' => array(fn($r) => array_merge($r, array('report_id' => $r['sensor']['id'] . '-1')), 422),
	'sensor.id keine UUID' => array(function($r) { $r['sensor']['id'] = 'sensor-1'; $r['report_id'] = 'sensor-1-' . strtotime($r['period']['start']); return $r; }, 422),
	'profile unbekannt' => array(function($r) { $r['sensor']['profile'] = 'mega'; return $r; }, 422),
	'mode unbekannt' => array(function($r) { $r['sensor']['mode'] = 'x'; return $r; }, 422),
	'version leer' => array(function($r) { $r['sensor']['version'] = ''; return $r; }, 422),
	'Ende in der Zukunft' => array(function($r) { $r['period']['end'] = gmdate('Y-m-d\TH:i:s\Z', time() + 900); return $r; }, 422),
	'Ende vor Start' => array(function($r) { $r['period']['end'] = $r['period']['start']; return $r; }, 422),
	'Zeitraum > 7 Tage' => array(function($r) { $s = time() - 8 * 86400; $r['period']['start'] = gmdate('Y-m-d\TH:i:s\Z', $s); $r['report_id'] = $r['sensor']['id'] . '-' . $s; return $r; }, 422),
	'Zeit ohne Zone' => array(function($r) { $r['period']['end'] = gmdate('Y-m-d\TH:i:s', time() - 10); return $r; }, 422),
	'Zeit 31. Februar' => array(function($r) { $r['period']['end'] = '2026-02-31T10:00:00Z'; return $r; }, 422),
	'Port 70000' => array(function($r) { $r['sources'][0]['port'] = 70000; return $r; }, 422),
	'Port als Text' => array(function($r) { $r['sources'][0]['port'] = '22'; return $r; }, 422),
	'count 0' => array(function($r) { $r['sources'][0]['count'] = 0; return $r; }, 422),
	'IP kein Text' => array(function($r) { $r['sources'][0]['ip'] = 'not-an-ip'; return $r; }, 422),
	'kind Format' => array(function($r) { $r['sources'][0]['kind'] = 'SSH Brute'; return $r; }, 422),
	'first nach last' => array(function($r) { [$r['sources'][0]['first'], $r['sources'][0]['last']] = array($r['sources'][0]['last'], $r['sources'][0]['first']); return $r; }, 422),
	'sources kein Array' => array(fn($r) => array_merge($r, array('sources' => 'x')), 422),
	'samples Pfad leer' => array(function($r) { $r['samples']['paths'][0]['key'] = ''; return $r; }, 422),
	'samples Pfad zu lang' => array(function($r) { $r['samples']['paths'][0]['key'] = '/' . str_repeat('a', 1024); return $r; }, 422),
	'payload head zu lang' => array(function($r) { $r['samples']['payloads'][0]['head'] = base64_encode(str_repeat('x', 257)); return $r; }, 422),
	'payload sha256 falsch' => array(function($r) { $r['samples']['payloads'][0]['sha256'] = 'abc'; return $r; }, 422),
	'dropped negativ' => array(fn($r) => array_merge($r, array('dropped' => -1)), 422),
);
foreach($cases as $name => [$mod, $want]) {
	$r = post(report($C, time() - 5, $mod));
	check("$name -> $want", $r['code'] === $want AND ($r['j']['code'] ?? '') !== '', code($r));
}
$P = hp_uuid();
$r = post(report($P, time() - 5, function($r) { $r['sensor']['profile'] = 'proxy'; return $r; }));
check('profile proxy (nur ueber PROXY64) -> 202', $r['code'] === 202 AND (one("SELECT profile FROM hp_sensors WHERE sensor_id = ?", array($P))['profile'] ?? '') === 'proxy', code($r));
check('keine Zeile fuer den ungueltigen Sensor', one("SELECT sensor_id FROM hp_sensors WHERE sensor_id = ?", array($C)) === false);
$r = req('POST', '/api_v2.php/honeypot/reports', '{"schema":1,', array());
check('kaputtes JSON 400', $r['code'] === 400, code($r));
$r = req('POST', '/api_v2.php/honeypot/reports', json_encode(report($C)), array('Content-Type: text/plain'));
check('falscher Content-Type 415', $r['code'] === 415, code($r));
$r = req('POST', '/api_v2.php/honeypot/reports', json_encode(report($C)), array('Content-Encoding: br'));
check('Content-Encoding br 415', $r['code'] === 415, code($r));
$r = req('POST', '/api_v2.php/honeypot/reports', 'kein gzip', array('Content-Encoding: gzip'));
check('kaputtes gzip 400', $r['code'] === 400, code($r));
$r = req('POST', '/api_v2.php/honeypot/reports', substr(gzencode(json_encode(report($C))), 0, 60), array('Content-Encoding: gzip'));
check('abgeschnittenes gzip 400', $r['code'] === 400, code($r));

// ---------------------------------------------------------------- Groesse
echo "Groesse\n";
$big = report($C, time() - 5, function($r) { $r['sources'][0]['detail'] = str_repeat('x', 200); $r['pad'] = str_repeat(' ', 2 * 1048576); return $r; });
$r = post($big);
check('ungepackt > 2 MiB 413', $r['code'] === 413, code($r));
$r = post($big, K1, array(), true);
check('gepackt klein, entpackt > 2 MiB (gzip-Bombe) 413', $r['code'] === 413, code($r));
$many = report($C, time() - 5, function($r) { $s = $r['sources'][0]; $r['sources'] = array(); for($i = 0; $i < 5001; $i++) { $s['ip'] = '9.9.' . intdiv($i, 250) . '.' . ($i % 250 + 1); $r['sources'][] = $s; } return $r; });
$r = post($many);
check('5001 Quellen 413', $r['code'] === 413, code($r));
array_pop($many['sources']);
$r = post($many, K1, array(), true);
check('5000 Quellen 202', $r['code'] === 202 AND ($r['j']['data']['accepted'] ?? 0) === 5000, code($r));
echo "        (5000 Quellen in {$r['ms']} ms)\n";
check('5000 Quellen in < 5 s', $r['ms'] < 5000, $r['ms'] . ' ms');

// ---------------------------------------------------------------- Account-Limit, gesperrt, Umzug
echo "Limits\n";
$st = $db->prepare("INSERT INTO hp_sensors (sensor_id, userid, first_seen, last_seen) VALUES (?, 2, UTC_TIMESTAMP(), UTC_TIMESTAMP())");
for($i = 0; $i < 50; $i++) { $st->execute(array(hp_uuid())); }
$r = post(report(hp_uuid()), K2);
check('51. Sensor 403 sensor_limit', $r['code'] === 403 AND ($r['j']['code'] ?? '') === 'sensor_limit', code($r));
$D = hp_uuid();
$r = post(report($D), K3);
check('Account 3 (users.apikey) 202', $r['code'] === 202, code($r));
$db->prepare("UPDATE hp_sensors SET disabled = 1, last_seen = last_seen - INTERVAL 3 MINUTE WHERE sensor_id = ?")->execute(array($D));
$r = post(report($D, time() - 2), K3);
check('gesperrter Sensor 403', $r['code'] === 403 AND ($r['j']['code'] ?? '') === 'sensor_disabled', code($r));
$db->prepare("UPDATE hp_sensors SET disabled = 0 WHERE sensor_id = ?")->execute(array($D));
$r = post(report($D, time() - 3), K1);
check('Sensor zieht zu Account 1 um 202', $r['code'] === 202 AND (int)one("SELECT userid FROM hp_sensors WHERE sensor_id = ?", array($D))['userid'] === 1, code($r));

// ---------------------------------------------------------------- GET
echo "GET sensors/stats\n";
$r = req('GET', '/api_v2.php/honeypot/sensors');
$list = $r['j']['data'] ?? array();
$ids = array_column($list, 'id');
check('sensors 200 mit A, B, C, D', $r['code'] === 200 AND !array_diff(array($A, $B, $C, $D), $ids), code($r));
$a = $list[array_search($A, $ids)] ?? array();
check('Sensor A: online, 2 Meldungen, Quell-IPs 24 h = 2, Ereignisse 24 h', ($a['online'] ?? false) === true AND ($a['reports'] ?? 0) === 2 AND ($a['sources_24h'] ?? 0) === 2 AND ($a['events_24h'] ?? 0) === 42, $a);
check('keine IP in /sensors', !str_contains($r['raw'], SENSOR_IP) AND !str_contains($r['raw'], 'last_ip'), $r['raw']);
$r = req('GET', '/api_v2.php/honeypot/sensors', null, array(), K2);
check('Account 2 sieht keine Sensoren von Account 1', $r['code'] === 200 AND !in_array($A, array_column($r['j']['data'] ?? array(), 'id'), true), code($r));
$r = req('GET', '/api_v2.php/honeypot/stats');
$s = $r['j']['data'] ?? array();
check('stats 200', $r['code'] === 200, code($r));
check('stats: Quell-IPs 7 d >= 5001, Ereignisse > 0', ($s['sources_7d'] ?? 0) >= 5001 AND ($s['events_24h'] ?? 0) > 0 AND ($s['contributor'] ?? false) === true, $s);
check('stats: Verlauf 7 Tage', count($s['timeline'] ?? array()) === 7 AND end($s['timeline'])['events'] > 0, $s['timeline'] ?? null);
check('stats: Top-Arten/Ports', ($s['top_kinds'][0]['kind'] ?? '') === 'ssh:bruteforce' AND ($s['top_ports'][0]['port'] ?? 0) === 22, array($s['top_kinds'] ?? null, $s['top_ports'] ?? null));
$r = req('GET', '/api_v2.php/honeypot/stats', null, array(), K3);
check('stats Account 3: Sensor umgezogen, Verlauf bleibt', $r['code'] === 200 AND ($r['j']['data']['events_7d'] ?? -1) === 21 AND ($r['j']['data']['sensors'] ?? -1) === 0, code($r));

// ---------------------------------------------------------------- Listen-Token (Node64 holt es ueber den API-Key)
echo "GET list-token
";
$r = req('GET', '/api_v2.php/honeypot/list-token');
$t1 = (string)($r['j']['data']['token'] ?? '');
check('list-token: 200, Token 32 Zeichen, Live-Adresse', $r['code'] === 200 AND preg_match('/^[A-Za-z0-9]{32}$/', $t1) === 1 AND ($r['j']['data']['base'] ?? '') === "https://ipv64.net/blocklists/live/$t1/", code($r));
check('list-token: Beitragende/r (Sensor in 7 Tagen) -> live', ($r['j']['data']['live'] ?? null) === true, $r['j']['data'] ?? null);
check('list-token: angelegt in hp_list_tokens', one("SELECT token FROM hp_list_tokens WHERE userid = 1")['token'] === $t1);
$r = req('GET', '/api_v2.php/honeypot/list-token');
check('list-token: zweiter Abruf gleiches Token (kein Widerruf)', ($r['j']['data']['token'] ?? '') === $t1);
$r = req('GET', '/api_v2.php/honeypot/list-token', null, array(), K3);
check('list-token: Standard ohne aktiven Sensor -> live false, eigenes Token', ($r['j']['data']['live'] ?? null) === false AND preg_match('/^[A-Za-z0-9]{32}$/', (string)($r['j']['data']['token'] ?? '')) === 1 AND ($r['j']['data']['token'] ?? '') !== $t1, $r['j']['data'] ?? null);
$r = req('GET', '/api_v2.php/honeypot/list-token', null, array(), null);
check('list-token ohne Key: 401', $r['code'] === 401, code($r));

// ---------------------------------------------------------------- Seite
echo "Seite honeypot/index.php\n";
$r = req('GET', '/honeypot/index.php');
check('Seite 200', $r['code'] === 200, code($r));
check('Seite: Titel, Sensoren zusammengefasst (seit 437d2db), Doku-Link', str_contains($r['raw'], 'Honeypot64 – deine Sensoren') AND preg_match('/<b>\d+ Sensor(en)?<\/b>/u', $r['raw']) AND str_contains($r['raw'], '/nodes.php') AND str_contains($r['raw'], 'node64.de/docs/honeypot/'), substr($r['raw'], 0, 500));
check('Seite: keine Sensor-IP', !str_contains($r['raw'], SENSOR_IP));
check('Seite: ssh:bruteforce in Top-Arten', str_contains($r['raw'], 'ssh:bruteforce'));
$r = req('GET', '/honeypot/index.php?as=3');
check('Seite Account 3 ohne fremde Sensoren', $r['code'] === 200 AND !str_contains($r['raw'], substr($A, 0, 8)) AND str_contains($r['raw'], 'Noch kein Sensor'), substr($r['raw'], 0, 300));
$r = req('GET', '/honeypot/index.php?as=0');
check('Seite ohne Anmeldung: Hinweis', str_contains($r['raw'], 'Bitte zuerst anmelden'), substr($r['raw'], 0, 300));

// ---------------------------------------------------------------- Aufraeumen
echo "Aufraeumen (bots/honeypot_cleanup.php)\n";
$old = gmdate('Y-m-d', time() - 100 * 86400); $oldT = $old . ' 12:00:00';
$db->exec("INSERT INTO hp_reports (day, report_id, sensor_id, userid, period_start, period_end, received_at, ip) VALUES ('$old', 'old-1', '$A', 1, '$oldT', '$oldT', '$oldT', '84.200.1.1')");
$ref = (int)$db->lastInsertId();
$ins = $db->prepare("INSERT INTO hp_report_sources (day, report_ref, userid, sensor_id, ip, ip_bin, kind, service, port, `count`, first_seen, last_seen) VALUES ('$old', $ref, ?, '$A', ?, ?, 'ssh:bruteforce', 'ssh', 22, ?, '$oldT', '$oldT')");
foreach(array(array(1, '9.9.9.9', 5), array(2, '9.9.9.10', 3), array(1, '2620:fe::fe', 2), array(1, '2620:fe::9', 1)) as [$uu, $ip, $c]) { $ins->execute(array($uu, $ip, inet_pton($ip), $c)); }
$out = shell_exec('cd ' . escapeshellarg($WEB . '/bots') . ' && php honeypot_cleanup.php 2>&1');
echo preg_replace('/^/m', '        ', trim((string)$out)), "\n";
$arch = all("SELECT HEX(net_bin) n, family, events, ips, accounts FROM hp_sources_archive WHERE day = ? ORDER BY family", array($old));
check('Archiv: /24 und /48', count($arch) === 2 AND $arch[0]['n'] === '09090900' AND (int)$arch[0]['events'] === 8 AND (int)$arch[0]['ips'] === 2 AND (int)$arch[0]['accounts'] === 2
	AND $arch[1]['n'] === '262000FE000000000000000000000000' AND (int)$arch[1]['ips'] === 2, $arch);
check('alte Quellen und Meldung geloescht', (int)one("SELECT count(*) c FROM hp_report_sources WHERE day = ?", array($old))['c'] === 0 AND one("SELECT id FROM hp_reports WHERE report_id = 'old-1'") === false);
check('aktuelle Daten bleiben', (int)one("SELECT count(*) c FROM hp_report_sources")['c'] > 5000);
shell_exec('cd ' . escapeshellarg($WEB . '/bots') . ' && php honeypot_cleanup.php 2>&1');
check('zweiter Lauf zaehlt nichts doppelt', (int)one("SELECT events FROM hp_sources_archive WHERE day = ? AND family = 4", array($old))['events'] === 8);

echo "\n$pass ok, $failed Fehler\n";
exit($failed > 0 ? 1 : 0);
