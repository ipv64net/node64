<?php
/**
 * Pruefung Sonar64 Teil W (Seiten unter /sonar) in der Testumgebung s64w* (run_agentbox.sh): Testdaten in sonar_*,
 * Aufruf aller Seiten (DE/EN, an- und abgemeldet), Escaping, keine IPs/genauen Koordinaten, me.php (Tabellen nur
 * eigener Knoten, CSRF, Token anlegen/Grenze/sperren, Angaben speichern inkl. Verschleierung). Mit api_v2.php
 * zusaetzlich die oeffentlichen JSON-Antworten (gespeichert unter <out> fuer sonar_test.js).
 *
 *   S64WTEST=1 S64WDB=<db> php run_tests.php http://127.0.0.1:8080 <webroot> <out>
 */
if(php_sapi_name() !== 'cli' OR getenv('S64WTEST') !== '1') { exit; }
$BASE = rtrim($argv[1] ?? 'http://127.0.0.1:8080', '/');
$WEB = rtrim($argv[2] ?? '/var/www/clients/client1/web58/web', '/');
$OUT = rtrim($argv[3] ?? '/w/tests/out', '/');
require "$WEB/sonar/s64_lib.php";
$pass = 0; $failed = 0;

function check(string $name, bool $ok, $info = ''): void {
	global $pass, $failed;
	if($ok) { $pass++; echo "  ok    $name\n"; }
	else { $failed++; echo "  FEHLER $name " . substr(is_string($info) ? $info : json_encode($info, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), 0, 600) . "\n"; }
}
$db = new PDO('mysql:host=' . getenv('S64WDB') . ';dbname=ipv64', 'root', 's64wtest', array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8mb4'"));
function x(string $sql, array $p = array()) { global $db; $st = $db->prepare($sql); $st->execute($p); return $st; }
function one(string $sql, array $p = array()) { return x($sql, $p)->fetch(PDO::FETCH_ASSOC); }

$jar = array(); // Cookies je Account (Sitzung)
/** HTTP-Anfrage als Account $as (0 = abgemeldet); $post = Formularfelder */
function req(string $path, int $as = 0, ?array $post = null): array {
	global $BASE, $jar;
	$c = array('s64w_as=' . $as);
	if(isset($jar[$as])) { $c[] = 'PHPSESSID=' . $jar[$as]; }
	$h = array('Cookie: ' . implode('; ', $c));
	if($post !== null) { $h[] = 'Content-Type: application/x-www-form-urlencoded'; }
	$ctx = stream_context_create(array('http' => array('method' => $post === null ? 'GET' : 'POST', 'header' => implode("\r\n", $h),
		'content' => $post === null ? '' : http_build_query($post), 'ignore_errors' => true, 'timeout' => 30)));
	$raw = (string)@file_get_contents($BASE . $path, false, $ctx);
	$code = 0;
	foreach($http_response_header ?? array() as $l) {
		if(preg_match('#^HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; }
		if(preg_match('/^Set-Cookie:\s*PHPSESSID=([^;]+)/i', $l, $m)) { $jar[$as] = $m[1]; }
	}
	return array('code' => $code, 'raw' => $raw);
}
function csrf_of(string $html): string { return preg_match('/name="csrf" value="([0-9a-f]{32})"/', $html, $m) ? $m[1] : ''; }
function clean(string $raw): bool { return !preg_match('/(Warning|Notice|Deprecated|Fatal error|Parse error|Uncaught)\b/', $raw); }

// ---------------------------------------------------------------- Testdaten
$now = time();
$dt = fn(int $ago) => s64_dt($now - $ago);
$nodes = array(
	// node_id, userid, role, name, slug, trust, lat, lon, asn4, asname4, ip4, measured, first_seen vor, last_seen vor, uptime
	array('a_fsn', 0, 'anchor', 'Anker-FSN', 'anker-fsn', 'anchor', 50.4778, 12.3713, 24940, 'Hetzner Online', '88.99.1.1', 1, 90 * 86400, 30, 1.0),
	array('a_nbg', 0, 'anchor', 'Anker-NBG', 'anker-nbg', 'anchor', 49.4521, 11.0767, 24940, 'Hetzner Online', '88.99.2.2', 1, 90 * 86400, 30, 1.0),
	array('n1aaaaaaaaaa', 1, 'node', 'Falke-1', 'falke-1', 'stable', 50.123456, 8.654321, 3320, 'Deutsche Telekom', '84.200.1.11', 1, 20 * 86400, 60, 0.95),
	array('n1bbbbbbbbbb', 1, 'node', 'Zweiter Knoten', 'zweiter-knoten', 'new', null, null, 3209, 'Vodafone', '84.200.1.12', 0, 2 * 86400, 120, 0.5),
	array('n2cccccccccc', 2, 'node', '<b>x</b>&"q', 'xss-knoten', 'trusted', 52.52, 13.405, 3320, 'Deutsche <i>Telekom</i>', '84.200.2.22', 1, 80 * 86400, 60, 0.99),
	array('n2dddddddddd', 2, 'node', 'Dachs-7', 'dachs-7', 'pillar', 48.137, 11.575, 6805, 'Telefonica', '84.200.2.23', 1, 200 * 86400, 60, 0.999),
	array('n2qqqqqqqqqq', 2, 'node', 'Quarantaene-Q', 'quarantaene-q', 'quarantine', 51.0, 7.0, 3320, 'Deutsche Telekom', '84.200.2.24', 1, 30 * 86400, 60, 0.9),
);
$tid = array();
foreach($nodes as $i => $n) {
	[$id, $u, $role, $name, $slug, $trust, $lat, $lon, $asn, $asname, $ip, $meas, $fs, $ls, $up] = $n;
	x("INSERT INTO sonar_tokens (userid, kind, name, token_hash, node_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		array($u, $role, $role === 'anchor' ? substr($id, 2) : 'T' . $i, hash('sha256', "tok$i"), $id, $dt($fs)));
	$tid[$id] = (int)$db->lastInsertId();
	$seed = 1000 + $i;
	$pc = $lat === null ? array(null, null) : s64_pub_coords($lat, $lon, $seed);
	x("INSERT INTO sonar_nodes (node_id, userid, token_id, role, pubkey, name, slug, lat, lon, pub_lat, pub_lon, jitter_seed, access, device, measured, budget, mode, version,
		ip4, asn4, asname4, place, reach4, trust, uptime30, first_seen, last_seen, last_report, active)
		VALUES (?, ?, ?, ?, 'cGs=', ?, ?, ?, ?, ?, ?, ?, 'fiber', 'pi', ?, 'normal', 'headless', '0.1.0', ?, ?, ?, 'Testort', 'udp', ?, ?, ?, ?, ?, 1)",
		array($id, $u, $tid[$id], $role, $name, $slug, $lat, $lon, $pc[0], $pc[1], $seed, $meas, $ip, $asn, $asname, $trust, $up, $dt($fs), $dt($ls), $dt($ls)));
}
$res = function(string $src, string $dst, int $ago, float $avg, int $valid = 1, ?string $reason = null, int $recv = 5) use ($dt, $now) {
	x("INSERT INTO sonar_results (round, src, dst, fam, method, sent, recv, min_ms, avg_ms, max_ms, jitter_ms, at, valid, reason) VALUES (?, ?, ?, 4, 'udp', 5, ?, ?, ?, ?, 0.4, ?, ?, ?)",
		array(gmdate('Y-m-d H:i:00', $now - $ago), $src, $dst, $recv, $avg - 1, $avg, $avg + 2, $dt($ago), $valid, $reason));
};
$res('n1aaaaaaaaaa', 'a_fsn', 300, 12.3);
$res('n1aaaaaaaaaa', 'n2cccccccccc', 600, 22.0);
$res('n1aaaaaaaaaa', 'n2dddddddddd', 900, 0.1, 0, 'below_light');
$res('n1aaaaaaaaaa', 'n2dddddddddd', 1200, 0, 1, null, 0);           // keine Antwort
$res('n2cccccccccc', 'n1aaaaaaaaaa', 400, 21.5);                     // gegen mich (gilt)
$res('n2qqqqqqqqqq', 'n1aaaaaaaaaa', 450, 5.5);                      // Quarantaene: nicht zeigen
$res('n2dddddddddd', 'n1aaaaaaaaaa', 500, 77.7, 0, 'too_smooth');    // ungueltig: nicht zeigen
$res('n2cccccccccc', 'n1bbbbbbbbbb', 550, 33.3);                     // anderer eigener Knoten
$res('n2cccccccccc', 'n2dddddddddd', 350, 18.4);                     // fremd
$res('n1aaaaaaaaaa', 'a_fsn', 100000, 99.9);                         // aelter als 24 h
x("INSERT INTO sonar_inbound (node_id, from_short, fam, at, count) VALUES ('n1aaaaaaaaaa', ?, 4, ?, 5), ('n1aaaaaaaaaa', 'deadbeef', 6, ?, 3), ('n2cccccccccc', ?, 4, ?, 9)",
	array(s64_short_id('n2cccccccccc'), $dt(200), $dt(250), s64_short_id('n1aaaaaaaaaa'), $dt(260)));
for($h = 1; $h <= 30; $h++) {
	x("INSERT INTO sonar_pair_1h (src, dst, fam, hour, n, avg_ms, p50_ms, loss) VALUES ('n1aaaaaaaaaa', 'a_fsn', 4, ?, 12, 12.5, 12.1, 0), ('n1aaaaaaaaaa', 'a_nbg', 4, ?, 12, 9.9, 9.7, 0.01),
		('n1aaaaaaaaaa', 'a_fsn', 6, ?, 12, 13.5, 13.2, 0), ('n2cccccccccc', 'n2dddddddddd', 4, ?, 12, 18.0, 18.2, 0)",
		array_fill(0, 4, gmdate('Y-m-d H:00:00', $now - $h * 3600)));
}
x("INSERT INTO sonar_outages (kind, keyval, label, started, ended, affected, total) VALUES ('asn', '3320', 'Deutsche <Telekom>', ?, NULL, 6, 10), ('region', '50.0,8.5', 'Rhein-Main', ?, ?, 5, 8)",
	array($dt(1800), $dt(86400), $dt(80000)));
echo "--- Testdaten angelegt\n";

// ---------------------------------------------------------------- Seiten (oeffentlich)
$pages = array('index.php' => 'data-page="map"', 'nodes.php' => 'data-page="nodes"', 'node.php?slug=falke-1' => 'data-slug="falke-1"', 'top.php' => 'data-page="top"', 'me.php' => 'data-page="me"');
foreach($pages as $p => $marker) {
	foreach(array('', 'lang=en') as $l) {
		$path = '/sonar/' . $p . ($l === '' ? '' : (str_contains($p, '?') ? '&' : '?') . $l);
		$r = req($path);
		check("$path: 200, Geruest", $r['code'] === 200 AND str_contains($r['raw'], $marker) AND str_contains($r['raw'], 'data-lang="' . ($l === '' ? 'de' : 'en') . '"'), $r['code'] . ' ' . substr($r['raw'], 0, 300));
		check("$path: ohne PHP-Meldungen", clean($r['raw']), $r['raw']);
		check("$path: nur lokale Skripte/Styles", preg_match_all('#<script src="([^"]+)"#', $r['raw'], $m) >= 1 AND !preg_grep('#^(https?:)?//#', $m[1])
			AND !preg_match('#<link[^>]+href="(https?:)?//#', $r['raw']), $m[1] ?? '');
		check("$path: keine IPs, keine genauen Koordinaten", !str_contains($r['raw'], '84.200.') AND !str_contains($r['raw'], '88.99.') AND !str_contains($r['raw'], '50.123456'));
		check("$path: Sprache", $l === '' ? (str_contains($r['raw'], '>English<') AND str_contains($r['raw'], 'Teilnehmer')) : (str_contains($r['raw'], '>Deutsch<') AND str_contains($r['raw'], 'Participants')));
	}
}
$r = req('/sonar/index.php');
check('Karte: Mitmachen-Box mit Links auf me.php und docs', str_contains($r['raw'], 'href="me.php"') AND str_contains($r['raw'], 'https://node64.de/docs/sonar64/'));
check('Karte: Zahlen-Kacheln', substr_count($r['raw'], 'data-s64-stat=') === 4);
$r = req('/sonar/nodes.php?trust=stable&asn=3320&q=Falke');
check('Liste: Filter vorbelegt', str_contains($r['raw'], '<option value="stable" selected>') AND str_contains($r['raw'], 'value="3320"') AND str_contains($r['raw'], 'value="Falke"'));
$r = req('/sonar/nodes.php?trust=%3Cscript%3E&asn=1%3Cb%3E&q=%22%3E%3Cscript%3Ealert(1)%3C/script%3E');
check('Liste: unsinnige Filter verworfen, nichts gespiegelt', !str_contains($r['raw'], '<script>alert') AND !str_contains($r['raw'], 'selected>') AND str_contains($r['raw'], 'id="s64fQ" name="q" maxlength="32"'));
$r = req('/sonar/nodes.php?q=a%22b&lang=en');
check('Sprach-Link escaped', !str_contains($r['raw'], 'a"b') AND clean($r['raw']));
$r = req('/sonar/node.php?slug=%3Cx%3E');
check('Knotenseite: ungueltiger Slug -> Hinweis', str_contains($r['raw'], 'Kein gültiger Knoten') AND str_contains($r['raw'], 'data-slug=""') AND !str_contains($r['raw'], '<x>'));
$r = req('/sonar/node.php?slug=falke-1&lang=en&x=%3Cy%3E');
check('Knotenseite: Sprach-Link mit Slug, fremde Parameter weg', str_contains($r['raw'], 'href="node.php?slug=falke-1"') AND !str_contains($r['raw'], '<y>'));

// ---------------------------------------------------------------- me.php
$r = req('/sonar/me.php');
check('me: abgemeldet -> Hinweis, keine Tabellen', str_contains($r['raw'], 'Bitte zuerst anmelden') AND !str_contains($r['raw'], 'Pings von mir'));
$r = req('/sonar/me.php', 1);
$h = $r['raw'];
check('me: Account 1, eigener Knoten', $r['code'] === 200 AND clean($h) AND str_contains($h, 'Falke-1') AND str_contains($h, '<code>n1aaaaaaaaaa</code>'), substr($h, 0, 500));
check('me: zweiter eigener Knoten als Reiter', str_contains($h, 'me.php?node=n1bbbbbbbbbb'));
check('me: keine fremden Knoten als Reiter', !str_contains($h, 'node=n2'));
check('me: keine IPs (auch nicht die eigenen)', !str_contains($h, '84.200.') AND !str_contains($h, '88.99.'));
check('me: genauer Standort nur im eigenen Formular', substr_count($h, '50.12346') === 1 AND str_contains($h, 'id="s64Lat" name="lat"'));
check('me: Pings von mir mit Anker, Ziel und Pruefung', str_contains($h, 'Anker-FSN') AND str_contains($h, 's64-ms s64-l1">12 ms') AND str_contains($h, 'schneller als Licht') AND str_contains($h, 'keine Antwort'));
check('me: aelter als 24 h fehlt', !str_contains($h, '>100 ms<') AND !str_contains($h, '98.9'));
check('me: Namen escaped', str_contains($h, '&lt;b&gt;x&lt;/b&gt;&amp;&quot;q') AND !str_contains($h, '<b>x</b>') AND str_contains($h, 'Deutsche &lt;i&gt;Telekom&lt;/i&gt;'));
$against = substr($h, strpos($h, 'Pings gegen mich'), 4000);
check('me: gegen mich nur gueltige, ohne Quarantaene', str_contains($against, '>22 ms<') AND !str_contains($against, '5,5 ms') AND !str_contains($against, '78 ms') AND !str_contains($against, 'Quarantaene-Q'));
$udp = substr($h, strpos($h, 'Auf UDP 6464'), 3000);
check('me: UDP 6464 ueber Kurz-ID zugeordnet', str_contains($udp, 'href="node.php?slug=xss-knoten"') AND str_contains($udp, 'deadbeef') AND str_contains($udp, '>5</td>'));
check('me: Fortschritt zur naechsten Stufe', str_contains($h, 'Weg zur nächsten Stufe') AND str_contains($h, '20 / 60 Tage'));
check('me: Karte zum Standort', str_contains($h, 'id="s64Pick"'));
$r = req('/sonar/me.php?node=n1bbbbbbbbbb', 1);
check('me: zweiter Knoten waehlbar', str_contains($r['raw'], '<code>n1bbbbbbbbbb</code>') AND str_contains($r['raw'], '>33 ms<') AND str_contains($r['raw'], 'misst nur ausgehend'));
$r = req('/sonar/me.php?node=n2cccccccccc', 1);
check('me: fremder Knoten per ?node -> eigener', str_contains($r['raw'], '<code>n1aaaaaaaaaa</code>') AND !str_contains($r['raw'], '<code>n2cccccccccc</code>'));
$r = req('/sonar/me.php?lang=en', 1);
check('me: englisch', str_contains($r['raw'], 'Pings from me') AND str_contains($r['raw'], 'Way to the next level') AND clean($r['raw']));
$r = req('/sonar/me.php', 2);
check('me: Account 2 sieht seine Knoten, Quarantaene-Hinweis', str_contains($r['raw'], 'node=n2qqqqqqqqqq') AND clean($r['raw']));
$r = req('/sonar/me.php?node=n2qqqqqqqqqq', 2);
check('me: Quarantaene erklaert', str_contains($r['raw'], 'Quarantäne: Der Knoten misst weiter'));

// CSRF
$tokBefore = (int)one("SELECT count(*) c FROM sonar_tokens")['c'];
$r = req('/sonar/me.php', 1, array('action' => 'token_new', 'name' => 'ohne csrf', 'csrf' => 'x'));
check('me: ohne CSRF kein Token', str_contains($r['raw'], 'Sitzung abgelaufen') AND (int)one("SELECT count(*) c FROM sonar_tokens")['c'] === $tokBefore);
$csrf = csrf_of(req('/sonar/me.php', 1)['raw']);
check('me: CSRF-Feld', strlen($csrf) === 32);
// Token anlegen
$r = req('/sonar/me.php', 1, array('action' => 'token_new', 'name' => 'Pi Wohnzimmer', 'csrf' => $csrf));
preg_match('/id="s64NewToken" value="(s64_[A-Za-z0-9]{40})"/', $r['raw'], $m);
$tok = $m[1] ?? '';
check('me: Token angezeigt (einmal)', $tok !== '' AND str_contains($r['raw'], 'SONAR64_TOKEN=' . $tok), substr($r['raw'], 0, 300));
$row = one("SELECT * FROM sonar_tokens WHERE token_hash = ?", array(hash('sha256', $tok)));
check('me: in der DB nur SHA-256', $row !== false AND (int)$row['userid'] === 1 AND $row['kind'] === 'node' AND $row['name'] === 'Pi Wohnzimmer' AND $row['node_id'] === null
	AND (int)one("SELECT count(*) c FROM sonar_tokens WHERE token_hash = ? OR name = ?", array($tok, $tok))['c'] === 0);
$r = req('/sonar/me.php', 1);
check('me: Klartext nicht erneut sichtbar', !str_contains($r['raw'], $tok) AND str_contains($r['raw'], 'Pi Wohnzimmer') AND str_contains($r['raw'], 'noch nicht gestartet'));
$r = req('/sonar/me.php', 1, array('action' => 'token_new', 'name' => '<script>', 'csrf' => $csrf));
check('me: unzulaessige Bezeichnung -> Standard', one("SELECT name FROM sonar_tokens WHERE userid = 1 ORDER BY id DESC LIMIT 1")['name'] === 'Sonar64' AND !str_contains($r['raw'], '<script>'));
for($i = 0; $i < 12; $i++) { $r = req('/sonar/me.php', 1, array('action' => 'token_new', 'name' => "n$i", 'csrf' => $csrf)); }
check('me: hoechstens 10 aktive Token', (int)one("SELECT count(*) c FROM sonar_tokens WHERE userid = 1 AND kind = 'node' AND revoked_at IS NULL")['c'] === 10 AND str_contains($r['raw'], 'Höchstens 10'));
// Sperren: fremdes Token nicht, eigenes ja (Knoten aus, IP und Standort weg)
$r = req('/sonar/me.php', 1, array('action' => 'token_revoke', 'id' => $tid['n2cccccccccc'], 'csrf' => $csrf));
check('me: fremdes Token bleibt', one("SELECT revoked_at FROM sonar_tokens WHERE id = ?", array($tid['n2cccccccccc']))['revoked_at'] === null
	AND (int)one("SELECT active FROM sonar_nodes WHERE node_id = 'n2cccccccccc'")['active'] === 1);
$r = req('/sonar/me.php', 1, array('action' => 'token_revoke', 'id' => $tid['n1bbbbbbbbbb'], 'csrf' => $csrf));
$nb = one("SELECT active, ip4, lat FROM sonar_nodes WHERE node_id = 'n1bbbbbbbbbb'");
check('me: eigenes Token gesperrt, Knoten aus, IP weg', str_contains($r['raw'], 'Token gesperrt') AND one("SELECT revoked_at FROM sonar_tokens WHERE id = ?", array($tid['n1bbbbbbbbbb']))['revoked_at'] !== null
	AND (int)$nb['active'] === 0 AND $nb['ip4'] === null AND !str_contains($r['raw'], 'node=n1bbbbbbbbbb'));
check('me: gesperrt in der Liste', str_contains($r['raw'], 'gesperrt'));
// Angaben speichern
$save = fn(array $f, int $as = 1, string $node = 'n1aaaaaaaaaa') => req('/sonar/me.php?node=' . $node, $as, $f + array('action' => 'node_save', 'node' => $node, 'csrf' => $csrf,
	'name' => 'Falke-1', 'access' => 'fiber', 'device' => 'pi', 'lat' => '50.123456', 'lon' => '8.654321'));
foreach(array(array('name' => 'ab'), array('name' => 'Fa  lke'), array('name' => 'a<b>c'), array('name' => 'Fälke'), array('name' => str_repeat('a', 33)), array('name' => 'Anker-X'),
	array('access' => 'isdn'), array('device' => 'Pi Zero!'), array('lat' => '91', 'lon' => '8'), array('lat' => '50', 'lon' => ''), array('lat' => '1e3', 'lon' => '8'),
	array('lat' => '50.1;DROP', 'lon' => '8')) as $bad) {
	$r = $save($bad);
	check('me: abgewiesen ' . json_encode($bad, JSON_UNESCAPED_UNICODE), str_contains($r['raw'], 'alert-danger') AND one("SELECT name FROM sonar_nodes WHERE node_id = 'n1aaaaaaaaaa'")['name'] === 'Falke-1');
}
$r = $save(array('name' => 'dachs-7'));
check('me: Name vergeben (ohne Gross/Klein)', str_contains($r['raw'], 'schon vergeben') AND one("SELECT name FROM sonar_nodes WHERE node_id = 'n1aaaaaaaaaa'")['name'] === 'Falke-1');
$r = $save(array('name' => 'Falke Neu.1', 'access' => 'cable', 'device' => '', 'lat' => '49,99', 'lon' => '8,2'));
$n = one("SELECT * FROM sonar_nodes WHERE node_id = 'n1aaaaaaaaaa'");
check('me: gespeichert', str_contains($r['raw'], 'Gespeichert') AND $n['name'] === 'Falke Neu.1' AND $n['slug'] === 'falke-neu-1' AND $n['access'] === 'cable' AND $n['device'] === 'other'
	AND abs((float)$n['lat'] - 49.99) < 1e-9 AND abs((float)$n['lon'] - 8.2) < 1e-9, $n);
$km = s64_distance_km((float)$n['lat'], (float)$n['lon'], (float)$n['pub_lat'], (float)$n['pub_lon']);
check('me: oeffentlicher Punkt verschleiert (0,2..1 km)', $km > 0.2 AND $km <= 1.0, $km);
check('me: Versatz fest je Knoten', abs($n['pub_lat'] - s64_pub_coords(49.99, 8.2, (int)$n['jitter_seed'])['lat']) < 1e-9);
$r = $save(array('name' => 'Falke Neu.1', 'lat' => '', 'lon' => ''));
$n = one("SELECT lat, pub_lat, slug FROM sonar_nodes WHERE node_id = 'n1aaaaaaaaaa'");
check('me: Standort loeschen', $n['lat'] === null AND $n['pub_lat'] === null AND $n['slug'] === 'falke-neu-1');
$r = $save(array('name' => 'Fremd-1'), 1, 'n2cccccccccc');
check('me: fremden Knoten nicht aendern', one("SELECT name FROM sonar_nodes WHERE node_id = 'n2cccccccccc'")['name'] === '<b>x</b>&"q' AND str_contains($r['raw'], 'alert-danger'));
x("UPDATE sonar_nodes SET userid = 1 WHERE node_id = 'a_nbg'");
$r = $save(array('name' => 'Anker-Neu'), 1, 'a_nbg');
check('me: Anker nicht aenderbar', one("SELECT name FROM sonar_nodes WHERE node_id = 'a_nbg'")['name'] === 'Anker-NBG' AND str_contains($r['raw'], 'Anker stellt ipv64 ein'));
x("UPDATE sonar_nodes SET userid = 0 WHERE node_id = 'a_nbg'");
$save(array('name' => 'Falke-1'));

// ---------------------------------------------------------------- Oeffentliche JSON-Antworten (Teil A), fuer sonar_test.js
if(is_file("$WEB/api_v2.php") AND is_file("$WEB/api_v2_sonar.php")) {
	@mkdir($OUT, 0777, true);
	foreach(array('map' => 'map', 'nodes' => 'nodes', 'node' => 'node/falke-1', 'stats' => 'stats', 'top' => 'top', 'matrix' => 'matrix', 'outages' => 'outages') as $k => $p) {
		$r = req('/api_v2.php/sonar/public/' . $p);
		$j = json_decode($r['raw'], true);
		check("API public/$p: 200 mit data", $r['code'] === 200 AND is_array($j) AND array_key_exists('data', $j), $r['code'] . ' ' . substr($r['raw'], 0, 300));
		check("API public/$p: keine IPs, keine genauen Koordinaten", !str_contains($r['raw'], '84.200.') AND !str_contains($r['raw'], '88.99.') AND !str_contains($r['raw'], '50.12346') AND !str_contains($r['raw'], '8.65432'));
		file_put_contents("$OUT/$k.json", $r['raw']);
	}
} else {
	echo "  (api_v2.php/api_v2_sonar.php fehlen: oeffentliche JSON-Antworten nicht geprueft)\n";
}

echo "\nWebseiten: $pass ok, $failed Fehler\n";
exit($failed > 0 ? 1 : 0);
