<?php
/**
 * Pruefung von api_v2_sonar.php, sonar/s64_lib.php, bots/sonar_keygen.php, bots/sonar_anchor_token.php und bots/sonar_node.php in der
 * Testumgebung s64a* (run_agentbox.sh). Spricht die API ueber den PHP-Builtin-Server an und prueft die Tabellen direkt.
 *
 *   S64ATEST=1 S64ADB=<db> php run_tests.php http://127.0.0.1:8080 /var/www/clients/client1/web58/web
 */
if(php_sapi_name() !== 'cli' OR getenv('S64ATEST') !== '1') { exit; }

$BASE = rtrim($argv[1] ?? 'http://127.0.0.1:8080', '/');
$WEB = $argv[2] ?? '/var/www/clients/client1/web58/web';
require $WEB . '/sonar/s64_lib.php';
const K1 = 'TestKeyAccountOne000000000000001';   // users.apikey, Account 1
const K2 = 'TestKeyApiKeysTwo000000000000002';   // api_keys, Account 2
const K3 = 'TestKeyAccountThree0000000000003';   // Account 3 (inaktiv)
const IP_A = '9.9.9.9';                          // Knoten A (X-Forwarded-For, REMOTE_ADDR ist privat)
const IP_B = '1.1.1.1';                          // Knoten B
const IP_F = '88.198.1.1';                       // Anker fsn
const IP_N = '2a01:4f8::10';                     // Anker nbg (IPv6)

$db = new PDO('mysql:host=' . getenv('S64ADB') . ';dbname=ipv64', 'root', 's64atest', array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8mb4'"));
$pass = 0; $failed = 0;

function check(string $name, bool $ok, $info = ''): void {
	global $pass, $failed;
	if($ok) { $pass++; echo "  ok    $name\n"; }
	else { $failed++; echo "  FEHLER $name " . (is_string($info) ? $info : json_encode($info, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) . "\n"; }
}

function req(string $method, string $path, ?string $body = null, array $headers = array(), ?string $key = null, string $ip = IP_A): array {
	global $BASE;
	$h = array('X-Forwarded-For: ' . $ip);
	if($key !== null) { $h[] = 'Authorization: Bearer ' . $key; }
	if($body !== null AND !preg_grep('/^Content-Type:/i', $headers)) { $h[] = 'Content-Type: application/json'; }
	$ctx = stream_context_create(array('http' => array('method' => $method, 'header' => implode("\r\n", array_merge($h, $headers)), 'content' => $body ?? '',
		'ignore_errors' => true, 'timeout' => 60)));
	$raw = @file_get_contents($BASE . '/api_v2.php' . $path, false, $ctx);
	$code = 0; $hdr = array();
	foreach($http_response_header ?? array() as $l) {
		if(preg_match('#^HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; }
		elseif(str_contains($l, ':')) { [$k, $v] = explode(':', $l, 2); $hdr[strtolower(trim($k))] = trim($v); }
	}
	return array('code' => $code, 'h' => $hdr, 'j' => json_decode((string)$raw, true), 'raw' => (string)$raw);
}
function jreq(string $method, string $path, $data, ?string $key, string $ip = IP_A): array { return req($method, $path, json_encode($data, JSON_UNESCAPED_SLASHES), array(), $key, $ip); }
function one(string $sql, array $p = array()) { global $db; $st = $db->prepare($sql); $st->execute($p); return $st->fetch(PDO::FETCH_ASSOC); }
function all(string $sql, array $p = array()): array { global $db; $st = $db->prepare($sql); $st->execute($p); return $st->fetchAll(PDO::FETCH_ASSOC); }
function exec_sql(string $sql, array $p = array()): void { global $db; $db->prepare($sql)->execute($p); }
function code(array $res): string { return $res['code'] . ' ' . substr($res['raw'], 0, 400); }
function cli(string $args): array { global $WEB; exec(escapeshellarg(PHP_BINARY) . ' ' . $WEB . '/bots/' . $args . ' 2>&1', $out, $rc); return array($rc, implode("\n", $out)); }
function iso(int $t, string $frac = ''): string { return gmdate('Y-m-d\TH:i:s', $t) . $frac . 'Z'; }
function clear_cache(): void { foreach(glob(sys_get_temp_dir() . '/ipv64_s64_cache/*') ?: array() as $f) { @unlink($f); } }
/** Meldung signieren (wie der Kern: exakte Bytes von report). */
function signed(array $report, string $sk): string {
	$r = json_encode($report, JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
	return '{"report":' . $r . ',"sig":"' . base64_encode(sodium_crypto_sign_detached($r, $sk)) . '"}';
}
function post_report(array $report, string $sk, string $tok, string $ip = IP_A): array { return req('POST', '/sonar/results', signed($report, $sk), array(), $tok, $ip); }
function back_report(string $node): void { exec_sql("UPDATE sonar_nodes set last_report = last_report - INTERVAL 2 MINUTE WHERE node_id = ?", array($node)); }
function res(int $R, string $target, array $v = array()): array {
	return array_merge(array('round' => iso($R), 'target' => $target, 'fam' => 4, 'method' => 'icmp', 'sent' => 3, 'recv' => 3,
		'min' => 9.5, 'avg' => 10.25, 'max' => 11.0, 'jitter' => 0.75, 'at' => iso($R + 40, '.123456789')), $v);
}
function report(string $node, int $seq, array $results, array $extra = array()): array {
	return array_merge(array('v' => 1, 'node_id' => $node, 'seq' => $seq, 'sent' => iso(time()), 'results' => $results,
		'health' => array('version' => '0.1.0', 'mode' => 'headless', 'uplink' => true, 'sent_today' => 12, 'budget' => 'normal', 'responder' => true)), $extra);
}
$dnsOk = s64_asn_lookup('9.9.9.9')['asn'] === 19281;
echo "DNS (Team Cymru) erreichbar: " . ($dnsOk ? 'ja' : 'nein, ASN-Pruefungen entfallen') . "\n";

// ---------------------------------------------------------------- Bibliothek
echo "Bibliothek\n";
$mx = 0; $mn = 1e9;
for($s = 1; $s < 3000; $s++) { $p = s64_pub_coords(53.55, 9.99, $s); $d = s64_distance_km(53.55, 9.99, $p[0], $p['lon']); $mx = max($mx, $d); $mn = min($mn, $d); }
check('pub_coords Versatz 0,29..1 km', $mn > 0.29 AND $mx <= 1.0, "$mn $mx");
check('pub_coords fest je seed', s64_pub_coords(50.0, 8.0, 7) === s64_pub_coords(50.0, 8.0, 7) AND s64_pub_coords(50.0, 8.0, 7) !== s64_pub_coords(50.0, 8.0, 8));
check('light_min_ms 600 km = 6 ms', abs(s64_light_min_ms(600) - 6.0) < 1e-9);
check('Entfernung Hamburg-Muenchen ~612 km', abs(s64_distance_km(53.55, 9.99, 48.14, 11.58) - 612) < 10, s64_distance_km(53.55, 9.99, 48.14, 11.58));
$pub = array('9.9.9.9' => true, '2a01:4f8::1' => true, '10.1.1.1' => false, '100.64.0.1' => false, '127.0.0.1' => false, '192.168.1.1' => false, '::1' => false,
	'fe80::1' => false, '::ffff:9.9.9.9' => false, '2001:db8::1' => false, 'fc00::1' => false, '224.0.0.1' => false, 'x' => false);
$bad = array_filter($pub, fn($want, $ip) => s64_is_public_ip($ip) !== $want, ARRAY_FILTER_USE_BOTH);
check('is_public_ip', $bad === array(), $bad);
check('trust_label de/en', s64_trust_label('pillar') === 'Säule' AND s64_trust_label('quarantine', 'en') === 'Quarantine');
check('short_id 8 hex', preg_match('/^[0-9a-f]{8}$/', s64_short_id('nabcdefghijk')) === 1);
check('median', s64_median(array(3, 1, 2)) === 2.0 AND s64_median(array(4, 1, 2, 3)) === 2.5 AND s64_median(array()) === null);
if($dnsOk) {
	$a = s64_asn_lookup('2a01:4f8::1');
	check('asn_lookup IPv6 Hetzner 24940', $a['asn'] === 24940 AND str_contains((string)$a['name'], 'HETZNER'), $a);
}
check('asn_lookup privat = null', s64_asn_lookup('10.0.0.1')['asn'] === null);

// ---------------------------------------------------------------- Plan-Schluessel
echo "Plan-Schluessel\n";
check('vor keygen: keys leer', ($j = req('GET', '/sonar/public/keys')['j']['data']['keys'] ?? null) === array(), $j);
[$rc, $out] = cli('sonar_keygen.php');
check('keygen legt an', $rc === 0 AND preg_match('/pubkey ([A-Za-z0-9+\/=]{44})/', $out, $m) === 1, $out);
$PUB = $m[1] ?? '';
check('keygen gibt keinen geheimen Schluessel aus', !str_contains($out, trim((string)@file_get_contents(s64_plan_key_file()))));
$kf = dirname($WEB) . '/private/sonar64/plan_ed25519.key';
check('Schluessel ausserhalb des Webroots, 0600', is_file($kf) AND (fileperms($kf) & 0777) === 0600 AND (fileperms(dirname($kf)) & 0777) === 0700, decoct(@fileperms($kf) & 0777));
[$rc, $out2] = cli('sonar_keygen.php');
check('keygen ohne --force ueberschreibt nicht', $rc === 1 AND str_contains($out2, 'existiert'), $out2);
[$rc, $out3] = cli('sonar_keygen.php --show');
check('keygen --show', $rc === 0 AND str_contains($out3, $PUB), $out3);
$r = req('GET', '/sonar/public/keys');
check('public/keys', ($r['j']['data']['keys'][0]['pubkey'] ?? '') === $PUB AND strlen($r['j']['data']['keys'][0]['kid'] ?? '') === 8, code($r));
check('public/keys Cache-Control public 60', ($r['h']['cache-control'] ?? '') === 'public, max-age=60', $r['h']);
$KID = $r['j']['data']['keys'][0]['kid'] ?? '';

// ---------------------------------------------------------------- Token (API-Key)
echo "Token\n";
$r = jreq('POST', '/sonar/tokens', array('name' => 'Pi im Keller'), null);
check('ohne API-Key 401', $r['code'] === 401, code($r));
$r = jreq('POST', '/sonar/tokens', array('name' => 'x'), K3);
check('inaktiver Account 401', $r['code'] === 401, code($r));
$r = jreq('POST', '/sonar/tokens', array('name' => '<script>'), K1);
check('Name mit < > 422', $r['code'] === 422, code($r));
$r = jreq('POST', '/sonar/tokens', array('name' => 'Pi im Keller'), K1);
check('Token anlegen 201', $r['code'] === 201 AND preg_match('/^s64_[A-Za-z0-9]{40}$/', $r['j']['data']['token'] ?? '') === 1, code($r));
$TA = $r['j']['data']['token'] ?? ''; $TA_ID = $r['j']['data']['id'] ?? 0;
$row = one("SELECT * FROM sonar_tokens WHERE id = ?", array($TA_ID));
check('nur SHA-256 gespeichert', $row AND $row['token_hash'] === hash('sha256', $TA) AND !in_array($TA, $row, true), $row);
$TB = jreq('POST', '/sonar/tokens', array('name' => 'B'), K2)['j']['data']['token'] ?? '';
$TC = jreq('POST', '/sonar/tokens', array('name' => 'C'), K2)['j']['data']['token'] ?? '';
check('Token Account 2 (api_keys)', str_starts_with($TB, 's64_') AND str_starts_with($TC, 's64_'));
$r = req('GET', '/sonar/tokens', null, array(), K1);
check('Liste ohne Klartext', $r['code'] === 200 AND count($r['j']['data']) === 1 AND !str_contains($r['raw'], $TA) AND !str_contains($r['raw'], 'hash'), code($r));
for($i = 0; $i < 9; $i++) { jreq('POST', '/sonar/tokens', array('name' => "t$i"), K1); }
$r = jreq('POST', '/sonar/tokens', array('name' => 'elf'), K1);
check('11. Token 403 limit_reached', $r['code'] === 403 AND ($r['j']['code'] ?? '') === 'limit_reached', code($r));
$ids = array_column(req('GET', '/sonar/tokens', null, array(), K1)['j']['data'], 'id');
$r = req('DELETE', '/sonar/tokens/' . end($ids), null, array(), K2);
check('fremdes Token loeschen 404', $r['code'] === 404, code($r));
$r = req('DELETE', '/sonar/tokens/' . end($ids), null, array(), K1);
check('eigenes Token loeschen 204', $r['code'] === 204, code($r));
$r = req('GET', '/sonar/tokens', null, array(), $TA);
check('Sonar-Token auf /sonar/tokens 401', $r['code'] === 401, code($r));

// ---------------------------------------------------------------- Anmeldung mit Sonar-Token
echo "Anmeldung\n";
$r = req('GET', '/sonar/me');
check('ohne Token 401', $r['code'] === 401, code($r));
$r = req('GET', '/sonar/me', null, array(), 's64_' . str_repeat('x', 40));
check('falsches Token 401', $r['code'] === 401 AND ($r['j']['code'] ?? '') === 'invalid_token', code($r));
$r = req('GET', '/sonar/me', null, array(), K1);
check('API-Key auf /sonar/me 401', $r['code'] === 401, code($r));
$r = req('GET', '/sonar/me', null, array(), $TA);
check('nicht registriert 409', $r['code'] === 409 AND ($r['j']['code'] ?? '') === 'not_registered', code($r));

$kpA = sodium_crypto_sign_keypair(); $skA = sodium_crypto_sign_secretkey($kpA); $pkA = base64_encode(sodium_crypto_sign_publickey($kpA));
$kpB = sodium_crypto_sign_keypair(); $skB = sodium_crypto_sign_secretkey($kpB); $pkB = base64_encode(sodium_crypto_sign_publickey($kpB));
$r = jreq('POST', '/sonar/register', array('pubkey' => 'abc', 'version' => '0.1.0', 'mode' => 'headless'), $TA);
check('register pubkey ungueltig 422', $r['code'] === 422, code($r));
$r = jreq('POST', '/sonar/register', array('pubkey' => $pkA, 'version' => '0.1.0', 'mode' => 'anchor'), $TA);
check('register mode anchor mit Knoten-Token 422', $r['code'] === 422, code($r));
$r = jreq('POST', '/sonar/register', array('pubkey' => $pkA, 'version' => '0.1.0 x', 'mode' => 'headless'), $TA);
check('register version ungueltig 422', $r['code'] === 422, code($r));
$r = req('POST', '/sonar/register', 'pubkey=x', array('Content-Type: application/x-www-form-urlencoded'), $TA);
check('register Content-Type 415', $r['code'] === 415, code($r));
$r = jreq('POST', '/sonar/register', array('pubkey' => $pkA, 'version' => '0.1.0', 'mode' => 'headless'), $TA);
$meA = $r['j']['data'] ?? array();
check('register 201 Me', $r['code'] === 201 AND preg_match('/^n[a-z0-9]{11}$/', $meA['node_id'] ?? '') === 1 AND str_starts_with($meA['name'] ?? '', 'Sonar-')
	AND $meA['trust'] === 'new' AND $meA['role'] === 'node' AND $meA['measured'] === false AND $meA['budget'] === 'sparsam' AND $meA['lat'] === null, code($r));
$A = $meA['node_id'] ?? '';
check('Me-Felder wie wire.go', array_diff(array_keys($meA), array('node_id', 'name', 'slug', 'lat', 'lon', 'pub_lat', 'pub_lon', 'access', 'device', 'measured', 'budget', 'role', 'trust', 'score',
	'asn4', 'asname4', 'asn6', 'asname6', 'reach4', 'reach6', 'since', 'uptime30')) === array(), array_keys($meA));
check('Me ohne IP', !str_contains($r['raw'], IP_A));
$nA = one("SELECT * FROM sonar_nodes WHERE node_id = ?", array($A));
check('IP aus der Verbindung gespeichert', $nA['ip4'] === IP_A AND $nA['ip6'] === null AND $nA['reach4'] === 'none', $nA);
check('Token an Knoten gebunden', one("SELECT node_id FROM sonar_tokens WHERE id = ?", array($TA_ID))['node_id'] === $A);
if($dnsOk) { check('ASN aus der IP (Quad9 19281)', ($meA['asn4'] ?? 0) === 19281 AND (int)$nA['asn4'] === 19281 AND $nA['asn_at'] !== null, $meA); }
$r = jreq('POST', '/sonar/register', array('pubkey' => $pkA, 'version' => '0.1.1', 'mode' => 'module'), $TA);
check('register erneut mit gleichem Key 200', $r['code'] === 200 AND ($r['j']['data']['node_id'] ?? '') === $A, code($r));
check('version/mode aktualisiert', one("SELECT version, mode FROM sonar_nodes WHERE node_id = ?", array($A)) === array('version' => '0.1.1', 'mode' => 'module'));
$r = jreq('POST', '/sonar/register', array('pubkey' => $pkB, 'version' => '0.1.0', 'mode' => 'headless'), $TA);
check('register mit anderem Key 409', $r['code'] === 409 AND ($r['j']['code'] ?? '') === 'already_registered', code($r));
$r = jreq('POST', '/sonar/register', array('pubkey' => $pkA, 'version' => '0.1.0', 'mode' => 'headless'), $TB, IP_B);
check('Key eines anderen Knotens 409', $r['code'] === 409 AND ($r['j']['code'] ?? '') === 'key_in_use', code($r));
$r = jreq('POST', '/sonar/register', array('pubkey' => $pkB, 'version' => '0.1.0', 'mode' => 'headless'), $TB, IP_B);
$B = $r['j']['data']['node_id'] ?? '';
check('Knoten B 201', $r['code'] === 201 AND $B !== '' AND $B !== $A, code($r));
$kpC = sodium_crypto_sign_keypair(); $skC = sodium_crypto_sign_secretkey($kpC);
$C = jreq('POST', '/sonar/register', array('pubkey' => base64_encode(sodium_crypto_sign_publickey($kpC)), 'version' => '0.1.0', 'mode' => 'headless'), $TC, '8.8.8.8')['j']['data']['node_id'] ?? '';
check('Knoten C 201', $C !== '');

// ---------------------------------------------------------------- PUT /sonar/me
echo "PUT /sonar/me\n";
$r = jreq('PUT', '/sonar/me', array('name' => 'ab'), $TA);
check('Name zu kurz 422', $r['code'] === 422, code($r));
$r = jreq('PUT', '/sonar/me', array('name' => 'Hallo  Welt'), $TA);
check('doppeltes Leerzeichen 422', $r['code'] === 422, code($r));
$r = jreq('PUT', '/sonar/me', array('name' => 'Anker-Fake'), $TA);
check('reservierter Name 422', $r['code'] === 422 AND ($r['j']['code'] ?? '') === 'reserved_name', code($r));
$r = jreq('PUT', '/sonar/me', array('name' => 'Hamburg Glasfaser'), $TA);
check('Name setzen 200, Slug', $r['code'] === 200 AND $r['j']['data']['name'] === 'Hamburg Glasfaser' AND $r['j']['data']['slug'] === 'hamburg-glasfaser', code($r));
$r = jreq('PUT', '/sonar/me', array('name' => 'hamburg glasfaser'), $TB, IP_B);
check('Name vergeben (ohne Gross/Klein) 409', $r['code'] === 409 AND ($r['j']['code'] ?? '') === 'name_taken', code($r));
$r = jreq('PUT', '/sonar/me', array('lat' => 53.55), $TA);
check('lat ohne lon 422', $r['code'] === 422, code($r));
$r = jreq('PUT', '/sonar/me', array('lat' => 91, 'lon' => 0), $TA);
check('lat ausserhalb 422', $r['code'] === 422, code($r));
$r = jreq('PUT', '/sonar/me', array('access' => 'modem'), $TA);
check('access unbekannt 422', $r['code'] === 422, code($r));
$r = jreq('PUT', '/sonar/me', array('device' => 'Pi Zero!'), $TA);
check('device ungueltig 422', $r['code'] === 422, code($r));
$r = jreq('PUT', '/sonar/me', array('budget' => 'riesig'), $TA);
check('budget unbekannt 422', $r['code'] === 422, code($r));
$r = jreq('PUT', '/sonar/me', array('measured' => 'yes'), $TA);
check('measured kein bool 422', $r['code'] === 422, code($r));
$full = $r = jreq('PUT', '/sonar/me', array_merge($meA, array('name' => '', 'lat' => 53.551234567, 'lon' => 9.993, 'access' => 'fiber', 'device' => 'pi', 'measured' => true,
	'budget' => 'normal', 'trust' => 'pillar', 'role' => 'anchor', 'score' => 1, 'node_id' => 'nxxxxxxxxxxx')), $TA);
$me = $r['j']['data'] ?? array();
check('ganzes Me (Go): schreibbare Felder gesetzt, ro ignoriert', $r['code'] === 200 AND $me['name'] === 'Hamburg Glasfaser' AND $me['lat'] === 53.55123 AND $me['access'] === 'fiber'
	AND $me['device'] === 'pi' AND $me['measured'] === true AND $me['budget'] === 'normal' AND $me['trust'] === 'new' AND $me['role'] === 'node' AND $me['node_id'] === $A, code($r));
$dd = s64_distance_km($me['lat'], $me['lon'], $me['pub_lat'], $me['pub_lon']);
check('pub_lat/lon verschleiert 0,29..1 km', $dd > 0.29 AND $dd <= 1.0, $dd);
jreq('PUT', '/sonar/me', array('lat' => 48.13712, 'lon' => 11.57534, 'measured' => true, 'name' => 'Muenchen Kabel'), $TB, IP_B);   // ~612 km von A
jreq('PUT', '/sonar/me', array('lat' => 50.11034, 'lon' => 8.68211, 'measured' => true), $TC, '8.8.8.8');
$r = req('GET', '/sonar/me', null, array(), $TA);
check('GET /sonar/me', $r['code'] === 200 AND $r['j']['data']['lat'] === 53.55123 AND ($r['h']['cache-control'] ?? '') === 'no-store', code($r));

// ---------------------------------------------------------------- Anker
echo "Anker\n";
[$rc, $out] = cli('sonar_anchor_token.php --name=FSN');
check('Anker-Name ungueltig', $rc === 1, $out);
[$rc, $out] = cli('sonar_anchor_token.php --name=fsn');
check('Anker-Token einmal ausgegeben', $rc === 0 AND preg_match('/^(s64a_[A-Za-z0-9]{40})$/m', $out, $m) === 1, $out);
$TF = $m[1] ?? '';
check('Anker-Token nur als Hash', one("SELECT count(*) c FROM sonar_tokens WHERE kind = 'anchor' AND name = 'fsn' AND token_hash = ?", array(hash('sha256', $TF)))['c'] == 1);
[$rc, $out] = cli('sonar_anchor_token.php --name=fsn');
check('zweites Anker-Token ohne --rotate abgelehnt', $rc === 1, $out);
[$rc, $out] = cli('sonar_anchor_token.php --name=fsn --lat=50.47 --lon=12.37');
check('Standort vor Anmeldung abgelehnt', $rc === 1, $out);
$kpF = sodium_crypto_sign_keypair(); $skF = sodium_crypto_sign_secretkey($kpF); $pkF = base64_encode(sodium_crypto_sign_publickey($kpF));
$r = jreq('POST', '/sonar/register', array('pubkey' => $pkF, 'version' => '0.1.0', 'mode' => 'headless'), $TF, IP_F);
check('Anker-Token mit mode headless 422', $r['code'] === 422, code($r));
$r = jreq('POST', '/sonar/register', array('pubkey' => $pkF, 'version' => '0.1.0', 'mode' => 'anchor'), $TF, IP_F);
check('Anker registriert a_fsn', $r['code'] === 201 AND ($r['j']['data']['node_id'] ?? '') === 'a_fsn' AND $r['j']['data']['trust'] === 'anchor' AND $r['j']['data']['role'] === 'anchor'
	AND $r['j']['data']['measured'] === true, code($r));
[$rc, $out] = cli('sonar_anchor_token.php --name=fsn --lat=50.47 --lon=12.37 --place=Falkenstein');
check('Anker-Standort gesetzt', $rc === 0 AND (float)one("SELECT lat FROM sonar_nodes WHERE node_id = 'a_fsn'")['lat'] === 50.47, $out);
$r = jreq('PUT', '/sonar/me', array('measured' => false, 'budget' => 'sparsam'), $TF, IP_F);
check('Anker bleibt gemessen/grosszuegig', $r['j']['data']['measured'] === true AND $r['j']['data']['budget'] === 'grosszuegig', code($r));
[$rc, $out] = cli('sonar_anchor_token.php --name=nbg');
preg_match('/^(s64a_[A-Za-z0-9]{40})$/m', $out, $m); $TN = $m[1] ?? '';
$kpN = sodium_crypto_sign_keypair(); $skN = sodium_crypto_sign_secretkey($kpN); $pkN = base64_encode(sodium_crypto_sign_publickey($kpN));
$r = jreq('POST', '/sonar/register', array('pubkey' => $pkN, 'version' => '0.1.0', 'mode' => 'anchor'), $TN, IP_N);
check('Anker a_nbg ueber IPv6', ($r['j']['data']['node_id'] ?? '') === 'a_nbg' AND one("SELECT ip6 FROM sonar_nodes WHERE node_id = 'a_nbg'")['ip6'] === IP_N, code($r));
cli('sonar_anchor_token.php --name=nbg --lat=49.45 --lon=11.08');
// Token-Wechsel: neuer Token, gleicher Knoten, neuer Schluessel, seq zurueck
[$rc, $out] = cli('sonar_anchor_token.php --name=nbg --rotate');
preg_match('/^(s64a_[A-Za-z0-9]{40})$/m', $out, $m); $TN2 = $m[1] ?? '';
$r = req('GET', '/sonar/me', null, array(), $TN, IP_N);
check('altes Anker-Token nach --rotate 401', $r['code'] === 401, code($r));
exec_sql("UPDATE sonar_nodes set last_seq = 99 WHERE node_id = 'a_nbg'");
$kpN = sodium_crypto_sign_keypair(); $skN = sodium_crypto_sign_secretkey($kpN); $pkN = base64_encode(sodium_crypto_sign_publickey($kpN));
$r = jreq('POST', '/sonar/register', array('pubkey' => $pkN, 'version' => '0.1.1', 'mode' => 'anchor'), $TN2, IP_N);
$nN = one("SELECT * FROM sonar_nodes WHERE node_id = 'a_nbg'");
check('Token-Wechsel: Knoten bleibt, neuer Key, seq 0, Standort bleibt', $r['code'] === 201 AND $nN['pubkey'] === $pkN AND (int)$nN['last_seq'] === 0 AND (float)$nN['lat'] === 49.45, code($r));

// ---------------------------------------------------------------- Plan
echo "Plan\n";
$r = req('GET', '/sonar/plan', null, array(), $TA);
check('kein Plan 204', $r['code'] === 204, code($r));
$now = time();
$R0 = intdiv($now, 300) * 300 - 600; $R1 = $R0 + 300; $R2 = $R0 + 600;
$plan = array('v' => 1, 'node_id' => $A, 'issued' => iso($now - 60), 'expires' => iso($now + 1500), 'rounds' => array(
	array('start' => iso($R0), 'targets' => array(
		array('id' => $B, 'addr' => IP_B, 'fam' => 4, 'method' => 'icmp', 'count' => 3),
		array('id' => $C, 'addr' => '8.8.8.8', 'fam' => 4, 'method' => 'udp', 'count' => 5),
		array('id' => 'a_fsn', 'addr' => IP_F, 'fam' => 4, 'method' => 'icmp', 'count' => 3),
		array('id' => 'a_fsn', 'addr' => IP_F, 'fam' => 4, 'method' => 'trace', 'count' => 1, 'max_ttl' => 30))),
	array('start' => iso($R1), 'targets' => array(
		array('id' => $B, 'addr' => IP_B, 'fam' => 4, 'method' => 'icmp', 'count' => 3),
		array('id' => $C, 'addr' => '8.8.8.8', 'fam' => 4, 'method' => 'udp', 'count' => 5)))),
	'anchors' => array(array('id' => 'a_fsn', 'addr' => IP_F, 'fam' => 4, 'method' => 'icmp', 'count' => 3)));
$body = json_encode($plan, JSON_UNESCAPED_SLASHES);
exec_sql("INSERT INTO sonar_plans (node_id, issued, expires, body, etag, controls) VALUES (?, ?, ?, ?, ?, '')",
	array($A, s64_dt($now - 60), s64_dt($now + 1500), $body, 'etag000000000001'));
$r = req('GET', '/sonar/plan', null, array(), $TA);
$okRaw = preg_match('/^\{"data":\{"plan":(.*),"kid":"([^"]+)","sig":"([^"]+)"\}\}$/s', $r['raw'], $m) === 1;
check('Plan 200 SignedPlan', $r['code'] === 200 AND $okRaw AND ($r['j']['data']['plan']['node_id'] ?? '') === $A, code($r));
check('Plan exakte Bytes', ($m[1] ?? '') === $body);
check('Plan-Signatur mit Public Key gueltig', $okRaw AND $m[2] === $KID AND sodium_crypto_sign_verify_detached(base64_decode($m[3]), $m[1], base64_decode($PUB)));
check('ETag', ($r['h']['etag'] ?? '') === '"etag000000000001"', $r['h']);
$r = req('GET', '/sonar/plan', null, array('If-None-Match: "etag000000000001"'), $TA);
check('If-None-Match 304', $r['code'] === 304 AND $r['raw'] === '' AND ($r['h']['etag'] ?? '') === '"etag000000000001"', code($r));
$r = req('GET', '/sonar/plan', null, array('If-None-Match: W/"etag000000000001", "x"'), $TA);
check('If-None-Match schwach/Liste 304', $r['code'] === 304, code($r));
$pl = one("SELECT * FROM sonar_plans WHERE node_id = ?", array($A));
check('ausgelieferter Plan vermerkt', $pl['sent_etag'] === 'etag000000000001' AND $pl['sent_body'] === $body AND $pl['prev_body'] === null, $pl);
check('last_plan gesetzt', one("SELECT last_plan FROM sonar_nodes WHERE node_id = ?", array($A))['last_plan'] !== null);
exec_sql("INSERT INTO sonar_plans (node_id, issued, expires, body, etag) VALUES (?, ?, ?, ?, ?)",
	array($B, s64_dt($now - 60), s64_dt($now - 1), json_encode(array_merge($plan, array('node_id' => $B))), 'etagexpired00001'));
check('abgelaufener Plan 204', req('GET', '/sonar/plan', null, array(), $TB, IP_B)['code'] === 204);
exec_sql("UPDATE sonar_plans set expires = ?, body = ? WHERE node_id = ?", array(s64_dt($now + 600), $body, $B));
check('Plan mit fremder node_id 204', req('GET', '/sonar/plan', null, array(), $TB, IP_B)['code'] === 204);
exec_sql("UPDATE sonar_plans set issued = ?, expires = ?, body = ? WHERE node_id = ?", array(s64_dt($now - 1900), s64_dt($now + 600), json_encode(array_merge($plan, array('node_id' => $B))), $B));
check('Plan aelter als 30 min 204', req('GET', '/sonar/plan', null, array(), $TB, IP_B)['code'] === 204);
// Plan fuer B (misst A), damit es Pings gegen A gibt
$planB = array('v' => 1, 'node_id' => $B, 'issued' => iso($now - 60), 'expires' => iso($now + 1500), 'rounds' => array(
	array('start' => iso($R0), 'targets' => array(array('id' => $A, 'addr' => IP_A, 'fam' => 4, 'method' => 'icmp', 'count' => 3)))), 'anchors' => array());
exec_sql("UPDATE sonar_plans set issued = ?, expires = ?, body = ?, etag = 'etagb00000000001' WHERE node_id = ?", array(s64_dt($now - 60), s64_dt($now + 1500), json_encode($planB), $B));
check('Plan B 200', req('GET', '/sonar/plan', null, array(), $TB, IP_B)['code'] === 200);

// ---------------------------------------------------------------- Meldungen
echo "Meldungen\n";
$good = array(res($R0, $B), res($R0, $C, array('method' => 'udp', 'sent' => 5, 'recv' => 4, 'min' => 8.0, 'avg' => 9.0, 'max' => 10.5, 'jitter' => 1.0)));
$r = req('POST', '/sonar/results', signed(report($A, 1, $good), $skB), array(), $TA);
check('falsche Signatur 403', $r['code'] === 403 AND ($r['j']['code'] ?? '') === 'invalid_signature', code($r));
$s = signed(report($A, 1, $good), $skA);
$r = req('POST', '/sonar/results', str_replace('"recv":4', '"recv":5', $s), array(), $TA);
check('veraenderte Meldung 403', $r['code'] === 403, code($r));
$r = req('POST', '/sonar/results', '{"report":' . json_encode(report($A, 1, $good)) . '}', array(), $TA);
check('ohne sig 422', $r['code'] === 422, code($r));
$r = req('POST', '/sonar/results', '{"report":{"v":1},"sig":"' . base64_encode(str_repeat('x', 64)) . '","x":1}', array(), $TA);
check('zusaetzlicher Schluessel 422', $r['code'] === 422, code($r));
$r = req('POST', '/sonar/results', '{"report":{"v":1},"report":{"v":2},"sig":"x"}', array(), $TA);
check('doppelter Schluessel 422', $r['code'] === 422, code($r));
$r = req('POST', '/sonar/results', signed(report($A, 1, $good), $skA), array('Content-Type: text/plain'), $TA);
check('Content-Type 415', $r['code'] === 415, code($r));
$r = req('POST', '/sonar/results', str_pad(signed(report($A, 1, $good), $skA), 262145, ' '), array(), $TA);
check('Body > 256 KiB 413', $r['code'] === 413, code($r));
$r = req('POST', '/sonar/results', gzencode(signed(report($A, 1, $good, array('pad' => str_repeat(' ', 300000))), $skA)), array('Content-Encoding: gzip'), $TA);
check('gzip entpackt > 256 KiB 413', $r['code'] === 413, code($r));
foreach(array(
	'v 2' => array(report($A, 1, $good, array('v' => 2)), 422),
	'fremde node_id' => array(report($B, 1, $good), 422),
	'seq 0' => array(report($A, 0, $good), 422),
	'seq als Text' => array(report($A, 1, $good, array('seq' => '1')), 422),
	'seq zu weit voraus' => array(report($A, (time() + 2 * 86400) * 1000, $good), 422),
	'Zone +99:99' => array(report($A, 1, array(res($R0, $B, array('round' => gmdate('Y-m-d\TH:i:s', $R0) . '+99:99')))), 422),
	'sent in der Zukunft' => array(report($A, 1, $good, array('sent' => iso(time() + 900))), 422),
	'fam 5' => array(report($A, 1, array(res($R0, $B, array('fam' => 5)))), 422),
	'method http' => array(report($A, 1, array(res($R0, $B, array('method' => 'http')))), 422),
	'target ungueltig' => array(report($A, 1, array(res($R0, $B, array('target' => '../x')))), 422),
	'round ohne Zone' => array(report($A, 1, array(res($R0, $B, array('round' => gmdate('Y-m-d\TH:i:s', $R0))))), 422),
	'min als Text' => array(report($A, 1, array(res($R0, $B, array('min' => '9')))), 422),
	'inbound.from ungueltig' => array(report($A, 1, $good, array('inbound' => array(array('from' => 'zz', 'fam' => 4, 'at' => iso(time()), 'count' => 1)))), 422),
) as $name => [$rep, $want]) {
	$r = post_report($rep, $skA, $TA);
	check("$name -> $want", $r['code'] === $want, code($r));
}
check('nichts gespeichert bei Fehlern', (int)one("SELECT count(*) c FROM sonar_results")['c'] === 0 AND (int)one("SELECT last_seq FROM sonar_nodes WHERE node_id = ?", array($A))['last_seq'] === 0);

// Verlauf fuer too_smooth: 11 glatte Meldungen A -> B (fam 6) direkt in der DB
for($i = 11; $i >= 1; $i--) {
	exec_sql("INSERT INTO sonar_results (`round`, src, dst, fam, method, sent, recv, min_ms, avg_ms, max_ms, jitter_ms, at, valid) VALUES (?, ?, ?, 6, 'icmp', 5, 5, 7, 7, 7, 0, ?, 1)",
		array(gmdate('Y-m-d H:i:s', $R0 - $i * 300), $A, $B, s64_dt($R0 - $i * 300 + 30)));
}
$planA6 = $plan; $planA6['rounds'][0]['targets'][] = array('id' => $B, 'addr' => '2606:4700::1111', 'fam' => 6, 'method' => 'icmp', 'count' => 5);
$planA6['rounds'][0]['targets'][] = array('id' => $C, 'addr' => '8.8.8.8', 'fam' => 4, 'method' => 'icmp', 'count' => 3);
exec_sql("UPDATE sonar_plans set body = ?, etag = 'etag000000000002' WHERE node_id = ?", array(json_encode($planA6, JSON_UNESCAPED_SLASHES), $A));
exec_sql("UPDATE sonar_nodes set ip6 = '2606:4700::1111' WHERE node_id = ?", array($B)); // Adresse laut Plan = aktuelle (sonst not_allowed)
req('GET', '/sonar/plan', null, array(), $TA);
check('zweiter Plan: prev_body = erster', one("SELECT prev_body FROM sonar_plans WHERE node_id = ?", array($A))['prev_body'] === $body);

$items = array(
	res($R0, $B),                                                                                     // gueltig
	res($R0, $C, array('method' => 'udp', 'sent' => 5, 'recv' => 4, 'min' => 8.0, 'avg' => 9.0, 'max' => 10.5, 'jitter' => 1.0)), // gueltig
	res($R1, $B, array('sent' => 3, 'recv' => 0, 'min' => 0, 'avg' => 0, 'max' => 0, 'jitter' => 0, 'err' => 'timeout')),   // gueltig (Verlust)
	res($R0, 'a_fsn', array('min' => 12.0, 'avg' => 12.5, 'max' => 13.0, 'jitter' => 0.4)),              // gueltig (Plan)
	res($R1, 'a_fsn', array('min' => 12.0, 'avg' => 12.5, 'max' => 13.0, 'jitter' => 0.4)),              // gueltig (Anker immer)
	res($R0, 'a_fsn', array('method' => 'trace', 'sent' => 30, 'recv' => 9, 'min' => 0, 'avg' => 0, 'max' => 0, 'jitter' => 0, 'hops' => array(
		array('ttl' => 1, 'addr' => '192.168.1.1', 'rtt' => 0.4), array('ttl' => 2, 'addr' => '62.155.1.1', 'rtt' => 5.1), array('ttl' => 3), array('ttl' => 4, 'addr' => IP_F, 'rtt' => 12.2)))),
	res($R0, 'a_nbg', array('fam' => 6, 'min' => 11.0, 'avg' => 11.5, 'max' => 12.0, 'jitter' => 0.5)),   // Anker nicht im Plan: erlaubt
	res($R0, 'nzzzzzzzzzzz'),                                                                            // not_in_plan (erfunden)
	res($R2 + 300, $B),                                                                                  // not_in_plan (Runde nicht im Plan, auch nicht +-1)
	res($R0, $B, array('method' => 'udp')),                                                              // not_in_plan (Methode)
	res($R0, $A),                                                                                        // not_in_plan (sich selbst)
	res($R0 + 7, 'a_nbg', array('fam' => 6, 'at' => iso($R0 + 47))),                                     // not_in_plan (Anker, aber nicht auf dem 5-min-Raster)
	res($R0, $B, array('at' => iso($R0 + 50))),                                                          // too_many (zweimal B in R0)
	res($R1, $C, array('method' => 'udp', 'sent' => 5, 'recv' => 5, 'min' => 8.0, 'avg' => 9.0, 'max' => 10.0, 'jitter' => 0.5, 'at' => iso($R1 + 420))), // bad_time
	res($R0, $C, array('fam' => 4, 'method' => 'icmp', 'sent' => 3, 'recv' => 4)),                       // bad_values (recv > sent)
	res($R0, $B, array('fam' => 6, 'sent' => 5, 'recv' => 5, 'min' => 7.0, 'avg' => 7.0, 'max' => 7.0, 'jitter' => 0.0)), // below_light? nein: zu glatt zuerst? (B ist 612 km weg, 7 ms > 6,1)
	res($R0, 'a_nbg', array('sent' => 0, 'recv' => 0, 'min' => 0, 'avg' => 0, 'max' => 0, 'jitter' => 0, 'err' => 'budget')), // not_measured
);
$rep = report($A, 1, $items, array('inbound' => array(array('from' => s64_short_id($B), 'fam' => 4, 'at' => iso(time() - 60), 'count' => 3),
	array('from' => s64_short_id($B), 'fam' => 4, 'at' => iso(time() - 60), 'count' => 2),   // gleiche Runde: zusammengefasst
	array('from' => 'deadbee0', 'fam' => 4, 'at' => iso(time() - 60), 'count' => 9),         // kein Knoten: verworfen
	array('from' => 'deadbeef', 'fam' => 6, 'at' => iso(time() - 30 * 86400), 'count' => 2))));
$r = post_report($rep, $skA, $TA);
$d = $r['j']['data'] ?? array();
$rs = (array)($d['reasons'] ?? array());
check('Meldung 200', $r['code'] === 200, code($r));
check('accepted 7 (6 Ergebnisse + 1 Trace)', ($d['accepted'] ?? null) === 7, $d);
check('not_in_plan 5', ($rs['not_in_plan'] ?? 0) === 5, $rs);
check('too_many 1', ($rs['too_many'] ?? 0) === 1, $rs);
check('bad_time 1', ($rs['bad_time'] ?? 0) === 1, $rs);
check('bad_values 1', ($rs['bad_values'] ?? 0) === 1, $rs);
check('too_smooth 1 (12. glatte Meldung)', ($rs['too_smooth'] ?? 0) === 1, $rs);
check('not_measured 1', ($rs['not_measured'] ?? 0) === 1, $rs);
check('rejected = Summe der Gruende', ($d['rejected'] ?? -1) === array_sum($rs), $d);
$nA = one("SELECT * FROM sonar_nodes WHERE node_id = ?", array($A));
check('seq, last_report, plaus_ok/bad', (int)$nA['last_seq'] === 1 AND $nA['last_report'] !== null AND (int)$nA['plaus_ok'] === 7 AND (int)$nA['plaus_bad'] === 9, $nA);
$hl = json_decode((string)$nA['health'], true);
check('health gespeichert, version uebernommen', ($hl['sent_today'] ?? 0) === 12 AND $hl['responder'] === true AND $nA['version'] === '0.1.0' AND $nA['mode'] === 'headless', $nA);
check('ungueltige mit Grund gespeichert (bad_time, too_smooth)', (int)one("SELECT count(*) c FROM sonar_results WHERE src = ? AND valid = 0 AND reason IN ('bad_time', 'too_smooth')", array($A))['c'] === 2);
check('bad_values/not_in_plan nicht gespeichert', (int)one("SELECT count(*) c FROM sonar_results WHERE src = ? AND (dst = 'nzzzzzzzzzzz' OR recv > sent)", array($A))['c'] === 0);
$row = one("SELECT * FROM sonar_results WHERE src = ? AND dst = ? AND fam = 4 AND method = 'udp' AND valid = 1", array($A, $C));
check('Ergebnis-Zeile (Zeit mit ms, Runde)', $row AND $row['round'] === gmdate('Y-m-d H:i:s', $R0) AND $row['at'] === gmdate('Y-m-d H:i:s', $R0 + 40) . '.123' AND (int)$row['recv'] === 4 AND abs((float)$row['avg_ms'] - 9.0) < 0.001, $row);
$tr = one("SELECT * FROM sonar_traces WHERE src = ?", array($A));
$hops = json_decode((string)($tr['hops'] ?? '[]'), true);
check('Trace gespeichert, Heimnetz-Hop ohne Adresse', $tr AND count($hops) === 4 AND !isset($hops[0]['addr']) AND $hops[1]['addr'] === '62.155.1.1' AND !isset($hops[2]['addr']), $hops);
$ib = all("SELECT * FROM sonar_inbound WHERE node_id = ?", array($A));
check('inbound gespeichert (zusammengefasst, unbekannte und zu alte verworfen)', count($ib) === 1 AND $ib[0]['from_short'] === s64_short_id($B) AND (int)$ib[0]['count'] === 5, $ib);

$r = post_report(report($A, 2, array(res($R1, $C, array('method' => 'udp', 'sent' => 5, 'recv' => 5, 'min' => 8.0, 'avg' => 9.0, 'max' => 10.0, 'jitter' => 0.5)))), $skA, $TA);
check('zweite Meldung in 60 s 429', $r['code'] === 429 AND (int)($r['h']['retry-after'] ?? 0) > 0 AND (int)$r['h']['retry-after'] <= 60, code($r));
back_report($A);
$r = post_report(report($A, 1, array()), $skA, $TA);
check('seq wiederholt 409 replay', $r['code'] === 409 AND ($r['j']['code'] ?? '') === 'replay' AND ($r['j']['last_seq'] ?? 0) === 1, code($r));
$r = post_report(report($A, 5, array_slice($items, 0, 2)), $skA, $TA);
check('erneut gesendete Ergebnisse: duplicate', $r['code'] === 200 AND ($r['j']['data']['accepted'] ?? -1) === 0 AND (($r['j']['data']['reasons']['duplicate'] ?? 0) === 2), code($r));
exec_sql("UPDATE sonar_nodes set last_report = ? WHERE node_id = ?", array(s64_dt(time() - 51), $A));
$r = post_report(report($A, 6, array()), $skA, $TA);
check('Meldung jede Minute passt (Abstand 51 s)', $r['code'] === 200, code($r));
$codes = array(); for($i = 0; $i < 5; $i++) { $codes[] = req('GET', '/sonar/plan', null, array('If-None-Match: "x"'), $TA)['code']; }
check('Plan-Abruf mehrmals je Minute ohne 429', !in_array(429, $codes, true), $codes);
check('keine doppelten Zeilen',(int)one("SELECT count(*) c FROM sonar_results WHERE src = ? AND dst = ? AND `round` = ? AND fam = 4 AND method = 'icmp'", array($A, $B, gmdate('Y-m-d H:i:s', $R0)))['c'] === 1);

// below_light und sofortige Abstufung: B (Muenchen) meldet A (Hamburg, 612 km, >= 6,1 ms) mit 1 ms; A und C vertraut
exec_sql("UPDATE sonar_nodes set trust = 'trusted' WHERE node_id IN (?, ?, ?)", array($B, $A, $C));
$planB['rounds'][] = array('start' => iso($R1), 'targets' => array(array('id' => $A, 'addr' => IP_A, 'fam' => 4, 'method' => 'icmp', 'count' => 3),
	array('id' => $C, 'addr' => '8.8.8.8', 'fam' => 4, 'method' => 'icmp', 'count' => 3), array('id' => 'a_fsn', 'addr' => IP_F, 'fam' => 4, 'method' => 'icmp', 'count' => 3)));
exec_sql("UPDATE sonar_plans set body = ?, etag = 'etagb00000000002' WHERE node_id = ?", array(json_encode($planB), $B));
req('GET', '/sonar/plan', null, array(), $TB, IP_B);
$fast = array('min' => 1.0, 'avg' => 1.2, 'max' => 1.5, 'jitter' => 0.2);
$r = post_report(report($B, 1, array(res($R0, $A), res($R1, $A, $fast), res($R1, $C, $fast), res($R1, 'a_fsn', $fast))), $skB, $TB, IP_B);
$rs = (array)($r['j']['data']['reasons'] ?? array());
check('below_light 3 (A, C, a_fsn mit 1 ms)', $r['code'] === 200 AND ($rs['below_light'] ?? 0) === 3 AND ($r['j']['data']['accepted'] ?? 0) === 1, code($r));
$nB = one("SELECT trust, plaus_bad FROM sonar_nodes WHERE node_id = ?", array($B));
check('sofortige Abstufung trusted -> stable', $nB['trust'] === 'stable' AND (int)$nB['plaus_bad'] === 3, $nB);
$tl = one("SELECT * FROM sonar_trust_log WHERE node_id = ?", array($B));
check('trust_log Eintrag', $tl AND $tl['old'] === 'trusted' AND $tl['new'] === 'stable' AND str_starts_with($tl['reason'], 'plaus_report'), $tl);
check('below_light gespeichert valid=0', (int)one("SELECT count(*) c FROM sonar_results WHERE src = ? AND reason = 'below_light'", array($B))['c'] === 3);
// Ziele mit unsicherem Standort (new): below_light zaehlt nicht gegen B (nur das gegen den Anker), keine Abstufung
exec_sql("UPDATE sonar_nodes set trust = 'new' WHERE node_id IN (?, ?)", array($A, $C));
exec_sql("UPDATE sonar_nodes set trust = 'trusted' WHERE node_id = ?", array($B));
back_report($B);
$fast2 = array_merge($fast, array('at' => iso($R2 + 40)));
$r = post_report(report($B, 2, array(res($R2, $A, $fast2), res($R2, $C, $fast2), res($R2, 'a_fsn', $fast2))), $skB, $TB, IP_B);
$nB = one("SELECT trust, plaus_bad FROM sonar_nodes WHERE node_id = ?", array($B));
check('below_light gegen neue Ziele: keine Abstufung, plaus_bad nur +1 (Anker)', $r['code'] === 200 AND (($r['j']['data']['reasons']['below_light'] ?? 0) === 3)
	AND $nB['trust'] === 'trusted' AND (int)$nB['plaus_bad'] === 4, array(code($r), $nB));
exec_sql("UPDATE sonar_nodes set trust = 'stable' WHERE node_id = ?", array($B));
// Anker meldet: Anker-Ziele ohne Plan nur icmp/udp, Trace nicht
$r = post_report(report('a_fsn', 1, array(res($R0, 'a_nbg', array('fam' => 6, 'min' => 4.0, 'avg' => 4.5, 'max' => 5.0, 'jitter' => 0.3)),
	res($R0, 'a_nbg', array('method' => 'trace', 'hops' => array())))), $skF, $TF, IP_F);
check('Anker misst Anker ohne Plan; Trace ohne Plan nicht', $r['code'] === 200 AND ($r['j']['data']['accepted'] ?? 0) === 1 AND (($r['j']['data']['reasons']['not_in_plan'] ?? 0) === 1), code($r));

// ---------------------------------------------------------------- Inbound
echo "Inbound\n";
$r = req('GET', '/sonar/inbound', null, array(), $TA);
$l = $r['j']['data'] ?? array();
check('Pings gegen A (von B, ungueltige below_light zaehlen nicht)', $r['code'] === 200 AND count($l) === 1 AND $l[0]['from'] === $B AND $l[0]['name'] === 'Muenchen Kabel' AND $l[0]['trust'] === 'stable', code($r));
check('InboundRow-Felder', array_keys($l[0] ?? array()) === array('from', 'name', 'asname', 'place', 'trust', 'fam', 'method', 'avg', 'loss', 'at'), array_keys($l[0] ?? array()));
check('ohne IPs', !str_contains($r['raw'], IP_B) AND !str_contains($r['raw'], IP_A));
$r = req('GET', '/sonar/inbound?since=' . urlencode(iso(time() - 5 * 86400)), null, array(), $TA);
check('since > 24 h wird begrenzt', $r['code'] === 200 AND count($r['j']['data']) === 1, code($r));
$r = req('GET', '/sonar/inbound?since=gestern', null, array(), $TA);
check('since ungueltig 400', $r['code'] === 400, code($r));
$r = req('GET', '/sonar/inbound?since=' . urlencode(gmdate('Y-m-d\TH:i:s') . '+99:99'), null, array(), $TA);
check('since mit Zone +99:99 400', $r['code'] === 400, code($r));
$r = req('GET', '/sonar/inbound?since=' . urlencode(iso(time() - 86400 + 60)), null, array(), $TB, IP_B);
check('B: 13 Pings von A (too_smooth zaehlt nicht)', $r['code'] === 200 AND count($r['j']['data']) === 13 AND array_unique(array_column($r['j']['data'], 'from')) === array($A), code($r));

// ---------------------------------------------------------------- Erreichbarkeit sofort
echo "Erreichbarkeit\n";
// Anker erreicht A per udp, B per icmp; C mit anderer Adresse als im Plan (IP gewechselt) nicht
check('vorher: reach4 none', one("SELECT GROUP_CONCAT(reach4 ORDER BY node_id) r FROM sonar_nodes WHERE node_id IN (?, ?, ?)", array($A, $B, $C))['r'] === 'none,none,none');
$planF = array('v' => 1, 'node_id' => 'a_fsn', 'issued' => iso($now - 60), 'expires' => iso($now + 1500), 'rounds' => array(array('start' => iso($R0), 'targets' => array(
	array('id' => $A, 'addr' => IP_A, 'fam' => 4, 'method' => 'udp', 'count' => 3), array('id' => $B, 'addr' => IP_B, 'fam' => 4, 'method' => 'icmp', 'count' => 3),
	array('id' => $C, 'addr' => '8.8.8.9', 'fam' => 4, 'method' => 'icmp', 'count' => 3)))), 'anchors' => array());
exec_sql("INSERT INTO sonar_plans (node_id, issued, expires, body, etag) VALUES ('a_fsn', ?, ?, ?, 'etagf00000000001')", array(s64_dt($now - 60), s64_dt($now + 1500), json_encode($planF, JSON_UNESCAPED_SLASHES)));
check('Anker-Plan 200', req('GET', '/sonar/plan', null, array(), $TF, IP_F)['code'] === 200);
back_report('a_fsn');
$pbF = (int)one("SELECT plaus_bad FROM sonar_nodes WHERE node_id = 'a_fsn'")['plaus_bad'];
$r = post_report(report('a_fsn', 2, array(res($R0, $A, array('method' => 'udp')), res($R0, $B), res($R0, $C))), $skF, $TF, IP_F);
$rr = array(); foreach(all("SELECT node_id, reach4 FROM sonar_nodes WHERE node_id IN (?, ?, ?)", array($A, $B, $C)) as $x) { $rr[$x['node_id']] = $x['reach4']; }
check('Anker-Meldung: reach4 sofort udp bzw. icmp, andere Adresse nicht (not_allowed)', $r['code'] === 200 AND ($r['j']['data']['accepted'] ?? 0) === 2
	AND ($r['j']['data']['reasons']['not_allowed'] ?? 0) === 1 AND $rr[$A] === 'udp' AND $rr[$B] === 'icmp' AND $rr[$C] === 'none', array(code($r), $rr));
check('not_allowed zaehlt nicht in plaus_bad', (int)one("SELECT plaus_bad FROM sonar_nodes WHERE node_id = 'a_fsn'")['plaus_bad'] === $pbF);

// ---------------------------------------------------------------- Oeffentlich
echo "Oeffentlich\n";
exec_sql("INSERT INTO sonar_nodes (node_id, userid, token_id, role, pubkey, name, slug, trust, first_seen, last_seen, pub_lat, pub_lon, lat, lon) VALUES
	('nquarantine1', 2, 999, 'node', 'q', 'Boese', 'boese', 'quarantine', ?, ?, 52.5, 13.4, 52.5, 13.4)", array(s64_dt(time() - 86400), s64_dt()));
exec_sql("UPDATE sonar_nodes set first_seen = ?, uptime30 = 0.99 WHERE node_id = ?", array(s64_dt(time() - 40 * 86400), $A));
$H = intdiv(time(), 3600) * 3600 - 3600;
exec_sql("INSERT INTO sonar_pair_1h (src, dst, fam, hour, n, avg_ms, p50_ms, loss) VALUES (?, 'a_fsn', 4, ?, 12, 12.4, 12.3, 0), (?, ?, 4, ?, 10, 15.0, 14.8, 0.01), (?, ?, 4, ?, 10, 16.0, 15.2, 0)",
	array($A, gmdate('Y-m-d H:i:s', $H), $A, $C, gmdate('Y-m-d H:i:s', $H), $C, $B, gmdate('Y-m-d H:i:s', $H)));
exec_sql("INSERT INTO sonar_outages (kind, keyval, label, started, ended, affected, total) VALUES ('asn', '3320', 'Telekom', ?, NULL, 6, 10), ('region', '53.5|10.0', 'Hamburg', ?, ?, 5, 8)",
	array(s64_dt(time() - 600), s64_dt(time() - 7200), s64_dt(time() - 3600)));
clear_cache();
$secret = array(IP_A, IP_B, IP_F, IP_N, '8.8.8.8', '53.55123', '48.13712', '50.11034', 'userid', 'pubkey', 'token');
$pubAll = '';
$r = req('GET', '/sonar/public/map');
$pubAll .= $r['raw'];
$mp = $r['j']['data'] ?? array();
$byId = array_column($mp['nodes'] ?? array(), null, 'id');
check('map 200, Cache-Control', $r['code'] === 200 AND ($r['h']['cache-control'] ?? '') === 'public, max-age=60' AND ($r['h']['access-control-allow-origin'] ?? '') === '*', code($r));
check('map Knoten A, B, C, Anker; ohne Quarantaene', isset($byId[$A], $byId[$B], $byId[$C], $byId['a_fsn'], $byId['a_nbg']) AND !isset($byId['nquarantine1']), array_keys($byId));
check('map Knoten-Felder (Vertrag 5)', array_keys($byId[$A] ?? array()) === array('id', 'slug', 'name', 'lat', 'lon', 'trust', 'role', 'asn', 'asname', 'access', 'device', 'online', 'anchor_ms'), array_keys($byId[$A] ?? array()));
check('map lat/lon verschleiert', ($byId[$A]['lat'] ?? 0) !== 53.55123 AND abs(($byId[$A]['lat'] ?? 0) - 53.55123) < 0.01, $byId[$A] ?? null);
check('map anchor_ms A->a_fsn, A->a_nbg', ($byId[$A]['anchor_ms']['a_fsn'] ?? 0) == 12.5 AND ($byId[$A]['anchor_ms']['a_nbg'] ?? 0) == 11.5, $byId[$A] ?? null);
$lk = array();
foreach($mp['links'] ?? array() as $x) { $lk[$x['a'] . '|' . $x['b'] . '|' . $x['fam']] = $x; }
$kAB = ($A < $B ? "$A|$B" : "$B|$A") . '|4';
check('map Link A-B (beide Richtungen zusammen)', isset($lk[$kAB]) AND $lk[$kAB]['n'] === 3 AND $lk[$kAB]['fam'] === 4, $mp['links'] ?? null);
check('map ohne Anker-Links', array_filter($mp['links'] ?? array(), fn($x) => str_starts_with($x['a'], 'a_') || str_starts_with($x['b'], 'a_')) === array());
check('map offene Stoerung', count($mp['outages'] ?? array()) === 1 AND $mp['outages'][0]['key'] === '3320', $mp['outages'] ?? null);
exec_sql("UPDATE sonar_nodes set last_seen = ? WHERE node_id = ?", array(s64_dt(time() - 3600), $C));
$r = req('GET', '/sonar/public/map');
check('map aus dem Cache (60 s)', isset(array_column($r['j']['data']['nodes'], null, 'id')[$C]));
check('map aus dem Cache: leeres anchor_ms bleibt {}', str_contains($r['raw'], '"anchor_ms":{}') AND !str_contains($r['raw'], '"anchor_ms":[]'), substr($r['raw'], 0, 600));
clear_cache();
check('map ohne offline-Knoten C', !isset(array_column(req('GET', '/sonar/public/map')['j']['data']['nodes'], null, 'id')[$C]));

$r = req('GET', '/sonar/public/nodes');
$pubAll .= $r['raw'];
$ids = array_column($r['j']['data'] ?? array(), 'id');
check('nodes: alle ausser Quarantaene (C offline dabei)', $r['code'] === 200 AND count($ids) === 5 AND !in_array('nquarantine1', $ids, true) AND in_array($C, $ids, true), $ids);
check('nodes: Anker zuerst', in_array($ids[0] ?? '', array('a_fsn', 'a_nbg'), true), $ids);
$r = req('GET', '/sonar/public/nodes?trust=anchor');
check('nodes trust=anchor', count($r['j']['data'] ?? array()) === 2, code($r));
$r = req('GET', '/sonar/public/nodes?q=hamburg');
check('nodes q=hamburg', array_column($r['j']['data'] ?? array(), 'id') === array($A), code($r));
if($dnsOk) { $r = req('GET', '/sonar/public/nodes?asn=19281'); check('nodes asn=19281', array_column($r['j']['data'] ?? array(), 'id') === array($A), code($r)); }
check('nodes trust=quarantine 400', req('GET', '/sonar/public/nodes?trust=quarantine')['code'] === 400);
check('node/{slug} in Quarantaene 404', req('GET', '/sonar/public/node/boese')['code'] === 404);
check('nodes asn=abc 400', req('GET', '/sonar/public/nodes?asn=abc')['code'] === 400);

$r = req('GET', '/sonar/public/node/hamburg-glasfaser');
$pubAll .= $r['raw'];
$nd = $r['j']['data'] ?? array();
check('node/{slug} 200 mit Verlauf', $r['code'] === 200 AND $nd['id'] === $A AND count($nd['history']['a_fsn'] ?? array()) === 1 AND $nd['history']['a_fsn'][0]['ms'] == 12.3 AND ($nd['anchor_ms']['a_fsn'] ?? 0) == 12.5, code($r));
check('node/{slug} unbekannt 404', req('GET', '/sonar/public/node/gibtsnicht')['code'] === 404);
check('node/{slug} ungueltig 404', req('GET', '/sonar/public/node/' . urlencode('a b'))['code'] === 404);

$r = req('GET', '/sonar/public/stats');
$pubAll .= $r['raw'];
$st = $r['j']['data'] ?? array();
check('stats', $r['code'] === 200 AND $st['nodes_total'] === 3 AND $st['nodes_active'] === 2 AND $st['anchors'] === 2 AND $st['measurements_today'] >= 1
	AND $st['by_trust']['anchor'] === 2 AND !isset($st['by_trust']['quarantine']) AND $st['regions'] >= 2, $st);
if($dnsOk) { check('stats providers 3', $st['providers'] === 3, $st); }

$r = req('GET', '/sonar/public/top');
$pubAll .= $r['raw'];
$tp = $r['j']['data'] ?? array();
check('top: zuverlaessigste nur ab 7 Tagen (A)', $r['code'] === 200 AND array_column($tp['reliable'] ?? array(), 'slug') === array('hamburg-glasfaser'), $tp);
check('top: laengste Teilnahme zuerst A', ($tp['longest'][0]['slug'] ?? '') === 'hamburg-glasfaser' AND count($tp['longest']) === 3, $tp['longest'] ?? null);
if($dnsOk) { check('top: je Provider', count($tp['providers'] ?? array()) === 3 AND isset($tp['providers'][0]['best']['slug']), $tp['providers'] ?? null); }

$r = req('GET', '/sonar/public/matrix');
$pubAll .= $r['raw'];
$mx = $r['j']['data'] ?? array();
if($dnsOk) {
	check('matrix: Provider und Zellen (Anker nicht)', $r['code'] === 200 AND count($mx['asns']) === 3 AND count($mx['cells']) === 2, $mx);
} else {
	check('matrix 200', $r['code'] === 200 AND isset($mx['asns'], $mx['cells']), code($r));
}
$r = req('GET', '/sonar/public/outages?active=1');
$pubAll .= $r['raw'];
check('outages active=1', $r['code'] === 200 AND count($r['j']['data']) === 1 AND array_keys($r['j']['data'][0]) === array('id', 'kind', 'key', 'label', 'started', 'ended', 'affected', 'total'), code($r));
$r = req('GET', '/sonar/public/outages');
check('outages 30 Tage', $r['code'] === 200 AND count($r['j']['data']) === 2 AND $r['j']['data'][1]['ended'] !== null, code($r));
$leak = array_filter($secret, fn($s) => str_contains($pubAll, $s));
check('oeffentlich: keine IPs, genauen Koordinaten, Account- oder Schluesseldaten', $leak === array(), array_values($leak));
check('oeffentlich: POST nicht erlaubt 405', req('POST', '/sonar/public/map', '{}')['code'] === 405);

// ---------------------------------------------------------------- aeltere Planfassung (Vertrag 10.1)
echo "Aeltere Planfassung\n";
$F = intdiv(time(), 300) * 300; $Rh = $F - 1500; $Rold = $F - 2400;
$mk = fn(array $rounds) => json_encode(array('v' => 1, 'node_id' => $A, 'issued' => iso(time() - 60), 'expires' => iso(time() + 1500), 'rounds' => $rounds, 'anchors' => array()), JSON_UNESCAPED_SLASHES);
$tB = array('id' => $B, 'addr' => IP_B, 'fam' => 4, 'method' => 'icmp', 'count' => 3);
$tC = array('id' => $C, 'addr' => '8.8.8.8', 'fam' => 4, 'method' => 'udp', 'count' => 3);
$versions = array( // v1 mit B, danach ohne (B gilt als nachgereicht gemessen), v3 ist die zuletzt, v2 die davor ausgelieferte
	$mk(array(array('start' => iso($Rold), 'targets' => array($tC)), array('start' => iso($Rh), 'targets' => array($tB, $tC)), array('start' => iso($Rh + 300), 'targets' => array($tB)))),
	$mk(array(array('start' => iso($Rh), 'targets' => array($tC)))),
	$mk(array(array('start' => iso($Rh), 'targets' => array($tC)), array('start' => iso($Rh + 600), 'targets' => array($tC)))));
foreach($versions as $i => $v) {
	exec_sql("UPDATE sonar_plans set issued = ?, expires = ?, body = ?, etag = ? WHERE node_id = ?", array(s64_dt(time() - 60), s64_dt(time() + 1500), $v, sprintf('etagh%011d', $i), $A));
	req('GET', '/sonar/plan', null, array(), $TA);
}
$hist = json_decode((string)one("SELECT sent_hist FROM sonar_plans WHERE node_id = ?", array($A))['sent_hist'], true);
check('sent_hist: Runde mit B aus der ersten Fassung, Runden aelter als 35 min nicht', isset($hist[$Rh]["$B|4|icmp"], $hist[$Rh + 300]["$B|4|icmp"]) AND $hist[$Rh]["$B|4|icmp"] === array(1, IP_B) AND !isset($hist[$Rold]), $hist);
check('sent_hist klein (' . strlen(json_encode($hist)) . ' Byte)', strlen(json_encode($hist)) < 1000);
$pbA = (int)one("SELECT plaus_bad FROM sonar_nodes WHERE node_id = ?", array($A))['plaus_bad'];
back_report($A);
$r = post_report(report($A, 10, array(res($Rh, $B), res($Rh, $C, array('method' => 'udp')))), $skA, $TA);
check('aeltere Fassung gemessen: angenommen, kein not_in_plan', $r['code'] === 200 AND ($r['j']['data']['accepted'] ?? 0) === 2 AND ($r['j']['data']['rejected'] ?? -1) === 0, code($r));
exec_sql("UPDATE sonar_nodes set measured = 0 WHERE node_id = ?", array($B)); // B nicht mehr erlaubt (Opt-out)
back_report($A);
$r = post_report(report($A, 11, array(res($Rh + 300, $B), res($Rh + 300, $C))), $skA, $TA); // C per icmp stand in keiner Fassung
check('herausgefallenes Ziel (Opt-out): not_allowed; nie geplantes: not_in_plan', $r['code'] === 200 AND ($r['j']['data']['reasons']['not_allowed'] ?? 0) === 1
	AND ($r['j']['data']['reasons']['not_in_plan'] ?? 0) === 1 AND ($r['j']['data']['accepted'] ?? -1) === 0, code($r));
check('plaus_bad nur +1 (not_in_plan, nicht not_allowed)', (int)one("SELECT plaus_bad FROM sonar_nodes WHERE node_id = ?", array($A))['plaus_bad'] === $pbA + 1);
exec_sql("UPDATE sonar_nodes set measured = 1 WHERE node_id = ?", array($B));

// ---------------------------------------------------------------- DELETE /sonar/me (Vertrag 10.2)
echo "DELETE /sonar/me\n";
$TD = jreq('POST', '/sonar/tokens', array('name' => 'D'), K2)['j']['data']['token'] ?? '';
$kpD = sodium_crypto_sign_keypair();
$D = jreq('POST', '/sonar/register', array('pubkey' => base64_encode(sodium_crypto_sign_publickey($kpD)), 'version' => '0.1.0', 'mode' => 'headless'), $TD, '8.8.4.4')['j']['data']['node_id'] ?? '';
jreq('PUT', '/sonar/me', array('lat' => 52.52, 'lon' => 13.405, 'name' => 'Berlin Test'), $TD, '8.8.4.4');
exec_sql("INSERT INTO sonar_plans (node_id, issued, expires, body, etag) VALUES (?, ?, ?, '{}', 'etagd00000000001')", array($D, s64_dt(time() - 60), s64_dt(time() + 1500)));
$r = req('DELETE', '/sonar/me', null, array(), $TD, '8.8.4.4');
check('DELETE /sonar/me 204', $r['code'] === 204 AND $r['raw'] === '', code($r));
$nD = one("SELECT * FROM sonar_nodes WHERE node_id = ?", array($D));
check('abgemeldet: aus, disabled_at, IP/Standort weg, Name/Slug frei', $D !== '' AND (int)$nD['active'] === 0 AND $nD['disabled_at'] !== null AND $nD['ip4'] === null
	AND $nD['lat'] === null AND $nD['pub_lat'] === null AND $nD['name'] === '~' . $D AND $nD['slug'] === '~' . $D, $nD);
check('Token widerrufen, Plan geloescht', one("SELECT revoked_at FROM sonar_tokens WHERE node_id = ?", array($D))['revoked_at'] !== null
	AND one("SELECT node_id FROM sonar_plans WHERE node_id = ?", array($D)) === false);
$tl = one("SELECT * FROM sonar_trust_log WHERE node_id = ? AND `new` = 'removed'", array($D));
check('trust_log removed / leave', $tl AND $tl['reason'] === 'leave' AND $tl['old'] === 'new', $tl);
foreach(array(array('GET', '/sonar/me', null), array('GET', '/sonar/plan', null), array('DELETE', '/sonar/me', null),
	array('POST', '/sonar/register', json_encode(array('pubkey' => base64_encode(sodium_crypto_sign_publickey($kpD)), 'version' => '0.1.0', 'mode' => 'headless')))) as [$m, $p, $b]) {
	$r = req($m, $p, $b, array(), $TD, '8.8.4.4');
	check("danach $m $p 401 invalid_token", $r['code'] === 401 AND ($r['j']['code'] ?? '') === 'invalid_token', code($r));
}
$r = post_report(report($D, 1, array()), sodium_crypto_sign_secretkey($kpD), $TD, '8.8.4.4');
check('danach POST /sonar/results 401', $r['code'] === 401, code($r));
$TE = jreq('POST', '/sonar/tokens', array('name' => 'E'), K2)['j']['data']['token'] ?? '';
$r = req('DELETE', '/sonar/me', null, array(), $TE, '8.8.4.4');
check('DELETE /sonar/me vor register: 204, Token widerrufen', $r['code'] === 204 AND one("SELECT revoked_at FROM sonar_tokens WHERE token_hash = ?", array(hash('sha256', $TE)))['revoked_at'] !== null, code($r));

// ---------------------------------------------------------------- Token loeschen
echo "Token loeschen\n";
$r = req('DELETE', '/sonar/tokens/' . $TA_ID, null, array(), K1);
check('Token A loeschen 204', $r['code'] === 204, code($r));
$nA = one("SELECT * FROM sonar_nodes WHERE node_id = ?", array($A));
check('Knoten deaktiviert, IP und Standort geloescht', (int)$nA['active'] === 0 AND $nA['ip4'] === null AND $nA['lat'] === null AND $nA['pub_lat'] === null, $nA);
check('Name und Slug frei', $nA['name'] === '~' . $A AND $nA['slug'] === '~' . $A, $nA);
check('disabled_at, Plan weg, trust_log removed/owner', $nA['disabled_at'] !== null AND one("SELECT node_id FROM sonar_plans WHERE node_id = ?", array($A)) === false
	AND (one("SELECT reason FROM sonar_trust_log WHERE node_id = ? AND `new` = 'removed'", array($A))['reason'] ?? '') === 'owner');
$r = jreq('PUT', '/sonar/me', array('name' => 'Hamburg Glasfaser'), $TB, IP_B);
check('frei gewordener Name wieder vergeben', $r['code'] === 200 AND $r['j']['data']['slug'] === 'hamburg-glasfaser', code($r));
for($i = 0, $r = null; $i < 15; $i++) {
	$r = jreq('POST', '/sonar/tokens', array('name' => "kreis$i"), K1);
	if($r['code'] !== 201) { break; }
	req('DELETE', '/sonar/tokens/' . $r['j']['data']['id'], null, array(), K1);
}
check('Anlegen/Loeschen im Kreis: 21. Token in 24 h 429', $r['code'] === 429 AND $i === 10, array($i, code($r)));
check('Token A danach 401', req('GET', '/sonar/me', null, array(), $TA)['code'] === 401);
clear_cache();
check('A nicht mehr oeffentlich', !in_array($A, array_column(req('GET', '/sonar/public/nodes')['j']['data'], 'id'), true));

// ---------------------------------------------------------------- Admin-CLI bots/sonar_node.php (Vertrag 10.2)
echo "Admin-CLI\n";
[$rc, $out] = cli('sonar_node.php --list');
check('--list: aktive Knoten (B, Anker), ohne A', $rc === 0 AND str_contains($out, $B) AND str_contains($out, 'a_fsn') AND !str_contains($out, $A), $out);
[$rc, $out] = cli('sonar_node.php --list --inactive');
check('--list --inactive: abgemeldete (A, D)', $rc === 0 AND str_contains($out, $A) AND str_contains($out, $D) AND str_contains($out, 'abgemeldet') AND !str_contains($out, $B), $out);
[$rc, $out] = cli('sonar_node.php --show=hamburg-glasfaser');
check('--show per Slug', $rc === 0 AND preg_match('/^node_id\s+' . $B . '$/m', $out) === 1 AND str_contains($out, 'token') AND !str_contains($out, $TB), $out);
[$rc, $out] = cli('sonar_node.php --show=' . escapeshellarg("x'; DROP TABLE sonar_nodes; --"));
check('--show mit ungueltigem Schluessel abgelehnt', $rc === 1 AND (int)one("SELECT count(*) c FROM sonar_nodes")['c'] > 0, $out);
[$rc, $out] = cli('sonar_node.php --revoke=a_nbg');
check('--revoke Anker ohne --force abgelehnt', $rc === 1 AND (int)one("SELECT active FROM sonar_nodes WHERE node_id = 'a_nbg'")['active'] === 1, $out);
[$rc, $out] = cli('sonar_node.php --revoke=' . $C . ' ' . escapeshellarg('--reason=Missbrauch <b>gemeldet</b>'));
$nC = one("SELECT active, disabled_at, ip4 FROM sonar_nodes WHERE node_id = ?", array($C));
check('--revoke Knoten: aus, IP weg', $rc === 0 AND (int)$nC['active'] === 0 AND $nC['disabled_at'] !== null AND $nC['ip4'] === null, array($out, $nC));
check('--revoke: trust_log admin mit Grund (bereinigt)', (one("SELECT reason FROM sonar_trust_log WHERE node_id = ? AND `new` = 'removed'", array($C))['reason'] ?? '') === 'admin Missbrauch bgemeldet/b', $out);
check('--revoke: Token danach 401', req('GET', '/sonar/me', null, array(), $TC, '8.8.8.8')['code'] === 401);
[$rc, $out] = cli('sonar_node.php --revoke=' . $C);
check('--revoke zweimal: schon abgemeldet', $rc === 0 AND str_contains($out, 'schon abgemeldet'), $out);
[$rc, $out] = cli('sonar_node.php --revoke=a_nbg --force');
check('--revoke Anker mit --force: aus, alle Anker-Token widerrufen', $rc === 0 AND (int)one("SELECT active FROM sonar_nodes WHERE node_id = 'a_nbg'")['active'] === 0
	AND (int)one("SELECT count(*) c FROM sonar_tokens WHERE kind = 'anchor' AND name = 'nbg' AND revoked_at IS NULL")['c'] === 0, $out);
check('Anker-Token danach 401', req('GET', '/sonar/me', null, array(), $TN2, IP_N)['code'] === 401);
[$rc, $out] = cli('sonar_anchor_token.php --name=nbg');
preg_match('/^(s64a_[A-Za-z0-9]{40})$/m', $out, $m); $TN3 = $m[1] ?? '';
$kpN = sodium_crypto_sign_keypair();
$r = jreq('POST', '/sonar/register', array('pubkey' => base64_encode(sodium_crypto_sign_publickey($kpN)), 'version' => '0.1.2', 'mode' => 'anchor'), $TN3, IP_N);
$nN = one("SELECT active, disabled_at, lat FROM sonar_nodes WHERE node_id = 'a_nbg'");
check('Anker mit neuem Token wieder aktiv: disabled_at NULL, Standort bleibt', $r['code'] === 201 AND (int)$nN['active'] === 1 AND $nN['disabled_at'] === null AND (float)$nN['lat'] === 49.45, array(code($r), $nN));
[$rc, $out] = cli('sonar_node.php --show=gibtsnicht');
check('--show unbekannt rc 1', $rc === 1, $out);
[$rc, $out] = cli('sonar_node.php');
check('ohne Option: Aufruf, rc 1', $rc === 1 AND str_contains($out, 'Aufruf'), $out);

echo "\n$pass ok, $failed Fehler\n";
exit($failed > 0 ? 1 : 0);
