<?php
/**
 * Pruefung Honeypot64 H3 (Bewertung + Listen) in der Testumgebung hp3a-* (run_agentbox.sh): honeypot_score.php,
 * create_blocklists_v2.php (v64), blocklists/live.php (ueber den Builtin-Server mit Router), honeypot/token.php,
 * v64_blocklists.php. Testdaten werden direkt in die H2-Tabellen geschrieben (wie api_v2_honeypot.php sie anlegt),
 * damit auch Treffer aelter als 7 Tage (Rausfallen nach 14 Tagen) moeglich sind.
 *
 *   HP3ATEST=1 php run_tests.php http://127.0.0.1:8080 /var/www/clients/client1/web58/web
 */
if(php_sapi_name() !== 'cli' OR getenv('HP3ATEST') !== '1') { exit; }

$BASE = rtrim($argv[1] ?? 'http://127.0.0.1:8080', '/');
$WEB = rtrim($argv[2] ?? '/var/www/clients/client1/web58/web', '/');
$PUB = "$WEB/blocklists";
$LIVE = dirname($WEB) . '/private/blocklists_live';
$db = new PDO('mysql:host=hp3a-db;dbname=ipv64', 'root', 'hp3atest', array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
$pass = 0; $failed = 0;

function check(string $name, bool $ok, $info = ''): void {
	global $pass, $failed;
	if($ok) { $pass++; echo "  ok    $name\n"; }
	else { $failed++; echo "  FEHLER $name " . (is_string($info) ? $info : json_encode($info, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) . "\n"; }
}
function x(string $sql, array $p = array()) { global $db; $st = $db->prepare($sql); $st->execute($p); return $st; }
function one(string $sql, array $p = array()) { return x($sql, $p)->fetch(PDO::FETCH_ASSOC); }
function dt(float $daysAgo): string { return gmdate('Y-m-d H:i:s', (int)(time() - $daysAgo * 86400)); }
function score(string $ip) { return one("SELECT * FROM hp_scores WHERE ip_bin = INET6_ATON(?)", array($ip)); }
function cli(string $cmd): string { global $WEB; return (string)shell_exec("cd $WEB && $cmd 2>&1"); }
function scorer(): string { global $WEB; return cli("php $WEB/bots/blocklist/honeypot_score.php"); }
function gen(string $args = ''): string { global $WEB; return cli("php $WEB/bots/blocklist/create_blocklists_v2.php $args"); }
function lines(string $path): array { return is_file($path) ? file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : array('(fehlt)'); }

/** HTTP-Anfrage; Rueckgabe code, h (Kopfzeilen klein), body */
function req(string $method, string $path, array $headers = array(), ?string $body = null): array {
	global $BASE;
	$ctx = stream_context_create(array('http' => array('method' => $method, 'header' => implode("\r\n", $headers), 'content' => $body ?? '',
		'ignore_errors' => true, 'timeout' => 30, 'follow_location' => 0)));
	$raw = @file_get_contents($BASE . $path, false, $ctx);
	$code = 0; $h = array(); $cookies = array();
	foreach($http_response_header ?? array() as $l) {
		if(preg_match('#^HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; }
		elseif(str_contains($l, ':')) { [$k, $v] = explode(':', $l, 2); $h[strtolower(trim($k))] = trim($v); if(strtolower(trim($k)) === 'set-cookie') { $cookies[] = explode(';', trim($v))[0]; } }
	}
	return array('code' => $code, 'h' => $h, 'body' => (string)$raw, 'cookies' => $cookies);
}

// ---------------------------------------------------------------- Testdaten
// Accounts 1-12 (30 Tage alt, Standard); 2 = VIP; 9 = neu (2 Tage); 10 = inaktiv; 8 = ohne Sensor; 11 = Sensor vor 10 Tagen
for($u = 1; $u <= 12; $u++) {
	x("INSERT INTO users (id, email, reg_date, account_status, user_class) VALUES (?, ?, ?, ?, ?)",
		array($u, "u$u@test", $u === 9 ? date('Y-m-d H:i:s', time() - 2 * 86400) : date('Y-m-d H:i:s', time() - 30 * 86400), $u === 10 ? 0 : 1, $u === 2 ? 2 : 1));
}
$reportNo = 0;
/** Sensor-IP je Account: eigenes /24; Accounts 5 und 6 im selben /24 */
function sensor_ip(int $u): string { return $u === 6 ? '84.200.50.20' : ($u === 5 ? '84.200.50.10' : "84.200.$u.10"); }
/** Meldung eines Accounts ueber eine IP (ein Bericht, eine Quelle), $days = vor wie vielen Tagen zuletzt gesehen */
function src(int $u, string $ip, string $kind, float $days = 0.1, string $source = 'honeypot', int $count = 3): void {
	global $reportNo;
	$sid = sprintf('00000000-0000-4000-8000-%012d', $u);
	$sip = sensor_ip($u);
	$seen = dt($u === 11 ? max($days, 10) : $days);
	x("INSERT INTO hp_sensors (sensor_id, userid, version, profile, mode, first_seen, last_seen, last_ip) VALUES (?, ?, '0.3.0', 'standard', 'headless', ?, ?, ?)
		ON DUPLICATE KEY UPDATE last_seen = GREATEST(last_seen, VALUES(last_seen))", array($sid, $u, dt(30), $u === 11 ? dt(10) : dt(0.01), $sip));
	$reportNo++;
	$day = substr($seen, 0, 10);
	x("INSERT INTO hp_reports (day, report_id, sensor_id, userid, period_start, period_end, received_at, sources, ip) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
		array($day, "$sid-$reportNo", $sid, $u, $seen, $seen, $seen, $sip));
	$ref = (int)x("SELECT LAST_INSERT_ID()")->fetchColumn();
	x("INSERT INTO hp_report_sources (day, report_ref, userid, sensor_id, ip, ip_bin, kind, service, port, `count`, first_seen, last_seen, source) VALUES (?, ?, ?, ?, ?, INET6_ATON(?), ?, 'ssh', 22, ?, ?, ?, ?)",
		array($day, $ref, $u, $sid, $ip, $ip, $kind, $count, $seen, $seen, $source));
}
function many(array $users, string $ip, string $kind, float $days = 0.1): void { foreach($users as $u) { src($u, $ip, $kind, $days); } }

many(array(1, 2), '45.1.0.1', 'ssh:bruteforce');            // A: 2 Accounts Login -> gelistet
many(array(1, 2), '45.1.0.2', 'generic:portscan');          // B: 2 Accounts Scan -> nicht
many(array(1, 2, 3), '45.1.0.3', 'generic:portscan');       // C: 3 Accounts Scan -> gelistet
many(array(5, 6), '45.1.0.4', 'ssh:bruteforce');            // D: gleiches /24 -> zaehlt einmal
many(array(5, 6, 7), '45.1.0.5', 'ssh:bruteforce');         // E: 2 Gruppen -> gelistet
many(array(1, 3), sensor_ip(4), 'ssh:bruteforce');          // F: Sensor-IP von Account 4
many(array(1, 2), '45.1.0.7', 'ssh:bruteforce');            // G: Freigabe hp_allowlist
many(array(1, 2), '45.1.0.8', 'ssh:bruteforce');            // H: Freigabe-Antrag geschuetzt
many(array(1, 2), '45.1.0.9', 'ssh:bruteforce');            // H2: Schutz abgelaufen -> gelistet
many(array(1, 2), '45.1.0.10', 'ssh:bruteforce');           // I: Kunden-IP (A-Record)
many(array(1, 2), '2a01:4f8:1:2::10', 'ssh:bruteforce');    // I2: Kunden-IP (AAAA, anders geschrieben)
many(array(1, 2), '45.1.0.11', 'ssh:bruteforce');           // J: Infrastruktur (cdn_server)
many(array(1, 2), '45.1.1.5', 'ssh:bruteforce');            // J2: Infrastruktur (hp_allowlist infra)
many(array(1, 2), '104.16.1.1', 'ssh:bruteforce');          // K: Cloudflare
many(array(1, 2), '45.1.0.12', 'ssh:bruteforce', 15);       // L: 15 Tage alt -> raus
many(array(1, 2), '45.1.0.14', 'ssh:bruteforce', 13);       // L2: 13 Tage alt -> noch drin, niedriger Wert
many(array(1, 2, 3), '45.1.0.20', 'scanner:research');      // M: Research -> nur research
many(array(1, 2), '45.1.0.21', 'scanner:research');         // M2: Research 2 Accounts -> nicht
many(array(1, 2), '45.1.0.30', 'http:exploit:sqli');        // N: web
many(array(1, 3), '45.1.0.31', 'mail:auth-bruteforce');     // N: mail
many(array(1, 3), '45.1.0.32', 'rdp:bruteforce');           // N: rdp
many(array(1, 2), '2a02:1::5', 'ssh:bruteforce');           // N: IPv6
many(array(1, 9), '45.1.0.40', 'ssh:bruteforce');           // O: neuer Account zaehlt halb -> nicht
many(array(1, 10), '45.1.0.41', 'ssh:bruteforce');          // O2: inaktiver Account zaehlt nicht
many(array(1, 2, 3), '45.1.0.50', 'generic:probe');         // P: nur Verbindungsaufbau, 3 Accounts
src(11, '45.1.0.60', 'generic:probe');                      // Account 11: Sensor vor 10 Tagen
src(4, '45.1.0.80', 'generic:probe');                       // Account 4: Sensor (seine IP ist Fall F)
src(1, '10.1.2.3', 'ssh:bruteforce'); src(2, '10.1.2.3', 'ssh:bruteforce');   // nicht oeffentlich (eigentlich schon von der API verworfen)

x("INSERT INTO hp_allowlist (cidr, ip_start, ip_end, reason, source, created_at) VALUES ('45.1.0.7/32', INET6_ATON('45.1.0.7'), INET6_ATON('45.1.0.7'), 'Test', 'manual', NOW())");
x("INSERT INTO hp_allowlist (cidr, ip_start, ip_end, reason, source, created_at) VALUES ('45.1.1.0/24', INET6_ATON('45.1.1.0'), INET6_ATON('45.1.1.255'), 'ipv64', 'infra', NOW())");
x("INSERT INTO hp_allowlist (cidr, ip_start, ip_end, reason, source, `until`, created_at) VALUES ('45.1.0.1/32', INET6_ATON('45.1.0.1'), INET6_ATON('45.1.0.1'), 'abgelaufen', 'manual', ?, NOW())", array(dt(1)));
x("INSERT INTO hp_release_requests (ip, ip_bin, reason, status, created_at, protected_until) VALUES ('45.1.0.8', INET6_ATON('45.1.0.8'), 'x', 'released', NOW(), ?)", array(dt(-20)));
x("INSERT INTO hp_release_requests (ip, ip_bin, reason, status, created_at, protected_until) VALUES ('45.1.0.9', INET6_ATON('45.1.0.9'), 'x', 'released', NOW(), ?)", array(dt(1)));
x("INSERT INTO subdomain_records (userid, domainname, content, type) VALUES (3, 'kunde.ipv64.net', '45.1.0.10', 'A'), (3, 'kunde.ipv64.net', '2A01:04F8:0001:0002:0000:0000:0000:0010', 'AAAA'),
	(3, 'alt.ipv64.net', '45.1.0.32', 'A')");
x("UPDATE subdomain_records SET deactivated = 1 WHERE domainname = 'alt.ipv64.net'"); // deaktiviert: zaehlt nicht
x("INSERT INTO cdn_server (name, hostname, ipv4, ipv6) VALUES ('t', 't', '45.1.0.11', '')");
// Alte Zeile, die nicht mehr im Fenster ist
x("INSERT INTO hp_scores (ip_bin, ip, family, score, first_seen, last_seen, listed, listed_since, reason, lists, updated_at) VALUES (INET6_ATON('45.1.0.13'), '45.1.0.13', 4, 80, ?, ?, 1, ?, 'threshold', 'v64,ssh', ?)",
	array(dt(20), dt(15), dt(20), dt(1)));

// ---------------------------------------------------------------- Bewertung
echo "Bewertung\n";
$o = scorer();
check('Lauf ohne Fehler', str_contains($o, 'hp_scores:') AND !preg_match('/Fehler|Warning|Notice|Deprecated/i', $o), $o);
echo preg_replace('/^/m', '        ', trim($o)) . "\n";
check('Schwelle unter 20 Accounts: 3 bzw. 2 mit Login/Exploit', str_contains($o, 'Schwelle: 3 bzw. 2 mit Login/Exploit'), $o);
$s = score('45.1.0.1');
check('A: 2 Accounts Login -> gelistet (abgelaufene Freigabe zaehlt nicht)', $s AND (int)$s['listed'] === 1 AND $s['reason'] === 'threshold' AND $s['lists'] === 'v64,ssh' AND $s['listed_since'] !== null, $s);
$s = score('45.1.0.2');
check('B: 2 Accounts Scan -> nicht gelistet', $s AND (int)$s['listed'] === 0 AND $s['reason'] === '' AND (int)$s['accounts'] === 2, $s);
$s = score('45.1.0.3');
check('C: 3 Accounts Scan -> gelistet, Teilliste scanner', $s AND (int)$s['listed'] === 1 AND $s['lists'] === 'v64,scanner', $s);
$s = score('45.1.0.4');
check('D: zwei Accounts im selben /24 zaehlen einmal', $s AND (int)$s['accounts'] === 1 AND (int)$s['listed'] === 0 AND (int)$s['sensors'] === 2, $s);
$s = score('45.1.0.5');
check('E: /24-Gruppe + weiterer Account = 2 -> gelistet', $s AND (int)$s['accounts'] === 2 AND (int)$s['listed'] === 1, $s);
check('F: Sensor-IP nie in hp_scores', score(sensor_ip(4)) === false);
check('nicht oeffentliche IP nie in hp_scores', score('10.1.2.3') === false);
$s = score('45.1.0.7');
check('G: Freigabe (hp_allowlist) -> nicht gelistet, reason allowlist', $s AND (int)$s['listed'] === 0 AND $s['reason'] === 'allowlist' AND $s['lists'] === '', $s);
$s = score('45.1.0.8');
check('H: Freigabe-Antrag geschuetzt -> allowlist', $s AND (int)$s['listed'] === 0 AND $s['reason'] === 'allowlist', $s);
$s = score('45.1.0.9');
check('H2: Schutz abgelaufen -> gelistet', $s AND (int)$s['listed'] === 1, $s);
$s = score('45.1.0.10');
check('I: Kunden-IP (A) -> customer_ip, nicht gelistet', $s AND (int)$s['listed'] === 0 AND $s['reason'] === 'customer_ip', $s);
$s = score('2a01:4f8:1:2::10');
check('I2: Kunden-IP (AAAA, andere Schreibweise) -> customer_ip', $s AND (int)$s['listed'] === 0 AND $s['reason'] === 'customer_ip' AND (int)$s['family'] === 6, $s);
check('deaktivierter Record zaehlt nicht (rdp gelistet)', (int)(score('45.1.0.32')['listed'] ?? 0) === 1);
$s = score('45.1.0.11');
check('J: Infrastruktur (cdn_server) -> infra', $s AND (int)$s['listed'] === 0 AND $s['reason'] === 'infra', $s);
$s = score('45.1.1.5');
check('J2: Infrastruktur (hp_allowlist source infra) -> infra', $s AND (int)$s['listed'] === 0 AND $s['reason'] === 'infra', $s);
$s = score('104.16.1.1');
check('K: Cloudflare -> cdn', $s AND (int)$s['listed'] === 0 AND $s['reason'] === 'cdn', $s);
check('L: 15 Tage alt -> nicht bewertet', score('45.1.0.12') === false);
check('L: alte gelistete Zeile ohne Treffer im Fenster entfernt', score('45.1.0.13') === false);
$s = score('45.1.0.14'); $a = score('45.1.0.1');
check('L2: 13 Tage alt -> noch gelistet, niedrigerer Wert', $s AND (int)$s['listed'] === 1 AND (int)$s['score'] < (int)$a['score'], array($s['score'] ?? null, $a['score'] ?? null));
$s = score('45.1.0.20');
check('M: Research 3 Accounts -> nur Liste research', $s AND (int)$s['listed'] === 1 AND $s['lists'] === 'research', $s);
$s = score('45.1.0.21');
check('M2: Research 2 Accounts -> nicht', $s AND (int)$s['listed'] === 0, $s);
check('N: web/mail/rdp', (score('45.1.0.30')['lists'] ?? '') === 'v64,web' AND (score('45.1.0.31')['lists'] ?? '') === 'v64,mail' AND (score('45.1.0.32')['lists'] ?? '') === 'v64,rdp',
	array(score('45.1.0.30')['lists'] ?? '', score('45.1.0.31')['lists'] ?? '', score('45.1.0.32')['lists'] ?? ''));
$s = score('45.1.0.40');
check('O: neuer Account zaehlt halb (1.5 < 2) -> nicht', $s AND (int)$s['listed'] === 0 AND (float)$s['strong_eff'] === 1.5, $s);
$s = score('45.1.0.41');
check('O2: inaktiver Account zaehlt nicht', $s AND (int)$s['listed'] === 0 AND (int)$s['accounts'] === 1, $s);
$s = score('45.1.0.50'); $c = score('45.1.0.3');
check('P: nur Verbindungsaufbau 3 Accounts -> gelistet, Wert < Scan < Login', $s AND (int)$s['listed'] === 1 AND (int)$s['score'] < (int)$c['score'] AND (int)$c['score'] < (int)score('45.1.0.5')['score'],
	array($s['score'] ?? null, $c['score'] ?? null));
check('Wert 0-100', (int)one("SELECT MAX(score) m FROM hp_scores")['m'] <= 100 AND (int)one("SELECT MIN(score) m FROM hp_scores")['m'] >= 0);
$since = score('45.1.0.1')['listed_since'];
sleep(1);
scorer();
check('zweiter Lauf: listed_since bleibt', score('45.1.0.1')['listed_since'] === $since);
check('--dry schreibt nichts', str_contains(cli("php $WEB/bots/blocklist/honeypot_score.php --dry"), 'DRY RUN'));

// ---------------------------------------------------------------- Generator
echo "Generator\n";
// fruehere Teillisten (bis 2026-10) liegen noch im Ordner: der Generator entfernt sie
@file_put_contents("$PUB/ipv64_blocklist_v64_ssh.txt", "1.2.3.4/32\n"); @file_put_contents("$PUB/v64_mikrotik_v4_v64_research.rsc", "x\n");
$o = gen();
check('voller Lauf ohne Fehler', str_contains($o, 'Fertig') AND !preg_match('/Warning|Notice|Deprecated|Fatal/i', $o), $o);
$v64 = lines("$PUB/ipv64_blocklist_v64.txt");
$expect = array('45.1.0.1/32', '45.1.0.3/32', '45.1.0.5/32', '45.1.0.9/32', '45.1.0.14/32', '45.1.0.30/32', '45.1.0.31/32', '45.1.0.32/32', '45.1.0.50/32', '2a02:1::5/128');
sort($expect);
$got = $v64; sort($got);
check('Tagesstand v64 = erwartete IPs', $got === $expect, $v64);
check('research nicht in v64', !in_array('45.1.0.20/32', $v64, true));
$old = array_merge(glob("$PUB/*v64_*") ?: array(), glob("$LIVE/*v64_*") ?: array());
$old = array_filter($old, fn($f) => preg_match('/v64_(ssh|web|mail|rdp|scanner|research)\./', $f));
check('keine Teillisten mehr (alte Dateien entfernt)', !$old, array_map('basename', $old));
check('v4/v6 getrennt', lines("$PUB/ipv64_blocklist_v6_v64.txt") === array('2a02:1::5/128') AND count(lines("$PUB/ipv64_blocklist_v4_v64.txt")) === 9);
$mk = (string)@file_get_contents("$PUB/v64_mikrotik_v4_v64.rsc");
check('MikroTik Listenname IPv64-v64', str_contains($mk, 'remove [find list=IPv64-v64 ') AND str_contains($mk, 'add list=IPv64-v64 address=45.1.0.1/32'), substr($mk, 0, 300));
check('Live-Fassung im nicht oeffentlichen Ordner', lines("$LIVE/ipv64_blocklist_v64.txt") === $v64 AND is_file("$LIVE/v64_mikrotik_v6_v64.rsc"));
$all = lines("$PUB/ipv64_blocklist_all.txt");
check('v64 nicht in all / all_notor', !in_array('45.1.0.1/32', $all, true) AND !in_array('45.1.0.1/32', lines("$PUB/ipv64_blocklist_all_notor.txt"), true) AND in_array('5.6.7.8/32', $all, true), $all);
$idx = json_decode((string)@file_get_contents("$PUB/index.json"), true);
$hp = array_values(array_filter($idx['lists'] ?? array(), fn($e) => ($e['category'] ?? '') === 'honeypot'));
check('index.json: 1 Eintrag Kategorie honeypot (nur v64), in_all false', count($hp) === 1 AND !array_filter($hp, fn($e) => $e['in_all'] !== false), array_column($hp, 'id'));
$e = $hp[0] ?? array();
check('index.json: v64 mit Anzahl, Lizenz, Dateien, live', ($e['id'] ?? '') === 'v64' AND $e['count'] === 10 AND $e['count_v4'] === 9 AND $e['count_v6'] === 1 AND $e['license'] !== ''
	AND ($e['files']['mikrotik_v4'] ?? '') === 'v64_mikrotik_v4_v64.rsc' AND $e['live'] === true, $e);
check('index.json: Live-Adresse', ($idx['live']['base'] ?? '') === 'https://ipv64.net/blocklists/live/{token}/', $idx['live'] ?? null);
$ok = true; foreach($hp as $x) { foreach($x['files'] as $f) { if(!is_file("$PUB/$f")) { $ok = false; } } }
check('index.json: jede genannte v64-Datei existiert', $ok);

// neue IP gelistet: Live sofort, Tagesstand erst am naechsten UTC-Tag
many(array(1, 2), '45.1.0.70', 'ssh:bruteforce');
scorer();
$o = gen('--only=v64');
check('--only=v64 ohne Fehler', str_contains($o, 'Fertig (nur v64)') AND str_contains($o, 'index.json: 1 v64-Listen'), $o);
check('Live enthaelt neue IP', in_array('45.1.0.70/32', lines("$LIVE/ipv64_blocklist_v64.txt"), true));
check('Tagesstand noch ohne neue IP (gleicher UTC-Tag)', !in_array('45.1.0.70/32', lines("$PUB/ipv64_blocklist_v64.txt"), true));
$idx2 = json_decode((string)@file_get_contents("$PUB/index.json"), true);
check('index.json nach --only=v64: andere Listen unveraendert, honeypot einmal', count($idx2['lists']) === count($idx['lists']) AND $idx2['combined'] === $idx['combined']);
touch("$PUB/ipv64_blocklist_v64.txt", time() - 86400 - 60);
gen('--only=v64');
check('Tagesstand am naechsten Tag mit neuer IP', in_array('45.1.0.70/32', lines("$PUB/ipv64_blocklist_v64.txt"), true));
// Freigabe wirkt im Live-Stand mit dem naechsten Lauf
x("INSERT INTO hp_allowlist (cidr, ip_start, ip_end, reason, source, created_at) VALUES ('45.1.0.70/32', INET6_ATON('45.1.0.70'), INET6_ATON('45.1.0.70'), 'Test', 'request', NOW())");
scorer(); gen('--only=v64');
check('Freigabe: Live sofort ohne IP, Tagesstand noch mit', !in_array('45.1.0.70/32', lines("$LIVE/ipv64_blocklist_v64.txt"), true) AND in_array('45.1.0.70/32', lines("$PUB/ipv64_blocklist_v64.txt"), true));

// ---------------------------------------------------------------- live.php
echo "live.php\n";
function tok(int $u): string { $t = substr(str_repeat(sprintf('Tok%02dAbC', $u), 6), 0, 32); x("INSERT INTO hp_list_tokens (userid, token, created_at) VALUES (?, ?, NOW())", array($u, $t)); return $t; }
$T1 = tok(1); $T2 = tok(2); $T8 = tok(8); $T11 = tok(11); $T10 = tok(10);
$r = req('GET', "/blocklists/live/$T1/ipv64_blocklist_v64.txt");
check('Beitragender (Standard, Sensor aktiv): 200 live', $r['code'] === 200 AND ($r['h']['x-ipv64-list'] ?? '') === 'live' AND $r['body'] === file_get_contents("$LIVE/ipv64_blocklist_v64.txt"), $r['code'] . ' ' . json_encode($r['h']));
$etag = $r['h']['etag'] ?? '';
check('ETag und Last-Modified gesetzt', $etag !== '' AND isset($r['h']['last-modified']));
check('last_used gesetzt', one("SELECT last_used FROM hp_list_tokens WHERE userid = 1")['last_used'] !== null);
$r = req('GET', "/blocklists/live/$T1/ipv64_blocklist_v64.txt");
check('gleiche Datei sofort wieder (zweite Node desselben Accounts): 200', $r['code'] === 200, $r['code'] . ' ' . json_encode($r['h']));
$r = req('GET', "/blocklists/live/$T1/ipv64_blocklist_v64.txt", array("If-None-Match: $etag"));
check('mit passendem ETag: 304', $r['code'] === 304 AND $r['body'] === '', $r['code']);
$r = req('GET', "/blocklists/live/$T1/v64_mikrotik_v4_v64.rsc");
check('andere Datei: 200', $r['code'] === 200 AND str_contains($r['body'], 'IPv64-v64 '), $r['code']);
$r = req('GET', "/blocklists/live/$T1/ipv64_blocklist_v64_ssh.txt");
check('fruehere Teilliste: 404 Unknown list file', $r['code'] === 404 AND str_contains($r['body'], 'Unknown list file'), $r['code']);
x("UPDATE hp_list_token_files SET last_at = ? WHERE userid = 1", array(gmdate('Y-m-d H:i:s', time() - 301)));
$r = req('GET', "/blocklists/live/$T1/ipv64_blocklist_v64.txt");
check('nach 5 Minuten wieder 200', $r['code'] === 200, $r['code']);
x("UPDATE hp_list_tokens SET uses_window_start = ?, uses_in_window = 60 WHERE userid = 1", array(gmdate('Y-m-d H:i:s', time() - 10)));
$r = req('GET', "/blocklists/live/$T1/ipv64_blocklist_v6_v64.txt");
check('Obergrenze 60 Abrufe je 5 Minuten: 429', $r['code'] === 429 AND (int)($r['h']['retry-after'] ?? 0) > 0, $r['code']);
$r = req('GET', "/blocklists/live/$T2/ipv64_blocklist_v64.txt");
check('Klasse VIP: live', $r['code'] === 200 AND ($r['h']['x-ipv64-list'] ?? '') === 'live' AND str_contains($r['body'], '45.1.0.1/32') AND !str_contains($r['body'], '45.1.0.70/32'), $r['code']);
$r = req('GET', "/blocklists/live/$T8/ipv64_blocklist_v64.txt");
check('Standard ohne Sensor: Tagesstand (200, X-IPv64-List daily)', $r['code'] === 200 AND ($r['h']['x-ipv64-list'] ?? '') === 'daily' AND $r['body'] === file_get_contents("$PUB/ipv64_blocklist_v64.txt"), $r['code'] . ' ' . json_encode($r['h']));
$r = req('GET', "/blocklists/live/$T11/ipv64_blocklist_v4_v64.txt");
check('Standard, Sensor zuletzt vor 10 Tagen: daily', $r['code'] === 200 AND ($r['h']['x-ipv64-list'] ?? '') === 'daily', $r['code']);
x("UPDATE users SET user_class = 3 WHERE id = 11");
$r = req('GET', "/blocklists/live/$T11/ipv64_blocklist_v6_v64.txt");
check('Klasse geaendert: beim naechsten Abruf live', ($r['h']['x-ipv64-list'] ?? '') === 'live', $r['code']);
$r = req('GET', "/blocklists/live/$T10/ipv64_blocklist_v64.txt");
check('inaktiver Account: 404', $r['code'] === 404, $r['code']);
$r = req('GET', '/blocklists/live/' . str_repeat('Z', 32) . '/ipv64_blocklist_v64.txt');
check('unbekanntes Token: 404', $r['code'] === 404, $r['code']);
$r = req('GET', '/blocklists/live/' . strtolower($T1) . '/ipv64_blocklist_v4_v64.txt');
check('Token in anderer Gross-/Kleinschreibung: 404', $r['code'] === 404, $r['code']);
$r = req('GET', '/blocklists/live.php?t=' . substr($T1, 0, 31) . '-&f=ipv64_blocklist_v4_v64.txt');
check('Token mit "-": 404', $r['code'] === 404, $r['code']);
$r = req('GET', "/blocklists/live.php?t=$T2&f=ipv64_blocklist_all.txt");
check('Datei ausserhalb der v64-Liste: 404', $r['code'] === 404 AND str_contains($r['body'], 'Unknown list file'), $r['code']);
foreach(array('../../dbconnect.php', '../private/blocklists_live/ipv64_blocklist_v64.txt', '..%2F..%2Fdbconnect.php', '/etc/passwd', 'ipv64_blocklist_v64.txt%00.php', 'ipv64_blocklist_v64.txt/') as $f) {
	$r = req('GET', "/blocklists/live.php?t=$T2&f=" . (str_contains($f, '%') ? $f : rawurlencode($f)));
	check("Traversal f=$f: 404", $r['code'] === 404 AND !str_contains($r['body'], 'PDO') AND !str_contains($r['body'], 'root:'), $r['code']);
}
$r = req('GET', "/blocklists/live/$T2/..%2F..%2Fdbconnect.php");
check('Traversal im Pfad: 404', $r['code'] === 404, $r['code']);
$r = req('POST', "/blocklists/live/$T2/ipv64_blocklist_v4_v64.txt");
check('POST: 405', $r['code'] === 405, $r['code']);
$r = req('GET', "/blocklists/live/$T2/ipv64_blocklist_v4_v64.txt");
check('Antwort text/plain, kein Cache oeffentlich', str_starts_with($r['h']['content-type'] ?? '', 'text/plain') AND str_contains($r['h']['cache-control'] ?? '', 'private'), $r['h']);

// ---------------------------------------------------------------- token.php, Seiten
echo "token.php und Seiten\n";
$r = req('GET', '/honeypot/token.php?as=0');
check('abgemeldet: Hinweis', str_contains($r['body'], 'Bitte zuerst anmelden'));
$r = req('GET', '/honeypot/token.php?as=4');
check('ohne Token: Knopf erzeugen, Stand Live (Beitragender)', str_contains($r['body'], 'Token erzeugen') AND str_contains($r['body'], 'badge-success">Live'), substr($r['body'], 0, 400));
preg_match('/name="csrf" value="([0-9a-f]{32})"/', $r['body'], $m); $csrf = $m[1] ?? '';
$cookie = 'Cookie: ' . implode('; ', $r['cookies']);
$r = req('POST', '/honeypot/token.php?as=4', array($cookie, 'Content-Type: application/x-www-form-urlencoded'), http_build_query(array('csrf' => 'falsch', 'action' => 'new')));
check('ohne gueltiges CSRF-Token: nichts angelegt', str_contains($r['body'], 'Sitzung abgelaufen') AND one("SELECT * FROM hp_list_tokens WHERE userid = 4") === false);
$r = req('POST', '/honeypot/token.php?as=4', array($cookie, 'Content-Type: application/x-www-form-urlencoded'), http_build_query(array('csrf' => $csrf, 'action' => 'new')));
$t4 = one("SELECT token FROM hp_list_tokens WHERE userid = 4")['token'] ?? '';
check('Token erzeugt: 32 Zeichen [A-Za-z0-9]', preg_match('/^[A-Za-z0-9]{32}$/', $t4) === 1, $t4);
check('Token maskiert angezeigt, Adressen maskiert', str_contains($r['body'], 'type="password"') AND str_contains($r['body'], 'https://ipv64.net/blocklists/live/' . substr($t4, 0, 4) . '••••••••/ipv64_blocklist_v64.txt'));
$r2 = req('GET', "/blocklists/live/$t4/ipv64_blocklist_v64.txt");
check('neues Token funktioniert', $r2['code'] === 200, $r2['code']);
$r = req('POST', '/honeypot/token.php?as=4', array($cookie, 'Content-Type: application/x-www-form-urlencoded'), http_build_query(array('csrf' => $csrf, 'action' => 'new')));
$t4b = one("SELECT token FROM hp_list_tokens WHERE userid = 4")['token'] ?? '';
check('neu erzeugen widerruft das alte', $t4b !== $t4 AND preg_match('/^[A-Za-z0-9]{32}$/', $t4b) === 1 AND req('GET', "/blocklists/live/$t4/ipv64_blocklist_v4_v64.txt")['code'] === 404);
check('neu erzeugen setzt Abrufsperre zurueck', req('GET', "/blocklists/live/$t4b/ipv64_blocklist_v64.txt")['code'] === 200);
$r = req('POST', '/honeypot/token.php?as=4', array($cookie, 'Content-Type: application/x-www-form-urlencoded'), http_build_query(array('csrf' => $csrf, 'action' => 'delete')));
check('loeschen', one("SELECT * FROM hp_list_tokens WHERE userid = 4") === false AND req('GET', "/blocklists/live/$t4b/ipv64_blocklist_v4_v64.txt")['code'] === 404);
$r = req('GET', '/honeypot/token.php?as=8');
check('Standard ohne Sensor: Hinweis Tagesstand', str_contains($r['body'], 'badge-secondary">Tagesstand'));
$r = req('GET', '/honeypot/index.php?as=1');
check('honeypot/index.php: Karte Live-Listen mit Link', $r['code'] === 200 AND str_contains($r['body'], 'href="/honeypot/token.php"'), $r['code']);
$r = req('GET', '/v64_blocklists.php');
check('Listenseite: Zeile v64 Blocklist (Honeypot64) statt Coming soon', $r['code'] === 200 AND str_contains($r['body'], 'v64 Blocklist (Honeypot64)') AND !str_contains($r['body'], 'Coming soon')
	AND !str_contains($r['body'], 'ipv64_blocklist_v64_research.txt') AND !str_contains($r['body'], 'Sub-lists') AND str_contains($r['body'], '/honeypot/token.php'), substr($r['body'], 0, 300));

// ---------------------------------------------------------------- Schwelle ab 20 aktiven Accounts
echo "Schwelle ab 20 aktiven Accounts\n";
for($u = 21; $u <= 40; $u++) { x("INSERT INTO users (id, email, reg_date) VALUES (?, ?, ?)", array($u, "u$u@test", date('Y-m-d H:i:s', time() - 30 * 86400))); src($u, "46.0.0.$u", 'generic:probe'); }
$o = scorer();
check('Schwelle 3 (20-200 Accounts)', preg_match('/Aktive Accounts \(7 Tage\): (\d+).*Schwelle: 3\n/', $o, $m) === 1 AND (int)$m[1] >= 20, $o);
check('A: 2 Accounts Login reichen nicht mehr', (int)score('45.1.0.1')['listed'] === 0);
check('C: 3 Accounts weiter gelistet', (int)score('45.1.0.3')['listed'] === 1);

echo "\n$pass ok, $failed Fehler\n";
exit($failed > 0 ? 1 : 0);
