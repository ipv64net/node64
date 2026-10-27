<?php
/**
 * Pruefung "Herkunft der Angreifer" (Teil ipv64) in der Testumgebung hp7g-* (run_agentbox.sh): country_ranges.txt.gz
 * und index.json "geo" (create_blocklists_v2.php), hp_scores.country (bots/blocklist/honeypot_score.php), IP-Auskunft
 * (GET /threat/ip, honeypot/ip.php), Rangliste nach Land (hp_stats_lib.php, GET /threat/stats, honeypot/stats.php).
 * --real: zusaetzlich echte RIR-Daten (read_countries_rir.php), Groesse und Laufzeit.
 *
 *   HP7GTEST=1 php run_tests.php http://127.0.0.1:8080 /var/www/clients/client1/web58/web [--real]
 */
if(php_sapi_name() !== 'cli' OR getenv('HP7GTEST') !== '1') { exit; }

$BASE = rtrim($argv[1] ?? 'http://127.0.0.1:8080', '/');
$WEB = rtrim($argv[2] ?? '/var/www/clients/client1/web58/web', '/');
$REAL = in_array('--real', $argv, true);
const SQLF = '/w/sql/datenbank.sql';

$db = new PDO('mysql:host=hp7g-db;dbname=ipv64', 'root', 'hp7gtest', array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8mb4'"));
$pass = 0; $failed = 0;

function check(string $name, bool $ok, $info = ''): void {
	global $pass, $failed;
	if($ok) { $pass++; echo "  ok    $name\n"; }
	else { $failed++; echo "  FEHLER $name " . (is_string($info) ? substr($info, 0, 900) : substr(json_encode($info, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), 0, 900)) . "\n"; }
}
function req(string $method, string $path, array $o = array()): array {
	global $BASE;
	$h = array('X-Forwarded-For: ' . ($o['ip'] ?? '84.200.9.9'));
	if(isset($o['key'])) { $h[] = 'Authorization: Bearer ' . $o['key']; }
	$ctx = stream_context_create(array('http' => array('method' => $method, 'header' => implode("\r\n", $h), 'ignore_errors' => true, 'timeout' => 120)));
	$raw = @file_get_contents($BASE . $path, false, $ctx);
	$code = 0;
	foreach($http_response_header ?? array() as $l) { if(preg_match('#^HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; } }
	return array('code' => $code, 'j' => json_decode((string)$raw, true), 'raw' => (string)$raw);
}
function api(string $method, string $path, array $o = array()): array { return req($method, '/api_v2.php' . $path, $o); }
function x(string $sql, array $p = array()) { global $db; $st = $db->prepare($sql); $st->execute($p); return $st; }
function one(string $sql, array $p = array()) { $r = x($sql, $p)->fetch(PDO::FETCH_ASSOC); return $r === false ? null : $r; }
function all(string $sql, array $p = array()): array { return x($sql, $p)->fetchAll(PDO::FETCH_ASSOC); }
function code(array $r): string { return $r['code'] . ' ' . substr($r['raw'], 0, 600); }
function dt(float $daysAgo): string { return gmdate('Y-m-d H:i:s', (int)(time() - $daysAgo * 86400)); }
function cli(string $cmd): string { global $WEB; return (string)shell_exec("cd " . escapeshellarg($WEB) . " && HP7GTEST=1 $cmd 2>&1"); }
function gen(string $a = ''): string { global $WEB; return cli("php -d auto_prepend_file=/tmp/hp7g_peak.php $WEB/bots/blocklist/create_blocklists_v2.php $a"); }
function scorer(): string { global $WEB; return cli("php -d auto_prepend_file=/tmp/hp7g_peak.php $WEB/bots/blocklist/honeypot_score.php"); }
function clean_out(string $o): bool { return !preg_match('/Fatal|Warning|Notice|Deprecated|Parse error/i', $o); }
function page_ok(string $h): bool { return $h !== '' AND !preg_match('/<b>(Warning|Fatal error|Notice|Deprecated)<\/b>|Uncaught|Stack trace/i', $h); }
/** Bewertungsdaten direkt (wie H6-Test): Account $u meldet $ip */
$repNo = 0;
function src(int $u, string $ip, string $kind = 'ssh:bruteforce'): void {
	global $repNo;
	$sid = sprintf('00000000-0000-4000-8000-%012d', $u); $sip = "84.210.$u.10"; $seen = dt(0.05); $day = substr($seen, 0, 10);
	x("INSERT INTO hp_sensors (sensor_id, userid, version, profile, mode, first_seen, last_seen, last_ip) VALUES (?, ?, '0.14.0', 'standard', 'headless', ?, ?, ?)
		ON DUPLICATE KEY UPDATE last_seen = VALUES(last_seen)", array($sid, $u, dt(30), dt(0.01), $sip));
	$repNo++;
	x("INSERT INTO hp_reports (day, report_id, sensor_id, userid, period_start, period_end, received_at, sources, ip) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
		array($day, "$sid-$repNo", $sid, $u, $seen, $seen, $seen, $sip));
	$ref = (int)x("SELECT LAST_INSERT_ID()")->fetchColumn();
	x("INSERT INTO hp_report_sources (day, report_ref, userid, sensor_id, ip, ip_bin, kind, service, port, `count`, first_seen, last_seen, source) VALUES (?, ?, ?, ?, ?, INET6_ATON(?), ?, 'ssh', 22, 3, ?, ?, 'honeypot')",
		array($day, $ref, $u, $sid, $ip, $ip, $kind, $seen, $seen));
}
function countries(): array { $o = array(); foreach(all("SELECT ip, country FROM hp_scores ORDER BY ip") as $r) { $o[$r['ip']] = $r['country']; } return $o; }
/** Zeilen ohne Kommentar aus der gz-Datei */
function gz_lines(string $f): array { return array_values(array_filter(explode("\n", (string)gzdecode((string)file_get_contents($f))), fn($l) => $l !== '' AND $l[0] !== '#')); }
function peak(string $o): string { return preg_match('/PEAK (\d+)/', $o, $m) ? round($m[1] / 1048576) . ' MB' : '?'; }
file_put_contents('/tmp/hp7g_peak.php', '<?php register_shutdown_function(function() { echo "\nPEAK " . memory_get_peak_usage(true) . "\n"; });');

$GZ = "$WEB/blocklists/country_ranges.txt.gz"; $IDX = "$WEB/blocklists/index.json";

// ---------------------------------------------------------------- SQL und Einbindung
echo "SQL und Einbindung\n";
$col = one("SHOW COLUMNS FROM hp_scores WHERE Field = 'country'");
check('hp_scores.country char(2) NULL (datenbank.sql zweimal eingespielt)', ($col['Type'] ?? '') === 'char(2)' AND ($col['Null'] ?? '') === 'YES', $col);
$api = (string)file_get_contents("$WEB/api_v2.php");
check('api_v2.php: nur die vier live vorhandenen require-Zeilen', substr_count($api, "require __DIR__ . '/api_v2_") === 4 AND str_contains($api, 'api_v2_threat_watch.php'));
$o = cli("php $WEB/bots/honeypot_cron.php --list");
check('kein neuer Cron-Job noetig (HPC_JOBS unveraendert: score mit --only=v64)', str_contains($o, 'honeypot_score.php') AND str_contains($o, '--only=v64'), $o);

// ---------------------------------------------------------------- Generator
echo "Generator (kleiner RIR-Testdatensatz)\n";
$o = gen('--only=v64');
check('--only=v64 schreibt keine country_ranges.txt.gz', !is_file($GZ) AND clean_out($o), $o);
// kein DB-IP-Abruf aus dem Test: frischer Versuchs-Stempel im Zwischenspeicher (geo_dbip.php) -> Laenderdaten aus RIR
@mkdir(dirname($WEB) . '/private/geo', 0777, true); touch(dirname($WEB) . '/private/geo/last_try');
$t = microtime(true); $o = gen(); $dt = microtime(true) - $t;
check('voller Lauf ohne PHP-Fehler, Zeile "Herkunft"', clean_out($o) AND preg_match('/Herkunft\s+7 Bereiche \(v4\s+5, v6\s+2\)/', $o), $o);
echo "        (voller Lauf " . round($dt, 2) . " s, Speicher " . peak($o) . ")\n";
check('country_ranges.txt.gz vorhanden, gzip, 0644', is_file($GZ) AND substr((string)file_get_contents($GZ), 0, 2) === "\x1f\x8b" AND (fileperms($GZ) & 0777) === 0644, @decoct(fileperms($GZ)));
$txt = (string)gzdecode((string)file_get_contents($GZ));
$head = array_values(array_filter(explode("\n", $txt), fn($l) => $l !== '' AND $l[0] === '#'));
check('Kopfzeilen mit # am Anfang (4), Datei endet mit Zeilenumbruch', count($head) === 4 AND str_starts_with($txt, '# IPv64.net country ranges') AND str_ends_with($txt, "\n") AND str_contains($head[3], 'Ranges: 7'), $head);
$want = array('CN 1.0.1.0 1.0.3.255', 'DE 5.1.0.0 5.1.3.255', 'NL 5.1.4.0 5.1.7.255', 'DE 5.1.8.0 5.1.8.255', 'US 8.0.0.0 8.255.255.255',
	'DE 2001:678:: 2001:687:ffff:ffff:ffff:ffff:ffff:ffff', 'CN 240e:: 240e:fff:ffff:ffff:ffff:ffff:ffff:ffff');
$got = gz_lines($GZ);
check('Bereiche: zusammengefasst, sortiert, v4 vor v6, Ueberlappung/nicht routbar/ungueltiger Code raus, Klein-Code gross', $got === $want, $got);
$ok = true;
foreach($got as $l) { if(!preg_match('/^[A-Z]{2} \S+ \S+$/', $l)) { $ok = false; } [, $a, $b] = explode(' ', $l); if(strcmp(inet_pton($a), inet_pton($b)) > 0) { $ok = false; } }
check('Format je Zeile "<CC> <erste IP> <letzte IP>", erste <= letzte', $ok);
$idx = json_decode((string)file_get_contents($IDX), true);
$g = $idx['geo'] ?? null;
check('index.json "geo": file, updated (RFC 3339), ranges, source (RIR ohne DB-IP-Datei)', is_array($g) AND $g['file'] === 'country_ranges.txt.gz' AND $g['ranges'] === 7
	AND DateTime::createFromFormat(DATE_RFC3339, (string)$g['updated']) !== false AND count($g) === 4 AND str_starts_with((string)($g['source'] ?? ''), 'RIR'), $g);
check('index.json: Laender und Listen weiter da', count($idx['countries'] ?? array()) >= 4 AND isset($idx['lists']), array_keys($idx));
$m1 = filemtime($GZ); sleep(1);
$o = gen('--only=v64'); clearstatcache();
$idx2 = json_decode((string)file_get_contents($IDX), true);
check('--only=v64 danach: Datei unveraendert, "geo" bleibt in index.json', filemtime($GZ) === $m1 AND ($idx2['geo'] ?? null) === $g AND clean_out($o), $o);
$o = gen('--dry'); clearstatcache();
check('--dry schreibt nichts', filemtime($GZ) === $m1 AND str_contains($o, 'Herkunft'), $o);

// ---------------------------------------------------------------- Bewertung
echo "Bewertung (hp_scores.country)\n";
// gelistet (2 Accounts mit Login): DE x3 (davon IPv6), US (liegt im ueberlappenden CN-Netz), CN, NL, unbekannt; nur 1 Account: DE (nicht gelistet)
foreach(array('5.1.2.7', '5.1.3.200', '2001:680::1', '8.8.8.8', '1.0.2.3', '5.1.5.5', '45.9.1.1') as $ip) { src(5, $ip); src(6, $ip); }
src(7, '5.1.8.8');
$db->exec("ALTER TABLE hp_scores DROP COLUMN country");
$o = scorer();
check('ohne Spalte country: Warnung, Bewertung laeuft trotzdem', str_contains($o, 'Warnung: Herkunft nicht geschrieben') AND (int)one("SELECT COUNT(*) n FROM hp_scores")['n'] === 8 AND !preg_match('/Fatal|PHP Warning/', $o), $o);
$db->exec((string)file_get_contents(SQLF));
rename($GZ, "$GZ.off");
$o = scorer();
rename("$GZ.off", $GZ);
check('ohne country_ranges.txt.gz: Hinweis, kein Fehler', str_contains($o, 'country_ranges.txt.gz fehlt') AND clean_out($o), $o);
$t = microtime(true); $o = scorer(); $dt = microtime(true) - $t;
$c = countries();
$wantC = array('1.0.2.3' => 'CN', '2001:680::1' => 'DE', '45.9.1.1' => null, '5.1.2.7' => 'DE', '5.1.3.200' => 'DE', '5.1.5.5' => 'NL', '5.1.8.8' => 'DE', '8.8.8.8' => 'US');
ksort($c); ksort($wantC);
check('country gefuellt (v4, v6, Ueberlappung, unbekannt = NULL, auch nicht gelistete IPs)', $c === $wantC, $c);
check('Ausgabe "7 von 8 IPs mit Land, 7 geaendert"', str_contains($o, 'Herkunft: 7 von 8 IPs mit Land, 7 geaendert') AND clean_out($o), $o);
echo "        (Bewertung " . round($dt, 2) . " s)\n";
$o = scorer();
check('zweiter Lauf: nichts geaendert', str_contains($o, '7 von 8 IPs mit Land, 0 geaendert'), $o);
x("UPDATE hp_scores SET country = 'ZZ' WHERE ip = '5.1.2.7'"); x("UPDATE hp_scores SET country = 'DE' WHERE ip = '45.9.1.1'");
$o = scorer();
check('falsches Land wird korrigiert, unbekannt wieder NULL', str_contains($o, '2 geaendert') AND countries()['5.1.2.7'] === 'DE' AND countries()['45.9.1.1'] === null, $o);
check('gelistet: 7 IPs mit v64', (int)one("SELECT COUNT(*) n FROM hp_scores WHERE listed = 1 AND FIND_IN_SET('v64', lists)")['n'] === 7, all("SELECT ip, listed, lists, reason FROM hp_scores"));

// ---------------------------------------------------------------- IP-Auskunft
echo "IP-Auskunft\n";
$r = api('GET', '/threat/ip/5.1.2.7');
check('GET /threat/ip/5.1.2.7: country DE', $r['code'] === 200 AND ($r['j']['data']['country'] ?? null) === 'DE' AND ($r['j']['data']['listed'] ?? null) === true, code($r));
$r = api('GET', '/threat/ip/2001:680::1', array('ip' => '84.200.9.10'));
check('GET /threat/ip/2001:680::1: country DE', $r['code'] === 200 AND ($r['j']['data']['country'] ?? null) === 'DE', code($r));
$r = api('GET', '/threat/ip/45.9.1.1', array('ip' => '84.200.9.11'));
check('GET /threat/ip/45.9.1.1 (gelistet, Land unbekannt): country null', $r['code'] === 200 AND array_key_exists('country', $r['j']['data'] ?? array()) AND $r['j']['data']['country'] === null, code($r));
$r = api('GET', '/threat/ip/5.1.8.8', array('ip' => '84.200.9.12'));
check('nicht gelistete IP: kein Land (keine Details)', $r['code'] === 200 AND ($r['j']['data']['listed'] ?? null) === false AND array_key_exists('country', $r['j']['data']) AND $r['j']['data']['country'] === null, code($r));
$h = req('GET', '/honeypot/ip.php?ip=8.8.8.8', array('ip' => '84.200.9.13'))['raw'];
check('ip.php?ip=8.8.8.8 zeigt Herkunft US', page_ok($h) AND preg_match('#Herkunft</th><td>US</td>#', $h), substr($h, 0, 600));

// ---------------------------------------------------------------- Statistik
echo "Statistik (Rangliste nach Land)\n";
x("DELETE FROM hp_stats_cache");
$r = api('GET', '/threat/stats');
$tc = $r['j']['data']['top']['countries'] ?? null;
check('GET /threat/stats: top.countries DE 3, dann CN, NL, US (nur gelistete v64-IPs, ohne unbekannt)', $r['code'] === 200 AND $tc === array(
	array('country' => 'DE', 'ips' => 3, 'events' => 18), array('country' => 'CN', 'ips' => 1, 'events' => 6), array('country' => 'NL', 'ips' => 1, 'events' => 6), array('country' => 'US', 'ips' => 1, 'events' => 6)), code($r));
// mehr Laender: 14 weitere (direkt, nur fuer die Rangliste); alte Sichtung (40 Tage) und research zaehlen nicht
$i = 0;
foreach(array('FR', 'GB', 'IT', 'ES', 'PL', 'RU', 'BR', 'IN', 'JP', 'KR', 'VN', 'TR', 'ID', 'AR') as $cc) {
	$i++;
	x("INSERT INTO hp_scores (ip_bin, ip, family, score, accounts, events, lists, first_seen, last_seen, listed, reason, updated_at, country) VALUES (INET6_ATON(?), ?, 4, 50, 2, ?, 'v64,ssh', ?, ?, 1, 'threshold', ?, ?)",
		array("31.0.$i.1", "31.0.$i.1", $i, dt(1), dt(1), dt(0), $cc));
}
x("INSERT INTO hp_scores (ip_bin, ip, family, score, accounts, events, lists, first_seen, last_seen, listed, reason, updated_at, country) VALUES (INET6_ATON('31.1.0.1'), '31.1.0.1', 4, 50, 2, 99, 'v64', ?, ?, 1, 'threshold', ?, 'FR')", array(dt(45), dt(40), dt(0)));
x("INSERT INTO hp_scores (ip_bin, ip, family, score, accounts, events, lists, first_seen, last_seen, listed, reason, updated_at, country) VALUES (INET6_ATON('31.1.0.2'), '31.1.0.2', 4, 50, 2, 99, 'research', ?, ?, 1, 'threshold', ?, 'FR')", array(dt(1), dt(1), dt(0)));
x("DELETE FROM hp_stats_cache");
$r = api('GET', '/threat/stats', array('ip' => '84.200.9.14'));
$tc = $r['j']['data']['top']['countries'] ?? array();
check('GET /threat/stats: Top 10, FR mit 1 IP (40 Tage alt und research nicht gezaehlt)', $r['code'] === 200 AND count($tc) === 10 AND $tc[0]['country'] === 'DE'
	AND in_array(array('country' => 'AR', 'ips' => 1, 'events' => 14), $tc, true) AND !in_array('FR', array_column($tc, 'country'), true), $tc);
$o = json_decode((string)one("SELECT data FROM hp_stats_cache WHERE name = 'overview'")['data'], true);
check('Cache: alle 18 Laender, FR 1 IP', count($o['top']['countries'] ?? array()) === 18 AND in_array(array('country' => 'FR', 'ips' => 1, 'events' => 1), $o['top']['countries'], true), $o['top']['countries'] ?? null);
$h = req('GET', '/honeypot/stats.php')['raw'];
check('stats.php (Ueberblick): rendert, Flaggen-Emoji, 10 Balken', page_ok($h) AND str_contains($h, 'Herkunft nach Land') AND str_contains($h, "\u{1F1E9}\u{1F1EA}") AND str_contains($h, "\u{1F1EB}\u{1F1F7}") === false
	AND substr_count($h, 'background:hsl(') === 10 AND str_contains($h, 'hsl(0,80%,50%)'), substr($h, 0, 600));
$h = req('GET', '/honeypot/stats.php?as=2&lang=en')['raw'];
check('stats.php (VIP, englisch): alle 18 Laender, CSV-Link', page_ok($h) AND str_contains($h, 'Origin by country') AND substr_count($h, 'background:hsl(') === 18 AND str_contains($h, 'export=countries'), substr($h, 0, 600));
$h = req('GET', '/honeypot/stats.php?as=2&export=countries')['raw'];
$lines = explode("\n", trim($h));
check('CSV-Export countries (VIP)', $lines[0] === 'country,ips,events' AND count($lines) === 19 AND $lines[1] === 'DE,3,18', $lines);
$h = req('GET', '/honeypot/stats.php?as=1&export=countries')['raw'];
check('CSV-Export fuer Standard: kein CSV', !str_starts_with($h, 'country,ips') AND page_ok($h), substr($h, 0, 300));
// Cache aus der Zeit vor der Herkunft (ohne top.countries)
$o = json_decode((string)one("SELECT data FROM hp_stats_cache WHERE name = 'overview'")['data'], true);
unset($o['top']['countries']);
x("UPDATE hp_stats_cache SET data = ?, updated_at = ? WHERE name = 'overview'", array(json_encode($o), gmdate('Y-m-d H:i:s')));
$r = api('GET', '/threat/stats', array('ip' => '84.200.9.15'));
$h = req('GET', '/honeypot/stats.php')['raw'];
check('alter Cache ohne countries: API liefert [], Seite "Noch keine Daten"', $r['code'] === 200 AND ($r['j']['data']['top']['countries'] ?? null) === array() AND page_ok($h) AND str_contains($h, 'Herkunft nach Land'), code($r));

// ---------------------------------------------------------------- echte RIR-Daten (Groesse, Laufzeit)
if($REAL) {
	echo "Echte RIR-Daten (read_countries_rir.php -> create_blocklists_v2.php -> honeypot_score.php)\n";
	// Kopie nur fuer den Test: ftp.lacnic.net war von der Testbox aus nicht erreichbar, RIPE spiegelt dieselbe Datei
	file_put_contents('/tmp/hp7g_rir.php', str_replace('https://ftp.lacnic.net/pub/stats/lacnic/', 'https://ftp.ripe.net/pub/stats/lacnic/', (string)file_get_contents("$WEB/bots/blocklist/read_countries_rir.php")));
	$t = microtime(true); $o = cli("timeout 900 php /tmp/hp7g_rir.php"); $dr = microtime(true) - $t;
	check('read_countries_rir.php: bl_countries_ips ersetzt', str_contains($o, 'bl_countries_ips ersetzt'), $o);
	echo "        " . str_replace("\n", "\n        ", trim($o)) . " (" . round($dr, 1) . " s)\n";
	$t = microtime(true); $o = gen(); $dg = microtime(true) - $t;
	preg_match('/Herkunft.*$/m', $o, $m);
	check('voller Lauf mit echten Daten ohne Fehler', clean_out($o) AND isset($m[0]), $o);
	$lines = gz_lines($GZ);
	echo "        " . ($m[0] ?? '') . "\n        Generator gesamt " . round($dg, 1) . " s, Speicher " . peak($o) . "; Datei " . round(filesize($GZ) / 1024) . " KB gz, "
		. round(strlen((string)gzdecode((string)file_get_contents($GZ))) / 1048576, 1) . " MB entpackt\n";
	foreach(array(0, (int)(count($lines) / 2), count($lines) - 1) as $k) { echo "        Beispiel: " . $lines[$k] . "\n"; }
	$find = function(string $ip) use ($lines) { $b = inet_pton($ip); foreach($lines as $l) { [$cc, $a, $z] = explode(' ', $l); $x = inet_pton($a);
		if(strlen($x) === strlen($b) AND strcmp($x, $b) <= 0 AND strcmp($b, inet_pton($z)) <= 0) { return $cc; } } return null; };
	$s = array('8.8.8.8' => $find('8.8.8.8'), '1.1.1.1' => $find('1.1.1.1'), '193.99.144.80' => $find('193.99.144.80'), '2a00:1450:4001::1' => $find('2a00:1450:4001::1'));
	check('Stichproben 8.8.8.8 US, 1.1.1.1 AU, 193.99.144.80 DE', $s['8.8.8.8'] === 'US' AND $s['1.1.1.1'] === 'AU' AND $s['193.99.144.80'] === 'DE', $s);
	$sorted = true; $prev = array(4 => '', 16 => ''); $pe = array(4 => '', 16 => '');
	foreach($lines as $l) { [, $a, $z] = explode(' ', $l); $x = inet_pton($a); $w = strlen($x); if(strcmp($x, $prev[$w]) < 0 OR ($pe[$w] !== '' AND strcmp($x, $pe[$w]) <= 0)) { $sorted = false; } $prev[$w] = $x; $pe[$w] = inet_pton($z); }
	check('echte Datei sortiert, ohne Ueberlappung', $sorted);
	$t = microtime(true); $o = scorer(); $ds = microtime(true) - $t;
	check('Bewertung mit echter Datei', preg_match('/Herkunft: \d+ von \d+ IPs mit Land/', $o) AND clean_out($o), $o);
	echo "        Bewertung gesamt " . round($ds, 2) . " s, Speicher " . peak($o) . "\n";
}

echo "\n$pass ok, $failed Fehler\n";
exit($failed > 0 ? 1 : 0);
