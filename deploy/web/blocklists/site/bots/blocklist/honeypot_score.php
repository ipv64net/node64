<?php
/**
 * Honeypot64 (Phase H3): Bewertung der gemeldeten IPs bei ipv64 -> Tabelle hp_scores. Danach schreibt der
 * Blocklisten-Generator die v64 Blocklist (Live-Stand bei jedem Lauf, Tagesstand einmal je UTC-Tag).
 * Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitt 6) im Node64-Repo, Tabellen: honeypot.sql, honeypot_h3_scoring.sql.
 *
 * Cron alle 30 Minuten, direkt danach der Generator nur fuer die v64-Listen:
 *   7,37 * * * * php .../bots/blocklist/honeypot_score.php > /dev/null && php .../bots/blocklist/create_blocklists_v2.php --only=v64 > /dev/null
 * Aufruf:  php honeypot_score.php          bewerten und hp_scores schreiben
 *          php honeypot_score.php --dry    nur rechnen und Zahlen ausgeben
 *
 * Bewertung (alle Zeiten UTC, Fenster 14 Tage aus hp_report_sources):
 *   - Gezaehlt werden Accounts, nicht Sensoren. Accounts, deren Sensoren im selben /24 (IPv4) bzw. /48 (IPv6) stehen
 *     (Sensor-IP aus hp_reports.ip und hp_sensors.last_ip), bilden eine Gruppe und zaehlen einmal.
 *   - Vertrauen je Sensor 1.0, halbiert fuer Accounts juenger als 7 Tage und fuer Sensoren, deren IPs fast nie von
 *     anderen bestaetigt werden (mind. 50 IPs, unter 5 % auch von einer anderen Gruppe gemeldet, erst ab 3 Gruppen);
 *     0 fuer gesperrte Sensoren und inaktive/geloeschte Accounts. Eine Gruppe zaehlt je IP mit dem hoechsten
 *     Vertrauen ihrer meldenden Sensoren (0.25 bis 1).
 *   - Schwelle nach aktiven Accounts (Meldung in 7 Tagen): unter 20: 2 Accounts mit Login/Exploit oder 3 Accounts;
 *     20-200: 3; ueber 200: 2 %, mindestens 3, hoechstens 10 (jeweils gewichtete Accounts).
 *     scanner:research zaehlt getrennt (eigene Liste research, nie in der Hauptliste v64), Schwelle wie ohne Login/Exploit.
 *   - Vertrauenswert 0-100: S = Summe je Gruppe (Vertrauen x Art x Quelle x Alter), Wert = 100 x (1 - e^(-S/1.5)).
 *     Art: Login/Exploit 1.0, Port-Scan/Verzeichnis-Scan/User-Agent 0.6, Research 0.6, blosser Verbindungsaufbau 0.3;
 *     Quelle: honeypot 1.0, log 0.8, syslog 0.7; Alter: bis 1 Tag 1.0, dann linear bis 0.25 nach 14 Tagen.
 *     Der Wert ist Auskunft (IP-Auskunft, Sortierung); ob gelistet wird, entscheidet die Schwelle.
 *   - Rausfallen: ohne Treffer in 14 Tagen faellt die IP aus dem Fenster und ihre Zeile wird geloescht.
 *   - Nie listen: nicht oeffentliche Adressen und IPs der Sensoren (beide gar nicht in hp_scores), Infrastruktur von
 *     ipv64 (reason infra), Cloudflare (cdn), Freigaben aus hp_allowlist und hp_release_requests.protected_until
 *     (allowlist), IPs von ipv64-Kunden (aktuelle A/AAAA-Records, oeffentliche VPN-IPs: customer_ip, nur markiert).
 *     customer_ip nur, wenn der Account des Records aktiv und aelter als HPS_CUSTOMER_AGE ist (ein frischer Account mit
 *     einem Record auf die eigene Scanner-IP schuetzt nicht) und die IP unter HPS_CUSTOMER_MAX x Schwelle bleibt
 *     (sehr viele unabhaengige Accounts: trotzdem listen). Ein Record ist kein Besitznachweis (jeder kann jede IP
 *     eintragen); einen echten Nachweis (Update-Quell-IP der DynDNS-Aktualisierung) gibt die Datenbank noch nicht her.
 *   - H6: jede Aenderung der gelisteten IPs (neu, nicht mehr gelistet, andere Listen) kommt in derselben Transaktion nach
 *     hp_list_changes (Aenderungs-Feed GET /threat/feed, api_v2_threat_feed.php), Frist 30 Tage.
 *   - Herkunft: hp_scores.country (ISO 3166-1, NULL = unbekannt) aus blocklists/country_ranges.txt.gz (Standort nach DB-IP, Luecken RIR).
 */
if(php_sapi_name() !== 'cli') { exit; }
include("/var/www/clients/client1/web58/web/dbconnect.php");
set_time_limit(900);
ini_set('memory_limit', '1024M');

const HPS_WINDOW      = 14 * 86400;  // Bewertungsfenster und Rausfallen
const HPS_ACTIVE      = 7 * 86400;   // aktive Accounts (Schwelle)
const HPS_SENSOR_IPS  = 30 * 86400;  // Sensor-IPs aus hp_reports.ip
const HPS_NEW_ACCOUNT = 7 * 86400;   // neue Accounts: halbes Vertrauen
const HPS_CONF_MIN    = 50;          // ab so vielen IPs je Sensor zaehlt die Bestaetigungsquote
const HPS_CONF_RATE   = 0.05;        // darunter: halbes Vertrauen
const HPS_CHUNK       = 500;         // Zeilen je INSERT
const HPS_CHANGES_KEEP = 30 * 86400; // H6: Aenderungs-Feed (hp_list_changes)
const HPS_CUSTOMER_AGE = 14 * 86400; // customer_ip nur fuer Records von Accounts, die aelter sind (laenger als das Fenster)
const HPS_CUSTOMER_MAX = 2;          // ab HPS_CUSTOMER_MAX x Schwelle (gewichtete Accounts) trotz Kunden-IP listen

// Infrastruktur von ipv64, die nie gelistet wird (zusaetzlich zu hp_allowlist source=infra und den Server-Tabellen
// cdn_server, vpn_gw_server, dns64_server, cdn64o_edges). Netze als CIDR, z. B. '203.0.113.0/24'.
// Healthchecks-hubs hc-srv01/hc-srv02 (pruefen fremde Ziele, auch Honeypots).
const HPS_INFRA_NETS = array('188.245.6.138/32', '2a01:4f8:c014:46b::1/128', '178.105.50.207/32', '2a01:4f8:1c1f:b393::1/128');

$dry = in_array('--dry', $argv, true);
$now = time();
$run = gmdate('Y-m-d H:i:s', $now);
$w14 = gmdate('Y-m-d H:i:s', $now - HPS_WINDOW);

// nicht zweimal gleichzeitig
$lock = fopen(sys_get_temp_dir() . '/ipv64_honeypot_score.lock', 'c');
if($lock === false OR !flock($lock, LOCK_EX | LOCK_NB)) { echo "Laeuft schon, Ende\n"; exit(0); }

// ---------------------------------------------------------------- Hilfen

function hps_q(string $sql, array $p = array()): PDOStatement { global $pdo; $st = $pdo->prepare($sql); $st->execute($p); return $st; }

/**
 * H6: Aenderungen der gelisteten IPs nach hp_list_changes (vor dem Schreiben von hp_scores, in derselben Transaktion).
 * Vorher = hp_scores mit listed = 1, nachher = $rowsOut mit listed = 1 (Spalten wie im INSERT unten); IPs, die ganz aus
 * hp_scores fallen, zaehlen als entfernt. Rueckgabe: Anzahl je Art.
 */
function hps_changes(array $rowsOut, string $run): array {
	$set = function(string $l): string { $a = $l === '' ? array() : explode(',', $l); sort($a); return implode(',', $a); };
	$old = array();
	foreach(hps_q("SELECT ip_bin, ip, lists FROM hp_scores WHERE listed = 1")->fetchAll(PDO::FETCH_ASSOC) as $r) { $old[$r['ip_bin']] = array($r['ip'], (string)$r['lists']); }
	$ch = array(); $n = array('add' => 0, 'remove' => 0, 'update' => 0);
	foreach($rowsOut as $x) {
		if((int)$x[13] !== 1) { continue; }
		$bin = hex2bin($x[0]);
		if(!isset($old[$bin])) { $ch[] = array($run, 'add', $x[1], $x[10], ''); $n['add']++; }
		elseif($set($old[$bin][1]) !== $set($x[10])) { $ch[] = array($run, 'update', $x[1], $x[10], $old[$bin][1]); $n['update']++; }
		unset($old[$bin]);
	}
	foreach($old as [$ip, $lists]) { $ch[] = array($run, 'remove', $ip, '', $lists); $n['remove']++; }
	foreach(array_chunk($ch, HPS_CHUNK) as $chunk) {
		hps_q("INSERT INTO hp_list_changes (created_at, action, ip, lists, prev_lists) VALUES " . implode(',', array_fill(0, count($chunk), '(?,?,?,?,?)')), array_merge(...$chunk));
	}
	return $n;
}

/** Zeilen ungepuffert lesen (grosse Abfragen); waehrenddessen keine andere Abfrage auf derselben Verbindung. */
function hps_stream(string $sql, array $p, callable $fn): void {
	global $pdo;
	$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, false);
	try {
		$st = $pdo->prepare($sql); $st->execute($p);
		while(($r = $st->fetch(PDO::FETCH_ASSOC)) !== false) { $fn($r); }
		$st->closeCursor();
	} finally {
		$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, true);
	}
}

/** "1.2.3.4" oder "1.2.3.0/24" -> [bin (Netzadresse), len] oder null */
function hps_net(string $s): ?array {
	$s = trim($s); $len = null;
	if(str_contains($s, '/')) { [$s, $l] = explode('/', $s, 2); if(!ctype_digit($l)) { return null; } $len = (int)$l; }
	$bin = filter_var($s, FILTER_VALIDATE_IP) ? inet_pton($s) : false;
	if($bin === false) { return null; }
	$bits = strlen($bin) * 8;
	if($len === null) { $len = $bits; }
	if($len < 0 OR $len > $bits) { return null; }
	return array(hps_mask($bin, $len), $len);
}

/** Hostbits loeschen */
function hps_mask(string $bin, int $len): string {
	$out = '';
	for($i = 0; $i < strlen($bin); $i++) { $b = max(0, min(8, $len - $i * 8)); $out .= chr(ord($bin[$i]) & ($b === 0 ? 0 : (0xFF << (8 - $b)) & 0xFF)); }
	return $out;
}

function hps_in_nets(string $bin, array $nets): bool {
	foreach($nets as [$n, $len]) { if(strlen($n) === strlen($bin) AND hps_mask($bin, $len) === $n) { return true; } }
	return false;
}

/** Oeffentliche Unicast-Adresse (wie hp_public_ip in api_v2_honeypot.php) */
function hps_public_ip(string $bin): bool {
	static $v4 = null, $v6 = null, $g6 = null;
	if($v4 === null) {
		$v4 = array_map('hps_net', array('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
			'192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4'));
		$v6 = array_map('hps_net', array('::/8', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64', '2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20', '5f00::/16',
			'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8'));
		$g6 = array(hps_net('2000::/3'));
	}
	if(strlen($bin) === 4) { return !hps_in_nets($bin, $v4); }
	return strlen($bin) === 16 && !hps_in_nets($bin, $v6) && hps_in_nets($bin, $g6);
}

/** Netz einer Sensor-IP fuer die Gruppierung: IPv4 /24, IPv6 /48 */
function hps_sensor_net(string $ip): ?string {
	$bin = filter_var($ip, FILTER_VALIDATE_IP) ? inet_pton($ip) : false;
	if($bin === false) { return null; }
	return strlen($bin) === 4 ? '4:' . bin2hex(substr($bin, 0, 3)) : '6:' . bin2hex(substr($bin, 0, 6));
}

/** Klasse einer Art: strong (Login/Exploit), medium (Scan), probe (Verbindungsaufbau), research (Forschungs-Scanner) */
function hps_class(string $kind): string {
	if($kind === 'scanner:research') { return 'research'; }
	if($kind === 'generic:probe') { return 'probe'; }
	if(str_ends_with($kind, 'bruteforce') OR str_starts_with($kind, 'http:exploit')) { return 'strong'; }
	return 'medium'; // generic:portscan, http:scan, http:bad-useragent und spaetere Arten
}
const HPS_KIND_W = array('strong' => 1.0, 'medium' => 0.6, 'research' => 0.6, 'probe' => 0.3);
const HPS_SRC_W  = array('honeypot' => 1.0, 'log' => 0.8, 'syslog' => 0.7);

/** Teillisten einer Art (Hauptliste v64 und research getrennt) */
function hps_sublists(string $kind): array {
	$l = array();
	if(str_starts_with($kind, 'ssh:') OR str_starts_with($kind, 'telnet:')) { $l[] = 'ssh'; }
	if(str_starts_with($kind, 'http:')) { $l[] = 'web'; }
	if(str_starts_with($kind, 'mail:')) { $l[] = 'mail'; }
	if(str_starts_with($kind, 'rdp:')) { $l[] = 'rdp'; }
	if(in_array($kind, array('generic:portscan', 'generic:probe', 'http:bad-useragent'), true)) { $l[] = 'scanner'; }
	return $l;
}

/** Alter in Tagen -> Gewicht: bis 1 Tag 1.0, dann linear bis 0.25 nach 14 Tagen */
function hps_age(int $ts, int $now): float { $d = max(0, $now - $ts) / 86400; return $d <= 1 ? 1.0 : max(0.25, 1 - 0.75 * ($d - 1) / 13); }

/**
 * Herkunft: blocklists/country_ranges.txt.gz (create_blocklists_v2.php, taeglich: DB-IP Lite, Luecken aus den RIR-Daten) einmal laden.
 * Rueckgabe je Adresslaenge (4/16 Byte) drei parallele, nach Anfang sortierte Listen [Anfang, Ende, Land] oder null.
 */
function hps_geo_load(string $file): ?array {
	$fh = is_file($file) ? gzopen($file, 'rb') : false;
	if($fh === false) { return null; }
	$g = array(4 => array(array(), array(), array()), 16 => array(array(), array(), array()));
	$sorted = true; $prev = array(4 => '', 16 => '');
	while(($l = gzgets($fh)) !== false) {
		if($l === '' OR $l[0] === '#') { continue; }
		$f = explode(' ', trim($l));
		if(count($f) !== 3 OR !preg_match('/^[A-Z]{2}$/', $f[0]) OR !filter_var($f[1], FILTER_VALIDATE_IP) OR !filter_var($f[2], FILTER_VALIDATE_IP)) { continue; }
		$a = inet_pton($f[1]); $b = inet_pton($f[2]); $w = strlen($a);
		if($w !== strlen($b) OR strcmp($a, $b) > 0) { continue; }
		if(strcmp($a, $prev[$w]) < 0) { $sorted = false; }
		$prev[$w] = $a;
		$g[$w][0][] = $a; $g[$w][1][] = $b; $g[$w][2][] = $f[0];
	}
	gzclose($fh);
	if(!$sorted) { foreach($g as $w => $x) { array_multisort($g[$w][0], SORT_STRING, $g[$w][1], $g[$w][2]); } }
	return (count($g[4][0]) + count($g[16][0])) > 0 ? $g : null;
}

/** Land einer IP (binaer) per Binaersuche: letzter Bereich mit Anfang <= IP, IP <= Ende; sonst null */
function hps_geo_find(array $g, string $bin): ?string {
	$w = strlen($bin);
	if(!isset($g[$w])) { return null; }
	$s = $g[$w][0]; $lo = 0; $hi = count($s) - 1; $hit = -1;
	while($lo <= $hi) { $m = ($lo + $hi) >> 1; if(strcmp($s[$m], $bin) <= 0) { $hit = $m; $lo = $m + 1; } else { $hi = $m - 1; } }
	return ($hit >= 0 AND strcmp($bin, $g[$w][1][$hit]) <= 0) ? $g[$w][2][$hit] : null;
}

// ---------------------------------------------------------------- 1. Sensoren, Gruppen, aktive Accounts

// Sensor-IPs (nie listen, nie in hp_scores): letzte IP aller Sensoren und alle Meldungs-IPs der letzten 30 Tage.
// IPv4 genau, IPv6 als /64 (Privacy-Adressen wechseln innerhalb des Netzes).
$sensorIps = array();
$addSensorIp = function(string $ip) use (&$sensorIps) {
	$bin = filter_var($ip, FILTER_VALIDATE_IP) ? inet_pton($ip) : false;
	if($bin !== false) { $sensorIps[strlen($bin) === 4 ? $bin : substr($bin, 0, 8)] = true; }
};
foreach(hps_q("SELECT DISTINCT last_ip FROM hp_sensors WHERE last_ip != ''")->fetchAll(PDO::FETCH_COLUMN) as $ip) { $addSensorIp($ip); }
foreach(hps_q("SELECT DISTINCT ip FROM hp_reports WHERE received_at >= :d AND ip != ''", array('d' => gmdate('Y-m-d H:i:s', $now - HPS_SENSOR_IPS)))->fetchAll(PDO::FETCH_COLUMN) as $ip) { $addSensorIp($ip); }
$isSensorIp = fn(string $bin): bool => isset($sensorIps[strlen($bin) === 4 ? $bin : substr($bin, 0, 8)]);

// Gruppen: Accounts mit Sensoren im selben Netz (Union-Find)
$parent = array();
$find = function(int $u) use (&$parent, &$find): int { if(!isset($parent[$u])) { $parent[$u] = $u; } if($parent[$u] !== $u) { $parent[$u] = $find($parent[$u]); } return $parent[$u]; };
$netOwner = array();
foreach(hps_q("SELECT DISTINCT userid, ip FROM hp_reports WHERE received_at >= :w AND ip != ''
	UNION SELECT userid, last_ip FROM hp_sensors WHERE last_seen >= :w2 AND last_ip != ''", array('w' => $w14, 'w2' => $w14))->fetchAll(PDO::FETCH_ASSOC) as $x) {
	$net = hps_sensor_net((string)$x['ip']);
	if($net === null) { continue; }
	$u = (int)$x['userid'];
	if(!isset($netOwner[$net])) { $netOwner[$net] = $u; $find($u); continue; }
	$a = $find($netOwner[$net]); $b = $find($u);
	if($a !== $b) { $parent[max($a, $b)] = min($a, $b); }
}

// aktive Accounts (Meldung in 7 Tagen, Sensor nicht gesperrt) -> Schwelle
$active = (int)hps_q("SELECT COUNT(DISTINCT r.userid) FROM hp_reports r JOIN hp_sensors s ON s.sensor_id = r.sensor_id
	WHERE r.received_at >= :d AND s.disabled = 0", array('d' => gmdate('Y-m-d H:i:s', $now - HPS_ACTIVE)))->fetchColumn();
if($active < 20) { $T = 3; $Tstrong = 2; }
elseif($active <= 200) { $T = 3; $Tstrong = null; }
else { $T = (int)min(10, max(3, ceil($active * 0.02))); $Tstrong = null; }

// ---------------------------------------------------------------- 2. Bestaetigungsquote je Sensor (erster Durchlauf)

$sensorUser = array(); $total = array(); $conf = array(); $groupsAll = array();
$cur = null; $rows = array();
$flush1 = function() use (&$rows, &$total, &$conf, $find) {
	$groups = array();
	foreach($rows as [$u, $s]) { $groups[$find($u)] = true; }
	foreach($rows as [$u, $s]) { $total[$s] = ($total[$s] ?? 0) + 1; if(count($groups) > 1) { $conf[$s] = ($conf[$s] ?? 0) + 1; } }
	$rows = array();
};
hps_stream("SELECT ip_bin, userid, sensor_id FROM hp_report_sources WHERE last_seen >= :w GROUP BY ip_bin, userid, sensor_id ORDER BY ip_bin", array('w' => $w14),
	function($r) use (&$cur, &$rows, &$sensorUser, &$groupsAll, $flush1, $find) {
		if($cur !== null AND $r['ip_bin'] !== $cur) { $flush1(); }
		$cur = $r['ip_bin'];
		$u = (int)$r['userid'];
		$rows[] = array($u, $r['sensor_id']);
		$sensorUser[$r['sensor_id']] = $u; $groupsAll[$find($u)] = true;
	});
if($rows) { $flush1(); }

// Vertrauen je Sensor
$users = array();
$uids = array_values(array_unique(array_values($sensorUser)));
foreach(array_chunk($uids, HPS_CHUNK) as $chunk) {
	foreach(hps_q("SELECT id, reg_date, account_status FROM users WHERE id IN (" . implode(',', array_fill(0, count($chunk), '?')) . ")", $chunk)->fetchAll(PDO::FETCH_ASSOC) as $x) { $users[(int)$x['id']] = $x; }
}
$disabled = array_fill_keys(hps_q("SELECT sensor_id FROM hp_sensors WHERE disabled = 1")->fetchAll(PDO::FETCH_COLUMN), true);
$trust = array(); $lowTrust = array('new' => 0, 'unconfirmed' => 0, 'none' => 0);
foreach($sensorUser as $s => $u) {
	$x = $users[$u] ?? null;
	if($x === null OR (string)$x['account_status'] !== '1' OR isset($disabled[$s])) { $trust[$s] = 0.0; $lowTrust['none']++; continue; }
	$t = 1.0;
	$reg = strtotime((string)$x['reg_date']);
	if($reg !== false AND $reg > $now - HPS_NEW_ACCOUNT) { $t *= 0.5; $lowTrust['new']++; }
	if(count($groupsAll) >= 3 AND ($total[$s] ?? 0) >= HPS_CONF_MIN AND ($conf[$s] ?? 0) / $total[$s] < HPS_CONF_RATE) { $t *= 0.5; $lowTrust['unconfirmed']++; }
	$trust[$s] = $t;
}
unset($total, $conf);

// ---------------------------------------------------------------- 3. Bewertung je IP (zweiter Durchlauf)

$out = array(); $skipped = array('not_public' => 0, 'sensor' => 0);
$cur = null; $acc = null;
$finish = function() use (&$acc, &$out, &$skipped, $isSensorIp, $trust, $find, $now, $T, $Tstrong) {
	$bin = $acc['bin'];
	if(!hps_public_ip($bin)) { $skipped['not_public']++; return; }
	if($isSensorIp($bin)) { $skipped['sensor']++; return; }
	// je Gruppe: Vertrauen (hoechstes der meldenden Sensoren), bester Beitrag zum Wert, Klassen
	$g = array(); $sensors = array(); $kinds = array(); $events = 0; $first = PHP_INT_MAX; $last = 0;
	foreach($acc['rows'] as $r) {
		$t = $trust[$r['sensor_id']] ?? 0.0;
		$sensors[$r['sensor_id']] = true; $kinds[$r['kind']] = true; $events += (int)$r['ev'];
		$first = min($first, strtotime($r['f'] . ' UTC')); $last = max($last, strtotime($r['l'] . ' UTC'));
		if($t <= 0) { continue; }
		$k = $find((int)$r['userid']); $cls = hps_class($r['kind']);
		if(!isset($g[$k])) { $g[$k] = array('t' => 0.0, 's' => 0.0, 'main' => 0.0, 'strong' => 0.0, 'research' => 0.0); }
		$g[$k]['s'] = max($g[$k]['s'], $t * HPS_KIND_W[$cls] * (HPS_SRC_W[$r['source']] ?? 0.7) * hps_age(strtotime($r['l'] . ' UTC'), $now));
		if($cls === 'research') { $g[$k]['research'] = max($g[$k]['research'], $t); }
		else { $g[$k]['main'] = max($g[$k]['main'], $t); }
		if($cls === 'strong') { $g[$k]['strong'] = max($g[$k]['strong'], $t); }
	}
	$S = 0.0; $eff = 0.0; $strong = 0.0; $res = 0.0;
	foreach($g as $x) { $S += $x['s']; $eff += $x['main']; $strong += $x['strong']; $res += $x['research']; }
	$eff = round($eff, 2); $strong = round($strong, 2); $res = round($res, 2);
	$main = ($eff >= $T || ($Tstrong !== null && $strong >= $Tstrong));
	$research = $res >= $T;
	$lists = array();
	if($main) {
		$lists[] = 'v64';
		foreach(array_keys($kinds) as $kd) { if(hps_class($kd) !== 'research') { foreach(hps_sublists($kd) as $l) { $lists[$l] = $l; } } }
	}
	if($research) { $lists[] = 'research'; }
	$kinds = array_keys($kinds); sort($kinds);
	$ks = ''; foreach($kinds as $kd) { if(strlen($ks) + strlen($kd) + 1 > 255) { break; } $ks .= ($ks === '' ? '' : ',') . $kd; }
	$out[] = array('bin' => $bin, 'family' => strlen($bin) === 4 ? 4 : 6, 'score' => (int)min(100, round(100 * (1 - exp(-$S / 1.5)))),
		'accounts' => count($g), 'eff' => $eff, 'strong' => $strong, 'sensors' => count($sensors), 'events' => $events, 'kinds' => $ks,
		'lists' => array_values(array_unique($lists)), 'first' => $first, 'last' => $last, 'cand' => ($main || $research));
};
hps_stream("SELECT ip_bin, userid, sensor_id, kind, source, SUM(`count`) ev, MIN(first_seen) f, MAX(last_seen) l
	FROM hp_report_sources WHERE last_seen >= :w GROUP BY ip_bin, userid, sensor_id, kind, source ORDER BY ip_bin", array('w' => $w14),
	function($r) use (&$cur, &$acc, $finish) {
		if($cur !== null AND $r['ip_bin'] !== $cur) { $finish(); }
		if($r['ip_bin'] !== $cur) { $cur = $r['ip_bin']; $acc = array('bin' => $r['ip_bin'], 'rows' => array()); }
		$acc['rows'][] = $r;
	});
if($acc !== null) { $finish(); }

// ---------------------------------------------------------------- 4. Nie listen (nur fuer IPs ueber der Schwelle)

$cand = array();
foreach($out as $i => $x) { if($x['cand']) { $cand[$x['bin']] = $i; } }
$reason = array(); // bin -> Grund (gelistet bzw. nicht gelistet trotz Schwelle)
$soft = array();   // bin -> infra/cdn fuer IPs unter der Schwelle (nur Kennzeichnung: die Fruehwarnung meldet sie nicht)
$warn = array();
if($out) {
	// Freigaben, Infrastruktur, CDN aus hp_allowlist (Teil Freigaben; hier nur lesend)
	$ranges = array();
	try {
		foreach(hps_q("SELECT ip_start, ip_end, source FROM hp_allowlist WHERE `until` IS NULL OR `until` > :n", array('n' => $run))->fetchAll(PDO::FETCH_ASSOC) as $x) {
			if(strlen($x['ip_start']) === strlen($x['ip_end']) AND strlen($x['ip_start']) > 0) { $ranges[] = $x; }
		}
	} catch(Throwable $e) { $warn[] = 'hp_allowlist nicht lesbar (' . $e->getMessage() . ')'; }
	$released = array();
	try {
		foreach(hps_q("SELECT ip_bin FROM hp_release_requests WHERE protected_until > :n", array('n' => $run))->fetchAll(PDO::FETCH_COLUMN) as $b) { $released[$b] = true; }
	} catch(Throwable $e) { $warn[] = 'hp_release_requests nicht lesbar (' . $e->getMessage() . ')'; }
	// Infrastruktur: Konstante und Server-Tabellen
	$infra = array_values(array_filter(array_map('hps_net', HPS_INFRA_NETS)));
	foreach(array('cdn_server', 'vpn_gw_server', 'dns64_server', 'cdn64o_edges') as $tbl) {
		try {
			foreach(hps_q("SELECT ipv4, ipv6 FROM `$tbl`")->fetchAll(PDO::FETCH_ASSOC) as $x) {
				foreach(array($x['ipv4'], $x['ipv6']) as $ip) { if(($n = hps_net((string)$ip)) !== null) { $infra[] = $n; } }
			}
		} catch(Throwable $e) { $warn[] = "$tbl nicht lesbar"; }
	}
	// Cloudflare (Liste bl_cloudflare aus den Blocklisten)
	$cdn = array();
	try { foreach(hps_q("SELECT ip FROM bl_cloudflare")->fetchAll(PDO::FETCH_COLUMN) as $ip) { if(($n = hps_net((string)$ip)) !== null) { $cdn[] = $n; } } }
	catch(Throwable $e) { $warn[] = 'bl_cloudflare nicht lesbar'; }
	if(!$cdn) { $warn[] = 'keine Cloudflare-Netze (bl_cloudflare leer)'; }
	// Kunden: aktuelle A/AAAA-Records (DynDNS) und oeffentliche VPN-IPs; Text kann unterschiedlich geschrieben sein -> binaer vergleichen
	$customer = array();
	$checkCustomer = function($r) use (&$customer, $cand) {
		$ip = trim((string)$r['ip']);
		$bin = filter_var($ip, FILTER_VALIDATE_IP) ? inet_pton($ip) : false;
		if($bin !== false AND isset($cand[$bin])) { $customer[$bin] = true; }
	};
	if($cand) {
		$custSince = gmdate('Y-m-d H:i:s', $now - HPS_CUSTOMER_AGE); // Account aktiv und aelter als das Fenster
		try { hps_stream("SELECT r.content ip FROM subdomain_records r JOIN users u ON u.id = r.userid WHERE r.type IN ('A', 'AAAA') AND r.deactivated = 0 AND u.account_status = '1' AND u.reg_date <= :o", array('o' => $custSince), $checkCustomer); }
		catch(Throwable $e) { $warn[] = 'subdomain_records nicht lesbar'; }
		try { hps_stream("SELECT v.ip FROM vpn_public_ips v JOIN users u ON u.id = v.userid WHERE v.deleted = 0 AND u.account_status = '1' AND u.reg_date <= :o", array('o' => $custSince), $checkCustomer); }
		catch(Throwable $e) { $warn[] = 'vpn_public_ips nicht lesbar'; }
	}

	foreach($cand as $bin => $i) {
		$why = null;
		foreach($ranges as $x) {
			if(strlen($x['ip_start']) === strlen($bin) AND strcmp($bin, $x['ip_start']) >= 0 AND strcmp($bin, $x['ip_end']) <= 0) {
				$w = $x['source'] === 'infra' ? 'infra' : ($x['source'] === 'cdn' ? 'cdn' : 'allowlist');
				if($why === null OR array_search($w, array('infra', 'cdn', 'allowlist')) < array_search($why, array('infra', 'cdn', 'allowlist'))) { $why = $w; }
			}
		}
		if($why === null AND hps_in_nets($bin, $infra)) { $why = 'infra'; }
		if($why === null AND hps_in_nets($bin, $cdn)) { $why = 'cdn'; }
		if($why === null AND isset($released[$bin])) { $why = 'allowlist'; }
		if($why === null AND isset($customer[$bin]) AND $out[$i]['eff'] < HPS_CUSTOMER_MAX * $T) { $why = 'customer_ip'; } // TODO H5: Kunden warnen (Fruehwarnung), Pruefung durch Dennis
		$reason[$bin] = $why ?? 'threshold';
	}
	foreach($out as $x) {
		if($x['cand']) { continue; }
		$bin = $x['bin'];
		foreach($ranges as $r) {
			if(($r['source'] === 'infra' OR $r['source'] === 'cdn') AND strlen($r['ip_start']) === strlen($bin) AND strcmp($bin, $r['ip_start']) >= 0 AND strcmp($bin, $r['ip_end']) <= 0) { $soft[$bin] = $r['source']; break; }
		}
		if(!isset($soft[$bin]) AND hps_in_nets($bin, $infra)) { $soft[$bin] = 'infra'; }
		if(!isset($soft[$bin]) AND hps_in_nets($bin, $cdn)) { $soft[$bin] = 'cdn'; }
	}
}

// ---------------------------------------------------------------- 5. Schreiben

$stat = array('ips' => count($out), 'listed' => 0, 'v64' => 0, 'research' => 0, 'threshold' => 0, 'customer_ip' => 0, 'allowlist' => 0, 'infra' => 0, 'cdn' => 0);
$rowsOut = array();
foreach($out as $x) {
	$why = $x['cand'] ? $reason[$x['bin']] : ($soft[$x['bin']] ?? '');
	$listed = $why === 'threshold' ? 1 : 0;
	if($why !== '' AND $x['cand']) { $stat[$why]++; }
	if($listed) { $stat['listed']++; if(in_array('v64', $x['lists'], true)) { $stat['v64']++; } if(in_array('research', $x['lists'], true)) { $stat['research']++; } }
	$rowsOut[] = array(bin2hex($x['bin']), inet_ntop($x['bin']), $x['family'], $x['score'], min(65535, $x['accounts']), $x['eff'], $x['strong'], $x['sensors'], $x['events'],
		$x['kinds'], $listed ? implode(',', $x['lists']) : '', gmdate('Y-m-d H:i:s', $x['first']), gmdate('Y-m-d H:i:s', $x['last']), $listed, $listed ? $run : null, $why, $run);
}

printf("Aktive Accounts (7 Tage): %d, Gruppen (14 Tage): %d, Schwelle: %s%s\n", $active, count($groupsAll), $T, $Tstrong !== null ? " bzw. $Tstrong mit Login/Exploit" : '');
printf("Sensoren: %d, halbes Vertrauen neu: %d, wenig bestaetigt: %d, ohne Vertrauen: %d\n", count($trust), $lowTrust['new'], $lowTrust['unconfirmed'], $lowTrust['none']);
printf("IPs bewertet: %d, gelistet: %d (v64 %d, research %d), nicht gelistet trotz Schwelle: Kunde %d, Freigabe %d, Infrastruktur %d, CDN %d; uebersprungen: Sensor %d, nicht oeffentlich %d\n",
	$stat['ips'], $stat['listed'], $stat['v64'], $stat['research'], $stat['customer_ip'], $stat['allowlist'], $stat['infra'], $stat['cdn'], $skipped['sensor'], $skipped['not_public']);
if($soft) { echo "Unter der Schwelle als Infrastruktur/CDN gekennzeichnet (keine Fruehwarnung): " . count($soft) . "\n"; }
foreach($warn as $w) { echo "Warnung: $w\n"; }
if($stat['customer_ip'] > 0) { echo "Hinweis: {$stat['customer_ip']} IPs von ipv64-Kunden nicht gelistet (reason customer_ip) - TODO: Kunden warnen\n"; }
if($dry) { echo "*** DRY RUN, nichts geschrieben ***\n"; exit(0); }

$pdo->beginTransaction();
try {
	// H6: Aenderungs-Feed; fehlt die Tabelle noch, laeuft die Bewertung ohne Protokoll weiter
	try { $chg = hps_changes($rowsOut, $run); echo "hp_list_changes: {$chg['add']} neu, {$chg['remove']} entfernt, {$chg['update']} geaendert\n"; }
	catch(Throwable $e) { echo "Warnung: hp_list_changes nicht geschrieben: " . $e->getMessage() . "\n"; }
	foreach(array_chunk($rowsOut, HPS_CHUNK) as $chunk) {
		hps_q("INSERT INTO hp_scores (ip_bin, ip, family, score, accounts, accounts_eff, strong_eff, sensors, events, kinds, lists, first_seen, last_seen, listed, listed_since, reason, updated_at) VALUES "
			. implode(',', array_fill(0, count($chunk), '(UNHEX(?),?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'))
			. " ON DUPLICATE KEY UPDATE listed_since = IF(VALUES(listed) = 1, IFNULL(listed_since, VALUES(listed_since)), NULL), ip = VALUES(ip), family = VALUES(family),
			score = VALUES(score), accounts = VALUES(accounts), accounts_eff = VALUES(accounts_eff), strong_eff = VALUES(strong_eff), sensors = VALUES(sensors),
			events = VALUES(events), kinds = VALUES(kinds), lists = VALUES(lists), first_seen = VALUES(first_seen), last_seen = VALUES(last_seen),
			listed = VALUES(listed), reason = VALUES(reason), updated_at = VALUES(updated_at)", array_merge(...$chunk));
	}
	// nicht mehr im Fenster (14 Tage ohne Treffer), Sensor-IPs, nicht oeffentlich: weg
	$del = hps_q("DELETE FROM hp_scores WHERE updated_at < :r", array('r' => $run))->rowCount();
	$pdo->commit();
} catch(Throwable $e) {
	if($pdo->inTransaction()) { $pdo->rollBack(); }
	fwrite(STDERR, "Fehler: " . $e->getMessage() . "\n");
	exit(1);
}
echo "hp_scores: " . count($rowsOut) . " geschrieben, $del entfernt\n";
// Herkunft (hp_scores.country): Bereiche einmal laden, je IP Binaersuche, geschrieben werden nur Aenderungen (je Land gesammelt).
// Fehlt die Spalte (datenbank.sql noch nicht eingespielt) oder die Datei, laeuft alles andere unveraendert weiter.
try {
	$geo = hps_geo_load(dirname(__DIR__, 2) . '/blocklists/country_ranges.txt.gz');
	if($geo === null) { echo "Herkunft: country_ranges.txt.gz fehlt (kommt mit dem naechsten vollen Lauf von create_blocklists_v2.php)\n"; }
	else {
		$geoSet = array(); $geoKnown = 0; $geoAll = 0;
		hps_stream("SELECT ip_bin, country FROM hp_scores", array(), function($r) use (&$geoSet, &$geoKnown, &$geoAll, $geo) {
			$cc = hps_geo_find($geo, $r['ip_bin']); $geoAll++;
			if($cc !== null) { $geoKnown++; }
			if($cc !== ($r['country'] === null ? null : strtoupper($r['country']))) { $geoSet[$cc ?? ''][] = bin2hex($r['ip_bin']); }
		});
		$geoChanged = 0;
		foreach($geoSet as $cc => $hex) {
			foreach(array_chunk($hex, HPS_CHUNK) as $chunk) {
				$geoChanged += hps_q("UPDATE hp_scores SET country = ? WHERE ip_bin IN (" . implode(',', array_fill(0, count($chunk), 'UNHEX(?)')) . ")",
					array_merge(array($cc === '' ? null : (string)$cc), $chunk))->rowCount();
			}
		}
		echo "Herkunft: $geoKnown von $geoAll IPs mit Land, $geoChanged geaendert\n";
	}
	unset($geo, $geoSet);
} catch(Throwable $e) { echo "Warnung: Herkunft nicht geschrieben (hp_scores.country fehlt? datenbank.sql): " . $e->getMessage() . "\n"; }
// H6: Aenderungs-Feed nach 30 Tagen loeschen
try {
	$cd = 0;
	do { $c = hps_q("DELETE FROM hp_list_changes WHERE created_at < :d LIMIT 10000", array('d' => gmdate('Y-m-d H:i:s', $now - HPS_CHANGES_KEEP)))->rowCount(); $cd += $c; } while($c >= 10000);
	if($cd > 0) { echo "hp_list_changes: $cd alte Eintraege geloescht\n"; }
} catch(Throwable $e) { echo "Warnung: hp_list_changes nicht aufgeraeumt: " . $e->getMessage() . "\n"; }
