<?php
/**
 * Honeypot64: Live-Karte auf ipv64.net (honeypot/live.php). Alle 2 Minuten ueber honeypot_cron.php (Job "live"), nur
 * Kommandozeile:
 *
 *   php honeypot_live.php          live.json neu schreiben
 *   php honeypot_live.php --dry    nur Zahlen anzeigen
 *
 * Liest die gemeldeten Quellen der letzten 60 Minuten (hp_report_sources, Index last_seen; hoechstens 3000 Zeilen) und
 * schreibt honeypot/live.json (statisch: Besucher der Seite loesen nie SQL aus). Je Eintrag: Zeit, Quelle maskiert
 * (IPv4 /24, IPv6 /48), Land der Quelle, Land des Sensors (nie Sensor, Account oder IP), Art, Dienst, Port, Anzahl.
 * Ziel-Land: eingestellter Standort des Sensors (hp_sensors.country, aus der Meldung), wenn die Karte das Land kennt
 * (honeypot/worldmap.json, Flaeche oder fester Punkt), sonst Land der IP der Meldung.
 * Keine Zugangsdaten. Weggelassen: Quellen, die selbst Sensor-IPs sind, und IPs, die die Bewertung als Infrastruktur,
 * CDN, Freigabe oder Kunden-IP kennzeichnet (hp_scores.reason). Laender aus blocklists/country_ranges.txt.gz in einem
 * Durchlauf (sortierte Bereiche, wenig Speicher; Standort nach DB-IP, Luecken aus den RIR-Daten). Die Meldungen kommen alle 10 Minuten: die Karte ist zeitversetzt.
 */
if(php_sapi_name() !== 'cli') { exit; }
include(__DIR__ . "/../dbconnect.php");
set_time_limit(120);

const HPL_MINUTES = 60;   // Zeitfenster
const HPL_ROWS    = 3000; // hoechstens so viele Quellen lesen
const HPL_OUT     = 800;  // hoechstens so viele Eintraege in live.json

$dry = in_array('--dry', $argv ?? array(), true);
$now = time();
$q = function(string $sql, array $a = array()) use ($pdo): PDOStatement { $st = $pdo->prepare($sql); $st->execute($a); return $st; };

$rows = $q("SELECT s.ip, s.ip_bin, s.kind, s.service, s.port, s.`count` n, s.last_seen, s.source, r.ip sensor_ip, se.country sensor_cc
	FROM hp_report_sources s JOIN hp_reports r ON r.id = s.report_ref AND r.day = s.day LEFT JOIN hp_sensors se ON se.sensor_id = r.sensor_id
	WHERE s.last_seen >= :d ORDER BY s.last_seen DESC LIMIT " . HPL_ROWS, array('d' => gmdate('Y-m-d H:i:s', $now - HPL_MINUTES * 60)))->fetchAll(PDO::FETCH_ASSOC);

// Sensor-IPs (nie als Angreifer zeigen) und Kennzeichen der Bewertung
$sensor = array();
foreach($rows as $r) { if(($b = @inet_pton((string)$r['sensor_ip'])) !== false) { $sensor[$b] = true; } }
$skip = array();
$bins = array_values(array_unique(array_map(fn($r) => $r['ip_bin'], $rows)));
foreach(array_chunk($bins, 500) as $chunk) {
	$in = implode(',', array_fill(0, count($chunk), '?'));
	foreach($q("SELECT ip_bin FROM hp_scores WHERE ip_bin IN ($in) AND reason IN ('infra', 'cdn', 'allowlist', 'customer_ip')", $chunk)->fetchAll(PDO::FETCH_COLUMN) as $b) { $skip[$b] = true; }
}

// Laender: benoetigte Adressen sortiert, dann ein Durchlauf durch die Bereiche
$need = array();
foreach($rows as $r) {
	$need[$r['ip_bin']] = true;
	if(($b = @inet_pton((string)$r['sensor_ip'])) !== false) { $need[$b] = true; }
}
$cc = hpl_countries(__DIR__ . '/../blocklists/country_ranges.txt.gz', array_keys($need));
$known = hpl_map_countries(__DIR__ . '/../honeypot/worldmap.json');

$agg = array(); $srcSet = array(); $dstSet = array(); $byCountry = array(); $events = 0; $skipped = 0;
foreach($rows as $r) {
	$b = $r['ip_bin'];
	if(isset($sensor[$b]) OR isset($skip[$b])) { $skipped++; continue; }
	$from = $cc[$b] ?? null;
	$sb = @inet_pton((string)$r['sensor_ip']);
	$to = isset($known[(string)$r['sensor_cc']]) ? $r['sensor_cc'] : ($sb !== false ? ($cc[$sb] ?? null) : null);
	if($from === null OR $to === null) { continue; }
	$src = hpl_mask((string)$r['ip']);
	$k = $src . '|' . $from . '|' . $to . '|' . $r['kind'] . '|' . $r['service'] . '|' . $r['port'];
	$t = (int)strtotime($r['last_seen'] . ' UTC') * 1000;
	if(!isset($agg[$k])) {
		$agg[$k] = array('t' => $t, 'src' => $src, 'cc' => $from, 'dst' => $to, 'kind' => (string)$r['kind'], 'group' => hpl_group((string)$r['kind'], (string)$r['source']),
			'svc' => (string)$r['service'], 'port' => (int)$r['port'], 'n' => 0);
	}
	$agg[$k]['n'] += (int)$r['n'];
	$agg[$k]['t'] = max($agg[$k]['t'], $t);
	$events += (int)$r['n'];
	$srcSet[$src] = true; $dstSet[$to] = true;
	$byCountry[$from] = ($byCountry[$from] ?? 0) + (int)$r['n'];
}
$list = array_values($agg);
usort($list, fn($a, $b) => $b['t'] <=> $a['t']);
$list = array_slice($list, 0, HPL_OUT);
arsort($byCountry);
$top = array();
foreach(array_slice($byCountry, 0, 8, true) as $c => $n) { $top[] = array($c, $n); }
$out = array('generated' => $now * 1000, 'minutes' => HPL_MINUTES, 'entries' => $list,
	'stats' => array('events' => $events, 'sources' => count($srcSet), 'targets' => count($dstSet), 'countries' => $top, 'by_country' => $byCountry));

printf("Zeilen %d, Eintraege %d, Ereignisse %d, Quellen %d, Ziel-Laender %d, ausgelassen (Sensor/Infrastruktur/Kunde) %d\n",
	count($rows), count($list), $events, count($srcSet), count($dstSet), $skipped);
if($dry) { echo "*** DRY RUN, nichts geschrieben ***\n"; exit(0); }
$file = __DIR__ . '/../honeypot/live.json';
$tmp = $file . '.tmp';
if(file_put_contents($tmp, json_encode($out, JSON_UNESCAPED_SLASHES)) === false OR !rename($tmp, $file)) {
	fwrite(STDERR, "live.json nicht geschrieben\n");
	exit(1);
}

/** Laender der Karte (Flaechen und feste Punkte) aus worldmap.json -> [CC => true]; fehlt die Datei: leer */
function hpl_map_countries(string $file): array {
	$m = json_decode((string)@file_get_contents($file), true);
	if(!is_array($m)) { return array(); }
	return array_fill_keys(array_merge(array_keys($m['countries'] ?? array()), array_keys($m['points'] ?? array())), true);
}

/** Quelle maskieren: IPv4 /24 (203.0.113.x), IPv6 /48 (2001:db8:1::/48) */
function hpl_mask(string $ip): string {
	$b = @inet_pton($ip);
	if($b === false) { return ''; }
	if(strlen($b) === 4) { $p = explode('.', inet_ntop($b)); return $p[0] . '.' . $p[1] . '.' . $p[2] . '.x'; }
	return inet_ntop(substr($b, 0, 6) . str_repeat("\0", 10)) . '/48';
}

/** Art-Gruppe wie in Node64 (honeypot.KindGroup): Farbe der Boegen */
function hpl_group(string $kind, string $source): string {
	if($source !== '' AND $source !== 'honeypot') { return 'log'; }
	if(str_contains($kind, 'bruteforce')) { return 'login'; }
	if(str_contains($kind, 'exploit')) { return 'exploit'; }
	if(str_contains($kind, 'scan')) { return 'scan'; }
	return 'probe';
}

/**
 * Laender der Adressen (binaer) in einem Durchlauf: Bereiche "CC von bis" aufsteigend sortiert (wie von
 * create_blocklists_v2.php geschrieben); liefert bin -> CC. Fehlt die Datei: leeres Ergebnis.
 */
function hpl_countries(string $file, array $bins): array {
	$fh = is_file($file) ? gzopen($file, 'rb') : false;
	if($fh === false) { return array(); }
	$byW = array(4 => array(), 16 => array());
	foreach($bins as $b) { if(isset($byW[strlen($b)])) { $byW[strlen($b)][] = $b; } }
	foreach($byW as $w => $l) { sort($l, SORT_STRING); $byW[$w] = $l; }
	$pos = array(4 => 0, 16 => 0); $out = array();
	while(($l = gzgets($fh)) !== false) {
		if($l === '' OR $l[0] === '#') { continue; }
		$f = explode(' ', trim($l));
		if(count($f) !== 3 OR strlen($f[0]) !== 2) { continue; }
		$a = @inet_pton($f[1]); $e = @inet_pton($f[2]);
		if($a === false OR $e === false OR strlen($a) !== strlen($e)) { continue; }
		$w = strlen($a); $list = $byW[$w]; $i = $pos[$w];
		while($i < count($list) AND strcmp($list[$i], $a) < 0) { $i++; }   // vor dem Bereich: kein Land
		while($i < count($list) AND strcmp($list[$i], $e) <= 0) { $out[$list[$i]] = $f[0]; $i++; }
		$pos[$w] = $i;
		if($pos[4] >= count($byW[4]) AND $pos[16] >= count($byW[16])) { break; }
	}
	gzclose($fh);
	return $out;
}
