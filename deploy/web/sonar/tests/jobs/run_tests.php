<?php
/**
 * Sonar64 Teil J: Pruefung der Jobs bots/sonar_plan|rollup|trust|outages|cleanup.php gegen die Testdatenbank
 * s64jobs_test (run_agentbox.sh). Erzeugt 60 Knoten und 2 Anker in 4 ASN mit einem Laufzeitmodell und 24 h Messungen,
 * darunter boesartige Knoten (geschoente Werte, erfundene Antworten, falsches Kontrollziel), WLAN-, LTE- und
 * Starlink-Knoten (duerfen nicht auffallen), Quarantaene, Opt-out, private IP; danach ein Provider-Ausfall.
 *
 *   S64J=1 php run_tests.php            (Stand: /w/web, /w/tests)
 */
if(php_sapi_name() !== 'cli' OR getenv('S64J') !== '1') { exit; }
$WEB = dirname(__DIR__) . '/web';
require $WEB . '/sonar/s64_lib.php';
$db = s64_pdo();
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pass = 0; $failed = 0;

function check(string $name, bool $ok, $info = ''): void {
	global $pass, $failed;
	if($ok) { $pass++; echo "  ok    $name\n"; }
	else { $failed++; echo "  FEHLER $name " . (is_string($info) ? $info : json_encode($info, JSON_UNESCAPED_SLASHES)) . "\n"; }
}
function job(string $name, string $args = ''): string {
	global $WEB;
	exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg("$WEB/bots/sonar_$name.php") . ' ' . $args . ' 2>&1', $out, $rc);
	$o = implode("\n", $out);
	if($rc !== 0) { echo "  (Job $name rc=$rc)\n"; }
	return $o;
}
function q(string $sql, array $p = array()): PDOStatement { global $db; $st = $db->prepare($sql); $st->execute($p); return $st; }
function all(string $sql, array $p = array()): array { return q($sql, $p)->fetchAll(PDO::FETCH_ASSOC); }
function one(string $sql, array $p = array()) { return q($sql, $p)->fetchColumn(); }
function dt(int $t): string { return gmdate('Y-m-d H:i:s', $t); }
function iso(int $t): string { return gmdate('Y-m-d\TH:i:s\Z', $t); }
/** Mehrzeiliges INSERT in Bloecken. */
function bulk(string $head, int $cols, array $rows): void {
	foreach(array_chunk($rows, 400) as $chunk) {
		q($head . ' VALUES ' . implode(',', array_fill(0, count($chunk), '(' . implode(',', array_fill(0, $cols, '?')) . ')')), array_merge(...$chunk));
	}
}
function plans(): array {
	$out = array();
	foreach(all("SELECT node_id, issued, expires, body, etag, controls FROM sonar_plans") as $r) { $r['plan'] = json_decode($r['body'], true); $out[$r['node_id']] = $r; }
	return $out;
}
function truncate(): void { foreach(array('sonar_nodes', 'sonar_plans', 'sonar_results', 'sonar_traces', 'sonar_inbound', 'sonar_pair_1h', 'sonar_asn_1d', 'sonar_outages', 'sonar_trust_log') as $t) { q("TRUNCATE $t"); } }

const T = 1761566520; // 2026-10-27 12:02:00 UTC
const H = 1761566400; // 12:00
const DAY = 86400;
$A = array('a_fsn' => array(50.47, 12.37, '5.9.1.10', '2a01:4f8:1::10'), 'a_nbg' => array(49.45, 11.08, '88.198.1.10', '2a01:4f9:1::10'));
$cities = array('Berlin' => array(52.52, 13.40), 'Hamburg' => array(53.55, 9.99), 'Muenchen' => array(48.14, 11.58), 'Frankfurt' => array(50.11, 8.68),
	'Stuttgart' => array(48.78, 9.18), 'Leipzig' => array(51.34, 12.37), 'Dresden' => array(51.05, 13.74), 'Hannover' => array(52.37, 9.73),
	'Nuernberg' => array(49.45, 11.08), 'Bremen' => array(53.08, 8.80));
$ASN = array(3320 => 'Deutsche Telekom AG', 3209 => 'Vodafone GmbH', 6805 => 'Telefonica Germany', 8881 => 'Versatel');
$ACC = array('fiber' => 1.0, 'dsl' => 8.0, 'cable' => 6.0, 'mobile' => 25.0, 'satellite' => 30.0, 'datacenter' => 0.2);

const EVIL = 'nt0000000010';   // schoent alles auf ~1 ms, sendet nichts
const FAKE = 'nt0000000011';   // plausible Werte, aber nie gesendet (Anker sehen keine Proben)
const CTL  = 'nt0000000012';   // falsches Kontrollziel
const PRIV = 'nt0000000013';   // private IP
const OPTOUT = 'nt0000000014'; // nur ausgehend
const NOICMP = 'nt0000000015'; // ICMP nicht erlaubt
const QOLD = 'nt0000000016';   // Quarantaene seit 4 Tagen, jetzt sauber
const QNEW = 'nt0000000017';   // Quarantaene seit 1 Tag
const FLAKY = 'nt0000000018';  // Verfuegbarkeit ~50 %
const OFFL = 'nt0000000019';   // seit 2 h ohne Meldung
const WIFI = 'nt0000000003';   // WLAN hinter dem Router (+25 ms eigene Messungen), Weg icmp
const LTE = 'nt0000000041';
const STAR = 'nt0000000052';

// ---------------------------------------------------------------- Testdaten
echo "Testdaten\n";
truncate();
$N = array(); // node_id => Angaben fuer das Modell
$rows = array();
foreach($A as $id => $a) {
	$rows[] = array($id, 0, 0, 'anchor', 'pk', $id, $id, $a[0], $a[1], 1, 'datacenter', 'anchor', 1, 'grosszuegig', 'anchor', $a[2], $a[3], 24940, 'Hetzner Online GmbH', 24940, 'Hetzner Online GmbH', 'Hetzner', 'none', 'none', 'anchor', dt(T - 400 * DAY), dt(T - 30), null, 1);
	$N[$id] = array('lat' => $a[0], 'lon' => $a[1], 'acc' => $ACC['datacenter'], 'reach' => 'udp', 'anchor' => true);
}
$cityNames = array_keys($cities);
for($i = 0; $i < 60; $i++) {
	$id = sprintf('nt%010d', $i);
	$asn = $i < 25 ? 3320 : ($i < 40 ? 3209 : ($i < 50 ? 6805 : 8881));
	if(($i >= 25 AND $i <= 30) OR $i === 0 OR $i === 1) { $city = 'Koeln'; $c = array(50.94, 6.96); } // Koeln: 6 Vodafone + 2 Telekom
	else { $city = $cityNames[$i % count($cityNames)]; $c = $cities[$city]; }
	$lat = $c[0] + (($i * 7) % 9 - 4) * 0.004; $lon = $c[1] + (($i * 5) % 9 - 4) * 0.004;
	$access = array('fiber', 'dsl', 'cable', 'fiber', 'dsl')[$i % 5];
	if($id === LTE) { $access = 'mobile'; } if($id === STAR) { $access = 'satellite'; }
	$trust = 'stable'; $first = T - 200 * DAY;
	if($i >= 40 AND $i < 50) { $trust = 'trusted'; }
	if($i >= 50 AND $i < 55) { $trust = 'new'; $first = T - 10 * DAY; }
	if($i >= 55) { $trust = 'new'; $first = T - 3 * DAY; }
	if($id === EVIL) { $trust = 'trusted'; }
	if($id === QOLD OR $id === QNEW) { $trust = 'quarantine'; }
	$ip4 = $id === PRIV ? '10.1.2.3' : sprintf('%d.%d.%d.%d', array(3320 => 80, 3209 => 92, 6805 => 77, 8881 => 62)[$asn], 128 + intdiv($i, 200), intdiv($i, 250) + 10, $i % 250 + 1);
	$ip6 = ($i % 3 === 0 AND $id !== PRIV) ? sprintf('2003:%x:%x::1', 4000 + $asn % 100, $i + 1) : null;
	$health = $id === NOICMP ? '{"icmp_denied":true}' : '{"icmp_denied":false}';
	$seen = $id === OFFL ? T - 7200 : T - 30;
	$rows[] = array($id, 1000 + $i, 100 + $i, 'node', 'pk', "Node $i", "node-$i", $lat, $lon, $i, $access, 'linux', $id === OPTOUT ? 0 : 1, array('sparsam', 'normal', 'grosszuegig')[$i % 3], 'headless',
		$ip4, $ip6, $asn, $ASN[$asn], $ip6 !== null ? $asn : null, $ip6 !== null ? $ASN[$asn] : null, $city, 'none', 'none', $trust, dt($first), dt($seen), $health, 1);
	$N[$id] = array('lat' => $lat, 'lon' => $lon, 'acc' => $ACC[$access], 'reach' => ($i % 4 === 0 OR $id === WIFI) ? 'icmp' : 'udp', 'anchor' => false, 'asn' => $asn, 'i' => $i, 'v6' => $ip6 !== null);
}
bulk("INSERT INTO sonar_nodes (node_id, userid, token_id, role, pubkey, name, slug, lat, lon, jitter_seed, access, device, measured, budget, mode, ip4, ip6, asn4, asname4, asn6, asname6, place, reach4, reach6, trust, first_seen, last_seen, health, active)", 29, $rows);
q("INSERT INTO sonar_trust_log (node_id, at, old, new, reason) VALUES (?, ?, 'stable', 'quarantine', 'implausible_24h'), (?, ?, 'stable', 'quarantine', 'implausible_24h')",
	array(QOLD, dt(T - 4 * DAY), QNEW, dt(T - DAY)));
check('62 Knoten angelegt', (int)one("SELECT COUNT(*) FROM sonar_nodes") === 62);

/** Modell-RTT (ms) von $s nach $d per $method; WLAN-Knoten misst selbst +25 ms (nur am Router gemessen: Hin/Zurueck ungleich). */
function rtt(string $s, string $d, string $method, int $round): float {
	global $N;
	$km = s64_distance_km($N[$s]['lat'], $N[$s]['lon'], $N[$d]['lat'], $N[$d]['lon']);
	$v = $km / 100 * 1.5 + $N[$s]['acc'] + $N[$d]['acc'] + 2 + ($s === WIFI ? 25 : 0);
	return round($v * (1 + ((crc32("$s|$d|$round") % 81) - 40) / 1000), 3);
}
$ids = array_values(array_filter(array_keys($N), function($x) use ($N) { return !$N[$x]['anchor']; }));
$res = array(); $inb = array();
$add = function(int $r, string $s, string $d, int $fam, string $method, int $recv, float $avg) use (&$res) {
	$at = $r + 30 + crc32("at|$s|$d|$r") % 200;
	$res[] = array(dt($r), $s, $d, $fam, $method, 5, $recv, $avg ? round($avg * 0.96, 3) : 0, $avg, $avg ? round($avg * 1.08, 3) : 0, $avg ? 0.4 : 0, dt($at), 1, null);
};
$t0 = microtime(true);
for($r = H - DAY; $r <= H; $r += 300) {
	if($r >= H - DAY + 3600) { // Anker untereinander
		$add($r, 'a_fsn', 'a_nbg', 4, 'udp', 3, rtt('a_fsn', 'a_nbg', 'udp', $r));
		$add($r, 'a_nbg', 'a_fsn', 4, 'udp', 3, rtt('a_nbg', 'a_fsn', 'udp', $r));
	}
	foreach($ids as $k => $s) {
		if($s === PRIV OR ($s === OFFL AND $r > T - 7200) OR ($s === FLAKY AND intdiv($r, 3600) % 2 === 1)) { continue; }
		foreach(array_keys($A) as $a) {
			// Knoten -> Anker (udp), Anker beantwortet und meldet die Proben
			$v = $s === EVIL ? 1.1 : rtt($s, $a, 'udp', $r);
			$add($r, $s, $a, 4, 'udp', 5, $v);
			if($s !== EVIL AND !($s === FAKE AND $a === 'a_nbg')) { $inb[] = array($a, s64_short_id($s), 4, dt($r + 240), 5); }
			// Anker -> Knoten auf dem bekannten Weg
			if($s !== OPTOUT) { $add($r, $a, $s, 4, $N[$s]['reach'], 3, rtt($a, $s, $N[$s]['reach'], $r)); }
		}
		// Knoten -> +-3 Nachbarn in der Liste (gegenseitig)
		for($o = -3; $o <= 3; $o++) {
			$d = $ids[($k + $o + 60) % 60];
			if($o === 0 OR $d === PRIV OR $d === OPTOUT) { continue; }
			$v = $s === EVIL ? 1.2 : rtt($s, $d, $N[$d]['reach'], $r);
			$add($r, $s, $d, 4, $N[$d]['reach'], 5, $v);
		}
	}
	if($r === H - 3000) { $add($r, CTL, 'a_fsn', 4, 'icmp', 5, 1.0); } // Kontrollziel: falsch
	if(count($res) >= 4000) { bulk("INSERT INTO sonar_results (`round`, src, dst, fam, method, sent, recv, min_ms, avg_ms, max_ms, jitter_ms, at, valid, reason)", 14, $res); $res = array(); }
}
bulk("INSERT INTO sonar_results (`round`, src, dst, fam, method, sent, recv, min_ms, avg_ms, max_ms, jitter_ms, at, valid, reason)", 14, $res);
bulk("INSERT INTO sonar_inbound (node_id, from_short, fam, at, `count`)", 5, $inb);
// aeltere Stunden (30 Tage) fuer die Verfuegbarkeit: eine Zeile je Stunde und Knoten (FLAKY nur jede zweite)
$pr = array();
for($h = H - 30 * DAY; $h < H - DAY; $h += 3600) {
	foreach($ids as $s) {
		if($s === PRIV OR ($s === FLAKY AND intdiv($h, 3600) % 2 === 1) OR ($s >= 'nt0000000050' AND $s < 'nt0000000055' AND $h < T - 10 * DAY) OR ($s >= 'nt0000000055' AND $h < T - 3 * DAY)) { continue; }
		$pr[] = array($s, 'a_fsn', 4, dt($h), 12, 15.0, 15.0, 0.0);
	}
	if(count($pr) >= 4000) { bulk("INSERT INTO sonar_pair_1h (src, dst, fam, hour, n, avg_ms, p50_ms, loss)", 8, $pr); $pr = array(); }
}
bulk("INSERT INTO sonar_pair_1h (src, dst, fam, hour, n, avg_ms, p50_ms, loss)", 8, $pr);
printf("  %d Ergebnisse, %d Proben, %d Stundenwerte in %.1f s\n", one("SELECT COUNT(*) FROM sonar_results"), one("SELECT COUNT(*) FROM sonar_inbound"), one("SELECT COUNT(*) FROM sonar_pair_1h"), microtime(true) - $t0);

// ---------------------------------------------------------------- Planer
echo "Planer\n";
$out = job('plan', '--now=' . iso(T));
echo "  $out\n";
check('Planer laeuft', str_contains($out, 'Plaene'), $out);
$reach = array();
foreach(all("SELECT node_id, reach4, reach6 FROM sonar_nodes") as $r) { $reach[$r['node_id']] = $r; }
check('Erreichbarkeit udp aus Anker-Messungen', $reach['nt0000000001']['reach4'] === 'udp', $reach['nt0000000001']);
check('Erreichbarkeit icmp (nur Router)', $reach[WIFI]['reach4'] === 'icmp' AND $reach['nt0000000004']['reach4'] === 'icmp', $reach[WIFI]);
check('Opt-out: Weg none', $reach[OPTOUT]['reach4'] === 'none');
check('ohne IPv6: reach6 none', $reach['nt0000000001']['reach6'] === 'none');
$P = plans();
$online = array_diff(array_merge($ids, array_keys($A)), array(PRIV, OFFL));
check('Plan fuer jeden Knoten online (ausser private IP)', count(array_diff($online, array_keys($P))) === 0 AND !isset($P[PRIV]) AND !isset($P[OFFL]), array_values(array_diff($online, array_keys($P))));

$nodeRows = array();
foreach(all("SELECT * FROM sonar_nodes") as $r) { $nodeRows[$r['node_id']] = $r; }
/** Pruefung aller Plaene: Grenzen, Ziele, Format. */
function check_plans(array $P, string $tag): void {
	global $nodeRows, $A;
	$errs = array(); $cnt = array(); $cntAd = array(); $anchorsIn = 0; $nodesCnt = 0;
	foreach($P as $m => $pl) {
		$p = $pl['plan'];
		if(($p['v'] ?? 0) !== 1 OR ($p['node_id'] ?? '') !== $m) { $errs[] = "$m Kopf"; continue; }
		$iss = strtotime($p['issued']); $exp = strtotime($p['expires']);
		if($exp - $iss !== 1800) { $errs[] = "$m expires"; }
		if(substr(hash('sha256', $pl['body']), 0, 16) !== $pl['etag']) { $errs[] = "$m etag"; }
		$isA = $nodeRows[$m]['role'] === 'anchor';
		$budget = $isA ? 2000 : array('sparsam' => 8, 'normal' => 15, 'grosszuegig' => 20)[$nodeRows[$m]['budget']];
		if(count($p['rounds']) < 1 OR count($p['rounds']) > 7) { $errs[] = "$m Runden " . count($p['rounds']); }
		foreach($p['rounds'] as $rd) {
			$s = strtotime($rd['start']);
			if($s % 300 !== 0) { $errs[] = "$m Raster"; }
			if(count($rd['targets']) > $budget) { $errs[] = "$m Budget " . count($rd['targets']) . ">$budget"; }
			$hasA = array(); $addrIn = array();
			$traces = 0;
			foreach($rd['targets'] as $t) {
				$d = $nodeRows[$t['id']] ?? null;
				if($d === null) { $errs[] = "$m unbekannt {$t['id']}"; continue; }
				if($t['addr'] !== $d['ip' . $t['fam']]) { $errs[] = "$m Adresse {$t['id']}"; }
				if(!s64_is_public_ip($t['addr'])) { $errs[] = "$m privat {$t['addr']}"; }
				if($t['id'] === $m) { $errs[] = "$m sich selbst"; }
				if($t['count'] < 1 OR $t['count'] > 5) { $errs[] = "$m count"; }
				if($t['method'] === 'trace') { $traces++; if(($t['max_ttl'] ?? 0) < 1 OR $t['max_ttl'] > 30) { $errs[] = "$m ttl"; } }
				if($d['role'] === 'anchor') { $hasA[$t['id']] = true; continue; }
				if((int)$d['measured'] !== 1) { $errs[] = "$m misst Opt-out {$t['id']}"; }
				if(!$isA AND $d['trust'] === 'quarantine') { $errs[] = "$m misst Quarantaene {$t['id']}"; }
				if(!$isA AND $t['method'] !== 'trace' AND $t['method'] !== $d['reach' . $t['fam']]) { $errs[] = "$m Methode {$t['id']} {$t['method']}"; }
				if(!$isA) { $cnt[$s][$t['id']][$m] = true; $cntAd[$s][$t['addr']][$m] = true; $nodesCnt++; }
				if(!$isA AND isset($addrIn[$t['addr']]) AND $addrIn[$t['addr']] !== $t['id']) { $errs[] = "$m Adresse doppelt {$t['addr']}"; }
				$addrIn[$t['addr']] = $t['id'];
				if(str_contains((string)$nodeRows[$m]['health'], '"icmp_denied":true') AND $t['method'] !== 'udp') { $errs[] = "$m icmp trotz Verbot"; }
			}
			if($traces > 1) { $errs[] = "$m mehrere Traces in einer Runde"; }
			if(!$isA AND count($hasA) === 2) { $anchorsIn++; }
		}
	}
	$maxPer = 0;
	foreach($cnt as $s => $byT) { foreach($byT as $t => $ms) { $maxPer = max($maxPer, count($ms)); } }
	check("$tag: Grenzen, Adressen, keine privaten/Opt-out/Quarantaene-Ziele", $errs === array(), array_slice(array_unique($errs), 0, 8));
	check("$tag: je Ziel und Runde hoechstens 10 Messende (max $maxPer)", $maxPer <= 10 AND $maxPer > 0);
	$maxAd = 0;
	foreach($cntAd as $s => $byA) { foreach($byA as $ad => $ms) { $maxAd = max($maxAd, count($ms)); } }
	check("$tag: je Adresse und Runde hoechstens 10 Messende (max $maxAd)", $maxAd <= 10 AND $maxAd > 0);
	check("$tag: Knoten messen beide Anker", $anchorsIn > 0);
	check("$tag: Knoten messen Knoten ($nodesCnt)", $nodesCnt > 0);
}
check_plans($P, 'Plan T');
$pa = $P['a_fsn']['plan'];
$aT = array(); foreach($pa['rounds'][0]['targets'] as $t) { $aT[$t['id']] = $t['method']; }
check('Anker misst gemessene Knoten, auch ohne Meldung seit 2 h und in Quarantaene', isset($aT['nt0000000002'], $aT[OFFL], $aT[QOLD]) AND !isset($aT[OPTOUT]) AND !isset($aT[PRIV]), array_keys($aT));
check('Anker misst den anderen Anker', isset($aT['a_nbg']));
$p1 = $P['nt0000000001']['plan'];
check('Rueckfall-Anker im Plan', count($p1['anchors']) >= 2 AND $p1['anchors'][0]['method'] === 'udp');
check('6 Runden ab der naechsten', count($p1['rounds']) === 6 AND strtotime($p1['rounds'][0]['start']) === H + 300, array_column($p1['rounds'], 'start'));
$koeln = array(); foreach($p1['rounds'][0]['targets'] as $t) { $koeln[] = $t['id']; }
check('Nachbarn: Koelner Knoten misst Koelner Knoten', count(array_intersect($koeln, array('nt0000000000', 'nt0000000025', 'nt0000000026', 'nt0000000027', 'nt0000000028', 'nt0000000029', 'nt0000000030'))) >= 2, $koeln);

// Stabil: zweiter Lauf 5 min spaeter laesst geplante Runden unveraendert und haengt eine an
q("UPDATE sonar_nodes SET last_seen = ? WHERE node_id <> ?", array(dt(T + 270), OFFL));
job('plan', '--now=' . iso(T + 300));
$P2 = plans();
/** Ziele einer Runde als "Ziel|fam|Methode". */
function tkeys(array $targets): array { return array_map(function($t) { return $t['id'] . '|' . $t['fam'] . '|' . $t['method']; }, $targets); }
/** Vergleich zweier Planstaende: Runden in beiden -> [gleich, nur ergaenzt, Ziel verloren]. */
function stable(array $A, array $B): array {
	$same = 0; $added = 0; $lost = 0;
	foreach($A as $m => $pl) {
		if(!isset($B[$m])) { continue; }
		$old = array(); foreach($pl['plan']['rounds'] as $rd) { $old[$rd['start']] = $rd['targets']; }
		foreach($B[$m]['plan']['rounds'] as $rd) {
			if(!isset($old[$rd['start']])) { continue; }
			if($old[$rd['start']] === $rd['targets']) { $same++; }
			elseif(array_slice($rd['targets'], 0, count($old[$rd['start']])) === $old[$rd['start']]) { $added++; }
			else { $lost++; }
		}
	}
	return array($same, $added, $lost);
}
[$same, $added, $lost] = stable($P, $P2);
check("Runden bleiben stabil: vorhandene Ziele bleiben ($same gleich, $added ergaenzt, $lost verloren)", $lost === 0 AND $same > 0);
$r2 = array_column($P2['nt0000000001']['plan']['rounds'], 'start');
check('laufende Runde bleibt, eine neue angehaengt', $r2 === array_map('iso', range(H + 300, H + 7 * 300, 300)), $r2);

// Opt-out wirkt sofort, auch in schon geplanten Runden
q("UPDATE sonar_nodes SET measured = 0 WHERE node_id = 'nt0000000002'");
q("UPDATE sonar_nodes SET last_seen = ? WHERE node_id <> ?", array(dt(T + 570), OFFL));
q("UPDATE sonar_nodes SET last_seen = ? WHERE node_id = 'nt0000000005'", array(dt(T + 600 - 1000))); // seit > 15 min still
job('plan', '--now=' . iso(T + 600));
$st5 = all("SELECT issued, expires FROM sonar_plans WHERE node_id = 'nt0000000005'")[0] ?? null;
check('nicht neu geplanter Plan (Knoten offline) wird nicht mehr ausgeliefert', $st5 !== null AND strtotime($st5['expires'] . ' UTC') <= T + 600, $st5);
$hit = 0;
foreach(plans() as $m => $pl) { if(strtotime($pl['expires'] . ' UTC') <= T + 600) { continue; } foreach($pl['plan']['rounds'] as $rd) { foreach($rd['targets'] as $t) { if($t['id'] === 'nt0000000002') { $hit++; } } } }
check('Opt-out: Knoten in keinem Plan mehr', $hit === 0, $hit);
q("UPDATE sonar_nodes SET measured = 1 WHERE node_id = 'nt0000000002'");

// Auffuellen (Vertrag 10.1): neuer gemessener Knoten X (Weg bekannt, z. B. durch die Sofortstufe der API, noch von keinem
// Knoten gemessen) und frisch angemeldeter Knoten Y; zweiter Lauf zum selben Zeitpunkt haengt keine Runde an, fuellt nur auf
$X = 'nt0000000099'; $Y = 'nt0000000098';
$before = plans();
q("UPDATE sonar_nodes SET budget = 'grosszuegig' WHERE node_id IN ('nt0000000021', 'nt0000000022')"); // freie Plaetze sicher
q("INSERT INTO sonar_nodes (node_id, userid, token_id, role, pubkey, name, slug, lat, lon, jitter_seed, access, device, measured, budget, mode, ip4, asn4, asname4, place, reach4, reach6, trust, first_seen, last_seen, health, active) VALUES
	(?, 1099, 199, 'node', 'pk', 'Node X', 'node-x', 52.51, 13.39, 99, 'fiber', 'pi', 1, 'normal', 'headless', '80.250.0.99', 3320, 'Deutsche Telekom AG', 'Berlin', 'udp', 'none', 'new', ?, ?, '{}', 1),
	(?, 1098, 198, 'node', 'pk', 'Node Y', 'node-y', 48.14, 11.58, 98, 'dsl', 'pi', 0, 'sparsam', 'headless', '80.250.0.98', 3320, 'Deutsche Telekom AG', 'Muenchen', 'none', 'none', 'new', ?, ?, NULL, 1)",
	array($X, dt(T + 400), dt(T + 590), $Y, dt(T + 590), dt(T + 590)));
$out = job('plan', '--now=' . iso(T + 600));
echo "  $out\n";
$P3 = plans();
$nodeRows = array(); foreach(all("SELECT * FROM sonar_nodes") as $r) { $nodeRows[$r['node_id']] = $r; }
check_plans(array_filter($P3, function($pl) { return strtotime($pl['expires'] . ' UTC') > T + 600; }), 'Plan aufgefuellt');
preg_match('/aufgefuellt (\d+)\), .*\(neu (\d+)\)/', $out, $mf);
check('Lauf meldet aufgefuellte Runden und neue Ziele', (int)($mf[1] ?? 0) > 0 AND (int)($mf[2] ?? 0) === 1, $out);
[$same, $added, $lost] = stable($before, $P3);
check("auffuellen: vorhandene Ziele bleiben ($same gleich, $added ergaenzt, $lost verloren)", $lost === 0 AND $added > 0);
$curR = iso(intdiv(T + 600, 300) * 300); $curSame = 0; $curDiff = 0;
foreach($before as $m => $pl) {
	$o = null; foreach($pl['plan']['rounds'] as $rd) { if($rd['start'] === $curR) { $o = $rd['targets']; } }
	if($o === null OR !isset($P3[$m])) { continue; }
	foreach($P3[$m]['plan']['rounds'] as $rd) { if($rd['start'] === $curR) { $rd['targets'] === $o ? $curSame++ : $curDiff++; } }
}
check("laufende Runde unveraendert ($curSame)", $curDiff === 0 AND $curSame > 0);
$xBy = array(); // Runde => Messende von X (ohne Anker), nur schon vorher geplante Runden
foreach($P3 as $m => $pl) {
	if(str_starts_with($m, 'a_')) { continue; }
	$had = array(); foreach($before[$m]['plan']['rounds'] ?? array() as $rd) { $had[$rd['start']] = true; }
	foreach($pl['plan']['rounds'] as $rd) { if(isset($had[$rd['start']]) AND in_array($X, array_column($rd['targets'], 'id'), true)) { $xBy[$rd['start']][$m] = true; } }
}
$xMax = $xBy ? max(array_map('count', $xBy)) : 0;
check('neues Ziel X sofort in schon geplanten kommenden Runden (' . count($xBy) . ' Runden, bis ' . $xMax . ' Messende)', count($xBy) >= 5 AND $xMax >= 3 AND $xMax <= 10 AND !isset($xBy[$curR]), array_map('count', $xBy));
$ax = 0; $ay = 0;
foreach(array('a_fsn', 'a_nbg') as $a) {
	foreach($P3[$a]['plan']['rounds'] as $rd) {
		if($rd['start'] === $curR) { continue; }
		$ids3 = array_column($rd['targets'], 'id');
		if(in_array($X, $ids3, true)) { $ax++; }
		if(in_array($Y, $ids3, true)) { $ay++; }
	}
}
check("Anker messen X in allen kommenden Runden ($ax von 12), Y (nur ausgehend) nicht", $ax === 12 AND $ay === 0, array($ax, $ay));
check('frisch angemeldeter Knoten Y hat gleich einen Plan (6 Runden)', isset($P3[$Y]) AND count($P3[$Y]['plan']['rounds']) === 6 AND strtotime($P3[$Y]['expires'] . ' UTC') > T + 600, $P3[$Y]['plan']['rounds'] ?? null);
q("DELETE FROM sonar_nodes WHERE node_id IN (?, ?)", array($X, $Y));
q("DELETE FROM sonar_plans WHERE node_id IN (?, ?)", array($X, $Y));
q("UPDATE sonar_nodes SET budget = 'sparsam' WHERE node_id = 'nt0000000021'");
q("UPDATE sonar_nodes SET budget = 'normal' WHERE node_id = 'nt0000000022'");
$nodeRows = array(); foreach(all("SELECT * FROM sonar_nodes") as $r) { $nodeRows[$r['node_id']] = $r; }

// eine Stunde: Traceroute hoechstens 2 je Knoten und Stunde, Kontrollziele
$slots = array(); // Knoten => Runde => Ziele (letzter Stand)
for($k = 3; $k <= 14; $k++) {
	q("UPDATE sonar_nodes SET last_seen = ? WHERE node_id <> ?", array(dt(T + $k * 300 - 30), OFFL));
	job('plan', '--now=' . iso(T + $k * 300));
	foreach(plans() as $m => $pl) { foreach($pl['plan']['rounds'] as $rd) { $slots[$m][$rd['start']] = $rd['targets']; } }
	if($k === 3) { $ctlRows = all("SELECT node_id, controls FROM sonar_plans WHERE controls <> '[]'"); }
}
$P = plans();
check_plans($P, 'Plan T+70min');
$tr = array(); $ctl = 0;
foreach($slots as $m => $byRound) {
	foreach($byRound as $start => $targets) {
		$h = intdiv(strtotime($start), 3600);
		foreach($targets as $t) {
			if($t['method'] === 'trace') { $tr[$m][$h] = ($tr[$m][$h] ?? 0) + 1; }
			if($t['method'] === 'icmp' AND str_starts_with($t['id'], 'a_') AND !str_starts_with($m, 'a_')) { $ctl++; }
		}
	}
}
$maxTr = 0; foreach($tr as $m => $byH) { $maxTr = max($maxTr, max($byH)); }
check("Traceroute hoechstens 2 je Knoten und Stunde (max $maxTr, Knoten mit Trace " . count($tr) . ")", $maxTr <= 2 AND count($tr) > 20);
check("Kontrollziele vorhanden ($ctl Anker per icmp) und in controls vermerkt", $ctl > 0 AND count($ctlRows) > 0);
$cj = json_decode($ctlRows[0]['controls'] ?? '[]', true);
check('controls: Runde und Anker-ID', is_array($cj) AND isset($cj[0]['round'], $cj[0]['id']) AND str_starts_with($cj[0]['id'], 'a_'), $cj);
$noicmp = 0; foreach($slots[NOICMP] ?? array() as $targets) { foreach($targets as $t) { if($t['method'] !== 'udp') { $noicmp++; } } }
check('ohne ICMP-Recht nur udp-Ziele', $noicmp === 0 AND isset($slots[NOICMP]));
$out = job('plan', '--dry --now=' . iso(T + 15 * 300));
check('--dry schreibt nicht', str_starts_with($out, 'NUR ANZEIGEN') AND (int)one("SELECT COUNT(*) FROM sonar_plans WHERE issued > ?", array(dt(T + 14 * 300))) === 0, $out);
// Zustand fuer die weiteren Teile zuruecksetzen
q("UPDATE sonar_nodes SET last_seen = ? WHERE node_id <> ?", array(dt(T - 30), OFFL));
q("DELETE FROM sonar_plans");

// ---------------------------------------------------------------- Verdichtung
echo "Verdichtung\n";
$out = job('rollup', '--now=' . iso(T));
echo "  $out\n";
check('24 Stunden verdichtet', str_contains($out, 'Stunden neu 24'), $out);
$h2 = H - 7200;
$vals = array_map('floatval', all("SELECT avg_ms FROM sonar_results WHERE src = 'nt0000000005' AND dst = 'nt0000000006' AND at >= ? AND at < ? AND valid = 1", array(dt($h2), dt($h2 + 3600))) ? array_column(all("SELECT avg_ms FROM sonar_results WHERE src = 'nt0000000005' AND dst = 'nt0000000006' AND at >= ? AND at < ? AND valid = 1", array(dt($h2), dt($h2 + 3600))), 'avg_ms') : array());
$row = all("SELECT * FROM sonar_pair_1h WHERE src = 'nt0000000005' AND dst = 'nt0000000006' AND hour = ?", array(dt($h2)))[0] ?? null;
check('Paar-Stunde: n, Median, Verlust', $row !== null AND (int)$row['n'] === count($vals) AND abs((float)$row['p50_ms'] - s64_median($vals)) < 0.01 AND (float)$row['loss'] == 0.0, array($row, count($vals), s64_median($vals)));
$asn = all("SELECT * FROM sonar_asn_1d WHERE asn_a = 3320 AND asn_b = 3209 AND fam = 4");
check('ASN-Tag 3320 -> 3209', count($asn) >= 1 AND (float)$asn[0]['p50_ms'] > 1 AND (int)$asn[0]['n'] > 10, $asn);
check('ASN-Tag Anker (24940) dabei', (int)one("SELECT COUNT(*) FROM sonar_asn_1d WHERE asn_a = 24940") > 0);
check('Quarantaene zaehlt nicht', (int)one("SELECT COUNT(*) FROM sonar_pair_1h WHERE src IN (?, ?) AND hour >= ?", array(QOLD, QNEW, dt(H - DAY))) === 0);
$out = job('rollup', '--now=' . iso(T));
check('mehrfach ausfuehrbar (nichts neu)', str_contains($out, 'Stunden neu 0'), $out);

// ---------------------------------------------------------------- Vertrauen stuendlich
echo "Vertrauen (stuendlich, 24 h nachholen)\n";
// Anker-Meldung unvollstaendig (Grenze im Antworter): a_fsn fehlen in einer Stunde die Proben von 70 % der Knoten
$hx = H - 5 * 3600;
$drop = array(); foreach($ids as $s) { if(crc32("drop|$s") % 10 < 7) { $drop[] = s64_short_id($s); } }
q("DELETE FROM sonar_inbound WHERE node_id = 'a_fsn' AND at >= ? AND at < ? AND from_short IN (" . implode(',', array_fill(0, count($drop), '?')) . ")",
	array_merge(array(dt($hx - 600), dt($hx + 4200)), $drop));
$pb = (int)one("SELECT plaus_bad FROM sonar_nodes WHERE node_id = ?", array(EVIL));
// Teil A speichert below_light gegen Ziele mit unsicherem Standort (new/stable) mit valid=0, das zaehlt nicht
q("UPDATE sonar_results SET valid = 0, reason = 'below_light' WHERE src = 'nt0000000021' AND dst LIKE 'nt%'");
$out = job('trust', '--hours=24 --now=' . iso(T));
echo '  ' . str_replace("\n", "\n  ", $out) . "\n";
$flag = array();
foreach(all("SELECT src, reason, COUNT(*) c FROM sonar_results WHERE valid = 0 AND reason IN ('anchor_truth', 'inbound', 'control', 'asym') GROUP BY src, reason") as $r) { $flag[$r['src']][$r['reason']] = (int)$r['c']; }
check('geschoente Werte: Anker-Wahrheit', ($flag[EVIL]['anchor_truth'] ?? 0) > 100, $flag[EVIL] ?? null);
check('geschoente Werte: Hin/Zurueck (Mehrheit)', ($flag[EVIL]['asym'] ?? 0) > 100, $flag[EVIL] ?? null);
check('erfundene Antworten: Proben der Anker fehlen', ($flag[FAKE]['inbound'] ?? 0) > 100, $flag[FAKE] ?? null);
check('falsches Kontrollziel', ($flag[CTL]['control'] ?? 0) >= 1, $flag[CTL] ?? null);
$honest = array_diff(array_keys($flag), array(EVIL, FAKE, CTL));
check('ehrliche Knoten (WLAN, LTE, Starlink, Router-Weg) ohne Befund', $honest === array(), array_intersect_key($flag, array_flip($honest)));
$tr = array(); foreach(all("SELECT node_id, trust FROM sonar_nodes") as $r) { $tr[$r['node_id']] = $r['trust']; }
check('boesartig -> Quarantaene', $tr[EVIL] === 'quarantine', $tr[EVIL]);
check('erfundene Antworten zu einem Anker (17 %) -> eine Stufe ab', $tr[FAKE] === 'new', $tr[FAKE]);
check('Kontrollziel allein: keine Abstufung', $tr[CTL] === 'stable', $tr[CTL]);
check('below_light gegen unsichere Ziele: keine Abstufung', $tr['nt0000000021'] === 'stable', $tr['nt0000000021']);
check('Quarantaene nach 72 h sauber -> new', $tr[QOLD] === 'new', $tr[QOLD]);
check('Quarantaene seit 1 Tag bleibt', $tr[QNEW] === 'quarantine', $tr[QNEW]);
check('stuendlich kein Aufstieg', $tr['nt0000000050'] === 'new' AND $tr['nt0000000020'] === 'stable');
check('plaus_bad erhoeht', (int)one("SELECT plaus_bad FROM sonar_nodes WHERE node_id = ?", array(EVIL)) > $pb);
$lg = all("SELECT node_id, old, new, reason FROM sonar_trust_log WHERE at = ?", array(dt(T) . '.000'));
check('Vertrauens-Log', count($lg) === 3, $lg);
$out = job('trust', '--hours=24 --now=' . iso(T));
check('mehrfach ausfuehrbar (nichts neu)', str_contains($out, 'verworfen 0, Stufen geaendert 0'), $out);
$out = job('rollup', '--now=' . iso(T));
check('Verdichtung rechnet nach Befunden neu', !str_contains($out, 'Stunden neu 0') AND (int)one("SELECT COUNT(*) FROM sonar_pair_1h WHERE src = ? AND hour >= ?", array(EVIL, dt(H - DAY))) === 0, $out);

// ---------------------------------------------------------------- Vertrauen taeglich
echo "Vertrauen (taeglich)\n";
$out = job('trust', '--full --now=' . iso(T));
echo '  ' . str_replace("\n", "\n  ", $out) . "\n";
$n = array(); foreach(all("SELECT node_id, trust, uptime30, score FROM sonar_nodes") as $r) { $n[$r['node_id']] = $r; }
check('Verfuegbarkeit ~1 bei durchgehenden Knoten', (float)$n['nt0000000020']['uptime30'] > 0.99, $n['nt0000000020']);
check('Verfuegbarkeit ~0,5 bei FLAKY', abs((float)$n[FLAKY]['uptime30'] - 0.5) < 0.05, $n[FLAKY]);
check('FLAKY: Bedingungen nicht erfuellt -> new', $n[FLAKY]['trust'] === 'new', $n[FLAKY]);
check('stable 200 Tage -> trusted (eine Stufe)', $n['nt0000000020']['trust'] === 'trusted', $n['nt0000000020']);
$pillars = count(array_filter($n, function($r) { return $r['trust'] === 'pillar'; }));
check("trusted 200 Tage, gemessen -> pillar ($pillars von 10)", $pillars >= 8, $pillars);
check('new 10 Tage -> stable', $n['nt0000000050']['trust'] === 'stable', $n['nt0000000050']);
check('new 3 Tage bleibt new', $n['nt0000000056']['trust'] === 'new', $n['nt0000000056']);
check('Opt-out wird nie pillar, aber trusted', $n[OPTOUT]['trust'] === 'trusted', $n[OPTOUT]);
check('WLAN/LTE/Starlink nicht abgestuft', !in_array($n[WIFI]['trust'], array('new', 'quarantine'), true) AND $n[LTE]['trust'] === 'pillar' AND $n[STAR]['trust'] === 'stable', array($n[WIFI]['trust'], $n[LTE]['trust'], $n[STAR]['trust']));
check('keine Median-Abstufung ehrlicher Knoten', (int)one("SELECT COUNT(*) FROM sonar_trust_log WHERE reason = 'median'") === 0);
check('score 0..1, Anker 1, Quarantaene 0', (float)$n['a_fsn']['score'] === 1.0 AND (float)$n[QNEW]['score'] === 0.0 AND (float)$n['nt0000000020']['score'] > 0.8 AND (float)$n['nt0000000020']['score'] <= 1.0, array($n['a_fsn']['score'], $n[QNEW]['score'], $n['nt0000000020']['score']));
$out = job('trust', '--full --now=' . iso(T + 3600));
check('Aufstieg hoechstens eine Stufe je 24 h', str_contains($out, 'Stufen geaendert 0'), $out);
check('below_light vor dem Aufstieg der Ziele zaehlt weiter nicht (bleibt stable, ohne Median-Belege kein trusted)', one("SELECT trust FROM sonar_nodes WHERE node_id = 'nt0000000021'") === 'stable');

// ---------------------------------------------------------------- Stoerungen
echo "Stoerungen\n";
$out = job('outages', '--now=' . iso(T));
echo "  $out\n";
check('ohne Ausfall keine Stoerung', (int)one("SELECT COUNT(*) FROM sonar_outages") === 0, $out);
$vf = array(); for($i = 25; $i < 40; $i++) { $vf[] = sprintf('nt%010d', $i); }
$tf = array(); for($i = 40; $i < 50; $i++) { $tf[] = sprintf('nt%010d', $i); }
$inV = implode(',', array_fill(0, count($vf), '?'));
$win = array(dt(T - 900));
$u = $db->prepare("UPDATE sonar_results SET recv = ?, avg_ms = ? WHERE id = ?");
$saveV = all("SELECT id, recv, avg_ms FROM sonar_results WHERE src LIKE 'a\_%' AND dst IN ($inV) AND at >= ?", array_merge($vf, $win));
$restoreV = function() use ($saveV, $u) { foreach($saveV as $b) { $u->execute(array($b['recv'], $b['avg_ms'], $b['id'])); } };
q("UPDATE sonar_results SET recv = 0, avg_ms = 0 WHERE src LIKE 'a\\_%' AND dst IN ($inV) AND at >= ?", array_merge($vf, $win));
$out = job('outages', '--now=' . iso(T));
echo '  ' . str_replace("\n", "\n  ", $out) . "\n";
$o = all("SELECT * FROM sonar_outages WHERE ended IS NULL");
$ok = array(); foreach($o as $r) { $ok[$r['kind'] . '|' . $r['keyval']] = $r; }
check('Provider-Ausfall: ASN 3209 offen', isset($ok['asn|3209']) AND (int)$ok['asn|3209']['total'] === 15 AND (int)$ok['asn|3209']['affected'] === 15 AND $ok['asn|3209']['label'] === 'Vodafone GmbH', $o);
check('Region Koeln offen (6 von 8)', isset($ok['region|50.5,6.5']) AND $ok['region|50.5,6.5']['label'] === 'Koeln', $o);
check('andere Provider nicht', !isset($ok['asn|3320']) AND !isset($ok['asn|6805']), array_keys($ok));
job('outages', '--now=' . iso(T + 60));
check('zweiter Lauf: keine doppelte Stoerung', (int)one("SELECT COUNT(*) FROM sonar_outages") === count($o));
$restoreV();
$out = job('outages', '--verbose --now=' . iso(T + 120));
check('Ende bei < 20 % betroffen', (int)one("SELECT COUNT(*) FROM sonar_outages WHERE ended IS NULL") === 0 AND (int)one("SELECT COUNT(*) FROM sonar_outages WHERE ended IS NOT NULL") === count($o), $out);
$id3209 = (int)one("SELECT id FROM sonar_outages WHERE kind = 'asn' AND keyval = '3209'");
q("UPDATE sonar_results SET recv = 0, avg_ms = 0 WHERE src LIKE 'a\\_%' AND dst IN ($inV) AND at >= ?", array_merge($vf, $win));
job('outages', '--now=' . iso(T + 180));
check('binnen 15 min wieder: dieselbe Stoerung', (int)one("SELECT COUNT(*) FROM sonar_outages WHERE kind = 'asn' AND keyval = '3209'") === 1 AND one("SELECT ended FROM sonar_outages WHERE id = ?", array($id3209)) === null);
$restoreV();
job('outages', '--now=' . iso(T + 240));
$before = (int)one("SELECT COUNT(*) FROM sonar_outages");
$backup = all("SELECT id, recv, avg_ms FROM sonar_results WHERE src LIKE 'a\\_%' AND at >= ?", $win);
q("UPDATE sonar_results SET recv = 0 WHERE src LIKE 'a\\_%' AND at >= ?", $win);
$out = job('outages', '--now=' . iso(T + 300));
check('alles weg = Anker gestoert: keine Stoerung', str_contains($out, 'Anker-Seite') AND (int)one("SELECT COUNT(*) FROM sonar_outages WHERE ended IS NULL") === 0 AND (int)one("SELECT COUNT(*) FROM sonar_outages") === $before, $out);
foreach($backup as $b) { $u->execute(array($b['recv'], $b['avg_ms'], $b['id'])); }
$inT = implode(',', array_fill(0, count($tf), '?'));
q("UPDATE sonar_results SET avg_ms = avg_ms * 10 WHERE src LIKE 'a\\_%' AND dst IN ($inT) AND at >= ?", array_merge($tf, $win));
$out = job('outages', '--now=' . iso(T + 360));
check('Latenz > 3x Wochenmittel: ASN 6805 offen', (int)one("SELECT COUNT(*) FROM sonar_outages WHERE kind = 'asn' AND keyval = '6805' AND ended IS NULL") === 1, $out);
q("UPDATE sonar_results SET avg_ms = avg_ms / 10 WHERE src LIKE 'a\\_%' AND dst IN ($inT) AND at >= ?", array_merge($tf, $win));

// ---------------------------------------------------------------- Aufraeumen
echo "Aufraeumen\n";
q("INSERT INTO sonar_results (`round`, src, dst, fam, method, sent, recv, at) VALUES (?, 'nt0000000001', 'a_fsn', 4, 'udp', 5, 5, ?)", array(dt(T - 8 * DAY), dt(T - 8 * DAY)));
q("INSERT INTO sonar_inbound (node_id, from_short, fam, at, `count`) VALUES ('a_fsn', 'abcdef01', 4, ?, 5)", array(dt(T - 25 * 3600)));
q("INSERT INTO sonar_traces (`round`, src, dst, fam, at, hops) VALUES (?, 'nt0000000001', 'a_fsn', 4, ?, '[]')", array(dt(T - 8 * DAY), dt(T - 8 * DAY)));
q("INSERT INTO sonar_pair_1h (src, dst, fam, hour, n) VALUES ('nt0000000001', 'a_fsn', 4, ?, 1)", array(dt(H - 91 * DAY)));
q("INSERT INTO sonar_plans (node_id, issued, expires, body, etag) VALUES ('nt0000000001', ?, ?, '{}', 'x'), ('nt0000000002', ?, ?, '{}', 'y')", array(dt(T - 7200), dt(T - 5400), dt(T), dt(T + 1800)));
q("UPDATE sonar_nodes SET active = 0, last_seen = ?, disabled_at = ? WHERE node_id = 'nt0000000054'", array(dt(T - 8 * DAY), dt(T - 8 * DAY)));
q("UPDATE sonar_nodes SET last_seen = ? WHERE node_id = 'nt0000000058'", array(dt(T - 91 * DAY)));
// Vertrag 10.3: inaktiv 30 Tage -> abmelden (auch nur first_seen), Anker nur Warnung; deaktiviert ohne Zeitpunkt -> jetzt
q("UPDATE sonar_nodes SET last_seen = NULL, first_seen = ? WHERE node_id = 'nt0000000055'", array(dt(T - 31 * DAY)));
q("UPDATE sonar_nodes SET last_seen = ? WHERE node_id = 'nt0000000057'", array(dt(T - 29 * DAY)));
q("UPDATE sonar_nodes SET last_seen = ? WHERE node_id = 'a_nbg'", array(dt(T - 31 * DAY)));
q("UPDATE sonar_nodes SET active = 0, disabled_at = NULL WHERE node_id = 'nt0000000053'");
q("UPDATE sonar_nodes SET active = 0, disabled_at = ? WHERE node_id = 'nt0000000056'", array(dt(T - 89 * DAY)));
// deaktiviert seit > 90 Tagen: nt59 mit allen Daten loeschen (Ziel-Stundenwert kurz nach der Deaktivierung)
$dis59 = T - 90 * DAY - 17280; $h59 = intdiv(T - 89 * DAY - 43200, 3600) * 3600;
q("UPDATE sonar_nodes SET active = 0, last_seen = ?, disabled_at = ? WHERE node_id = 'nt0000000059'", array(dt($dis59), dt($dis59)));
q("INSERT INTO sonar_results (`round`, src, dst, fam, method, sent, recv, at) VALUES (?, 'nt0000000059', 'a_fsn', 4, 'udp', 5, 5, ?), (?, 'a_fsn', 'nt0000000059', 4, 'udp', 5, 5, ?)",
	array(dt(T - DAY), dt(T - DAY), dt(T - DAY), dt(T - DAY)));
q("INSERT INTO sonar_traces (`round`, src, dst, fam, at, hops) VALUES (?, 'nt0000000059', 'a_fsn', 4, ?, '[]'), (?, 'nt0000000001', 'nt0000000059', 4, ?, '[]')", array(dt(T - DAY), dt(T - DAY), dt(T - DAY), dt(T - DAY)));
q("INSERT INTO sonar_inbound (node_id, from_short, fam, at, `count`) VALUES ('nt0000000059', 'abcdef02', 4, ?, 5)", array(dt(T - 3600)));
q("INSERT INTO sonar_pair_1h (src, dst, fam, hour, n) VALUES ('nt0000000059', 'a_fsn', 4, ?, 1), ('nt0000000001', 'nt0000000059', 4, ?, 1), ('nt0000000001', 'nt0000000002', 4, ?, 1)",
	array(dt(H - 10 * DAY), dt($h59), dt($h59)));
q("INSERT INTO sonar_trust_log (node_id, at, old, new, reason) VALUES ('nt0000000059', ?, 'stable', 'removed', 'owner'), ('nt0000000020', ?, 'new', 'stable', 'daily'), ('nt0000000020', ?, 'stable', 'trusted', 'daily')",
	array(dt($dis59), dt(T - 366 * DAY), dt(T - 300 * DAY)));
q("INSERT INTO sonar_plans (node_id, issued, expires, body, etag) VALUES ('nt0000000059', ?, ?, '{}', 'z')", array(dt(T), dt(T + 1800)));
// Token: 159/160 zu nt59 (loeschen), 170 unbenutzt 31 Tage (widerrufen), 171 unbenutzt 29 Tage, 172 widerrufen ohne Knoten
// 91 Tage (loeschen), 156 widerrufen 91 Tage, gehoert aber zu nt56 (bleibt), 174 widerrufen 89 Tage (bleibt), 158 zu nt58
$tk = function(int $id, ?string $node, int $created, ?int $revoked) { q("INSERT INTO sonar_tokens (id, userid, kind, name, token_hash, node_id, created_at, revoked_at) VALUES (?, 1, 'node', 't', ?, ?, ?, ?)",
	array($id, hash('sha256', "tok$id"), $node, dt($created), $revoked === null ? null : dt($revoked))); };
$tk(159, 'nt0000000059', T - 200 * DAY, (int)$dis59); $tk(160, 'nt0000000059', T - 300 * DAY, T - 200 * DAY); $tk(170, null, T - 31 * DAY, null); $tk(171, null, T - 29 * DAY, null);
$tk(172, null, T - 120 * DAY, T - 91 * DAY); $tk(156, 'nt0000000056', T - 120 * DAY, T - 91 * DAY); $tk(174, null, T - 120 * DAY, T - 89 * DAY); $tk(158, 'nt0000000058', T - 200 * DAY, null);
q("INSERT INTO sonar_asn_1d (day, asn_a, asn_b, fam, n) VALUES (?, 1, 2, 4, 1), (?, 1, 2, 4, 1)", array(gmdate('Y-m-d', T - 731 * DAY), gmdate('Y-m-d', T - 700 * DAY)));
q("INSERT INTO sonar_outages (kind, keyval, label, started, ended) VALUES ('asn', '1', 'alt', ?, ?), ('asn', '2', 'lang offen', ?, NULL), ('asn', '3', 'juenger', ?, ?)",
	array(dt(T - 740 * DAY), dt(T - 731 * DAY), dt(T - 800 * DAY), dt(T - 700 * DAY), dt(T - 699 * DAY)));
// Stundenwerte als Ziel entstehen nach der Deaktivierung nicht mehr (Planer nimmt inaktive Ziele heraus): die aus den Testdaten weg
q("DELETE FROM sonar_pair_1h WHERE dst = 'nt0000000059' AND hour >= ?", array(dt($dis59 + DAY)));
$n59 = (int)one("SELECT COUNT(*) FROM sonar_results WHERE src = 'nt0000000059' OR dst = 'nt0000000059'");
$cntR = (int)one("SELECT COUNT(*) FROM sonar_results");
$cntO = (int)one("SELECT COUNT(*) FROM sonar_outages");
$out = job('cleanup', '--dry --now=' . iso(T));
check('--dry aendert nichts', str_starts_with($out, 'NUR ANZEIGEN') AND (int)one("SELECT COUNT(*) FROM sonar_results") === $cntR AND (int)one("SELECT active FROM sonar_nodes WHERE node_id = 'nt0000000058'") === 1, $out);
$out = job('cleanup', '--now=' . iso(T));
echo "  $out\n";
check('Ergebnisse > 7 Tage weg, Rest bleibt', (int)one("SELECT COUNT(*) FROM sonar_results WHERE at < ?", array(dt(T - 7 * DAY))) === 0 AND (int)one("SELECT COUNT(*) FROM sonar_results") === $cntR - 1 - $n59, array($cntR, $n59));
$st = array(); foreach(all("SELECT node_id, active, disabled_at, ip4 FROM sonar_nodes WHERE node_id IN ('nt0000000053', 'nt0000000055', 'nt0000000057', 'nt0000000058', 'a_nbg')") as $r) { $st[$r['node_id']] = $r; }
check('inaktiv seit 30 Tagen abgemeldet (auch nur first_seen), 29 Tage bleibt', (int)$st['nt0000000058']['active'] === 0 AND $st['nt0000000058']['disabled_at'] === dt(T) . '.000'
	AND (int)$st['nt0000000055']['active'] === 0 AND (int)$st['nt0000000057']['active'] === 1, $st);
check('Abmeldung: Token widerrufen, trust_log removed/inactive', one("SELECT revoked_at FROM sonar_tokens WHERE id = 158") !== null
	AND one("SELECT reason FROM sonar_trust_log WHERE node_id = 'nt0000000058' AND new = 'removed'") === 'inactive', $out);
check('Anker nie automatisch, nur Warnung', (int)$st['a_nbg']['active'] === 1 AND str_contains($out, 'WARNUNG Anker a_nbg seit 31 Tagen'), $out);
check('deaktiviert ohne Zeitpunkt: disabled_at gesetzt', $st['nt0000000053']['disabled_at'] === dt(T) . '.000', $st['nt0000000053']);
check('unbenutzte Token: 31 Tage widerrufen, 29 Tage nicht', one("SELECT revoked_at FROM sonar_tokens WHERE id = 170") !== null AND one("SELECT revoked_at FROM sonar_tokens WHERE id = 171") === null);
$left59 = array();
foreach(array('sonar_nodes' => 'node_id', 'sonar_results' => "src = ? OR dst", 'sonar_traces' => "src = ? OR dst", 'sonar_inbound' => 'node_id', 'sonar_pair_1h' => "src = ? OR dst",
	'sonar_trust_log' => 'node_id', 'sonar_plans' => 'node_id', 'sonar_tokens' => 'node_id') as $tb => $w) {
	$n = (int)one("SELECT COUNT(*) FROM $tb WHERE $w = ?", str_contains($w, '?') ? array('nt0000000059', 'nt0000000059') : array('nt0000000059'));
	if($n > 0) { $left59[$tb] = $n; }
}
check('deaktiviert > 90 Tage: Knoten und alle Daten geloescht', $left59 === array() AND (int)one("SELECT COUNT(*) FROM sonar_tokens WHERE id IN (159, 160)") === 0, $left59);
check('deaktiviert 89 Tage bleibt, fremder Stundenwert bleibt', (int)one("SELECT COUNT(*) FROM sonar_nodes WHERE node_id = 'nt0000000056'") === 1
	AND (int)one("SELECT COUNT(*) FROM sonar_pair_1h WHERE src = 'nt0000000001' AND dst = 'nt0000000002' AND hour = ?", array(dt($h59))) === 1);
check('widerrufene Token ohne Knoten nach 90 Tagen geloescht, mit Knoten oder juenger bleiben',
	one("SELECT GROUP_CONCAT(id ORDER BY id) FROM sonar_tokens WHERE id IN (156, 172, 174)") === '156,174');
check('Aufbewahrung: ASN-Tage und beendete Stoerungen 2 Jahre, offene bleiben', one("SELECT GROUP_CONCAT(day) FROM sonar_asn_1d WHERE asn_a = 1") === gmdate('Y-m-d', T - 700 * DAY)
	AND (int)one("SELECT COUNT(*) FROM sonar_outages") === $cntO - 1 AND (int)one("SELECT COUNT(*) FROM sonar_outages WHERE keyval = '2'") === 1);
check('Aufbewahrung: trust_log 1 Jahr', (int)one("SELECT COUNT(*) FROM sonar_trust_log WHERE node_id = 'nt0000000020' AND at < ?", array(dt(T - 365 * DAY))) === 0
	AND (int)one("SELECT COUNT(*) FROM sonar_trust_log WHERE node_id = 'nt0000000020' AND at = ?", array(dt(T - 300 * DAY) . '.000')) === 1);
check('Proben > 24 h, Traces > 7 Tage, Stundenwerte > 90 Tage weg', (int)one("SELECT COUNT(*) FROM sonar_inbound WHERE at < ?", array(dt(T - DAY))) === 0
	AND (int)one("SELECT COUNT(*) FROM sonar_traces") === 0 AND (int)one("SELECT COUNT(*) FROM sonar_pair_1h WHERE hour < ?", array(dt(H - 90 * DAY))) === 0
	AND (int)one("SELECT COUNT(*) FROM sonar_pair_1h") > 1000);
check('abgelaufener Plan weg, gueltiger bleibt', one("SELECT GROUP_CONCAT(node_id) FROM sonar_plans") === 'nt0000000002');
check('IPs: deaktiviert > 7 Tage und 90 Tage ohne Meldung entfernt', one("SELECT CONCAT_WS(',', ip4, ip6) FROM sonar_nodes WHERE node_id = 'nt0000000054'") === ''
	AND one("SELECT ip4 FROM sonar_nodes WHERE node_id = 'nt0000000058'") === null AND one("SELECT ip4 FROM sonar_nodes WHERE node_id = 'nt0000000057'") !== null);
check('Log und Stoerungen bleiben', (int)one("SELECT COUNT(*) FROM sonar_trust_log") > 0 AND (int)one("SELECT COUNT(*) FROM sonar_outages") > 0);

// ---------------------------------------------------------------- Sperre und Cron
echo "Sperre und Cron\n";
$fh = fopen(sys_get_temp_dir() . '/sonar_plan.lock', 'c');
flock($fh, LOCK_EX);
$out = job('plan', '--now=' . iso(T));
check('Sperre gegen Doppellauf', str_contains($out, 'laeuft bereits'), $out);
flock($fh, LOCK_UN); fclose($fh);
exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg("$WEB/bots/honeypot_cron.php") . ' --list', $lst);
$lst = implode("\n", $lst);
check('HPC_JOBS: alle fuenf Jobs', preg_match_all('/sonar_(plan|rollup|trust|outages|cleanup)\.php/', $lst) === 5, $lst);
$out = job('plan', '--now=kaputt');
check('--now wird geprueft', str_contains($out, 'ungueltig'), $out);

// ---------------------------------------------------------------- Groesse: 3.000 Knoten
echo "Groesse\n";
truncate();
$rows = array();
foreach($A as $id => $a) {
	$rows[] = array($id, 0, 0, 'anchor', 'pk', $id, $id, $a[0], $a[1], 1, 'datacenter', 'anchor', 1, 'grosszuegig', 'anchor', $a[2], $a[3], 24940, 'Hetzner', null, null, null, 'none', 'none', 'anchor', dt(T - 400 * DAY), dt(T - 30), null, 1);
}
for($i = 0; $i < 3000; $i++) {
	$c = array_values($cities)[$i % 10];
	$lat = $c[0] + (crc32("la$i") % 2000 - 1000) / 4000; $lon = $c[1] + (crc32("lo$i") % 2000 - 1000) / 4000;
	if($i < 300) { $lat = 50.94 + ($i % 20) * 0.001; $lon = 6.96; } // 300 Knoten auf engem Raum (Zielgrenze)
	$ip4 = sprintf('%d.%d.%d.%d', 80 + $i % 4, 128 + intdiv($i, 250) % 100, $i % 250 + 1, 7);
	if($i < 300 AND $i % 10 === 0) { $ip4 = '80.200.0.7'; } // 30 Knoten hinter einer IP (CGNAT): Zielgrenze je Adresse
	$rows[] = array(sprintf('ns%010d', $i), 1, $i, 'node', 'pk', "S $i", "s-$i", $lat, $lon, $i, 'fiber', 'pi', 1, array('sparsam', 'normal', 'grosszuegig')[$i % 3], 'headless',
		$ip4, $i % 2 ? sprintf('2003:%x::%x', $i + 1, $i + 1) : null, 3320 + $i % 4, 'AS', $i % 2 ? 3320 + $i % 4 : null, $i % 2 ? 'AS' : null, null,
		'udp', $i % 2 ? 'udp' : 'none', array('new', 'stable', 'trusted')[$i % 3], dt(T - 100 * DAY), dt(T - 30), null, 1);
}
bulk("INSERT INTO sonar_nodes (node_id, userid, token_id, role, pubkey, name, slug, lat, lon, jitter_seed, access, device, measured, budget, mode, ip4, ip6, asn4, asname4, asn6, asname6, place, reach4, reach6, trust, first_seen, last_seen, health, active)", 29, $rows);
$t0 = microtime(true);
$out = job('plan', '--now=' . iso(T));
$sec = microtime(true) - $t0;
echo "  $out (" . round($sec, 1) . " s)\n";
$nodeRows = array(); foreach(all("SELECT * FROM sonar_nodes") as $r) { $nodeRows[$r['node_id']] = $r; }
check_plans(plans(), '3.000 Knoten');
check('3.000 Knoten in < 60 s', $sec < 60 AND str_contains($out, 'Plaene 3002'), $sec);
preg_match('/Speicher ([0-9.]+) MB/', $out, $mm);
check('Speicher < 64 MB (' . ($mm[1] ?? '?') . ' MB)', isset($mm[1]) AND (float)$mm[1] < 64);
q("UPDATE sonar_nodes SET last_seen = ?", array(dt(T + 270)));
$t0 = microtime(true);
$out2 = job('plan', '--now=' . iso(T + 300));
echo "  $out2 (" . round(microtime(true) - $t0, 1) . " s, im Betrieb)\n";
preg_match('/Speicher ([0-9.]+) MB/', $out2, $m2);
check('im Betrieb (eine neue Runde) weniger Speicher (' . ($m2[1] ?? '?') . ' MB)', isset($m2[1], $mm[1]) AND (float)$m2[1] < (float)$mm[1] AND (float)$m2[1] < 40 AND str_contains($out2, 'neue Runden 3002'), $out2);
$aBody = strlen((string)one("SELECT body FROM sonar_plans WHERE node_id = 'a_fsn'"));
check('Anker-Plan: 2.000 Ziele je Runde (' . round($aBody / 1048576, 1) . ' MB)', count(json_decode((string)one("SELECT body FROM sonar_plans WHERE node_id = 'a_fsn'"), true)['rounds'][0]['targets']) === 2000);
truncate();

echo "\n$pass ok, $failed Fehler\n";
exit($failed ? 1 : 0);
