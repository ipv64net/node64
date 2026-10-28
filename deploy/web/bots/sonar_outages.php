<?php
/**
 * Sonar64 Stoerungserkennung (Vertrag docs/SONAR64-VERTRAG.md Abschnitt 7, Teil J). Alle 5 min ueber honeypot_cron.php,
 * nur auf der Kommandozeile:
 *
 *   php sonar_outages.php              ausfuehren
 *   php sonar_outages.php --dry        nur anzeigen
 *   php sonar_outages.php --verbose    je Gruppe die Zahlen zeigen
 *   php sonar_outages.php --now=<ISO>  Zeitpunkt vorgeben (Tests)
 *
 * Grundlage sind nur die Messungen der Anker (letzte 15 min, Meldungen kommen bis 5 min spaet). Zur Gruppe gehoeren
 * gemessene Knoten ausser Quarantaene, die ein Anker in den letzten 24 h erreicht hat. Je Knoten zaehlt der bekannte Weg
 * (reach4/6), ohne Weg jede Methode: eine Antwort = erreichbar, nur Verluste = nicht erreichbar, nichts = unbekannt.
 * Langsam = Median > 3x Wochenmittel und > 10 ms mehr.
 * Je ASN und je Raster 0,5 Grad mit >= 5 bekannten Knoten (gewichtet nach Vertrauen):
 *   >= 50 % nicht erreichbar oder Median der Gruppe > 3x Wochenmittel -> Stoerung offen (binnen 15 min nach Ende wieder
 *   dieselbe); Ende, wenn < 20 % betroffen; ohne Daten (< 5 bekannt) Ende nach 6 h.
 * Sind >= 80 % aller bekannten Knoten in mindestens 3 ASN nicht erreichbar, liegt es an den Ankern: nichts aendern.
 */
if(php_sapi_name() !== 'cli') { exit; }
if(!is_file(__DIR__ . '/../sonar/s64_lib.php')) { fwrite(STDERR, "sonar/s64_lib.php fehlt\n"); exit(1); }
require_once __DIR__ . '/../sonar/s64_lib.php';

const S64O_WINDOW     = 900;
const S64O_MIN_NODES  = 5;
const S64O_OPEN       = 0.5;
const S64O_CLOSE      = 0.2;
const S64O_SLOW       = 3.0;
const S64O_SLOW_MS    = 10.0;
const S64O_REOPEN     = 900;
const S64O_STALE      = 21600;
const S64O_GUARD      = 0.8;
const S64O_TIME_LIMIT = 200;
const S64O_WEIGHT     = array('new' => 0.2, 'stable' => 1.0, 'trusted' => 2.0, 'pillar' => 3.0);

$opt = getopt('', array('dry', 'now:', 'verbose'));
$dry = isset($opt['dry']);
$now = isset($opt['now']) ? strtotime((string)$opt['now']) : time();
if($now === false) { fwrite(STDERR, "--now ungueltig\n"); exit(1); }
$lock = fopen(sys_get_temp_dir() . '/sonar_outages.lock', 'c');
if($lock === false OR !flock($lock, LOCK_EX | LOCK_NB)) { echo "laeuft bereits\n"; exit(0); }
set_time_limit(S64O_TIME_LIMIT + 60);
$pdo = s64_pdo();
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

function s64o_db(int $t): string { return gmdate('Y-m-d H:i:s', $t); }
function s64o_in(array $ids): string { return implode(',', array_fill(0, count($ids), '?')); }
function s64o_median(array $v): ?float {
	$c = count($v);
	if($c === 0) { return null; }
	sort($v);
	return $c % 2 ? (float)$v[intdiv($c, 2)] : ($v[$c / 2 - 1] + $v[$c / 2]) / 2;
}

$anchors = $pdo->query("SELECT node_id FROM sonar_nodes WHERE role = 'anchor' AND active = 1")->fetchAll(PDO::FETCH_COLUMN);
if(!$anchors) { echo "keine Anker\n"; exit(0); }
$in = s64o_in($anchors);

// Gruppe: vom Anker in 24 h erreicht; Wochenmittel der Anker-Latenz
$member = array();
$st = $pdo->prepare("SELECT dst, SUM(p50_ms * n) / SUM(n) wk, MAX(hour >= ?) recent FROM sonar_pair_1h
	WHERE src IN ($in) AND hour >= ? AND loss < 1 GROUP BY dst");
$st->execute(array_merge(array(s64o_db($now - 86400)), $anchors, array(s64o_db($now - 7 * 86400))));
$week = array();
while($r = $st->fetch(PDO::FETCH_ASSOC)) {
	$week[$r['dst']] = (float)$r['wk'];
	if((int)$r['recent']) { $member[$r['dst']] = true; }
}

$nodes = array();
foreach($pdo->query("SELECT node_id, trust, lat, lon, asn4, asname4, asn6, asname6, place, reach4, reach6 FROM sonar_nodes
	WHERE active = 1 AND role = 'node' AND measured = 1 AND trust <> 'quarantine'")->fetchAll(PDO::FETCH_ASSOC) as $n) {
	if(isset($member[$n['node_id']])) { $nodes[$n['node_id']] = $n + array('res' => array()); }
}

$st = $pdo->prepare("SELECT dst, fam, method, recv, avg_ms FROM sonar_results WHERE src IN ($in) AND at >= ? AND at < ? AND valid = 1 AND method IN ('icmp', 'udp')");
$st->execute(array_merge($anchors, array(s64o_db($now - S64O_WINDOW), s64o_db($now + 60))));
while($r = $st->fetch(PDO::FETCH_ASSOC)) {
	if(!isset($nodes[$r['dst']])) { continue; }
	$known = $nodes[$r['dst']]['reach' . (int)$r['fam']] ?? 'none';
	if($known !== 'none' AND $known !== $r['method']) { continue; } // Suche nach dem anderen Weg zaehlt nicht
	$nodes[$r['dst']]['res'][] = array((int)$r['recv'], $r['avg_ms'] !== null ? (float)$r['avg_ms'] : null);
}

// Zustand je Knoten: ok | down | slow, unbekannt = nicht in $state
$state = array(); $lat = array();
foreach($nodes as $id => $n) {
	if(!$n['res']) { continue; }
	$v = array();
	foreach($n['res'] as $e) { if($e[0] > 0 AND $e[1] !== null) { $v[] = $e[1]; } }
	if(!$v) { $state[$id] = 'down'; continue; }
	$lat[$id] = s64o_median($v);
	$wk = $week[$id] ?? null;
	$state[$id] = ($wk !== null AND $lat[$id] > S64O_SLOW * $wk AND $lat[$id] - $wk > S64O_SLOW_MS) ? 'slow' : 'ok';
}

// Gruppen
$groups = array(); // kind|key => array(label, Knoten)
foreach($nodes as $id => $n) {
	$asn = $n['asn4'] !== null ? (int)$n['asn4'] : ($n['asn6'] !== null ? (int)$n['asn6'] : null);
	if($asn !== null) {
		$k = 'asn|' . $asn;
		$groups[$k]['label'] = $groups[$k]['label'] ?? mb_substr((string)($n['asname4'] ?? $n['asname6'] ?? ('AS' . $asn)), 0, 120);
		$groups[$k]['ids'][] = $id;
	}
	if($n['lat'] !== null AND $n['lon'] !== null) {
		$y = floor((float)$n['lat'] * 2) / 2; $x = floor((float)$n['lon'] * 2) / 2;
		$k = 'region|' . sprintf('%.1f,%.1f', $y, $x);
		$groups[$k]['ids'][] = $id;
		$place = trim((string)$n['place']);
		if($place !== '') { $groups[$k]['places'][$place] = ($groups[$k]['places'][$place] ?? 0) + 1; }
		$groups[$k]['label'] = sprintf('%.1f°N %.1f°E', $y + 0.25, $x + 0.25);
	}
}

// Schutz: faellt (fast) alles aus, liegt es an den Ankern
$known = count($state);
$down = count(array_filter($state, function($s) { return $s === 'down'; }));
$downAsn = array();
foreach($state as $id => $s) { if($s === 'down' AND $nodes[$id]['asn4'] !== null) { $downAsn[(int)$nodes[$id]['asn4']] = true; } }
if($known >= 10 AND $down >= S64O_GUARD * $known AND count($downAsn) >= 3) {
	printf("Anker-Seite gestoert? %d von %d Knoten in %d ASN nicht erreichbar - keine Aenderung\n", $down, $known, count($downAsn));
	exit(0);
}

$open = array(); // kind|key => Zeile (offen oder vor kurzem beendet)
$st = $pdo->prepare("SELECT id, kind, keyval, started, ended FROM sonar_outages WHERE ended IS NULL OR ended >= ? ORDER BY id");
$st->execute(array(s64o_db($now - S64O_REOPEN)));
while($r = $st->fetch(PDO::FETCH_ASSOC)) {
	$k = $r['kind'] . '|' . $r['keyval'];
	if(!isset($open[$k]) OR $r['ended'] === null) { $open[$k] = $r; }
}

$opened = 0; $closed = 0; $kept = 0;
$ins = $pdo->prepare("INSERT INTO sonar_outages (kind, keyval, label, started, ended, affected, total) VALUES (?, ?, ?, ?, NULL, ?, ?)");
$upd = $pdo->prepare("UPDATE sonar_outages SET ended = NULL, label = ?, affected = ?, total = ? WHERE id = ?");
$end = $pdo->prepare("UPDATE sonar_outages SET ended = ?, affected = ?, total = ? WHERE id = ?");
foreach($groups as $k => $g) {
	$w = 0.0; $wDown = 0.0; $wAff = 0.0; $cnt = 0; $aff = 0; $lats = array(); $wks = array();
	foreach($g['ids'] as $id) {
		if(!isset($state[$id])) { continue; }
		$wt = S64O_WEIGHT[$nodes[$id]['trust']] ?? 0.2;
		$cnt++; $w += $wt;
		if($state[$id] === 'down') { $wDown += $wt; }
		if($state[$id] !== 'ok') { $wAff += $wt; $aff++; }
		if(isset($lat[$id], $week[$id])) { $lats[] = $lat[$id]; $wks[] = $week[$id]; }
	}
	if(!empty($g['places'])) { arsort($g['places']); $g['label'] = mb_substr((string)array_key_first($g['places']), 0, 120); }
	[$kind, $key] = explode('|', $k, 2);
	$row = $open[$k] ?? null;
	$isOpen = $row !== null && $row['ended'] === null;
	if($cnt < S64O_MIN_NODES OR $w <= 0) {
		// zu wenig Daten: offene Stoerung bleibt, bis 6 h ohne Daten
		if($isOpen AND (int)strtotime($row['started'] . ' UTC') < $now - S64O_STALE) {
			$closed++;
			if(!$dry) { $end->execute(array(s64o_db($now), $aff, $cnt, $row['id'])); }
		}
		continue;
	}
	$mLat = s64o_median($lats); $mWk = s64o_median($wks);
	$slow = $mLat !== null && $mWk !== null && $mLat > S64O_SLOW * $mWk && $mLat - $mWk > S64O_SLOW_MS;
	$trigger = $wDown / $w >= S64O_OPEN || $slow;
	if(isset($opt['verbose'])) {
		$sl = array(); foreach($g['ids'] as $id) { if(($state[$id] ?? '') === 'slow') { $sl[] = $id; } }
		printf("  %s %s: bekannt %d, betroffen %d (%.0f %%, nicht erreichbar %.0f %%), Median %s/%s ms%s
", $kind, $key, $cnt, $aff, 100 * $wAff / $w, 100 * $wDown / $w,
			$mLat === null ? '-' : round($mLat, 1), $mWk === null ? '-' : round($mWk, 1), $sl ? ', langsam ' . implode(' ', $sl) : '');
	}
	if($isOpen) {
		if($wAff / $w < S64O_CLOSE) {
			$closed++;
			echo "Ende $kind $key ({$g['label']}): $aff/$cnt\n";
			if(!$dry) { $end->execute(array(s64o_db($now), $aff, $cnt, $row['id'])); }
		} else {
			$kept++;
			if(!$dry) { $upd->execute(array($g['label'], $aff, $cnt, $row['id'])); }
		}
	} elseif($trigger) {
		$opened++;
		echo "Stoerung $kind $key ({$g['label']}): $aff/$cnt" . ($slow ? ' langsam' : '') . "\n";
		if(!$dry) {
			if($row !== null) { $upd->execute(array($g['label'], $aff, $cnt, $row['id'])); } // kurz nach dem Ende: dieselbe
			else { $ins->execute(array($kind, $key, $g['label'], s64o_db($now), $aff, $cnt)); }
		}
	}
}
// offene Stoerungen ohne Gruppe mehr (z. B. alle Knoten weg): nach 6 h beenden
foreach($open as $k => $row) {
	if($row['ended'] !== null OR isset($groups[$k]) OR (int)strtotime($row['started'] . ' UTC') >= $now - S64O_STALE) { continue; }
	$closed++;
	if(!$dry) { $end->execute(array(s64o_db($now), 0, 0, $row['id'])); }
}
printf("%sKnoten bekannt %d (nicht erreichbar %d), Gruppen %d, neu %d, offen %d, beendet %d\n", $dry ? 'NUR ANZEIGEN: ' : '', $known, $down, count($groups), $opened, $kept, $closed);
