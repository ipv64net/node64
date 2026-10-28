<?php
/**
 * Sonar64 Verdichtung (Vertrag docs/SONAR64-VERTRAG.md Abschnitt 7, Teil J). Stuendlich ueber honeypot_cron.php,
 * nur auf der Kommandozeile:
 *
 *   php sonar_rollup.php               ausfuehren
 *   php sonar_rollup.php --dry         nur anzeigen
 *   php sonar_rollup.php --now=<ISO>   Zeitpunkt vorgeben (Tests)
 *
 * 1. sonar_pair_1h: je Paar, Familie und Stunde (nach "at") aus den gueltigen Ergebnissen (Messende nicht in
 *    Quarantaene): n, Mittel (nach Antworten gewichtet), Median, Verlust. Geprueft werden die letzten 24 vollen
 *    Stunden; ohne jede Antwort avg/p50 = 0 und loss = 1. Neu gerechnet wird eine Stunde nur, wenn sich die Zahl der Ergebnisse geaendert hat (nachgereichte
 *    Meldungen, nachtraeglich verworfene Ergebnisse aus sonar_trust.php). Damit mehrfach ausfuehrbar.
 * 2. sonar_asn_1d: je Tag und ASN-Paar (ASN des Messenden -> ASN des Ziels) aus sonar_pair_1h, Median gewichtet nach
 *    Vertrauen des Messenden (new 0,2 · stable 1 · trusted 2 · pillar 3 · anchor 3) und Messungen; nur Tage mit neu
 *    gerechneten Stunden.
 */
if(php_sapi_name() !== 'cli') { exit; }
if(!is_file(__DIR__ . '/../sonar/s64_lib.php')) { fwrite(STDERR, "sonar/s64_lib.php fehlt\n"); exit(1); }
require_once __DIR__ . '/../sonar/s64_lib.php';

const S64R_HOURS      = 24;   // so viele volle Stunden pruefen
const S64R_SRC_CHUNK  = 50;   // Messende je Abfrage
const S64R_TIME_LIMIT = 1500;
const S64R_WEIGHT     = array('new' => 0.2, 'stable' => 1.0, 'trusted' => 2.0, 'pillar' => 3.0, 'anchor' => 3.0, 'quarantine' => 0.0);

$opt = getopt('', array('dry', 'now:'));
$dry = isset($opt['dry']);
$now = isset($opt['now']) ? strtotime((string)$opt['now']) : time();
if($now === false) { fwrite(STDERR, "--now ungueltig\n"); exit(1); }
$lock = fopen(sys_get_temp_dir() . '/sonar_rollup.lock', 'c');
if($lock === false OR !flock($lock, LOCK_EX | LOCK_NB)) { echo "laeuft bereits\n"; exit(0); }
set_time_limit(S64R_TIME_LIMIT + 60);
$deadline = microtime(true) + S64R_TIME_LIMIT;
$pdo = s64_pdo();
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

function s64r_db(int $t): string { return gmdate('Y-m-d H:i:s', $t); }
function s64r_in(array $ids): string { return implode(',', array_fill(0, count($ids), '?')); }
function s64r_one(string $sql, array $p) { global $pdo; $st = $pdo->prepare($sql); $st->execute($p); return $st->fetchColumn(); }

function s64r_median(array $v): ?float {
	$c = count($v);
	if($c === 0) { return null; }
	sort($v);
	return $c % 2 ? (float)$v[intdiv($c, 2)] : ($v[$c / 2 - 1] + $v[$c / 2]) / 2;
}

/** Gewichteter Median aus einem Histogramm (Klasse 0,1 ms => Gewicht). */
function s64r_wmedian(array $hist): ?float {
	$total = array_sum($hist);
	if($total <= 0) { return null; }
	ksort($hist);
	$acc = 0.0;
	foreach($hist as $bin => $w) { $acc += $w; if($acc >= $total / 2) { return $bin / 10; } }
	return null;
}

// Messende in Quarantaene zaehlen nicht (Abfrage wie in der Verdichtung, damit der Vergleich stimmt)
const S64R_FROM = "FROM sonar_results r JOIN sonar_nodes n ON n.node_id = r.src WHERE r.at >= ? AND r.at < ? AND r.valid = 1 AND n.trust <> 'quarantine'";

// ---------------------------------------------------------------- 1. Stunden je Paar
$top = intdiv($now, 3600) * 3600; // laufende Stunde (nicht fertig)
$days = array();
$hoursDone = 0; $rows = 0; $aborted = false;
$ins = $pdo->prepare("INSERT INTO sonar_pair_1h (src, dst, fam, hour, n, avg_ms, p50_ms, loss) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
for($h = $top - S64R_HOURS * 3600; $h < $top; $h += 3600) {
	if(microtime(true) > $deadline) { $aborted = true; break; }
	$a = s64r_db($h); $b = s64r_db($h + 3600);
	$have = (int)s64r_one("SELECT COUNT(*) " . S64R_FROM, array($a, $b));
	$done = (int)s64r_one("SELECT COALESCE(SUM(n), 0) FROM sonar_pair_1h WHERE hour = ?", array($a));
	if($have === $done) { continue; }
	$hoursDone++;
	$days[gmdate('Y-m-d', $h)] = true;
	if($dry) { echo "Stunde $a: $have Ergebnisse (bisher $done)\n"; continue; }
	$st = $pdo->prepare("SELECT DISTINCT r.src " . S64R_FROM);
	$st->execute(array($a, $b));
	$srcs = $st->fetchAll(PDO::FETCH_COLUMN);
	$pdo->beginTransaction();
	$pdo->prepare("DELETE FROM sonar_pair_1h WHERE hour = ?")->execute(array($a));
	foreach(array_chunk($srcs, S64R_SRC_CHUNK) as $chunk) {
		$st = $pdo->prepare("SELECT r.src, r.dst, r.fam, r.sent, r.recv, r.avg_ms FROM sonar_results r JOIN sonar_nodes n ON n.node_id = r.src
			WHERE r.src IN (" . s64r_in($chunk) . ") AND r.at >= ? AND r.at < ? AND r.valid = 1 AND n.trust <> 'quarantine'");
		$st->execute(array_merge($chunk, array($a, $b)));
		$agg = array();
		while($r = $st->fetch(PDO::FETCH_ASSOC)) {
			$k = $r['src'] . '|' . $r['dst'] . '|' . (int)$r['fam'];
			$g = &$agg[$k];
			if($g === null) { $g = array('n' => 0, 'sent' => 0, 'recv' => 0, 'sum' => 0.0, 'rw' => 0, 'v' => array()); }
			$g['n']++;
			$g['sent'] += max(0, (int)$r['sent']);
			$recv = max(0, (int)$r['recv']);
			$g['recv'] += $recv;
			if($recv > 0 AND $r['avg_ms'] !== null) { $g['sum'] += (float)$r['avg_ms'] * $recv; $g['rw'] += $recv; $g['v'][] = (float)$r['avg_ms']; }
			unset($g);
		}
		foreach($agg as $k => $g) {
			[$src, $dst, $fam] = explode('|', $k);
			$avg = $g['rw'] > 0 ? round($g['sum'] / $g['rw'], 3) : 0.0; // ohne Antwort 0 (Spalte NOT NULL), loss = 1
			$p50 = $g['v'] ? round(s64r_median($g['v']), 3) : 0.0;
			$loss = $g['sent'] > 0 ? round(1 - min($g['recv'], $g['sent']) / $g['sent'], 4) : 1.0;
			$ins->execute(array($src, $dst, (int)$fam, $a, $g['n'], $avg, $p50, $loss));
			$rows++;
		}
	}
	$pdo->commit();
}

// ---------------------------------------------------------------- 2. Tage je ASN-Paar
$asnRows = 0;
$insA = $pdo->prepare("INSERT INTO sonar_asn_1d (day, asn_a, asn_b, fam, n, p50_ms, loss) VALUES (?, ?, ?, ?, ?, ?, ?)");
foreach(array_keys($days) as $day) {
	if($dry OR microtime(true) > $deadline) { break; }
	$a = $day . ' 00:00:00';
	$b = gmdate('Y-m-d', strtotime($day . ' UTC') + 86400) . ' 00:00:00';
	$st = $pdo->prepare("SELECT DISTINCT src FROM sonar_pair_1h WHERE hour >= ? AND hour < ?");
	$st->execute(array($a, $b));
	$srcs = $st->fetchAll(PDO::FETCH_COLUMN);
	$agg = array(); // "asn_a|asn_b|fam" => array(hist, n, lossw, w)
	foreach(array_chunk($srcs, S64R_SRC_CHUNK) as $chunk) {
		$st = $pdo->prepare("SELECT p.fam, p.n, p.p50_ms, p.loss, s.trust, s.asn4 sa4, s.asn6 sa6, d.asn4 da4, d.asn6 da6
			FROM sonar_pair_1h p JOIN sonar_nodes s ON s.node_id = p.src JOIN sonar_nodes d ON d.node_id = p.dst
			WHERE p.src IN (" . s64r_in($chunk) . ") AND p.hour >= ? AND p.hour < ?");
		$st->execute(array_merge($chunk, array($a, $b)));
		while($r = $st->fetch(PDO::FETCH_ASSOC)) {
			$fam = (int)$r['fam'];
			$sa = $fam === 6 ? $r['sa6'] : $r['sa4'];
			$da = $fam === 6 ? $r['da6'] : $r['da4'];
			$w = S64R_WEIGHT[$r['trust']] ?? 0.0;
			if($sa === null OR $da === null OR $w <= 0) { continue; }
			$k = (int)$sa . '|' . (int)$da . '|' . $fam;
			$g = &$agg[$k];
			if($g === null) { $g = array('h' => array(), 'n' => 0, 'lw' => 0.0, 'w' => 0.0); }
			$wn = $w * (int)$r['n'];
			$g['n'] += (int)$r['n'];
			$g['lw'] += $wn * (float)$r['loss'];
			$g['w'] += $wn;
			if((float)$r['loss'] < 1) { $bin = (int)round(min(10000.0, (float)$r['p50_ms']) * 10); $g['h'][$bin] = ($g['h'][$bin] ?? 0) + $wn; }
			unset($g);
		}
	}
	$pdo->beginTransaction();
	$pdo->prepare("DELETE FROM sonar_asn_1d WHERE day = ?")->execute(array($day));
	foreach($agg as $k => $g) {
		[$sa, $da, $fam] = explode('|', $k);
		$p50 = s64r_wmedian($g['h']);
		$insA->execute(array($day, (int)$sa, (int)$da, (int)$fam, $g['n'], $p50 ?? 0.0, $g['w'] > 0 ? round($g['lw'] / $g['w'], 4) : 1.0));
		$asnRows++;
	}
	$pdo->commit();
}
printf("%sStunden neu %d (Paare %d), Tage %d (ASN-Paare %d)%s\n", $dry ? 'NUR ANZEIGEN: ' : '', $hoursDone, $rows, count($days), $asnRows, $aborted ? ', ABGEBROCHEN (Zeitgrenze)' : '');
