<?php
/**
 * Sonar64 Vertrauen (Vertrag docs/SONAR64-VERTRAG.md Abschnitt 7, Plan Abschnitt 6/6a, Teil J). Stuendlich ueber
 * honeypot_cron.php; einmal am Tag (02 Uhr UTC oder --full) zusaetzlich Verfuegbarkeit, Median-Pruefung und Aufstieg.
 *
 *   php sonar_trust.php                ausfuehren (stuendlicher Teil, um 02 Uhr UTC alles)
 *   php sonar_trust.php --full         alles
 *   php sonar_trust.php --dry          nur anzeigen
 *   php sonar_trust.php --hours=<1..24> stuendliche Pruefung ueber mehr Stunden (Nachholen nach einer Pause)
 *   php sonar_trust.php --now=<ISO>    Zeitpunkt vorgeben (Tests)
 *
 * Stuendlich (letzte 3 volle Stunden, nur noch gueltige Ergebnisse; mehrfach ausfuehrbar):
 *  a) Anker-Wahrheit: Knoten->Anker (udp, Median der Stunde) gegen Anker->Knoten. Misst der Anker per udp bis zum
 *     Knoten: Abweichung > max(5 ms, 50 %) -> unplausibel. Misst er nur den Router (icmp): nur "schneller als der eigene
 *     Router" zaehlt (WLAN hinter dem Router ist kein Betrug).
 *  b) Antworten der Anker: meldet ein Knoten per udp mehr Antworten eines Ankers, als dieser beantwortet hat
 *     (sonar_inbound des Ankers, < 50 %), sind die Werte erfunden.
 *  c) Kontrollziele (Anker per icmp aus dem Planer) gegen die Messung des Ankers wie a).
 *  d) Hin und zurueck (sonar_pair_1h, 24 h): A->B gegen B->A > max(10 ms, 100 %); gezaehlt nur gegen den Knoten, der
 *     mit mindestens 3 von mindestens 4 Partnern (Mehrheit) nicht zusammenpasst.
 *  Unplausible Ergebnisse bekommen valid=0 und einen Grund (anchor_truth, inbound, control, asym), plaus_bad steigt.
 *  e) Quote unplausibler Ergebnisse 24 h (Teil A und hier, ohne below_light gegen new/stable): > 30 % Quarantaene, > 10 % eine Stufe ab (sofort,
 *     hoechstens einmal je 24 h); Quarantaene endet fruehestens nach 72 h bei <= 5 % (dann wieder "new").
 * Taeglich zusaetzlich:
 *  f) Verfuegbarkeit 30 Tage (Stunden mit eigenen Messungen oder vom Anker erreicht) -> uptime30.
 *  g) Median: eigener Wert gegen den gewichteten Median der anderen Messenden zum selben Ziel (je um Entfernung und
 *     eigene Anker-Latenz bereinigt, damit Ort, LTE, Starlink und WLAN nicht auffallen); > max(5 ms, 50 %) in > 20 %
 *     -> eine Stufe ab.
 *  h) Stufen laut Plan Abschnitt 6: Aufstieg hoechstens eine Stufe je 24 h, Abstufung sofort; score 0..1.
 */
if(php_sapi_name() !== 'cli') { exit; }
if(!is_file(__DIR__ . '/../sonar/s64_lib.php')) { fwrite(STDERR, "sonar/s64_lib.php fehlt\n"); exit(1); }
require_once __DIR__ . '/../sonar/s64_lib.php';

const S64T_TIME_LIMIT = 1500;
const S64T_HOURS      = 3;        // stuendliche Pruefung: so viele volle Stunden
const S64T_MIN_TOTAL  = 20;       // Ergebnisse in 24 h, ab denen die Quote zaehlt
const S64T_QUARANTINE = 0.30;
const S64T_DEMOTE     = 0.10;
const S64T_Q_MIN      = 259200;   // Quarantaene mindestens 72 h
const S64T_Q_EXIT     = 0.05;
const S64T_DAY        = 86400;
const S64T_LEVELS     = array('new', 'stable', 'trusted', 'pillar');
// Stufe => array(Tage, Verfuegbarkeit, hoechste Quote unplausibel, hoechste Median-Abweichung, Median noetig)
const S64T_RULES      = array(
	'stable'  => array(7, 0.90, 0.05, 0.20, false),
	'trusted' => array(60, 0.97, 0.02, 0.10, true),
	'pillar'  => array(180, 0.99, 0.01, 0.05, true),
);
const S64T_WEIGHT     = array('new' => 0.2, 'stable' => 1.0, 'trusted' => 2.0, 'pillar' => 3.0, 'anchor' => 3.0, 'quarantine' => 0.0);

$opt = getopt('', array('dry', 'full', 'now:', 'hours:'));
$dry = isset($opt['dry']);
$now = isset($opt['now']) ? strtotime((string)$opt['now']) : time();
if($now === false) { fwrite(STDERR, "--now ungueltig\n"); exit(1); }
$full = isset($opt['full']) || (int)gmdate('G', $now) === 2;
$hours = isset($opt['hours']) ? max(1, min(24, (int)$opt['hours'])) : S64T_HOURS;
$lock = fopen(sys_get_temp_dir() . '/sonar_trust.lock', 'c');
if($lock === false OR !flock($lock, LOCK_EX | LOCK_NB)) { echo "laeuft bereits\n"; exit(0); }
set_time_limit(S64T_TIME_LIMIT + 60);
$deadline = microtime(true) + S64T_TIME_LIMIT;
$pdo = s64_pdo();
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

function s64t_db(int $t): string { return gmdate('Y-m-d H:i:s', $t); }
function s64t_ts(?string $s): ?int { return $s === null ? null : (int)strtotime($s . ' UTC'); }
function s64t_in(array $ids): string { return implode(',', array_fill(0, count($ids), '?')); }
function s64t_rows(string $sql, array $p): array { global $pdo; $st = $pdo->prepare($sql); $st->execute($p); return $st->fetchAll(PDO::FETCH_ASSOC); }
function s64t_median(array $v): ?float {
	$c = count($v);
	if($c === 0) { return null; }
	sort($v);
	return $c % 2 ? (float)$v[intdiv($c, 2)] : ($v[$c / 2 - 1] + $v[$c / 2]) / 2;
}
/** Gewichteter Median aus Paaren array(Wert, Gewicht). */
function s64t_wmedian(array $vw): ?float {
	$total = 0.0;
	foreach($vw as $e) { $total += $e[1]; }
	if($total <= 0) { return null; }
	usort($vw, function($a, $b) { return $a[0] <=> $b[0]; });
	$acc = 0.0;
	foreach($vw as $e) { $acc += $e[1]; if($acc >= $total / 2) { return (float)$e[0]; } }
	return null;
}
/** Weicht $v von $ref um mehr als max($abs ms, $rel) ab? */
function s64t_off(float $v, float $ref, float $abs = 5.0, float $rel = 0.5): bool { return abs($v - $ref) > max($abs, $rel * $ref); }

$bad = array();   // node_id => neu verworfene Ergebnisse
$found = array(); // Grund => Anzahl

/** Ergebnisse eines Knotens als unplausibel markieren (nur noch gueltige; Bedingungen als Spalte => Wert). */
function s64t_flag(string $src, array $cond, int $from, int $to, string $reason): void {
	global $pdo, $dry, $bad, $found;
	$w = array('src = ?', 'at >= ?', 'at < ?', 'valid = 1');
	$p = array($src, s64t_db($from), s64t_db($to));
	foreach($cond as $col => $v) {
		if(is_array($v)) { $w[] = "$col IN (" . s64t_in($v) . ")"; $p = array_merge($p, $v); }
		else { $w[] = "$col = ?"; $p[] = $v; }
	}
	if($dry) {
		$st = $pdo->prepare("SELECT COUNT(*) FROM sonar_results WHERE " . implode(' AND ', $w));
		$st->execute($p);
		$n = (int)$st->fetchColumn();
	} else {
		$st = $pdo->prepare("UPDATE sonar_results SET valid = 0, reason = ? WHERE " . implode(' AND ', $w));
		$st->execute(array_merge(array($reason), $p));
		$n = $st->rowCount();
	}
	if($n > 0) { $bad[$src] = ($bad[$src] ?? 0) + $n; $found[$reason] = ($found[$reason] ?? 0) + $n; }
}

$anchors = $pdo->query("SELECT node_id FROM sonar_nodes WHERE role = 'anchor'")->fetchAll(PDO::FETCH_COLUMN);
$isAnchor = array_fill_keys($anchors, true);
$top = intdiv($now, 3600) * 3600;

// ---------------------------------------------------------------- a) b) c) Anker-Wahrheit, Antworten, Kontrollziele
if($anchors) {
	$in = s64t_in($anchors);
	for($h = $top - $hours * 3600; $h < $top; $h += 3600) {
		$p = array_merge($anchors, array(s64t_db($h), s64t_db($h + 3600)));
		$down = array(); // Knoten|Anker|fam => method => Werte (Anker misst Knoten)
		foreach(s64t_rows("SELECT src, dst, fam, method, avg_ms FROM sonar_results WHERE src IN ($in) AND at >= ? AND at < ? AND valid = 1 AND recv > 0 AND avg_ms IS NOT NULL", $p) as $r) {
			if(isset($isAnchor[$r['dst']])) { continue; }
			$down[$r['dst'] . '|' . $r['src'] . '|' . (int)$r['fam']][$r['method']][] = (float)$r['avg_ms'];
		}
		$up = array(); $ctl = array(); $recv = array();
		foreach(s64t_rows("SELECT src, dst, fam, method, recv, avg_ms FROM sonar_results WHERE dst IN ($in) AND at >= ? AND at < ? AND valid = 1 AND recv > 0 AND avg_ms IS NOT NULL", $p) as $r) {
			if(isset($isAnchor[$r['src']])) { continue; }
			$k = $r['src'] . '|' . $r['dst'] . '|' . (int)$r['fam'];
			if($r['method'] === 'udp') { $up[$k][] = (float)$r['avg_ms']; $recv[$k] = ($recv[$k] ?? 0) + (int)$r['recv']; }
			elseif($r['method'] === 'icmp') { $ctl[$k][] = (float)$r['avg_ms']; }
		}
		// Referenz des Ankers: udp bis zum Knoten (beidseitig pruefen) oder icmp zum Router (nur "zu schnell")
		$ref = function(string $k) use ($down): ?array {
			if(count($down[$k]['udp'] ?? array()) >= 3) { return array(s64t_median($down[$k]['udp']), true); }
			if(count($down[$k]['icmp'] ?? array()) >= 3) { return array(s64t_median($down[$k]['icmp']), false); }
			return null;
		};
		$isBad = function(float $v, array $rf): bool { return $rf[1] ? s64t_off($v, $rf[0]) : ($v < $rf[0] - max(5.0, 0.5 * $rf[0])); };
		foreach($up as $k => $vals) {
			if(count($vals) < 3 OR ($rf = $ref($k)) === null) { continue; }
			if($isBad(s64t_median($vals), $rf)) {
				[$s, $a, $f] = explode('|', $k);
				s64t_flag($s, array('dst' => $a, 'fam' => (int)$f, 'method' => 'udp'), $h, $h + 3600, 'anchor_truth');
			}
		}
		foreach($ctl as $k => $vals) {
			if(($rf = $ref($k)) === null) { continue; }
			if($isBad(s64t_median($vals), $rf)) {
				[$s, $a, $f] = explode('|', $k);
				s64t_flag($s, array('dst' => $a, 'fam' => (int)$f, 'method' => array('icmp', 'udp')), $h, $h + 3600, 'control');
			}
		}
		// b) beantwortete Proben der Anker (Puffer +-10 min, Abschnitte der Meldungen)
		$inb = array(); $tot = array();
		foreach(s64t_rows("SELECT node_id, from_short, fam, SUM(`count`) c FROM sonar_inbound WHERE node_id IN ($in) AND at >= ? AND at < ? GROUP BY node_id, from_short, fam",
			array_merge($anchors, array(s64t_db($h - 600), s64t_db($h + 4200)))) as $r) {
			$inb[$r['node_id'] . '|' . $r['from_short'] . '|' . (int)$r['fam']] = (int)$r['c'];
			$tot[$r['node_id']] = ($tot[$r['node_id']] ?? 0) + (int)$r['c'];
		}
		foreach($recv as $k => $n) {
			[$s, $a, $f] = explode('|', $k);
			if($n < 10 OR empty($tot[$a])) { continue; } // Anker meldet keine Proben: keine Aussage
			$c = $inb[$a . '|' . substr(hash('sha256', $s), 0, 8) . '|' . $f] ?? 0;
			if($c < 0.5 * $n) { s64t_flag($s, array('dst' => $a, 'fam' => (int)$f, 'method' => 'udp'), $h, $h + 3600, 'inbound'); }
		}
		unset($down, $up, $ctl, $recv, $inb, $tot);
	}
}

// ---------------------------------------------------------------- d) Hin und zurueck (Stundenmediane, 24 h)
$pairs = array(); // "a|b|fam" (a < b) => array(Werte a->b, Werte b->a)
$st = $pdo->prepare("SELECT x.src, x.dst, x.fam, x.p50_ms pa, y.p50_ms pb FROM sonar_pair_1h x
	JOIN sonar_pair_1h y ON y.src = x.dst AND y.dst = x.src AND y.fam = x.fam AND y.hour = x.hour
	WHERE x.hour >= ? AND x.hour < ? AND x.src < x.dst AND x.loss < 1 AND y.loss < 1");
$st->execute(array(s64t_db($top - S64T_DAY), s64t_db($top)));
while($r = $st->fetch(PDO::FETCH_ASSOC)) {
	if(isset($isAnchor[$r['src']]) OR isset($isAnchor[$r['dst']])) { continue; }
	$k = $r['src'] . '|' . $r['dst'] . '|' . (int)$r['fam'];
	$pairs[$k][0][] = (float)$r['pa'];
	$pairs[$k][1][] = (float)$r['pb'];
}
$partners = array(); $asym = array(); // node => Partner => true
foreach($pairs as $k => $v) {
	if(count($v[0]) < 2) { continue; }
	[$a, $b] = explode('|', $k);
	$ma = s64t_median($v[0]); $mb = s64t_median($v[1]);
	$partners[$a][$b] = $partners[$b][$a] = true;
	if(abs($ma - $mb) > max(10.0, min($ma, $mb))) { $asym[$a][$b] = $asym[$b][$a] = true; }
}
foreach($asym as $x => $ps) {
	if(count($ps) >= 3 AND count($partners[$x]) >= 4 AND count($ps) >= 0.5 * count($partners[$x])) {
		s64t_flag($x, array('dst' => array_keys($ps)), $top - S64T_DAY, $top, 'asym');
	}
}
unset($pairs, $partners, $asym);

// plaus_bad nachziehen
if(!$dry) {
	$u = $pdo->prepare("UPDATE sonar_nodes SET plaus_bad = plaus_bad + ? WHERE node_id = ?");
	foreach($bad as $s => $n) { $u->execute(array($n, $s)); }
}

// ---------------------------------------------------------------- e) Quote 24 h und Stufen
$ratio = array(); $total = array();
// below_light gegen ein Ziel mit unsicherem Standort (new/stable) zaehlt nicht (Vertrag Abschnitt 3, Teil A); hat
// sich die Stufe des Ziels nach der Messung geaendert, ist unbekannt, wie Teil A gewertet hat: dann auch nicht
$st = $pdo->prepare("SELECT r.src, COUNT(*) t, SUM(r.valid = 0 AND NOT (r.reason = 'below_light' AND (COALESCE(d.trust, 'new') NOT IN ('anchor', 'pillar', 'trusted')
		OR (l.ch IS NOT NULL AND r.at < l.ch)))) b
	FROM sonar_results r LEFT JOIN sonar_nodes d ON d.node_id = r.dst
	LEFT JOIN (SELECT node_id, MAX(at) ch FROM sonar_trust_log GROUP BY node_id) l ON l.node_id = r.dst
	WHERE r.at >= ? GROUP BY r.src");
$st->execute(array(s64t_db($now - S64T_DAY)));
while($r = $st->fetch(PDO::FETCH_ASSOC)) { $total[$r['src']] = (int)$r['t']; $ratio[$r['src']] = (int)$r['t'] > 0 ? (int)$r['b'] / (int)$r['t'] : 0.0; }

$log = array(); // node => array(letzte Aenderung, Quarantaene seit, Quarantaene Ende, letzte Abstufung "implausible"/"median")
foreach($pdo->query("SELECT node_id, MAX(at) last, MAX(CASE WHEN new = 'quarantine' THEN at END) qin, MAX(CASE WHEN old = 'quarantine' THEN at END) qout,
	MAX(CASE WHEN reason = 'implausible' THEN at END) imp, MAX(CASE WHEN reason = 'median' THEN at END) med FROM sonar_trust_log GROUP BY node_id") as $r) {
	$log[$r['node_id']] = array(s64t_ts($r['last']), s64t_ts($r['qin']), s64t_ts($r['qout']), s64t_ts($r['imp']), s64t_ts($r['med']));
}

$nodes = $pdo->query("SELECT node_id, role, trust, first_seen, uptime30, measured, reach4, reach6, lat, lon FROM sonar_nodes WHERE active = 1")->fetchAll(PDO::FETCH_ASSOC);

// ---------------------------------------------------------------- f) g) taeglich: Verfuegbarkeit und Median
$uptime = array(); $dev = array();
if($full) {
	$from = $top - 30 * S64T_DAY;
	$p = array(s64t_db($from), s64t_db($top));
	$aw = '';
	if($anchors) { $aw = " UNION SELECT dst node, hour FROM sonar_pair_1h WHERE hour >= ? AND hour < ? AND loss < 1 AND src IN (" . s64t_in($anchors) . ")"; $p = array_merge($p, $p, $anchors); }
	$upHours = array();
	foreach(s64t_rows("SELECT node, COUNT(DISTINCT hour) h FROM (SELECT src node, hour FROM sonar_pair_1h WHERE hour >= ? AND hour < ?$aw) x GROUP BY node", $p) as $r) { $upHours[$r['node']] = (int)$r['h']; }
	foreach($nodes as $n) {
		$id = $n['node_id'];
		if($n['trust'] === 'quarantine') { continue; } // eingefroren
		$since = max($from, (int)s64t_ts($n['first_seen']), $log[$id][2] ?? 0);
		$span = intdiv(max(0, $top - $since), 3600);
		if($span < 1) { $uptime[$id] = 0.0; continue; }
		$have = $upHours[$id] ?? 0;
		if($since > $from) { // erst seit kurzem dabei oder aus der Quarantaene: genau ab $since zaehlen
			$q = array(s64t_db($since), s64t_db($top), $id);
			$qa = '';
			if($anchors) { $qa = " UNION SELECT hour FROM sonar_pair_1h WHERE hour >= ? AND hour < ? AND dst = ? AND loss < 1 AND src IN (" . s64t_in($anchors) . ")"; $q = array_merge($q, array(s64t_db($since), s64t_db($top), $id), $anchors); }
			$have = (int)s64t_rows("SELECT COUNT(*) c FROM (SELECT hour FROM sonar_pair_1h WHERE hour >= ? AND hour < ? AND src = ?$qa) x", $q)[0]['c'];
		}
		$uptime[$id] = min(1.0, $have / $span);
	}
	unset($upHours);

	// Bereinigung: Entfernungsanteil (1,5 x Licht in der Faser) und eigene Anker-Latenz (Anschluss, WLAN) abziehen,
	// damit nur bleibt, was nicht zu Ort und Anschluss passt. Ohne Standort keine Pruefung.
	$pos = array(); $trustOf = array();
	foreach($nodes as $n) {
		$trustOf[$n['node_id']] = $n['trust'];
		if($n['lat'] !== null AND $n['lon'] !== null) { $pos[$n['node_id']] = array((float)$n['lat'], (float)$n['lon']); }
	}
	$geo = function(string $a, string $b) use ($pos): ?float {
		if(!isset($pos[$a], $pos[$b])) { return null; }
		return 1.5 * s64_light_min_ms(s64_distance_km($pos[$a][0], $pos[$a][1], $pos[$b][0], $pos[$b][1]));
	};
	$base = array(); // src|fam|hour => Median ueber die Anker (Anker-Latenz ohne Entfernungsanteil)
	if($anchors) {
		for($h = $top - S64T_DAY; $h < $top; $h += 3600) {
			if(microtime(true) > $deadline) { break; }
			$tmp = array();
			foreach(s64t_rows("SELECT src, dst, fam, avg_ms FROM sonar_results WHERE dst IN (" . s64t_in($anchors) . ") AND at >= ? AND at < ? AND valid = 1 AND recv > 0 AND method = 'udp'",
				array_merge($anchors, array(s64t_db($h), s64t_db($h + 3600)))) as $r) { $tmp[$r['src'] . '|' . (int)$r['fam']][$r['dst']][] = (float)$r['avg_ms']; }
			foreach($tmp as $k => $byA) {
				$src = explode('|', $k)[0];
				$v = array();
				foreach($byA as $a => $vals) { if(($g = $geo($src, $a)) !== null) { $v[] = s64t_median($vals) - $g; } }
				if($v) { $base[$k . '|' . $h] = s64t_median($v); }
			}
		}
	}
	$checked = array(); $off = array();
	$q = $pdo->prepare("SELECT src, fam, at, avg_ms FROM sonar_results WHERE dst = ? AND at >= ? AND at < ? AND valid = 1 AND recv > 0 AND method IN ('udp', 'icmp') AND avg_ms IS NOT NULL");
	foreach($nodes as $d) {
		if($d['role'] === 'anchor' OR !(int)$d['measured'] OR microtime(true) > $deadline) { continue; }
		$q->execute(array($d['node_id'], s64t_db($top - S64T_DAY), s64t_db($top)));
		$g = array(); // fam|hour => src => Werte
		while($r = $q->fetch(PDO::FETCH_ASSOC)) {
			$h = intdiv((int)strtotime($r['at'] . ' UTC'), 3600) * 3600;
			$g[(int)$r['fam'] . '|' . $h][$r['src']][] = (float)$r['avg_ms'];
		}
		foreach($g as $fh => $bySrc) {
			[$f, $h] = explode('|', $fh);
			$m = array(); // src => array(roh, bereinigt, Gewicht)
			foreach($bySrc as $s => $v) {
				$b = $base[$s . '|' . $f . '|' . $h] ?? null;
				$gd = $geo($s, $d['node_id']);
				$w = S64T_WEIGHT[$trustOf[$s] ?? 'quarantine'] ?? 0.0;
				if($b === null OR $gd === null) { continue; }
				$raw = s64t_median($v);
				$m[$s] = array($raw, $raw - $b - $gd, $w);
			}
			if(count($m) < 4) { continue; }
			foreach($m as $s => $e) {
				$vw = array(); $raws = array(); $wsum = 0.0;
				foreach($m as $o => $oe) { if($o !== $s AND $oe[2] > 0) { $vw[] = array($oe[1], $oe[2]); $raws[] = $oe[0]; $wsum += $oe[2]; } }
				if(count($vw) < 3 OR $wsum < 0.6) { continue; }
				$checked[$s] = ($checked[$s] ?? 0) + 1;
				if(abs($e[1] - s64t_wmedian($vw)) > max(5.0, 0.5 * s64t_median($raws))) { $off[$s] = ($off[$s] ?? 0) + 1; }
			}
		}
	}
	foreach($checked as $s => $c) { if($c >= 10) { $dev[$s] = ($off[$s] ?? 0) / $c; } }
	unset($base, $checked, $off);
}

// ---------------------------------------------------------------- h) Stufen setzen
$changes = array();
$setT = $pdo->prepare("UPDATE sonar_nodes SET trust = ? WHERE node_id = ?");
$addL = $pdo->prepare("INSERT INTO sonar_trust_log (node_id, at, old, new, reason) VALUES (?, ?, ?, ?, ?)");
$setU = $pdo->prepare("UPDATE sonar_nodes SET uptime30 = ?, score = ? WHERE node_id = ?");
foreach($nodes as $n) {
	$id = $n['node_id'];
	$old = $n['trust'];
	$new = $old; $why = '';
	$t = $total[$id] ?? 0;
	$rt = $t >= S64T_MIN_TOTAL ? ($ratio[$id] ?? 0.0) : 0.0;
	$lg = $log[$id] ?? array(null, null, null, null, null);
	$lvl = array_search($old, S64T_LEVELS, true);
	if($n['role'] === 'anchor') { if($old !== 'anchor') { $new = 'anchor'; $why = 'anchor'; } }
	elseif($old === 'anchor' OR ($old !== 'quarantine' AND $lvl === false)) { $new = 'new'; $why = 'role'; }
	elseif($old !== 'quarantine' AND $rt > S64T_QUARANTINE) { $new = 'quarantine'; $why = 'implausible_24h'; }
	elseif($old === 'quarantine') {
		if(($lg[1] === null OR $lg[1] <= $now - S64T_Q_MIN) AND $t >= S64T_MIN_TOTAL AND $rt <= S64T_Q_EXIT) { $new = 'new'; $why = 'quarantine_end'; }
	} elseif($lvl > 0 AND $rt > S64T_DEMOTE AND ($lg[3] === null OR $lg[3] < $now - S64T_DAY)) { $new = S64T_LEVELS[$lvl - 1]; $why = 'implausible'; }
	elseif($full AND $lvl !== false) {
		$up = $uptime[$id] ?? (float)$n['uptime30'];
		$dv = $dev[$id] ?? null;
		$since = max((int)s64t_ts($n['first_seen']), $lg[2] ?? 0);
		$age = ($now - $since) / S64T_DAY;
		$can = 0;
		foreach(array('stable' => 1, 'trusted' => 2, 'pillar' => 3) as $name => $i) {
			[$days, $minUp, $maxRt, $maxDev, $needDev] = S64T_RULES[$name];
			if($age < $days OR $up < $minUp OR $rt > $maxRt OR ($dv === null ? $needDev : $dv > $maxDev)) { break; }
			if($name === 'pillar' AND (!(int)$n['measured'] OR ($n['reach4'] === 'none' AND $n['reach6'] === 'none'))) { break; }
			$can = $i;
		}
		if($dv !== null AND $dv > S64T_RULES['stable'][3] AND $lvl > 0 AND ($lg[4] === null OR $lg[4] < $now - S64T_DAY)) { $new = S64T_LEVELS[$lvl - 1]; $why = 'median'; }
		elseif($can < $lvl) { $new = S64T_LEVELS[$can]; $why = 'conditions'; }
		elseif($can > $lvl AND ($lg[0] === null OR $lg[0] <= $now - S64T_DAY)) { $new = S64T_LEVELS[$lvl + 1]; $why = 'promote'; }
	}
	if($new !== $old) {
		$changes[] = "$id $old -> $new ($why)";
		if(!$dry) { $setT->execute(array($new, $id)); $addL->execute(array($id, s64t_db($now), $old, $new, $why)); }
	}
	if($full AND !$dry AND isset($uptime[$id])) {
		$age = min(1.0, ($now - max((int)s64t_ts($n['first_seen']), $lg[2] ?? 0)) / (180 * S64T_DAY));
		$score = $new === 'anchor' ? 1.0 : ($new === 'quarantine' ? 0.0 : 0.35 * $age + 0.45 * $uptime[$id] + 0.2 * (1 - min(1.0, $rt / S64T_QUARANTINE)));
		$setU->execute(array(round($uptime[$id], 4), round(max(0.0, $score), 3), $id));
	} elseif(!$dry AND $new === 'quarantine' AND $old !== 'quarantine') {
		$pdo->prepare("UPDATE sonar_nodes SET score = 0 WHERE node_id = ?")->execute(array($id));
	}
}
foreach($changes as $c) { echo "$c\n"; }
$fs = array(); foreach($found as $k => $v) { $fs[] = "$k $v"; }
printf("%s%s: verworfen %s, Stufen geaendert %d, Knoten %d\n", $dry ? 'NUR ANZEIGEN: ' : '', $full ? 'taeglich' : 'stuendlich',
	$fs ? implode(', ', $fs) : '0', count($changes), count($nodes));
