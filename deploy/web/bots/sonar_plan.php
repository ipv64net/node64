<?php
/**
 * Sonar64 Planer (Vertrag docs/SONAR64-VERTRAG.md Abschnitt 7, Teil J). Alle 5 min ueber honeypot_cron.php (HPC_JOBS),
 * nur auf der Kommandozeile:
 *
 *   php sonar_plan.php                 ausfuehren
 *   php sonar_plan.php --dry           nur rechnen und Zahlen zeigen, nichts schreiben
 *   php sonar_plan.php --now=<ISO>     Zeitpunkt vorgeben (Tests)
 *
 * 1. Erreichbarkeit reach4/6 der gemessenen Knoten aus den Anker-Messungen der letzten Stunde (udp vor icmp, keine
 *    Anker-Messung = alter Stand).
 * 2. Je aktivem Knoten (online <= 15 min, also auch gleich nach register) ein Plan mit den Runden der naechsten 30 min
 *    (5-min-Raster, UTC). Die laufende Runde bleibt unveraendert; in schon geplanten kommenden Runden bleiben die Ziele,
 *    freie Budget-Plaetze werden mit weiteren Zielen aufgefuellt (Vertrag 10.1); dazu kommt je Lauf eine neue Runde.
 *    Ziele, die nicht mehr gemessen werden duerfen (Opt-out, Quarantaene, andere IP, anderer Weg), fallen sofort heraus.
 *    Knoten: Anker, Kontrollziel (~5 %), Traceroute (2 je Stunde), neue Ziele (noch keine gueltige Messung von einem
 *    Nicht-Anker in 24 h) mit Vorrang, 3 Nachbarn, gleicher und fremder ASN, Stichprobe (deterministisch ueber
 *    Knoten + Stunde), hoechstens Budget-Ziele je Runde und 10 Messende je Ziel und Runde.
 *    Anker: alle gemessenen Knoten (auch ohne Weg, um ihn zu finden, und bis 6 h nach der letzten Meldung, damit
 *    sonar_outages.php Ausfaelle sieht; neu gemessene sofort in allen kommenden Runden) und die anderen Anker,
 *    hoechstens 2.000 je Runde.
 * 3. Abgelaufene Plaene und Plaene deaktivierter Knoten loeschen (enthalten IPs).
 */
if(php_sapi_name() !== 'cli') { exit; }
if(!is_file(__DIR__ . '/../sonar/s64_lib.php')) { fwrite(STDERR, "sonar/s64_lib.php fehlt\n"); exit(1); }
require_once __DIR__ . '/../sonar/s64_lib.php';

const S64P_ROUND        = 300;   // Runde 5 min
const S64P_ROUNDS       = 6;     // 30 min
const S64P_ONLINE       = 900;   // online = letzte Meldung <= 15 min
const S64P_RECENT       = 21600; // Anker messen gemessene Knoten bis 6 h nach der letzten Meldung (Stoerungen sehen)
const S64P_VALID        = 1800;  // Plan gilt 30 min
const S64P_BUDGET       = array('sparsam' => 8, 'normal' => 15, 'grosszuegig' => 20);
const S64P_ANCHOR_MAX   = 2000;  // Ziele je Runde eines Ankers
const S64P_PER_TARGET   = 10;    // Messende (ohne Anker) je Ziel und Runde
const S64P_COUNT        = 5;     // Pakete je Ping eines Knotens
const S64P_COUNT_ANCHOR = 3;     // Pakete je Ping eines Ankers
const S64P_NEIGHBORS    = 3;
const S64P_SAMPLE       = 2;     // Stichprobe: Kandidaten je Budget-Platz
const S64P_CONTROL_PCT  = 5;     // Anteil der Knoten-Stunden mit Kontrollziel
const S64P_MAX_TTL      = 30;
const S64P_TIME_LIMIT   = 200;   // Sekunden, danach bleiben die alten Plaene der restlichen Knoten
const S64P_CHUNK        = 100;

$opt = getopt('', array('dry', 'now:'));
$dry = isset($opt['dry']);
$now = isset($opt['now']) ? strtotime((string)$opt['now']) : time();
if($now === false) { fwrite(STDERR, "--now ungueltig\n"); exit(1); }
$lock = fopen(sys_get_temp_dir() . '/sonar_plan.lock', 'c');
if($lock === false OR !flock($lock, LOCK_EX | LOCK_NB)) { echo "laeuft bereits\n"; exit(0); }
set_time_limit(S64P_TIME_LIMIT + 60);
$deadline = microtime(true) + S64P_TIME_LIMIT;
$pdo = s64_pdo();
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

function s64p_db(int $t): string { return gmdate('Y-m-d H:i:s', $t); }
function s64p_iso(int $t): string { return gmdate('Y-m-d\TH:i:s\Z', $t); }
function s64p_hash(string ...$p): int { return crc32(implode('|', $p)); }
function s64p_ip_ok(?string $ip, int $fam): bool {
	if($ip === null OR $ip === '') { return false; }
	if(filter_var($ip, FILTER_VALIDATE_IP, $fam === 4 ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6) === false) { return false; }
	return s64_is_public_ip($ip);
}
function s64p_in(array $ids): string { return implode(',', array_fill(0, count($ids), '?')); }

// ---------------------------------------------------------------- 1. Erreichbarkeit aus den Anker-Messungen
$anchorIds = $pdo->query("SELECT node_id FROM sonar_nodes WHERE role = 'anchor' AND active = 1")->fetchAll(PDO::FETCH_COLUMN);
$seen = array(); // dst => fam => method => erfolgreiche Messungen
if($anchorIds) {
	$st = $pdo->prepare("SELECT dst, fam, method, SUM(recv > 0) ok FROM sonar_results
		WHERE src IN (" . s64p_in($anchorIds) . ") AND at >= ? AND valid = 1 AND method IN ('icmp', 'udp') GROUP BY dst, fam, method");
	$st->execute(array_merge($anchorIds, array(s64p_db($now - 3600))));
	while($r = $st->fetch(PDO::FETCH_ASSOC)) { $seen[$r['dst']][(int)$r['fam']][$r['method']] = (int)$r['ok']; }
}
$reach = array(); // node_id => array(4 => ..., 6 => ...)
$reachChanged = 0;
$upd = $pdo->prepare("UPDATE sonar_nodes SET reach4 = ?, reach6 = ? WHERE node_id = ?");
foreach($pdo->query("SELECT node_id, measured, ip4, ip6, reach4, reach6 FROM sonar_nodes WHERE active = 1 AND role = 'node'")->fetchAll(PDO::FETCH_ASSOC) as $n) {
	$new = array();
	foreach(array(4, 6) as $f) {
		if(!(int)$n['measured'] OR !s64p_ip_ok($n['ip' . $f], $f)) { $new[$f] = 'none'; }
		elseif(isset($seen[$n['node_id']][$f])) {
			$m = $seen[$n['node_id']][$f];
			$new[$f] = !empty($m['udp']) ? 'udp' : (!empty($m['icmp']) ? 'icmp' : 'none');
		} else { $new[$f] = in_array($n['reach' . $f], array('icmp', 'udp'), true) ? $n['reach' . $f] : 'none'; }
	}
	$reach[$n['node_id']] = $new;
	if($new[4] !== $n['reach4'] OR $new[6] !== $n['reach6']) {
		$reachChanged++;
		if(!$dry) { $upd->execute(array($new[4], $new[6], $n['node_id'])); }
	}
}
unset($seen);

// ---------------------------------------------------------------- 2. Knoten laden
$cur = intdiv($now, S64P_ROUND) * S64P_ROUND; // laufende Runde
$N = array();       // node_id => Angaben
$pool = array();    // moegliche Ziele (Knoten)
$byAsn = array();   // ASN => Ziele
$grid = array();    // Raster 0,5 Grad => Ziele mit Standort
$anchors = array(); // Anker online
$st = $pdo->prepare("SELECT node_id, role, lat, lon, measured, budget, ip4, ip6, asn4, asn6, trust, health, last_seen FROM sonar_nodes
	WHERE active = 1 AND last_seen >= ? ORDER BY node_id");
$st->execute(array(s64p_db($now - S64P_RECENT)));
$ids = array(); // online: messen und sind Ziele
while($r = $st->fetch(PDO::FETCH_ASSOC)) {
	$id = $r['node_id'];
	$isAnchor = $r['role'] === 'anchor';
	$online = (int)strtotime($r['last_seen'] . ' UTC') >= $now - S64P_ONLINE;
	if(!$online AND ($isAnchor OR !(int)$r['measured'])) { continue; } // nur noch Ziel der Anker
	$fams = array();
	foreach(array(4, 6) as $f) { if(s64p_ip_ok($r['ip' . $f], $f)) { $fams[$f] = $r['ip' . $f]; } }
	if(!$fams) { continue; } // ohne oeffentliche Adresse weder Ziel noch sinnvoll messend
	$health = $r['health'] !== null ? json_decode((string)$r['health'], true) : null;
	$n = array(
		'anchor' => $isAnchor,
		'lat' => $r['lat'] !== null ? (float)$r['lat'] : null,
		'lon' => $r['lon'] !== null ? (float)$r['lon'] : null,
		'fams' => $fams,
		'asn' => $r['asn4'] !== null ? (int)$r['asn4'] : ($r['asn6'] !== null ? (int)$r['asn6'] : null),
		'budget' => $isAnchor ? S64P_ANCHOR_MAX : (S64P_BUDGET[$r['budget']] ?? S64P_BUDGET['sparsam']),
		'icmp' => !(is_array($health) AND !empty($health['icmp_denied'])),
		'measured' => (int)$r['measured'] === 1,
		'reach' => $reach[$id] ?? array(4 => 'none', 6 => 'none'),
		'tfam' => array(), // Familie => Methode, wenn Ziel fuer Knoten
	);
	if($n['lat'] !== null AND ($n['lat'] < -90 OR $n['lat'] > 90 OR $n['lon'] === null OR $n['lon'] < -180 OR $n['lon'] > 180)) { $n['lat'] = $n['lon'] = null; }
	if($online) { $ids[] = $id; }
	if($isAnchor) {
		$anchors[] = $id;
	} elseif($online AND $n['measured'] AND $r['trust'] !== 'quarantine') {
		foreach($fams as $f => $ip) { if(in_array($n['reach'][$f], array('icmp', 'udp'), true)) { $n['tfam'][$f] = $n['reach'][$f]; } }
		if($n['tfam']) {
			$pool[] = $id;
			if($n['asn'] !== null) { $byAsn[$n['asn']][] = $id; }
			if($n['lat'] !== null) { $grid[(int)floor($n['lat'] * 2) . ':' . (int)floor($n['lon'] * 2)][] = $id; }
		}
	}
	$N[$id] = $n;
}
// neue Ziele: noch keine gueltige Messung von einem Nicht-Anker in den letzten 24 h (Vorrang bei freien Plaetzen)
$newT = array();
foreach(array_chunk($pool, 500) as $chunk) {
	$st = $pdo->prepare("SELECT n.node_id FROM sonar_nodes n WHERE n.node_id IN (" . s64p_in($chunk) . ") AND NOT EXISTS (SELECT 1 FROM sonar_results r
		WHERE r.dst = n.node_id AND r.at >= ? AND r.valid = 1 AND r.src NOT LIKE 'a\\_%')");
	$st->execute(array_merge($chunk, array(s64p_db($now - 86400))));
	foreach($st->fetchAll(PDO::FETCH_COLUMN) as $id) { $newT[$id] = true; }
}
$newList = array_values(array_filter($pool, function($t) use ($newT) { return isset($newT[$t]); }));

/** Quadrat der Entfernung (gleichabstaendig, nur zum Sortieren). */
function s64p_d2(array $a, array $b): float {
	$dy = $a['lat'] - $b['lat'];
	$dx = ($a['lon'] - $b['lon']) * cos(deg2rad(($a['lat'] + $b['lat']) / 2));
	return $dx * $dx + $dy * $dy;
}

/** Gleiche oeffentliche IP (zwei Knoten im selben Haushalt messen sich nicht). */
function s64p_same_ip(array $a, array $b): bool {
	foreach($a['fams'] as $f => $ip) { if(isset($b['fams'][$f]) AND $b['fams'][$f] === $ip) { return true; } }
	return false;
}

/** Eintraege (Ziel, Familie, Methode), die Knoten $m bei Ziel $t messen kann. */
function s64p_entries(string $m, string $t): array {
	global $N;
	if($m === $t OR !isset($N[$t]) OR s64p_same_ip($N[$m], $N[$t])) { return array(); }
	$out = array();
	foreach($N[$m]['fams'] as $f => $ip) {
		$meth = $N[$t]['tfam'][$f] ?? null;
		if($meth === null OR ($meth === 'icmp' AND !$N[$m]['icmp'])) { continue; }
		$out[] = array($t, $f, $meth);
	}
	return $out;
}

/** Deterministische Auswahl aus $list (Startwert $seed), hoechstens $want Ziele, die $ok erfuellen. */
function s64p_pick(array $list, string $seed, int $want, callable $ok): array {
	$out = array();
	$c = count($list);
	if($c === 0) { return $out; }
	for($k = 0, $tries = $want * 4 + 8; $k < $tries AND count($out) < $want; $k++) {
		$t = $list[s64p_hash($seed, (string)$k) % $c];
		if(!isset($out[$t]) AND $ok($t)) { $out[$t] = true; }
	}
	return array_keys($out);
}

/** Die $k naechsten Ziele aus dem Raster. */
function s64p_nearest(string $m, int $k, callable $ok): array {
	global $N, $grid;
	if($N[$m]['lat'] === null OR !$grid) { return array(); }
	$cy = (int)floor($N[$m]['lat'] * 2);
	$cx = (int)floor($N[$m]['lon'] * 2);
	$found = array();
	for($r = 0, $extra = -1; $r <= 12; $r++) {
		for($y = $cy - $r; $y <= $cy + $r; $y++) {
			for($x = $cx - $r; $x <= $cx + $r; $x++) {
				if(max(abs($y - $cy), abs($x - $cx)) !== $r) { continue; }
				foreach($grid["$y:$x"] ?? array() as $t) { if($t !== $m AND $ok($t)) { $found[$t] = s64p_d2($N[$m], $N[$t]); } }
			}
		}
		// ein Ring mehr, damit die Ecken des Rasters keine naeheren Ziele verstecken
		if($extra < 0 AND count($found) >= $k) { $extra = $r + 1; }
		if($extra >= 0 AND $r >= $extra) { break; }
	}
	asort($found);
	return array_slice(array_keys($found), 0, $k);
}

/** Anker nach Entfernung (ohne Standort nach Kennung). */
function s64p_anchors_for(string $m): array {
	global $N, $anchors;
	$list = array();
	foreach($anchors as $a) {
		if($a === $m) { continue; }
		$list[$a] = ($N[$m]['lat'] !== null AND $N[$a]['lat'] !== null) ? s64p_d2($N[$m], $N[$a]) : 0.0;
	}
	asort($list);
	return array_keys($list);
}

/** Kandidaten eines Knotens fuer eine Stunde (gleich fuer alle Runden der Stunde, damit Paare Stundenwerte bekommen;
 * ohne Zwischenspeicher, im Betrieb kommt je Lauf nur eine Runde dazu). */
function s64p_candidates(string $m, int $hour): array {
	global $N, $pool, $byAsn, $newList;
	$h = (string)$hour;
	$ok = function($t) use ($m) { return s64p_entries($m, $t) !== array(); };
	$asn = $N[$m]['asn'];
	$order = s64p_pick($newList, "new|$m|$h", $N[$m]['budget'], $ok); // neue Ziele zuerst
	$order = array_merge($order, s64p_nearest($m, S64P_NEIGHBORS, $ok));
	if($asn !== null) { $order = array_merge($order, s64p_pick($byAsn[$asn] ?? array(), "same|$m|$h", 1, $ok)); }
	$order = array_merge($order, s64p_pick($pool, "foreign|$m|$h", 1, function($t) use ($N, $ok, $asn) { return $N[$t]['asn'] !== $asn AND $ok($t); }));
	$order = array_merge($order, s64p_pick($pool, "sample|$m|$h", $N[$m]['budget'] * S64P_SAMPLE, $ok));
	$out = array();
	foreach(array_unique($order) as $t) { foreach(s64p_entries($m, $t) as $e) { $out[] = $e; } }
	return $out;
}

function s64p_target(string $t, int $fam, string $method, int $count): array {
	global $N;
	$e = array('id' => $t, 'addr' => $N[$t]['fams'][$fam], 'fam' => $fam, 'method' => $method, 'count' => $method === 'trace' ? 1 : $count);
	if($method === 'trace') { $e['max_ttl'] = S64P_MAX_TTL; }
	return $e;
}

/** Darf ein Ziel aus einem frueheren Plan bleiben? */
function s64p_keep(string $m, array $t): bool {
	global $N;
	$id = (string)($t['id'] ?? '');
	$fam = (int)($t['fam'] ?? 0);
	$meth = (string)($t['method'] ?? '');
	if(!isset($N[$id], $N[$id]['fams'][$fam]) OR $id === $m OR ($t['addr'] ?? '') !== $N[$id]['fams'][$fam] OR !isset($N[$m]['fams'][$fam])) { return false; }
	if(!in_array($meth, array('icmp', 'udp', 'trace'), true)) { return false; }
	if($meth !== 'udp' AND !$N[$m]['icmp'] AND !$N[$m]['anchor']) { return false; }
	if($N[$id]['anchor']) { return true; }
	if($N[$m]['anchor']) { return $N[$id]['measured']; }
	if(!isset($N[$id]['tfam'][$fam])) { return false; }
	return $meth === 'trace' OR $meth === $N[$id]['tfam'][$fam];
}

/** Runde ablegen: Ziele gleich als JSON (wenig Speicher), Kontrollziele und Zahl merken. */
function s64p_store(string $m, int $s, array $list): void {
	global $N, $plans, $controls, $tcount;
	$plans[$m][$s] = json_encode(array_values($list), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	$tcount[$m] = ($tcount[$m] ?? 0) + count($list);
	if($N[$m]['anchor']) { return; }
	foreach($list as $t) { if($t['method'] === 'icmp' AND $N[$t['id']]['anchor']) { $controls[$m][] = array('round' => s64p_iso($s), 'id' => $t['id'], 'fam' => $t['fam']); } }
}

/** Runden eines frueheren Plans, die bleiben (laufende und kommende, nur noch erlaubte Ziele): Runde => Ziele. */
function s64p_retained(string $m, array $row): array {
	global $N, $now, $cur;
	if((int)strtotime($row['issued'] . ' UTC') < $now - S64P_VALID) { return array(); }
	$body = json_decode((string)$row['body'], true);
	if(!is_array($body) OR !isset($body['rounds']) OR !is_array($body['rounds'])) { return array(); }
	$out = array();
	foreach($body['rounds'] as $rd) {
		$s = isset($rd['start']) ? strtotime((string)$rd['start']) : false;
		if($s === false OR $s < $cur OR $s > $cur + S64P_ROUNDS * S64P_ROUND OR $s % S64P_ROUND !== 0 OR !is_array($rd['targets'] ?? null)) { continue; }
		$keep = array();
		foreach($rd['targets'] as $t) {
			if(count($keep) >= $N[$m]['budget']) { break; }
			if(is_array($t) AND s64p_keep($m, $t)) { $keep[] = $t; }
		}
		if($keep) { $out[$s] = $keep; } // leere Runde neu planen
	}
	return $out;
}

/** Bisherige Plaene eines Blocks von Knoten: node_id => Zeile. */
function s64p_prev(array $chunk): array {
	global $pdo;
	$st = $pdo->prepare("SELECT node_id, issued, body FROM sonar_plans WHERE node_id IN (" . s64p_in($chunk) . ")");
	$st->execute($chunk);
	$out = array();
	while($r = $st->fetch(PDO::FETCH_ASSOC)) { $out[$r['node_id']] = $r; }
	return $out;
}

// ---------------------------------------------------------------- 3. bisherige Plaene (Runden bleiben stabil)
// Erster Durchgang nur zaehlen (Zielgrenze) und merken, welche Runden schon geplant sind; beim Schreiben werden die
// Plaene noch einmal gelesen. So liegen im Speicher nur die neuen Runden (im Betrieb eine je Knoten).
$slots = array();
for($i = 1; $i <= S64P_ROUNDS; $i++) { $slots[] = $cur + $i * S64P_ROUND; }
$plans = array();    // node_id => array(slot => Ziele als JSON), nur neue Runden
$have = array();     // node_id => slot => true (schon geplant)
$controls = array(); // node_id => Kontrollziele
$tcount = array();   // node_id => Ziele
$cnt = array();      // slot => Ziel => Zahl der Messenden (ohne Anker)
$cntA = array();     // slot => Adresse => Zahl der Messenden (mehrere Knoten hinter einer IP, z. B. CGNAT)
$part = array();     // node_id => slot => Ziele einer kommenden Runde mit freien Plaetzen ("Ziel|fam|Methode|Adresse" je Zeile)
$addl = array();     // node_id => slot => dort aufgefuellte Ziele
foreach(array_chunk($ids, 200) as $chunk) {
	foreach(s64p_prev($chunk) as $m => $row) {
		foreach(s64p_retained($m, $row) as $s => $keep) {
			$have[$m][$s] = true;
			if($s > $cur AND count($keep) < $N[$m]['budget']) {
				$part[$m][$s] = implode("\n", array_map(function($t) { return $t['id'] . '|' . (int)$t['fam'] . '|' . $t['method'] . '|' . $t['addr']; }, $keep));
			}
			if(!$N[$m]['anchor']) {
				$seenT = array(); $seenA = array();
				foreach($keep as $t) {
					if($N[$t['id']]['anchor']) { continue; }
					if(!isset($seenT[$t['id']])) { $seenT[$t['id']] = true; $cnt[$s][$t['id']] = ($cnt[$s][$t['id']] ?? 0) + 1; }
					if(!isset($seenA[$t['addr']])) { $seenA[$t['addr']] = true; $cntA[$s][$t['addr']] = ($cntA[$s][$t['addr']] ?? 0) + 1; }
				}
			}
		}
	}
}

// ---------------------------------------------------------------- 4. neue Runden planen, kommende auffuellen
$newRounds = 0;
$filled = 0;
$aborted = false;
foreach($slots as $s) {
	$hour = intdiv($s, 3600);
	$idx = intdiv($s % 3600, S64P_ROUND); // Runde in der Stunde 0..11
	$order = $ids;
	usort($order, function($a, $b) use ($s) { return s64p_hash($a, (string)$s) <=> s64p_hash($b, (string)$s); });
	foreach($order as $m) {
		$fill = $part[$m][$s] ?? null; // schon geplant mit freien Plaetzen: nur Ziele dazu (Anker, Kontrollziel, Trace hat die Runde schon)
		if(isset($have[$m][$s]) AND $fill === null) { continue; }
		if(microtime(true) > $deadline) { $aborted = true; break 2; }
		$n = $N[$m];
		$list = array();
		$exN = 0; $exK = array(); // vorhandene Ziele der Runde: Zahl, "Ziel|fam|Methode" und "Ziel|fam"
		$mineT = array(); // Ziele dieses Knotens in dieser Runde
		$mineA = array(); // Adresse => Ziel (eine Adresse nur fuer ein Ziel, zaehlt einmal)
		if($fill !== null) {
			unset($part[$m][$s]);
			foreach(explode("\n", $fill) as $l) {
				[$t, $f, $meth, $ad] = explode('|', $l, 4);
				$exN++; $exK["$t|$f|$meth"] = true; $exK["$t|$f"] = true;
				if(!$N[$t]['anchor']) { $mineT[$t] = true; $mineA[$ad] = $t; }
			}
		}
		if($n['anchor']) {
			// andere Anker, dann alle gemessenen Knoten (Weg suchen: ohne bekannten Weg abwechselnd, sonst bekannter
			// Weg und in jeder 6. Runde der andere); beim Auffuellen nur, was in der Runde noch fehlt
			foreach(s64p_anchors_for($m) as $a) { foreach($n['fams'] as $f => $ip) { if(isset($N[$a]['fams'][$f]) AND !isset($exK["$a|$f"])) { $list[] = s64p_target($a, $f, 'udp', S64P_COUNT_ANCHOR); } } }
			$nodes = array();
			foreach($N as $t => $tn) {
				if($tn['anchor'] OR !$tn['measured']) { continue; }
				foreach($n['fams'] as $f => $ip) {
					if(!isset($tn['fams'][$f]) OR isset($exK["$t|$f"])) { continue; }
					$alt = (s64p_hash('disc', $t) + $idx) % 6 === 0;
					$known = $tn['reach'][$f];
					if($known === 'none') { $meth = (s64p_hash('alt', $t) + $idx) % 2 === 0 ? 'udp' : 'icmp'; }
					else { $meth = $alt ? ($known === 'udp' ? 'icmp' : 'udp') : $known; }
					$nodes[] = array(s64p_hash('a', $m, $t, (string)$hour), s64p_target($t, $f, $meth, S64P_COUNT_ANCHOR));
				}
			}
			$room = S64P_ANCHOR_MAX - $exN - count($list);
			if(count($nodes) > $room) {
				usort($nodes, function($a, $b) { return $a[0] <=> $b[0]; });
				$nodes = array_slice($nodes, 0, max(0, $room));
			}
			foreach($nodes as $e) { $list[] = $e[1]; }
		} else {
			$budget = $n['budget'] - $exN; // freie Plaetze
			$mine = s64p_anchors_for($m);
			if($fill === null) {
				$anchorMax = max(2, intdiv($budget, 2));
				foreach($mine as $a) {
					foreach($n['fams'] as $f => $ip) {
						if(isset($N[$a]['fams'][$f]) AND count($list) < $anchorMax) { $list[] = s64p_target($a, $f, 'udp', S64P_COUNT); }
					}
				}
				// Kontrollziel: in ~5 % der Knoten-Stunden einmal ein Anker per icmp (Pruefung in sonar_trust.php)
				if($mine AND $n['icmp'] AND count($list) < $budget AND s64p_hash('ctl', $m, (string)$hour) % 100 < S64P_CONTROL_PCT
					AND s64p_hash('ctlslot', $m, (string)$hour) % 12 === $idx) {
					$a = $mine[s64p_hash('ctla', $m, (string)$hour) % count($mine)];
					$f = isset($N[$a]['fams'][4], $n['fams'][4]) ? 4 : 6;
					if(isset($N[$a]['fams'][$f], $n['fams'][$f])) { $list[] = s64p_target($a, $f, 'icmp', S64P_COUNT); }
				}
			}
			$cands = s64p_candidates($m, $hour);
			// Traceroute: zwei Runden je Stunde, erst ein Anker, dann der naechste Nachbar (sonst ein Anker; kein neues Ziel)
			$t1 = s64p_hash('tr', $m, (string)$hour) % 6;
			if($fill === null AND $n['icmp'] AND count($list) < $budget AND ($idx === $t1 OR $idx === $t1 + 6)) {
				$tr = null;
				if($idx === $t1 + 6) {
					foreach($cands as $e) {
						if(isset($newT[$e[0]])) { continue; }
						$ad = $N[$e[0]]['fams'][$e[1]];
						if(($cnt[$s][$e[0]] ?? 0) < S64P_PER_TARGET AND ($cntA[$s][$ad] ?? 0) < S64P_PER_TARGET) {
							$tr = $e; $cnt[$s][$e[0]] = ($cnt[$s][$e[0]] ?? 0) + 1; $mineT[$e[0]] = true;
							$cntA[$s][$ad] = ($cntA[$s][$ad] ?? 0) + 1; $mineA[$ad] = $e[0];
						}
						break;
					}
				}
				if($tr === null AND $mine) {
					$a = $mine[s64p_hash('tra', $m, (string)$hour, (string)$idx) % count($mine)];
					foreach($n['fams'] as $f => $ip) { if(isset($N[$a]['fams'][$f])) { $tr = array($a, $f); break; } }
				}
				if($tr !== null) { $list[] = s64p_target($tr[0], $tr[1], 'trace', 1); }
			}
			foreach($cands as $e) {
				if(count($list) >= $budget) { break; }
				[$t, $f, $meth] = $e;
				if(isset($exK["$t|$f|$meth"])) { continue; } // steht schon in der Runde
				$ad = $N[$t]['fams'][$f];
				// hoechstens 10 Messende je Adresse (auch ueber mehrere Knoten hinter einer IP), dieselbe Adresse nicht doppelt
				if(isset($mineA[$ad]) ? $mineA[$ad] !== $t : ($cntA[$s][$ad] ?? 0) >= S64P_PER_TARGET) { continue; }
				if(!isset($mineT[$t])) { // zweite Familie desselben Ziels zaehlt nicht noch einmal
					if(($cnt[$s][$t] ?? 0) >= S64P_PER_TARGET) { continue; }
					$cnt[$s][$t] = ($cnt[$s][$t] ?? 0) + 1;
					$mineT[$t] = true;
				}
				if(!isset($mineA[$ad])) { $cntA[$s][$ad] = ($cntA[$s][$ad] ?? 0) + 1; $mineA[$ad] = $t; }
				$list[] = s64p_target($t, $f, $meth, S64P_COUNT);
			}
		}
		if($list AND $fill !== null) { $addl[$m][$s] = $list; $filled++; }
		elseif($list) { s64p_store($m, $s, $list); $newRounds++; }
	}
}

// ---------------------------------------------------------------- 5. schreiben
$written = 0; $targets = 0;
$ins = $pdo->prepare("INSERT INTO sonar_plans (node_id, issued, expires, body, etag, controls) VALUES (?, ?, ?, ?, ?, ?)
	ON DUPLICATE KEY UPDATE issued = VALUES(issued), expires = VALUES(expires), body = VALUES(body), etag = VALUES(etag), controls = VALUES(controls)");
foreach(array_chunk(array_keys($plans + $have), S64P_CHUNK) as $chunk) {
	$prev = s64p_prev(array_keys(array_intersect_key($have, array_flip($chunk))) ?: array(''));
	if(!$dry) { $pdo->beginTransaction(); }
	foreach($chunk as $m) {
		if(isset($prev[$m])) {
			foreach(s64p_retained($m, $prev[$m]) as $s => $keep) { if(!isset($plans[$m][$s])) { s64p_store($m, $s, isset($addl[$m][$s]) ? array_merge($keep, $addl[$m][$s]) : $keep); } }
		}
		unset($addl[$m]);
		if(empty($plans[$m])) { continue; }
		ksort($plans[$m]);
		$rounds = array();
		foreach($plans[$m] as $s => $js) { $rounds[] = '{"start":"' . s64p_iso($s) . '","targets":' . $js . '}'; }
		$targets += $tcount[$m] ?? 0;
		$fallback = array();
		foreach(s64p_anchors_for($m) as $a) {
			foreach($N[$m]['fams'] as $f => $ip) { if(isset($N[$a]['fams'][$f]) AND count($fallback) < 4) { $fallback[] = s64p_target($a, $f, 'udp', S64P_COUNT); } }
		}
		// Plan wie wire.go (Plan): v, node_id, issued, expires, rounds, anchors
		$body = '{"v":1,"node_id":' . json_encode($m) . ',"issued":"' . s64p_iso($now) . '","expires":"' . s64p_iso($now + S64P_VALID) . '","rounds":['
			. implode(',', $rounds) . '],"anchors":' . json_encode($fallback, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . '}';
		unset($plans[$m]);
		if(!$dry) { $ins->execute(array($m, s64p_db($now), s64p_db($now + S64P_VALID), $body, substr(hash('sha256', $body), 0, 16), json_encode($controls[$m] ?? array()))); }
		$written++;
	}
	if(!$dry) { $pdo->commit(); }
}

// ---------------------------------------------------------------- 6. alte Plaene loeschen (enthalten IPs)
$deleted = 0;
if(!$dry AND !$aborted) {
	// nicht neu geschriebene Plaene (Knoten offline oder nichts mehr zu planen) nicht mehr ausliefern: sie koennten
	// Ziele enthalten, die nicht mehr erlaubt sind (Opt-out, Quarantaene, neue IP); sent_body bleibt fuer Teil A
	$st = $pdo->prepare("UPDATE sonar_plans SET expires = ? WHERE expires > ? AND issued < ?");
	$st->execute(array(s64p_db($now), s64p_db($now), s64p_db($now)));
}
if(!$dry) {
	$st = $pdo->prepare("DELETE FROM sonar_plans WHERE expires < ? LIMIT 5000");
	$st->execute(array(s64p_db($now - 3600)));
	$deleted += $st->rowCount();
	$st = $pdo->query("DELETE p FROM sonar_plans p JOIN sonar_nodes n ON n.node_id = p.node_id WHERE n.active = 0");
	$deleted += $st->rowCount();
}
printf("%sPlaene %d (Ziele %d, neue Runden %d, aufgefuellt %d), Anker %d, Ziele moeglich %d (neu %d), Weg geaendert %d, geloescht %d, Speicher %.1f MB%s\n",
	$dry ? 'NUR ANZEIGEN: ' : '', $written, $targets, $newRounds, $filled, count($anchors), count($pool), count($newList), $reachChanged, $deleted,
	memory_get_peak_usage() / 1048576, $aborted ? ', ABGEBROCHEN (Zeitgrenze)' : '');
