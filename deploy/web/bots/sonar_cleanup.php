<?php
/**
 * Sonar64 Aufraeumen (Vertrag docs/SONAR64-VERTRAG.md Abschnitte 6/7 und 10.3, Teil J). Taeglich ueber honeypot_cron.php,
 * nur auf der Kommandozeile:
 *
 *   php sonar_cleanup.php              ausfuehren
 *   php sonar_cleanup.php --dry        nur anzeigen
 *   php sonar_cleanup.php --now=<ISO>  Zeitpunkt vorgeben (Tests)
 *
 * 1. Abmelden: Knoten ohne Kontakt (last_seen, sonst first_seen) seit 30 Tagen wie DELETE /sonar/tokens/{id}
 *    (s64_leave, reason inactive); Anker nie, nur Warnung in der Ausgabe. Nie registrierte Knoten-Token, die aelter als
 *    30 Tage sind, werden widerrufen (geben Plaetze der 10 je Account frei).
 * 2. Loeschen: deaktivierte Knoten 90 Tage nach disabled_at endgueltig samt Plan, Ergebnissen, Traces, Proben,
 *    Stundenwerten, Vertrauens-Log und Token; widerrufene Token ohne Knoten nach 90 Tagen.
 * 3. Aufbewahrung: sonar_results und sonar_traces 7 Tage, sonar_inbound 24 h, sonar_pair_1h 90 Tage, sonar_asn_1d und
 *    (beendete) sonar_outages 2 Jahre, sonar_trust_log 1 Jahr. Plaene: abgelaufen > 1 h oder Knoten deaktiviert
 *    (enthalten IPs). Datensparsam: IPs deaktivierter Knoten nach 7 Tagen, IPs aller Knoten nach 90 Tagen ohne Meldung
 *    entfernen (bei der naechsten Anfrage nimmt ipv64 die IP wieder aus der Verbindung).
 * Geloescht wird in Bloecken (kurze Sperren); ein Abbruch schadet nicht, der naechste Lauf macht weiter.
 */
if(php_sapi_name() !== 'cli') { exit; }
if(!is_file(__DIR__ . '/../sonar/s64_lib.php')) { fwrite(STDERR, "sonar/s64_lib.php fehlt\n"); exit(1); }
require_once __DIR__ . '/../sonar/s64_lib.php';

const S64C_BATCH      = 10000;
const S64C_NODES      = 500;    // Knoten je Lauf (abmelden bzw. loeschen)
const S64C_TIME_LIMIT = 1500;
const S64C_DAY        = 86400;
const S64C_INACTIVE   = 30;     // Tage ohne Kontakt -> abmelden; nie registriertes Token -> widerrufen
const S64C_DELETE     = 90;     // Tage nach disabled_at bzw. revoked_at -> loeschen

$opt = getopt('', array('dry', 'now:'));
$dry = isset($opt['dry']);
$now = isset($opt['now']) ? strtotime((string)$opt['now']) : time();
if($now === false) { fwrite(STDERR, "--now ungueltig\n"); exit(1); }
$lock = fopen(sys_get_temp_dir() . '/sonar_cleanup.lock', 'c');
if($lock === false OR !flock($lock, LOCK_EX | LOCK_NB)) { echo "laeuft bereits\n"; exit(0); }
set_time_limit(S64C_TIME_LIMIT + 60);
$deadline = microtime(true) + S64C_TIME_LIMIT;
$pdo = s64_pdo();
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

function s64c_db(int $t): string { return gmdate('Y-m-d H:i:s', $t); }

/** In Bloecken loeschen ($set leer) bzw. aendern ($set ohne Platzhalter); --dry zaehlt nur. */
function s64c_batch(string $table, string $set, string $where, array $p): int {
	global $pdo, $dry, $deadline;
	if($dry) { $st = $pdo->prepare("SELECT COUNT(*) FROM $table WHERE $where"); $st->execute($p); return (int)$st->fetchColumn(); }
	$sql = $set === '' ? "DELETE FROM $table WHERE $where LIMIT " . S64C_BATCH : "UPDATE $table SET $set WHERE $where LIMIT " . S64C_BATCH;
	$n = 0;
	do {
		$st = $pdo->prepare($sql);
		$st->execute($p);
		$n += $st->rowCount();
	} while($st->rowCount() === S64C_BATCH AND microtime(true) < $deadline);
	return $n;
}
$out = array();

// ---------------------------------------------------------------- 1. inaktive Knoten abmelden, unbenutzte Token widerrufen
$st = $pdo->prepare("SELECT token_id, node_id, role, COALESCE(last_seen, first_seen) seen FROM sonar_nodes WHERE active = 1 AND COALESCE(last_seen, first_seen) < ?
	ORDER BY id LIMIT " . S64C_NODES);
$st->execute(array(s64c_db($now - S64C_INACTIVE * S64C_DAY)));
$left = 0;
foreach($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
	if($r['role'] === 'anchor') { // Anker nie automatisch
		$out[] = 'WARNUNG Anker ' . $r['node_id'] . ' seit ' . intdiv($now - (int)strtotime($r['seen'] . ' UTC'), S64C_DAY) . ' Tagen ohne Kontakt';
		continue;
	}
	if(microtime(true) > $deadline) { break; }
	if(!$dry) { s64_leave($pdo, (int)$r['token_id'], 'inactive', (float)$now); }
	$left++;
}
$out[] = "abgemeldet (inaktiv) $left";
$nowSql = "'" . s64c_db($now) . "'"; // feste Zeit, kein Eingabewert
$out[] = 'Token unbenutzt widerrufen ' . s64c_batch('sonar_tokens', "revoked_at = $nowSql", "kind = 'node' AND node_id IS NULL AND revoked_at IS NULL AND created_at < ?",
	array(s64c_db($now - S64C_INACTIVE * S64C_DAY)));
s64c_batch('sonar_nodes', "disabled_at = $nowSql", 'active = 0 AND disabled_at IS NULL', array()); // deaktiviert ohne Zeitpunkt (aeltere Zeilen)

// ---------------------------------------------------------------- 2. deaktivierte Knoten endgueltig loeschen
$jobs = array();
$st = $pdo->prepare("SELECT id, node_id, token_id, disabled_at FROM sonar_nodes WHERE active = 0 AND disabled_at < ? ORDER BY disabled_at LIMIT " . S64C_NODES);
$st->execute(array(s64c_db($now - S64C_DELETE * S64C_DAY)));
$del = $st->fetchAll(PDO::FETCH_ASSOC);
if($del) {
	$nids = array_column($del, 'node_id');
	$in = implode(',', array_fill(0, count($nids), '?'));
	$last = max(array_map(function($r) { return (int)strtotime($r['disabled_at'] . ' UTC'); }, $del));
	$tok = array_map('intval', array_column($del, 'token_id'));
	$jobs = array(
		array('sonar_results',   '', "src IN ($in)", $nids),
		array('sonar_results',   '', "dst IN ($in)", $nids),
		array('sonar_traces',    '', "src IN ($in)", $nids),
		array('sonar_traces',    '', "dst IN ($in)", $nids),
		array('sonar_inbound',   '', "node_id IN ($in)", $nids),
		array('sonar_pair_1h',   '', "src IN ($in)", $nids),
		// als Ziel: nach der Deaktivierung entstehen keine Stundenwerte mehr, aeltere loescht die Aufbewahrung (kein Index auf dst)
		array('sonar_pair_1h',   '', "hour >= ? AND hour < ? AND dst IN ($in)", array_merge(array(s64c_db($now - (S64C_DELETE + 1) * S64C_DAY), s64c_db($last + S64C_DAY)), $nids)),
		array('sonar_trust_log', '', "node_id IN ($in)", $nids),
		array('sonar_plans',     '', "node_id IN ($in)", $nids),
		array('sonar_tokens',    '', "node_id IN ($in) OR id IN (" . implode(',', array_fill(0, count($tok), '?')) . ")", array_merge($nids, $tok)),
		array('sonar_nodes',     '', "id IN (" . implode(',', array_fill(0, count($del), '?')) . ") AND active = 0", array_map('intval', array_column($del, 'id')), 'sonar_nodes geloescht'),
	);
}
$jobs[] = array('sonar_tokens', '', 'revoked_at < ? AND NOT EXISTS (SELECT 1 FROM sonar_nodes n WHERE n.token_id = sonar_tokens.id)',
	array(s64c_db($now - S64C_DELETE * S64C_DAY)), 'sonar_tokens widerrufen ohne Knoten');

// ---------------------------------------------------------------- 3. Aufbewahrung
$jobs = array_merge($jobs, array(
	array('sonar_results',   '', 'at < ?',      array(s64c_db($now - 7 * S64C_DAY))),
	array('sonar_traces',    '', 'at < ?',      array(s64c_db($now - 7 * S64C_DAY))),
	array('sonar_inbound',   '', 'at < ?',      array(s64c_db($now - S64C_DAY))),
	array('sonar_pair_1h',   '', 'hour < ?',    array(s64c_db($now - 90 * S64C_DAY))),
	array('sonar_asn_1d',    '', 'day < ?',     array(gmdate('Y-m-d', $now - 730 * S64C_DAY))),
	array('sonar_outages',   '', 'ended IS NOT NULL AND ended < ?', array(s64c_db($now - 730 * S64C_DAY))),
	array('sonar_trust_log', '', 'at < ?',      array(s64c_db($now - 365 * S64C_DAY))),
	array('sonar_plans',     '', 'expires < ?', array(s64c_db($now - 3600))),
	array('sonar_plans',     '', 'node_id IN (SELECT node_id FROM sonar_nodes WHERE active = 0)', array()),
	array('sonar_nodes', 'ip4 = NULL, ip6 = NULL', '(ip4 IS NOT NULL OR ip6 IS NOT NULL) AND active = 0 AND (last_seen IS NULL OR last_seen < ?)', array(s64c_db($now - 7 * S64C_DAY))),
	array('sonar_nodes', 'ip4 = NULL, ip6 = NULL', '(ip4 IS NOT NULL OR ip6 IS NOT NULL) AND last_seen < ?', array(s64c_db($now - 90 * S64C_DAY))),
));
foreach($jobs as $j) {
	if(microtime(true) > $deadline) { $out[] = 'ABGEBROCHEN (Zeitgrenze)'; break; }
	$n = s64c_batch($j[0], $j[1], $j[2], $j[3]);
	$out[] = ($j[4] ?? $j[0] . ($j[1] !== '' ? ' (IPs)' : '')) . " $n";
}
echo ($dry ? 'NUR ANZEIGEN: ' : '') . implode(', ', $out) . "\n";
