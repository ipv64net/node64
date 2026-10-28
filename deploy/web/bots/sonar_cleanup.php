<?php
/**
 * Sonar64 Aufraeumen (Vertrag docs/SONAR64-VERTRAG.md Abschnitte 6/7, Teil J). Taeglich ueber honeypot_cron.php,
 * nur auf der Kommandozeile:
 *
 *   php sonar_cleanup.php              ausfuehren
 *   php sonar_cleanup.php --dry        nur anzeigen
 *   php sonar_cleanup.php --now=<ISO>  Zeitpunkt vorgeben (Tests)
 *
 * Aufbewahrung: sonar_results und sonar_traces 7 Tage, sonar_inbound 24 h, sonar_pair_1h 90 Tage, sonar_asn_1d,
 * sonar_outages und sonar_trust_log dauerhaft. Plaene: abgelaufen > 1 h oder Knoten deaktiviert (enthalten IPs).
 * Datensparsam: IPs deaktivierter Knoten nach 7 Tagen, IPs aller Knoten nach 90 Tagen ohne Meldung entfernen (bei der
 * naechsten Anfrage nimmt ipv64 die IP wieder aus der Verbindung).
 * Geloescht wird in Bloecken (kurze Sperren); ein Abbruch schadet nicht, der naechste Lauf macht weiter.
 */
if(php_sapi_name() !== 'cli') { exit; }
if(!is_file(__DIR__ . '/../sonar/s64_lib.php')) { fwrite(STDERR, "sonar/s64_lib.php fehlt\n"); exit(1); }
require_once __DIR__ . '/../sonar/s64_lib.php';

const S64C_BATCH      = 10000;
const S64C_TIME_LIMIT = 1500;
const S64C_DAY        = 86400;

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

/** In Bloecken loeschen ($set leer) bzw. aendern; --dry zaehlt nur. */
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

$jobs = array(
	array('sonar_results',   '', 'at < ?',      array(s64c_db($now - 7 * S64C_DAY))),
	array('sonar_traces',    '', 'at < ?',      array(s64c_db($now - 7 * S64C_DAY))),
	array('sonar_inbound',   '', 'at < ?',      array(s64c_db($now - S64C_DAY))),
	array('sonar_pair_1h',   '', 'hour < ?',    array(s64c_db($now - 90 * S64C_DAY))),
	array('sonar_plans',     '', 'expires < ?', array(s64c_db($now - 3600))),
	array('sonar_plans',     '', 'node_id IN (SELECT node_id FROM sonar_nodes WHERE active = 0)', array()),
	array('sonar_nodes', 'ip4 = NULL, ip6 = NULL', '(ip4 IS NOT NULL OR ip6 IS NOT NULL) AND active = 0 AND (last_seen IS NULL OR last_seen < ?)', array(s64c_db($now - 7 * S64C_DAY))),
	array('sonar_nodes', 'ip4 = NULL, ip6 = NULL', '(ip4 IS NOT NULL OR ip6 IS NOT NULL) AND last_seen < ?', array(s64c_db($now - 90 * S64C_DAY))),
);
$out = array();
foreach($jobs as $j) {
	if(microtime(true) > $deadline) { $out[] = 'ABGEBROCHEN (Zeitgrenze)'; break; }
	$n = s64c_batch($j[0], $j[1], $j[2], $j[3]);
	$out[] = $j[0] . ($j[1] !== '' ? ' (IPs)' : '') . " $n";
}
echo ($dry ? 'NUR ANZEIGEN: ' : '') . implode(', ', $out) . "\n";
