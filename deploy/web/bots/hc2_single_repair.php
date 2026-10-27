<?php
/**
 * Docker- und Proxmox-Checks gehoeren auf ihre Node und laufen nie online. Bis 2026-10-27 stellte das Entfernen einer
 * Node (nodes.php) sie auf „online“ um; seitdem misst der hub sie dort nicht mehr. Dieser Job holt solche Checks auf
 * die verknuepfte Node zurueck, die sie zuletzt gemessen hat (Messpunkte node:<id> der letzten 7 Tage). Ohne solche
 * Node bleibt der Check stehen (wird nicht gemessen) und kann im Portal geloescht werden. Alle 10 Minuten ueber
 * honeypot_cron.php (Job "hc2fix"), nur Kommandozeile; ohne Treffer tut er nichts.
 *
 *   php hc2_single_repair.php            ausfuehren
 */
if(php_sapi_name() !== 'cli') { exit; }
include(__DIR__ . "/../dbconnect.php");
require_once __DIR__ . '/../dbconnect_hc2.php';
require_once __DIR__ . '/../healthchecks2/hc2_lib.php';

$db = hc2_pdo();
$list = $db->query("SELECT userid, token, name, type FROM hc2_checks WHERE deleted_at IS NULL AND type IN ('docker','proxmox') AND execution IN ('online','both')")->fetchAll(PDO::FETCH_ASSOC);
$last = $db->prepare("SELECT SUBSTRING(m.source, 6) FROM hc2_measurements m
	JOIN hc2_nodes n ON n.node_id = SUBSTRING(m.source, 6) AND n.userid = :u AND n.revoked_at IS NULL
	WHERE m.token = :t AND m.source LIKE 'node:%' ORDER BY m.time DESC LIMIT 1");
$fixed = 0; $left = 0;
foreach($list as $c) {
	$last->execute(array('u' => (int)$c['userid'], 't' => $c['token']));
	$node = (string)($last->fetchColumn() ?: '');
	if($node === '') { $left++; echo "ohne Node: user " . (int)$c['userid'] . " " . $c['type'] . " " . $c['name'] . "\n"; continue; }
	hc2_set_check((int)$c['userid'], $c['token'], array('execution' => 'local', 'node_id' => $node, 'nodes' => ''));
	$fixed++;
	echo "zurueck auf Node: user " . (int)$c['userid'] . " " . $c['type'] . " " . $c['name'] . "\n";
}
echo count($list) . " gefunden, $fixed zurueck auf ihre Node, $left ohne Node\n";
