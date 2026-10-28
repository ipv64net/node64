<?php
/**
 * Sonar64: Anker-Token ausstellen (nur ipv64, von Hand auf dem Webserver). Das Token wird genau einmal ausgegeben und
 * nur als SHA-256 gespeichert. Der Anker meldet sich damit an (POST /sonar/register, Mode anchor) und wird Knoten a_<name>.
 *
 *   php bots/sonar_anchor_token.php --name=fsn [--user=<id>]       neues Anker-Token (Abbruch, wenn eins aktiv ist)
 *   php bots/sonar_anchor_token.php --name=fsn --rotate             altes Token widerrufen, neues ausgeben (Token-Wechsel:
 *                                                                   der Anker meldet sich mit dem neuen neu an, Knoten bleibt)
 *   php bots/sonar_anchor_token.php --name=fsn --lat=50.47 --lon=12.37 [--place=Falkenstein]
 *                                                                   Standort des angemeldeten Ankers setzen (kein Token)
 *
 * name: 2 bis 12 Zeichen a-z 0-9 (z. B. fsn, nbg). user: Account des Betreibers, Standard 0 (ipv64).
 */
if(php_sapi_name() !== 'cli') { exit; }
require __DIR__ . '/../sonar/s64_lib.php';

$opt = getopt('', array('name:', 'user:', 'rotate', 'lat:', 'lon:', 'place:'));
$name = (string)($opt['name'] ?? '');
if(!preg_match('/^[a-z0-9]{2,12}\z/', $name)) { fwrite(STDERR, "--name=<a-z0-9, 2..12 Zeichen> fehlt\n"); exit(1); }
$user = (string)($opt['user'] ?? '0');
if(!ctype_digit($user) OR strlen($user) > 10) { fwrite(STDERR, "--user muss eine Zahl sein\n"); exit(1); }
$pdo = s64_pdo();
$q = function(string $sql, array $a = array()) use ($pdo): PDOStatement { $st = $pdo->prepare($sql); $st->execute($a); return $st; };
$node = 'a_' . $name;

if(isset($opt['lat']) OR isset($opt['lon'])) {
	$lat = filter_var($opt['lat'] ?? '', FILTER_VALIDATE_FLOAT); $lon = filter_var($opt['lon'] ?? '', FILTER_VALIDATE_FLOAT);
	if($lat === false OR $lon === false OR $lat < -90 OR $lat > 90 OR $lon < -180 OR $lon > 180) { fwrite(STDERR, "--lat (-90..90) und --lon (-180..180) zusammen angeben\n"); exit(1); }
	$n = $q("SELECT id, jitter_seed FROM sonar_nodes WHERE node_id = :n", array('n' => $node))->fetch(PDO::FETCH_ASSOC);
	if(!$n) { fwrite(STDERR, "Anker $node ist noch nicht angemeldet (erst Token ausstellen und Anker starten)\n"); exit(1); }
	$place = isset($opt['place']) ? mb_substr(trim((string)preg_replace('/[^\p{L}\p{N} .,()\/-]+/u', '', (string)$opt['place'])), 0, 80) : null;
	$lat = round($lat, 5); $lon = round($lon, 5);
	$pc = s64_pub_coords($lat, $lon, (int)$n['jitter_seed']);
	$q("UPDATE sonar_nodes set lat = :la, lon = :lo, pub_lat = :pla, pub_lon = :plo" . ($place !== null ? ", place = :pl" : "") . " WHERE id = :i",
		array('la' => $lat, 'lo' => $lon, 'pla' => $pc['lat'], 'plo' => $pc['lon'], 'i' => $n['id']) + ($place !== null ? array('pl' => $place) : array()));
	echo "Standort von $node gesetzt.\n";
	exit(0);
}

$active = $q("SELECT id FROM sonar_tokens WHERE kind = 'anchor' AND name = :n AND revoked_at IS NULL", array('n' => $name))->fetchAll(PDO::FETCH_ASSOC);
if($active AND !isset($opt['rotate'])) { fwrite(STDERR, "Fuer $name gibt es schon ein aktives Anker-Token (Wechsel: --rotate)\n"); exit(1); }
$a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; $tok = 's64a_';
for($i = 0; $i < 40; $i++) { $tok .= $a[random_int(0, 61)]; }
$pdo->beginTransaction();
$now = s64_dt();
foreach($active as $t) { $q("UPDATE sonar_tokens set revoked_at = :t WHERE id = :i", array('t' => $now, 'i' => $t['id'])); }
$q("INSERT INTO sonar_tokens (userid, kind, name, token_hash, created_at) VALUES (:u, 'anchor', :n, :h, :t)",
	array('u' => (int)$user, 'n' => $name, 'h' => hash('sha256', $tok), 't' => $now));
$pdo->commit();
echo "Anker-Token fuer $node (wird nur jetzt angezeigt):\n$tok\n";
echo "Start: docker run -d --network host -e SONAR64_MODE=anchor -e SONAR64_TOKEN=<token> ghcr.io/ipv64net/sonar64\n";
