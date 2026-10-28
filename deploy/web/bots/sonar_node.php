<?php
/**
 * Sonar64: Knoten ansehen und abmelden (nur ipv64, von Hand auf dem Webserver; Vertrag Abschnitt 10.2). Gibt keine
 * Token aus. Abmelden wie DELETE /sonar/tokens/{id} (s64_lib.php s64_leave: Token widerrufen, Knoten aus, IP/Standort
 * weg, Plan geloescht, sonar_trust_log removed/admin, add_log beim Account).
 *
 *   php bots/sonar_node.php --list [--inactive]              aktive Knoten; --inactive: ohne Kontakt seit 7 Tagen
 *                                                             und abgemeldete (bis zum Loeschen nach 90 Tagen)
 *   php bots/sonar_node.php --show=<node_id|slug>             Angaben zu einem Knoten
 *   php bots/sonar_node.php --revoke=<node_id|slug> [--reason=<text>] [--force]
 *                                                             abmelden; Anker nur mit --force (widerruft auch ihre Token)
 */
if(php_sapi_name() !== 'cli') { exit; }
require __DIR__ . '/../sonar/s64_lib.php';

const S64N_LIST = 2000;  // Zeilen der Liste
const S64N_IDLE = 7;     // --inactive: Tage ohne Kontakt

$opt = getopt('', array('list', 'inactive', 'show:', 'revoke:', 'reason:', 'force'));
$pdo = s64_pdo();
$q = function(string $sql, array $a = array()) use ($pdo): PDOStatement { return s64_exec($pdo, $sql, $a); };
$ago = function($t): string {
	if($t === null OR $t === '') { return '-'; }
	$s = max(0, time() - (int)strtotime($t . ' UTC'));
	return $s < 3600 ? intdiv($s, 60) . ' min' : ($s < 2 * 86400 ? intdiv($s, 3600) . ' h' : intdiv($s, 86400) . ' d');
};
/** Knoten ueber node_id oder Slug (nur Muster, Prepared Statement). */
$find = function(string $key) use ($q): array {
	if(!preg_match(S64_NODE_RE, $key) AND !preg_match('/^[a-z0-9-]{1,40}\z/', $key)) { fwrite(STDERR, "node_id oder Slug ungueltig\n"); exit(1); }
	$n = $q("SELECT * FROM sonar_nodes WHERE node_id = ? OR slug = ? ORDER BY node_id = ? DESC LIMIT 1", array($key, $key, $key))->fetch(PDO::FETCH_ASSOC);
	if($n === false) { fwrite(STDERR, "Knoten $key nicht gefunden\n"); exit(1); }
	return $n;
};

if(isset($opt['list'])) {
	$idle = isset($opt['inactive']);
	$rows = $q("SELECT node_id, role, name, userid, trust, active, version, asn4, asn6, ip4 IS NOT NULL v4, ip6 IS NOT NULL v6, last_seen, first_seen, disabled_at FROM sonar_nodes WHERE "
		. ($idle ? "active = 0 OR COALESCE(last_seen, first_seen) < ?" : "active = 1") . " ORDER BY active DESC, last_seen DESC LIMIT " . (S64N_LIST + 1),
		$idle ? array(s64_dt(time() - S64N_IDLE * 86400)) : array())->fetchAll(PDO::FETCH_ASSOC);
	printf("%-13s %-6s %-10s %-11s %-8s %-8s %-5s %-10s %s\n", 'node_id', 'Rolle', 'Stufe', 'Status', 'Kontakt', 'Account', 'IP', 'ASN', 'Name');
	foreach(array_slice($rows, 0, S64N_LIST) as $r) {
		$status = (int)$r['active'] === 1 ? (($r['last_seen'] !== null AND strtotime($r['last_seen'] . ' UTC') >= time() - S64_ONLINE) ? 'online' : 'offline') : 'abgemeldet';
		printf("%-13s %-6s %-10s %-11s %-8s %-8s %-5s %-10s %s\n", $r['node_id'], $r['role'], $r['trust'], $status,
			$status === 'abgemeldet' ? $ago($r['disabled_at']) : $ago($r['last_seen'] ?? $r['first_seen']), (string)(int)$r['userid'],
			trim(((int)$r['v4'] ? '4' : '') . ((int)$r['v6'] ? '6' : '')) ?: '-', $r['asn4'] ?? $r['asn6'] ?? '-', $r['name']);
	}
	echo count($rows) > S64N_LIST ? "(nur die ersten " . S64N_LIST . ")\n" : count($rows) . " Knoten\n";
	exit(0);
}

if(isset($opt['show'])) {
	$n = $find((string)$opt['show']);
	$t = $q("SELECT id, kind, name, created_at, last_used_at, revoked_at FROM sonar_tokens WHERE id = ?", array((int)$n['token_id']))->fetch(PDO::FETCH_ASSOC);
	$pl = $q("SELECT issued, expires, sent_at FROM sonar_plans WHERE node_id = ?", array($n['node_id']))->fetch(PDO::FETCH_ASSOC);
	foreach(array('node_id', 'role', 'name', 'slug', 'userid', 'trust', 'score', 'uptime30', 'active', 'disabled_at', 'mode', 'version', 'measured', 'budget', 'access', 'device',
		'ip4', 'ip6', 'asn4', 'asname4', 'asn6', 'asname6', 'place', 'lat', 'lon', 'reach4', 'reach6', 'plaus_ok', 'plaus_bad', 'first_seen', 'last_seen', 'last_report', 'last_plan') as $k) {
		printf("%-12s %s\n", $k, $n[$k] ?? '-');
	}
	printf("%-12s %s\n", 'token', $t ? "#{$t['id']} {$t['kind']} '{$t['name']}' erzeugt {$t['created_at']}, benutzt " . ($t['last_used_at'] ?? '-') . ', widerrufen ' . ($t['revoked_at'] ?? '-') : '-');
	printf("%-12s %s\n", 'plan', $pl ? "ausgestellt {$pl['issued']}, gueltig bis {$pl['expires']}, ausgeliefert " . ($pl['sent_at'] ?? '-') : '-');
	foreach($q("SELECT at, `old`, `new`, reason FROM sonar_trust_log WHERE node_id = ? ORDER BY at DESC LIMIT 10", array($n['node_id']))->fetchAll(PDO::FETCH_ASSOC) as $l) {
		printf("%-12s %s %s -> %s (%s)\n", 'stufe', $l['at'], $l['old'], $l['new'], $l['reason']);
	}
	exit(0);
}

if(isset($opt['revoke'])) {
	$n = $find((string)$opt['revoke']);
	$text = trim((string)preg_replace('/[^\p{L}\p{N} ._:,()\/-]+/u', '', (string)($opt['reason'] ?? '')));
	$text = mb_substr((string)preg_replace('/\s+/', ' ', $text), 0, 50);
	if((int)$n['active'] !== 1) { echo "{$n['node_id']} ist schon abgemeldet (seit " . ($n['disabled_at'] ?? '-') . ").\n"; exit(0); }
	if($n['role'] === 'anchor' AND !isset($opt['force'])) { fwrite(STDERR, "{$n['node_id']} ist ein Anker: nur mit --force abmelden\n"); exit(1); }
	$nid = s64_leave($pdo, (int)$n['token_id'], 'admin' . ($text !== '' ? ' ' . $text : ''));
	if($nid === null) { fwrite(STDERR, "Knoten {$n['node_id']} wurde nicht abgemeldet (gleichzeitig geaendert?)\n"); exit(1); }
	if($n['role'] === 'anchor') { // sonst meldet sich der Anker mit einem neueren Token wieder an
		foreach($q("SELECT id FROM sonar_tokens WHERE kind = 'anchor' AND name = ? AND revoked_at IS NULL", array(substr($n['node_id'], 2)))->fetchAll(PDO::FETCH_COLUMN) as $tid) {
			s64_leave($pdo, (int)$tid, 'admin' . ($text !== '' ? ' ' . $text : ''));
		}
	}
	echo "$nid abgemeldet" . ($text !== '' ? " ($text)" : '') . ".\n";
	exit(0);
}

fwrite(STDERR, "Aufruf: --list [--inactive] | --show=<node_id|slug> | --revoke=<node_id|slug> [--reason=<text>] [--force]\n");
exit(1);
