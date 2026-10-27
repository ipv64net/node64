<?php
/**
 * Node64: alle Nodes des Accounts in einer Liste – egal ob Healthchecks-Sync (hubs), Honeypot64, CDN64-Tunnel oder
 * DynDNS per API-Key. Zusammengefuehrt aus node64_nodes (Anmeldung der Node per API, Hauptdatenbank), hc2_nodes
 * (Datenbank ipv64_hc, ueber hub_node_id), hp_sensors (sensor_id) und cdn64o_tunnels (tunnel_id). Aeltere Container ohne
 * Anmeldung erscheinen ueber hub bzw. Sensor. Entfernen: Merker removed_at (hello antwortet 403 node_removed), hub-Node
 * trennen, Sensor sperren; CDN64-Namen laufen weiter. Detail einer hub-Node wie bisher (Checks, Konflikte, Umbenennen,
 * Fernverwaltung, Token widerrufen). Bewusst ohne Menülink; nur per URL erreichbar. SQL: deploy/sql/node64_nodes.sql.
 */
ob_start(); // header.php gibt HTML aus; hc2_redirect()/hc2_json() verwerfen es
include("header.php");
require_once(__DIR__ . '/healthchecks2/hc2_lib.php');
hc2_require_login();
$db = $pdo; // Hauptdatenbank aus header.php (node64_nodes, hp_sensors, cdn64o_*)
$uid = (int)$userid; $pdo = hc2_pdo();
$msg = '';
$nid = preg_replace('/[^A-Za-z0-9_-]/', '', (string)($_GET['node'] ?? $_POST['node_id'] ?? ''));
$sid = preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', (string)($_POST['sensor_id'] ?? '')) ? (string)$_POST['sensor_id'] : '';
/** Abfrage in der Hauptdatenbank; Fehler (z. B. Tabelle noch nicht angelegt) = leer. */
$dbq = function(string $sql, array $p) use ($db): array {
	try { $st = $db->prepare($sql); if ($st && $st->execute($p)) { return $st->fetchAll(PDO::FETCH_ASSOC); } error_log('nodes.php: ' . implode(' ', ($st ?: $db)->errorInfo())); }
	catch (Throwable $e) { error_log('nodes.php: ' . $e->getMessage()); }
	return array();
};
$dbx = function(string $sql, array $p) use ($db): int { $st = $db->prepare($sql); if (!$st || !$st->execute($p)) { throw new RuntimeException('nodes.php: ' . implode(' ', ($st ?: $db)->errorInfo())); } return $st->rowCount(); };
$loadNode = function(string $id) use ($pdo, $uid) { if ($id === '') { return null; } $st = $pdo->prepare("SELECT * FROM hc2_nodes WHERE node_id = :n AND userid = :u"); $st->execute(array('n' => $id, 'u' => $uid)); return $st->fetch(PDO::FETCH_ASSOC) ?: null; };

/** hub-Node trennen (Token widerrufen, Checks online weiter oder loeschen); liefert den Text zum Ergebnis. */
$revokeHub = function(string $nid, bool $keep) use ($pdo, $uid): string {
	$pdo->prepare("UPDATE hc2_node_tokens SET revoked_at = UTC_TIMESTAMP(3) WHERE node_id = :n AND revoked_at IS NULL")->execute(array('n' => $nid));
	$pdo->prepare("UPDATE hc2_nodes SET revoked_at = UTC_TIMESTAMP(3), online = 0 WHERE node_id = :n")->execute(array('n' => $nid));
	hc2_log_change($uid, 'node', $nid, 'delete', 'portal');
	hc2_signal('hc2:node:' . $nid, 'revoke');
	$st = $pdo->prepare("SELECT * FROM hc2_checks WHERE (node_id = :n OR FIND_IN_SET(:n2, nodes) > 0) AND userid = :u AND deleted_at IS NULL AND execution IN ('local','both')"); $st->execute(array('n' => $nid, 'n2' => $nid, 'u' => $uid));
	$kept = 0; $dropped = 0; $moved = 0;
	foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $c) {
		// weitere messende Nodes: diese austragen, Besitz an die naechste
		$rest = array_values(array_diff(hc2_check_nodes($c), array($nid)));
		if ($rest) { hc2_set_check($uid, $c['token'], array('nodes' => implode(',', $rest), 'node_id' => (string)$c['node_id'] === $nid ? $rest[0] : $c['node_id'])); $moved++; continue; }
		$acc = hc2_account($uid); $locs = array_filter(explode(',', $c['locations'])) ?: array_keys(hc2_locations());
		// Docker/Proxmox nie online (Ziel ist ein Container bzw. Gast der Node, kein Netzziel): mit der Node geloescht
		$fits = $keep && !hc2_single_node_type($c['type']) && !hc2_private_target($c['type'], $c['target']) && ($acc['healthcheck_limit'] <= 0 || hc2_online_used($uid, $c['token']) + count($locs) <= $acc['healthcheck_limit']);
		if ($fits) { hc2_set_check($uid, $c['token'], array('execution' => 'online', 'node_id' => null, 'nodes' => '')); $kept++; } else { hc2_delete_check($uid, $c['token']); $dropped++; }
	}
	return ($moved ? $moved . ' Check(s) messen andere Nodes weiter. ' : '') . ($keep ? $kept . ' Check(s) laufen online weiter, ' . $dropped . ' gelöscht (privates Ziel oder Limit).' : $dropped . ' Check(s) der Node gelöscht.');
};
/** getrennte hub-Node samt Token, Befehlen und Node-Kanaelen loeschen (Messwerte bleiben). */
$deleteHub = function(string $nid) use ($pdo, $uid): void {
	$st = $pdo->prepare("SELECT id FROM hc2_channels WHERE node_id = :n AND userid = :u AND deleted_at IS NULL"); $st->execute(array('n' => $nid, 'u' => $uid));
	foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $chId) {
		$chId = (int)$chId; hc2_log_change($uid, 'channel', (string)$chId, 'delete', 'portal');
		foreach (hc2_checks($uid) as $c) { $ids = hc2_check_channels($c); if (in_array($chId, $ids, true)) { hc2_set_check($uid, $c['token'], array('channels' => implode(',', array_diff($ids, array($chId))))); } }
	}
	foreach (array('hc2_node_tokens', 'hc2_commands', 'hc2_send_orders', 'hc2_link_codes') as $t) { $pdo->prepare("DELETE FROM $t WHERE node_id = :n")->execute(array('n' => $nid)); }
	$pdo->prepare("DELETE FROM hc2_nodes WHERE node_id = :n AND userid = :u AND revoked_at IS NOT NULL")->execute(array('n' => $nid, 'u' => $uid));
};
/** Eintrag der Node-Liste (node64_nodes) des Accounts. */
$loadReg = function(string $id) use ($dbq, $uid) { return $id === '' ? null : ($dbq("SELECT * FROM node64_nodes WHERE userid = :u AND node_id = :n", array('u' => $uid, 'n' => $id))[0] ?? null); };

if (hc2_is_post() && hc2_csrf_ok()) {
	$node = $loadNode($nid); $action = (string)($_POST['action'] ?? '');
	try {
		if ($action === 'remove') {
			// Entfernen: Merker in der Node-Liste (hello -> 403 node_removed), hub-Node trennen, Sensor sperren; CDN64 bleibt
			$reg = $loadReg($nid !== '' ? $nid : $sid);
			$key = $reg['node_id'] ?? ($nid !== '' ? $nid : $sid);
			$hub = $loadNode($reg ? ($reg['hub_node_id'] !== '' ? $reg['hub_node_id'] : $reg['node_id']) : $nid);
			$sensorId = $reg ? ($reg['sensor_id'] !== '' ? $reg['sensor_id'] : '') : $sid;
			$sensor = $sensorId !== '' ? ($dbq("SELECT sensor_id, disabled FROM hp_sensors WHERE sensor_id = :s AND userid = :u", array('s' => $sensorId, 'u' => $uid))[0] ?? null) : null;
			if ($key === '' || (!$reg && !$hub && !$sensor)) { $msg = 'Node nicht gefunden.'; }
			else {
				$name = (string)preg_replace('/[\x{10000}-\x{10FFFF}]/u', "\u{FFFD}", $reg['name'] ?? ($hub['name'] ?? 'Honeypot-Sensor')); // Hauptdatenbank: SET NAMES 'utf8'
				$dbx("INSERT INTO node64_nodes (userid, node_id, name, location, version, hub_node_id, sensor_id, first_seen, removed_at) VALUES (:u, :n, :na, :l, :v, :h, :s, UTC_TIMESTAMP(), UTC_TIMESTAMP())
					ON DUPLICATE KEY UPDATE removed_at = UTC_TIMESTAMP()", array('u' => $uid, 'n' => $key, 'na' => mb_substr($name, 0, 100), 'l' => mb_substr((string)preg_replace('/[\x{10000}-\x{10FFFF}]/u', "\u{FFFD}", (string)($hub['location'] ?? '')), 0, 100),
					'v' => mb_substr((string)($hub['version'] ?? ''), 0, 32), 'h' => $hub ? $hub['node_id'] : '', 's' => $sensor ? $sensor['sensor_id'] : ''));
				$parts = array();
				if ($hub && empty($hub['revoked_at'])) { $parts[] = 'Healthchecks-Sync getrennt: ' . $revokeHub($hub['node_id'], !empty($_POST['keep_checks'])); }
				if ($sensor && (int)$sensor['disabled'] === 0 && $dbx("UPDATE hp_sensors SET disabled = 1 WHERE sensor_id = :s AND userid = :u AND disabled = 0", array('s' => $sensor['sensor_id'], 'u' => $uid)) === 1) {
					$dbx("UPDATE node64_nodes SET sensor_disabled = 1 WHERE userid = :u AND node_id = :n", array('u' => $uid, 'n' => $key));
					$parts[] = 'Honeypot-Sensor gesperrt.';
				}
				if (!empty($reg['tunnel_id'])) {
					$hosts = array_column($dbq("SELECT h.fqdn FROM cdn64o_host_tunnels t JOIN cdn64o_hosts h ON h.id = t.host_id WHERE t.tunnel_id = :t AND h.userid = :u ORDER BY h.fqdn", array('t' => $reg['tunnel_id'], 'u' => $uid)), 'fqdn');
					if ($hosts) { $parts[] = 'CDN64: ' . implode(', ', $hosts) . ' laufen weiter über den Tunnel dieser Node, bis du sie in PROXY64 oder unter ipv64.net/cdn64 ausschaltest.'; }
				}
				$msg = 'Node „' . $name . '“ entfernt. ' . implode(' ', $parts) . ' Meldet sie sich wieder, löscht sie ihren API-Key und die Healthchecks-Verknüpfung (lokale Daten bleiben).';
			}
			$nid = '';
		} elseif ($action === 'allow' || $action === 'forget') {
			// Wieder zulassen bzw. endgueltig aus der Liste loeschen (nur entfernte Nodes); ein von uns gesperrter Sensor wird frei
			$reg = $loadReg($nid);
			if (!$reg || $reg['removed_at'] === null) { $msg = 'Node nicht gefunden.'; }
			else {
				if ((int)$reg['sensor_disabled'] === 1 && $reg['sensor_id'] !== '') { $dbx("UPDATE hp_sensors SET disabled = 0 WHERE sensor_id = :s AND userid = :u AND disabled = 1", array('s' => $reg['sensor_id'], 'u' => $uid)); }
				$ids = array_values(array_unique(array_filter(array($reg['node_id'], $reg['sensor_id'])))); // auch der Eintrag "nur Sensor" derselben Node
				$in = implode(',', array_map(fn($i) => ':i' . $i, array_keys($ids))); $p = array('u' => $uid); foreach ($ids as $i => $x) { $p['i' . $i] = $x; }
				if ($action === 'allow') {
					$dbx("UPDATE node64_nodes SET removed_at = NULL, sensor_disabled = 0 WHERE userid = :u AND node_id IN ($in)", $p);
					$msg = 'Node „' . $reg['name'] . '“ wieder zugelassen. In der Node den API-Key neu eintragen; den Healthchecks-Sync bei Bedarf mit einem neuen Code verknüpfen.';
				} else {
					$hub = $loadNode($reg['hub_node_id'] !== '' ? $reg['hub_node_id'] : $reg['node_id']);
					if ($hub && !empty($hub['revoked_at'])) { $deleteHub($hub['node_id']); }
					$dbx("DELETE FROM node64_nodes WHERE userid = :u AND node_id IN ($in) AND removed_at IS NOT NULL", $p);
					$msg = 'Node „' . $reg['name'] . '“ aus der Liste gelöscht.';
				}
			}
			$nid = '';
		} elseif ($node) {
			switch ($action) {
				case 'revoke':
					$msg = 'Node getrennt. ' . $revokeHub($nid, !empty($_POST['keep_checks']));
					$nid = '';
					break;
				case 'delete':
					// nur getrennte Nodes: Eintrag samt Token, Befehlen und Agent-Kanaelen entfernen (Messwerte bleiben)
					if (empty($node['revoked_at'])) { $msg = 'Bitte die Node zuerst trennen.'; break; }
					$deleteHub($nid);
					$msg = 'Node „' . $node['name'] . '“ entfernt.'; $nid = '';
					break;
				case 'rename':
					$name = mb_substr(trim((string)($_POST['name'] ?? '')), 0, 100); $loc = mb_substr(trim((string)($_POST['location'] ?? '')), 0, 100);
					$rm = in_array($_POST['remote_mgmt'] ?? '', array('off','read','full'), true) ? $_POST['remote_mgmt'] : $node['remote_mgmt'];
					if ($name !== '') {
						$pdo->prepare("UPDATE hc2_nodes SET name = :na, location = :l, remote_mgmt = :r WHERE node_id = :n")->execute(array('na' => $name, 'l' => $loc, 'r' => $rm, 'n' => $nid));
						hc2_log_change($uid, 'node', $nid, 'upsert', 'portal'); $msg = 'Node gespeichert.';
					}
					break;
				case 'command':
					$name = in_array($_POST['cmd'] ?? '', array('run_check', 'repair'), true) ? $_POST['cmd'] : '';
					$token = preg_replace('/[^A-Za-z0-9]/', '', (string)($_POST['token'] ?? ''));
					if ($name !== '') { hc2_command($nid, $name, $token !== '' ? array('token' => $token) : array()); $msg = 'Befehl an die Node gegeben.'; }
					break;
				case 'resolve':
					$keep = ($_POST['keep'] ?? 'server') === 'local' ? 'local' : 'server';
					hc2_command($nid, 'resolve_conflict', array('id' => (int)($_POST['conflict_id'] ?? 0), 'keep' => $keep));
					$msg = 'Konfliktlösung an die Node gegeben (' . ($keep === 'server' ? 'Server-Version' : 'Node-Version') . ').';
					break;
			}
		}
	} catch (Throwable $e) { error_log('nodes.php: ' . $e->getMessage()); $msg = 'Aktion fehlgeschlagen.'; }
}
$st = $pdo->prepare("SELECT n.*, (SELECT COUNT(*) FROM hc2_checks c WHERE (c.node_id = n.node_id OR FIND_IN_SET(n.node_id, c.nodes) > 0) AND c.deleted_at IS NULL AND c.execution IN ('local','both')) AS checks FROM hc2_nodes n WHERE userid = :u ORDER BY revoked_at IS NOT NULL, created_at DESC");
$st->execute(array('u' => $uid)); $nodes = $st->fetchAll(PDO::FETCH_ASSOC);
$detail = $loadNode($nid); $nodeMap = hc2_nodes($uid);
// ---- eine Zeile je Container: Anmeldung (node64_nodes) + hub-Node + Honeypot-Sensor + CDN64-Tunnel
$hubs = array(); foreach ($nodes as $n) { $hubs[$n['node_id']] = $n; }
$sensors = array(); foreach ($dbq("SELECT sensor_id, version, mode, last_seen, reports, disabled, last_seen >= UTC_TIMESTAMP() - INTERVAL 30 MINUTE AS fresh FROM hp_sensors WHERE userid = :u AND last_seen IS NOT NULL ORDER BY last_seen DESC", array('u' => $uid)) as $x) { $sensors[$x['sensor_id']] = $x; }
$tunnels = array(); foreach ($dbq("SELECT t.id, t.name, t.status, t.last_seen >= NOW() - INTERVAL 5 MINUTE AS fresh, (SELECT COUNT(*) FROM cdn64o_host_tunnels ht JOIN cdn64o_hosts h ON h.id = ht.host_id WHERE ht.tunnel_id = t.id AND h.userid = t.userid) AS hosts FROM cdn64o_tunnels t WHERE t.userid = :u", array('u' => $uid)) as $x) { $tunnels[$x['id']] = $x; }
$rows = array(); $gone = array();
foreach ($dbq("SELECT *, last_seen >= UTC_TIMESTAMP() - INTERVAL 20 MINUTE AS fresh FROM node64_nodes WHERE userid = :u ORDER BY removed_at IS NOT NULL, name, node_id", array('u' => $uid)) as $r) {
	$hid = $r['hub_node_id'] !== '' ? $r['hub_node_id'] : $r['node_id'];
	$row = array('id' => $r['node_id'], 'reg' => $r, 'hub' => $hubs[$hid] ?? null, 'sensor' => $sensors[$r['sensor_id']] ?? null, 'tunnel' => $tunnels[$r['tunnel_id']] ?? null);
	unset($hubs[$hid]); if ($r['sensor_id'] !== '') { unset($sensors[$r['sensor_id']]); }
	if ($r['removed_at'] !== null) { $gone[] = $row; } else { $rows[] = $row; }
}
foreach ($hubs as $h) { $row = array('id' => $h['node_id'], 'reg' => null, 'hub' => $h, 'sensor' => null, 'tunnel' => null); if (!empty($h['revoked_at'])) { $gone[] = $row; } else { $rows[] = $row; } } // meldet sich nur ueber die hubs
foreach ($sensors as $x) { $rows[] = array('id' => $x['sensor_id'], 'reg' => null, 'hub' => null, 'sensor' => $x, 'tunnel' => null); } // nur Sensor (Modus ohne Oberflaeche, aeltere Container)
$hubOn = fn($row) => $row['hub'] && empty($row['hub']['revoked_at']);
$isOnline = fn($row) => !empty($row['reg']['fresh']) || ($hubOn($row) && (int)$row['hub']['online'] === 1) || (!empty($row['sensor']['fresh']) && !(int)$row['sensor']['disabled']) || !empty($row['tunnel']['fresh']);
$kpi = array('all' => count($rows), 'online' => count(array_filter($rows, $isOnline)), 'hc' => count(array_filter($rows, $hubOn)), 'hp' => count(array_filter($rows, fn($r) => $r['sensor'] !== null)));
$modNames = array('healthchecks' => 'Healthchecks', 'dyndns' => 'DynDNS', 'dns64' => 'DNS64', 'cdn64' => 'PROXY64', 'honeypot' => 'Honeypot64');
$tile = function(string $label, int $n, string $color, string $icon): string {
	return '<div class="col-6 col-md-3 mb-3"><div class="card bg-light h-100" style="border-left:4px solid var(--' . $color . ')"><div class="card-body p-2"><i class="fa-solid ' . $icon . ' fa-2xl float-right pt-4 text-' . $color . '"></i><p class="lead m-0">' . hc2_h($label) . '</p><p class="card-text h3">' . $n . '</p></div></div></div>';
};
?>
<p></p>
<div class="container">
	<?php echo hc2_subnav('nodes'); if ($msg !== '') { echo '<div class="alert alert-info">' . hc2_h($msg) . '</div>'; } ?>
	<div class="row">
		<?php echo $tile('Nodes gesamt', $kpi['all'], 'primary', 'fa-server') . $tile('Online', $kpi['online'], 'success', 'fa-signal') . $tile('Mit Healthchecks-Sync', $kpi['hc'], 'info', 'fa-heart-pulse') . $tile('Honeypot-Sensoren', $kpi['hp'], 'warning', 'fa-bug'); ?>
	</div>
	<div class="card shadow-sm mb-3">
		<div class="card-header p-2 d-flex justify-content-between align-items-center"><span><i class="fa-solid fa-server"></i> Meine Nodes</span><a class="btn btn-sm btn-primary" href="link.php"><i class="fa-solid fa-link"></i> Node mit Healthchecks verknüpfen</a></div>
		<?php if (!$rows) { ?><div class="card-body"><p class="text-muted mb-0">Noch keine Node gemeldet. Node64 installieren und dort in den Einstellungen einen ipv64-API-Key eintragen – die Node erscheint dann hier. Für den Healthchecks-Sync in der Node unter <em>ipv64-Verknüpfung</em> einen Code anfordern und unter <a href="link.php">Node verknüpfen</a> eingeben.</p></div><?php } else { ?>
		<div class="table-responsive"><table class="table table-sm mb-0">
			<thead><tr><th>Name</th><th>Version</th><th>Zuletzt gemeldet</th><th>Healthchecks-Server</th><th>Honeypot</th><th>CDN64</th><th>Module</th><th></th></tr></thead>
			<tbody>
			<?php foreach ($rows as $row) { $r = $row['reg']; $h = $row['hub']; $x = $row['sensor']; $t = $row['tunnel'];
				$name = $r['name'] ?? ($h['name'] ?? 'Honeypot-Sensor'); $loc = $r['location'] ?? ($h['location'] ?? '');
				$mods = array_filter(explode(',', (string)($r['modules'] ?? ($h['modules'] ?? ($x ? 'honeypot' : ''))))); ?>
			<tr>
				<td><?php echo $hubOn($row) ? '<a href="nodes.php?node=' . hc2_h($h['node_id']) . '">' . hc2_h($name) . '</a>' : hc2_h($name); echo $isOnline($row) ? ' <i class="fa-solid fa-circle text-success small" title="online"></i>' : ' <i class="fa-solid fa-circle text-secondary small" title="offline"></i>';
					if ($loc !== '') { echo '<br><small>' . hc2_h($loc) . '</small>'; }
					if (($r['mode'] ?? ($x['mode'] ?? '')) === 'headless') { echo ' <span class="badge badge-light">ohne Oberfläche</span>'; }
					if (!empty($h['proxy_via'])) { echo ' <span class="badge badge-light" title="meldet über eine andere Node des Clusters">über ' . hc2_h(hc2_node_label($nodeMap, $h['proxy_via']) ?: $h['proxy_via']) . '</span>'; } ?>
					<br><small class="text-muted"><?php echo hc2_h($row['id']); ?></small></td>
				<td><?php echo hc2_h($r['version'] ?? ($h['version'] ?? ($x['version'] ?? ''))); if (!empty($r['os_arch'])) { echo '<br><small class="text-muted">' . hc2_h($r['os_arch']) . '</small>'; } ?></td>
				<td class="small"><?php echo $r ? '<span title="' . hc2_dt($r['last_seen']) . '">vor ' . hc2_ago($r['last_seen']) . '</span>' : '<span class="text-muted" title="Ältere Node64-Version oder kein API-Key in der Node">meldet sich noch nicht direkt</span>'; ?></td>
				<td class="small"><?php if (!$h) { echo !empty($r['hc_linked']) ? '<span class="badge badge-warning" title="Die Node ist verknüpft, aber nicht mit diesem Account">verknüpft (anderer Account?)</span>' : '<span class="text-muted">nicht verknüpft</span>'; }
					elseif (!empty($h['revoked_at'])) { echo '<span class="badge badge-secondary">getrennt</span>'; }
					else { echo (int)$h['online'] === 1 ? '<span class="badge badge-success">verbunden</span> <span class="text-muted">' . hc2_h($h['node']) . '</span>' : '<span class="badge badge-warning">offline</span> <span class="text-muted">seit ' . hc2_dt($h['last_seen']) . '</span>';
						echo '<br>Abgleich ' . hc2_dt($h['last_sync']) . ' · ' . (int)$h['checks'] . ' Checks'; if ((int)$h['conflicts'] > 0) { echo ' <span class="badge badge-danger">' . (int)$h['conflicts'] . ' Konflikte</span>'; } } ?></td>
				<td class="small"><?php if ($x) { echo (int)$x['disabled'] === 1 ? '<span class="badge badge-danger">gesperrt</span>' : ($x['fresh'] ? '<span class="badge badge-success">meldet</span>' : '<span class="badge badge-secondary">offline</span>'); echo '<br><span class="text-muted">vor ' . hc2_ago($x['last_seen']) . '</span>'; }
					elseif (in_array('honeypot', $mods, true)) { echo '<span class="text-muted">Modul an, meldet nicht</span>'; } else { echo '<span class="text-muted">–</span>'; } ?></td>
				<td class="small"><?php if ($t) { echo $t['status'] === 'blocked' ? '<span class="badge badge-danger">gesperrt</span>' : ($t['fresh'] ? '<span class="badge badge-success">Tunnel verbunden</span>' : '<span class="badge badge-secondary">Tunnel getrennt</span>'); echo '<br><a href="/cdn64" class="text-muted">' . (int)$t['hosts'] . ' Name(n)</a>'; }
					else { echo '<span class="text-muted">–</span>'; } ?></td>
				<td><?php foreach ($mods as $m) { echo '<span class="badge badge-light mr-1">' . hc2_h($modNames[$m] ?? $m) . '</span>'; } ?></td>
				<td class="text-nowrap text-right"><?php if ($hubOn($row)) { ?><a class="btn btn-sm btn-outline-secondary" href="nodes.php?node=<?php echo hc2_h($h['node_id']); ?>">Details</a> <?php } ?>
					<form method="post" class="d-inline" onsubmit="return confirm('Node „<?php echo hc2_h(addslashes($name)); ?>“ entfernen?\n\n– Healthchecks-Sync wird getrennt (Checks laufen online weiter, soweit möglich)\n– der Honeypot-Sensor wird gesperrt\n– meldet sich die Node wieder, löscht sie ihren API-Key und die Verknüpfung (lokale Daten bleiben)\n– CDN64-Namen laufen weiter, bis du sie ausschaltest\n\nRückgängig mit „Wieder zulassen“.');"><?php echo hc2_csrf_field(); ?>
						<input type="hidden" name="action" value="remove"><input type="hidden" name="keep_checks" value="1"><?php if ($r || $h) { ?><input type="hidden" name="node_id" value="<?php echo hc2_h($row['id']); ?>"><?php } else { ?><input type="hidden" name="sensor_id" value="<?php echo hc2_h($x['sensor_id']); ?>"><?php } ?>
						<button class="btn btn-sm btn-outline-danger" type="submit" title="Node entfernen"><i class="fa-solid fa-user-slash"></i> Entfernen</button></form></td>
			</tr>
			<?php } ?>
			</tbody>
		</table></div>
		<?php } ?>
	</div>
	<?php if ($gone) { ?>
	<div class="card shadow-sm mb-3">
		<div class="card-header p-2"><i class="fa-solid fa-ban"></i> Entfernte Nodes <span class="badge badge-secondary"><?php echo count($gone); ?></span></div>
		<div class="table-responsive"><table class="table table-sm mb-0 text-muted">
			<thead><tr><th>Name</th><th>Entfernt</th><th>Zuletzt gemeldet</th><th></th></tr></thead>
			<tbody>
			<?php foreach ($gone as $row) { $r = $row['reg']; $h = $row['hub']; $name = $r['name'] ?? ($h['name'] ?? ''); ?>
			<tr>
				<td><?php echo hc2_h($name); ?><br><small><?php echo hc2_h($row['id']); ?></small></td>
				<td class="small"><?php echo $r ? hc2_dt($r['removed_at']) : 'Healthchecks-Sync getrennt ' . hc2_dt($h['revoked_at']); ?></td>
				<td class="small"><?php echo hc2_dt($r['last_seen'] ?? ($h['last_seen'] ?? null)); ?></td>
				<td class="text-nowrap text-right"><?php if ($r) { ?>
					<form method="post" class="d-inline"><?php echo hc2_csrf_field(); ?><input type="hidden" name="node_id" value="<?php echo hc2_h($r['node_id']); ?>"><input type="hidden" name="action" value="allow"><button class="btn btn-sm btn-outline-primary" type="submit"><i class="fa-solid fa-rotate-left"></i> Wieder zulassen</button></form>
					<form method="post" class="d-inline" onsubmit="return confirm('Node endgültig aus der Liste löschen? Meldet sie sich später wieder, erscheint sie erneut.');"><?php echo hc2_csrf_field(); ?><input type="hidden" name="node_id" value="<?php echo hc2_h($r['node_id']); ?>"><input type="hidden" name="action" value="forget"><button class="btn btn-sm btn-outline-danger" type="submit"><i class="fa-solid fa-trash"></i> Löschen</button></form>
				<?php } else { ?><form method="post" class="d-inline" onsubmit="return confirm('Getrennte Node endgültig aus der Liste entfernen?');"><?php echo hc2_csrf_field(); ?><input type="hidden" name="node_id" value="<?php echo hc2_h($h['node_id']); ?>"><input type="hidden" name="action" value="delete"><button class="btn btn-sm btn-outline-danger" type="submit" title="Entfernen"><i class="fa-solid fa-trash"></i> Löschen</button></form><?php } ?></td>
			</tr>
			<?php } ?>
			</tbody>
		</table></div>
	</div>
	<?php } ?>
	<?php if ($detail && empty($detail['revoked_at'])) { $N = $detail['node_id'];
		$st = $pdo->prepare("SELECT * FROM hc2_checks WHERE (node_id = :n OR FIND_IN_SET(:n2, nodes) > 0) AND userid = :u AND deleted_at IS NULL AND execution IN ('local','both') ORDER BY name"); $st->execute(array('n' => $N, 'n2' => $N, 'u' => $uid)); $nchecks = $st->fetchAll(PDO::FETCH_ASSOC);
		$st = $pdo->prepare("SELECT * FROM hc2_commands WHERE node_id = :n ORDER BY id DESC LIMIT 10"); $st->execute(array('n' => $N)); $cmds = $st->fetchAll(PDO::FETCH_ASSOC);
		$pills = hc2_pills_many(array_column($nchecks, 'token'), 20, $nodeMap);
	?>
	<div class="row">
		<div class="col-lg-8">
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2 d-flex align-items-center"><span><i class="fa-solid fa-heart-pulse"></i> Checks von <?php echo hc2_h($detail['name']); ?> <span class="badge badge-secondary"><?php echo count($nchecks); ?></span></span>
					<span class="ml-auto"><a class="btn btn-sm btn-primary" href="<?php echo HC2_BASE; ?>/edit.php?node=<?php echo hc2_h($N); ?>"><i class="fa-solid fa-plus"></i> Check auf dieser Node anlegen</a></span></div>
				<div class="table-responsive"><table class="table table-sm mb-0">
					<thead><tr><th>Zustand</th><th>Name</th><th>Typ</th><th>Messungen</th><th></th></tr></thead><tbody>
					<?php if (!$nchecks) { echo '<tr><td colspan="5" class="text-muted">Keine Checks auf dieser Node. Checks lassen sich in der Node anlegen oder hier (die Node übernimmt sie, solange die Fernverwaltung nicht „aus“ ist).</td></tr>'; } ?>
					<?php foreach ($nchecks as $c) { ?>
					<tr><td><?php echo hc2_state_badge((int)$c['paused'] ? 'paused' : ($c['state'] ?: 'pending')); ?></td>
						<td><a href="<?php echo HC2_BASE; ?>/check.php?token=<?php echo hc2_h($c['token']); ?>"><?php echo hc2_h($c['name']); ?></a> <?php echo $c['execution'] === 'both' ? '<span class="badge badge-light">hybrid</span>' : ''; ?><br><small class="text-muted"><?php echo hc2_h($c['target']); ?></small></td>
						<td><span class="badge badge-light"><?php echo hc2_h(hc2_types()[$c['type']] ?? $c['type']); ?></span></td>
						<td class="barr2 text-nowrap"><?php echo $pills[$c['token']] ?? ''; ?></td>
						<td class="text-right text-nowrap"><form method="post" class="d-inline"><?php echo hc2_csrf_field(); ?><input type="hidden" name="node_id" value="<?php echo hc2_h($N); ?>"><input type="hidden" name="action" value="command"><input type="hidden" name="cmd" value="run_check"><input type="hidden" name="token" value="<?php echo hc2_h($c['token']); ?>"><button class="btn btn-sm btn-outline-secondary" title="Jetzt prüfen"><i class="fa-solid fa-rotate"></i></button></form>
							<a class="btn btn-sm btn-outline-secondary" href="<?php echo HC2_BASE; ?>/move.php?tokens=<?php echo hc2_h($c['token']); ?>&to=online" title="Online umhängen"><i class="fa-solid fa-cloud-arrow-up"></i></a></td></tr>
					<?php } ?>
					</tbody></table></div>
			</div>
			<?php if ((int)$detail['conflicts'] > 0) { ?>
			<div class="card shadow-sm mb-3 border-danger">
				<div class="card-header p-2"><i class="fa-solid fa-code-merge"></i> Konflikte: <?php echo (int)$detail['conflicts']; ?></div>
				<div class="card-body small">
					<p>Die Node hat Änderungen, die sich mit Änderungen hier überschneiden (sie war zwischendurch offline). Die beiden Versionen zeigt die Node unter <em>ipv64-Verknüpfung</em>. Du kannst die Entscheidung auch von hier an die Node geben:</p>
					<form method="post" class="form-inline" style="gap:.4rem"><?php echo hc2_csrf_field(); ?><input type="hidden" name="node_id" value="<?php echo hc2_h($N); ?>"><input type="hidden" name="action" value="resolve">
						<input class="form-control form-control-sm" type="number" name="conflict_id" placeholder="Konflikt-Nr. (aus der Node)" min="1" required>
						<button class="btn btn-sm btn-outline-primary" name="keep" value="server">Server-Version behalten</button><button class="btn btn-sm btn-outline-secondary" name="keep" value="local">Node-Version übernehmen</button></form>
				</div>
			</div>
			<?php } ?>
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-terminal"></i> Letzte Befehle</div>
				<div class="table-responsive"><table class="table table-sm mb-0"><thead><tr><th>Zeit</th><th>Befehl</th><th>Ergebnis</th></tr></thead><tbody>
					<?php if (!$cmds) { echo '<tr><td colspan="3" class="text-muted">Keine Befehle.</td></tr>'; } foreach ($cmds as $cm) { ?><tr><td class="small text-nowrap"><?php echo hc2_dt($cm['created_at']); ?></td><td class="small"><?php echo hc2_h($cm['name']); ?></td><td class="small"><?php echo $cm['done_at'] ? ((int)$cm['ok'] ? '<span class="text-success">OK</span>' : '<span class="text-danger">Fehler</span>') . ' ' . hc2_h(mb_substr((string)$cm['output'], 0, 120)) : '<span class="text-muted">offen</span>'; ?></td></tr><?php } ?>
					</tbody></table></div>
			</div>
		</div>
		<div class="col-lg-4">
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-server"></i> Node</div>
				<div class="card-body">
					<form method="post"><?php echo hc2_csrf_field(); ?><input type="hidden" name="node_id" value="<?php echo hc2_h($N); ?>"><input type="hidden" name="action" value="rename">
						<div class="form-group"><label>Name</label><input class="form-control" name="name" value="<?php echo hc2_h($detail['name']); ?>" maxlength="100" required></div>
						<div class="form-group"><label>Standort</label><input class="form-control" name="location" value="<?php echo hc2_h($detail['location']); ?>" maxlength="100"></div>
						<div class="form-group"><label>Fernverwaltung</label><select class="custom-select" name="remote_mgmt"><option value="full"<?php echo $detail['remote_mgmt'] === 'full' ? ' selected' : ''; ?>>Vollständig</option><option value="read"<?php echo $detail['remote_mgmt'] === 'read' ? ' selected' : ''; ?>>Nur lesen und Testläufe</option><option value="off"<?php echo $detail['remote_mgmt'] === 'off' ? ' selected' : ''; ?>>Aus</option></select><small class="form-text text-muted">Die Node entscheidet selbst, was sie annimmt; die Einstellung wird mit dem nächsten Abgleich übertragen.</small></div>
						<button class="btn btn-primary btn-sm" type="submit">Speichern</button>
					</form>
					<hr>
					<dl class="row small mb-0">
						<dt class="col-5">Status</dt><dd class="col-7"><?php echo (int)$detail['online'] ? '<span class="badge badge-success">online</span> an ' . hc2_h($detail['node']) : '<span class="badge badge-warning">offline</span> seit ' . hc2_dt($detail['last_seen']); ?></dd>
						<dt class="col-5">Version</dt><dd class="col-7"><?php echo hc2_h($detail['version']); ?></dd>
						<dt class="col-5">Zeitzone</dt><dd class="col-7"><?php echo hc2_h($detail['timezone']); ?></dd>
						<dt class="col-5">Module</dt><dd class="col-7"><?php echo hc2_h($detail['modules'] ?: '–'); ?></dd>
						<dt class="col-5">Letzter Abgleich</dt><dd class="col-7"><?php echo hc2_dt($detail['last_sync']); ?></dd>
						<dt class="col-5">Postausgang</dt><dd class="col-7"><?php echo (int)$detail['outbox_size']; ?> offen</dd>
						<dt class="col-5">Verknüpft seit</dt><dd class="col-7"><?php echo hc2_dt($detail['created_at'], 'd.m.Y'); ?></dd>
						<dt class="col-5">ID</dt><dd class="col-7"><code><?php echo hc2_h($N); ?></code></dd>
					</dl>
				</div>
			</div>
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-screwdriver-wrench"></i> Aktionen</div>
				<div class="card-body">
					<form method="post" class="mb-2"><?php echo hc2_csrf_field(); ?><input type="hidden" name="node_id" value="<?php echo hc2_h($N); ?>"><input type="hidden" name="action" value="command"><input type="hidden" name="cmd" value="repair"><button class="btn btn-sm btn-outline-secondary" type="submit"><i class="fa-solid fa-arrows-rotate"></i> Vollabgleich anstoßen</button></form>
					<form method="post" onsubmit="return confirm('Node trennen? Sie läuft danach standalone weiter.');"><?php echo hc2_csrf_field(); ?><input type="hidden" name="node_id" value="<?php echo hc2_h($N); ?>"><input type="hidden" name="action" value="revoke">
						<div class="custom-control custom-checkbox mb-2"><input class="custom-control-input" type="checkbox" id="keep_checks" name="keep_checks" value="1" checked><label class="custom-control-label" for="keep_checks">Checks als Online-Checks weiterführen (öffentliche Ziele, soweit das Limit reicht)</label></div>
						<button class="btn btn-sm btn-outline-danger" type="submit"><i class="fa-solid fa-link-slash"></i> Healthchecks-Sync trennen (Token widerrufen)</button>
					</form>
				</div>
			</div>
		</div>
	</div>
	<?php } ?>
</div>
<?php include("footer.php"); ?>
<script>$(function(){ $('[data-toggle="tooltip"]').tooltip(); });</script>
