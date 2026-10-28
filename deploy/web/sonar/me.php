<?php
/**
 * Sonar64 – Mein Knoten (Teil W, Plan Abschnitt 7 „Fuer den Teilnehmer“, Vertrag Abschnitt 2/6): eigene Knoten mit
 * Stufe und Fortschritt, Tabellen „Pings von mir“ und „Pings gegen mich“ (aus sonar_results, 24 h) sowie UDP 6464
 * live (sonar_inbound), Sonar-Token verwalten (anlegen, Klartext nur einmal, sperren = Knoten deaktivieren) und
 * Name/Standort/Anschluss/Geraet setzen. Nur Zeilen des angemeldeten Accounts; keine IPs, auch nicht die eigenen.
 * Token wie POST /sonar/tokens: "s64_" + 40 [A-Za-z0-9], in der DB nur SHA-256, hoechstens 10 aktive je Account.
 * Oeffentliche Koordinaten ueber s64_pub_coords() aus s64_lib.php (Teil A).
 *
 *   me.php[?node=<node_id>][&lang=en]
 */
include("../header.php");
require_once __DIR__ . '/s64_web.php';
require_once __DIR__ . '/s64_lib.php';

const S64M_MAX_TOKENS = 10;     // aktive Knoten-Token je Account (Vertrag Abschnitt 2)
const S64M_ROWS       = 50;     // Zeilen je Tabelle

function s64m_q(string $sql, array $p = array()): PDOStatement { global $pdo; $st = $pdo->prepare($sql); $st->execute($p); return $st; }
/** UTC aus der DB -> Ortszeit der Seite */
function s64m_time($utc): string {
	if($utc === null OR $utc === '' OR str_starts_with((string)$utc, '0000')) { return '–'; }
	return date(s64w_lang() === 'en' ? 'Y-m-d H:i' : 'd.m.Y H:i', strtotime($utc . ' UTC'));
}
/** "s64_" + 40 Zeichen aus [A-Za-z0-9], gleichverteilt (random_int) */
function s64m_new_token(): string {
	$a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; $t = 's64_';
	for($i = 0; $i < 40; $i++) { $t .= $a[random_int(0, 61)]; }
	return $t;
}
/** ms-Badge mit Farbe nach Latenz (<15 gruen, <30 hellgruen, <60 orange, sonst rot) */
function s64m_ms($ms): string {
	if($ms === null OR $ms === '' OR !is_numeric($ms)) { return '<span class="s64-ms s64-l0">–</span>'; }
	$v = (float)$ms; $c = $v < 15 ? 1 : ($v < 30 ? 2 : ($v < 60 ? 3 : 4));
	return '<span class="s64-ms s64-l' . $c . '">' . s64w_h(number_format($v, $v < 10 ? 1 : 0, s64w_lang() === 'en' ? '.' : ',', '')) . ' ms</span>';
}
function s64m_access(string $a): string {
	$n = array('fiber' => array('Glasfaser', 'Fibre'), 'dsl' => array('DSL', 'DSL'), 'cable' => array('Kabel', 'Cable'), 'mobile' => array('LTE/5G', 'LTE/5G'),
		'satellite' => array('Satellit', 'Satellite'), 'datacenter' => array('Rechenzentrum', 'Data centre'), 'other' => array('Sonstiges', 'Other'));
	return isset($n[$a]) ? s64w_t($n[$a][0], $n[$a][1]) : '–';
}
function s64m_reason(?string $r): string {
	$n = array('not_in_plan' => array('nicht im Plan', 'not in plan'), 'too_many' => array('zu viele', 'too many'), 'bad_time' => array('falsche Zeit', 'wrong time'),
		'bad_values' => array('unmögliche Werte', 'impossible values'), 'below_light' => array('schneller als Licht', 'faster than light'), 'too_smooth' => array('zu glatt', 'too smooth'));
	return isset($n[(string)$r]) ? s64w_t($n[$r][0], $n[$r][1]) : s64w_t('verworfen', 'rejected');
}
function s64m_reach(?string $r): string {
	return match((string)$r) { 'udp' => 'UDP 6464', 'icmp' => 'ICMP', default => s64w_t('nur ausgehend', 'outgoing only') };
}
/** Slug wie s64_slug() in api_v2_sonar.php (PUT /sonar/me): aus dem Namen, eindeutig, sonst mit Teil der Node-ID */
function s64m_slug(string $name, string $nodeId): string {
	$s = trim((string)preg_replace('/[^a-z0-9]+/', '-', strtolower($name)), '-');
	if($s === '') { $s = str_replace('_', '-', $nodeId); }
	$s = substr($s, 0, 40);
	if(s64m_q("SELECT id FROM sonar_nodes WHERE slug = :s AND node_id != :n", array('s' => $s, 'n' => $nodeId))->fetch() !== false) {
		$s = substr($s, 0, 33) . '-' . substr(str_replace('_', '', $nodeId), -6);
	}
	return $s;
}
function s64m_node_link(?string $name, ?string $slug, string $fallback): string {
	if($name === null OR $name === '') { return '<span class="text-muted">' . s64w_h($fallback) . '</span>'; }
	if($slug === null OR !preg_match('/^[a-z0-9][a-z0-9_-]{0,39}$/', $slug)) { return s64w_h($name); }
	return '<a href="' . s64w_h(s64w_url('node.php', array('slug' => $slug))) . '">' . s64w_h($name) . '</a>';
}
/** Zahl aus dem Formular (Komma oder Punkt), null = leer, false = ungueltig */
function s64m_coord(string $s, float $max) {
	$s = str_replace(',', '.', trim($s));
	if($s === '') { return null; }
	if(!preg_match('/^-?[0-9]{1,3}(\.[0-9]{1,8})?$/', $s)) { return false; }
	$v = (float)$s;
	return ($v < -$max OR $v > $max) ? false : round($v, 5);
}
/** Ergebnis-Tabelle (von mir / gegen mich) */
function s64m_results_table(array $rows, bool $mine): void {
	echo '<div class="table-responsive"><table class="table table-sm table-striped mb-0 small"><thead><tr><th>' . s64w_h(s64w_t('Zeit', 'Time')) . '</th><th>'
		. s64w_h($mine ? s64w_t('Ziel', 'Target') : s64w_t('Von', 'From')) . '</th><th>Provider</th><th>' . s64w_h(s64w_t('Ort', 'Place')) . '</th><th>' . s64w_h(s64w_t('Weg', 'Path'))
		. '</th><th class="text-right">ms</th><th class="text-right">Min/Max</th><th class="text-right">' . s64w_h(s64w_t('Verlust', 'Loss')) . '</th>' . ($mine ? '<th>' . s64w_h(s64w_t('Prüfung', 'Check')) . '</th>' : '') . '</tr></thead><tbody>';
	if(empty($rows)) { echo '<tr><td colspan="' . ($mine ? 9 : 8) . '" class="text-muted">' . s64w_h(s64w_t('In den letzten 24 Stunden keine Messungen.', 'No measurements in the last 24 hours.')) . '</td></tr>'; }
	foreach($rows as $r) {
		$sent = max(0, (int)$r['sent']); $loss = $sent > 0 ? max(0, $sent - (int)$r['recv']) / $sent : 0;
		$as = ((int)$r['fam'] === 6 AND (string)$r['asname6'] !== '') ? $r['asname6'] : $r['asname4'];
		echo '<tr><td class="text-nowrap">' . s64w_h(s64m_time($r['at'])) . '</td><td>' . s64m_node_link($r['name'], $r['slug'], (string)$r['peer']) . '</td><td>' . s64w_h($as ?? '–')
			. '</td><td>' . s64w_h($r['place'] ?? '–') . '</td><td class="text-nowrap">' . s64w_h(strtoupper((string)$r['method'])) . ' · IPv' . (int)$r['fam']
			. '</td><td class="text-right">' . ((int)$r['recv'] > 0 ? s64m_ms($r['avg_ms']) : '<span class="s64-ms s64-l4">' . s64w_h(s64w_t('keine Antwort', 'no reply')) . '</span>')
			. '</td><td class="text-right text-nowrap text-muted">' . ((int)$r['recv'] > 0 ? s64w_h(round((float)$r['min_ms'], 1) . ' / ' . round((float)$r['max_ms'], 1)) : '–')
			. '</td><td class="text-right">' . s64w_h(round($loss * 100) . ' %') . '</td>';
		if($mine) { echo '<td>' . ((int)$r['valid'] === 1 ? '<span class="text-success"><i class="fa-solid fa-check"></i></span>' : '<span class="badge badge-warning">' . s64w_h(s64m_reason($r['reason'])) . '</span>') . '</td>'; }
		echo '</tr>';
	}
	echo '</tbody></table></div>';
}

s64w_head('me', s64w_t('Mein Knoten', 'My node'), s64w_t('Deine Sonar64-Knoten: Stufe, Messungen von dir und gegen dich, Standort und Sonar-Token. Gilt auch für Knoten ohne Oberfläche (Raspberry Pi, MikroTik, Container).',
	'Your Sonar64 nodes: trust level, measurements from you and against you, location and Sonar tokens. Also for nodes without a dashboard (Raspberry Pi, MikroTik, container).'));

if($userid == "") {
	echo '<div class="alert alert-info" role="alert">' . s64w_h(s64w_t('Bitte zuerst anmelden.', 'Please log in first.')) . '</div>';
	s64w_join();
	s64w_foot(); include("../footer.php");
	exit;
}

$u = (int)$userid; $now = time(); $msg = ''; $newToken = '';
if(empty($_SESSION['s64m_csrf'])) { $_SESSION['s64m_csrf'] = bin2hex(random_bytes(16)); }
$csrf = $_SESSION['s64m_csrf'];
$sel = (string)($_POST['node'] ?? $_GET['node'] ?? '');
if(!preg_match('/^(n[a-z0-9]{11}|a_[a-z0-9_-]{1,13})$/', $sel)) { $sel = ''; }
$okMsg = fn(string $t, string $c = 'success') => '<div class="alert alert-' . $c . '" role="alert">' . s64w_h($t) . '</div>';

try {
	if($_SERVER['REQUEST_METHOD'] === 'POST') {
		$act = (string)($_POST['action'] ?? '');
		if(!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) {
			$msg = $okMsg(s64w_t('Sitzung abgelaufen, bitte noch einmal versuchen.', 'Session expired, please try again.'), 'danger');
		} elseif($act === 'token_new') {
			$name = trim((string)($_POST['name'] ?? ''));
			if(!preg_match('/^[A-Za-z0-9 ._-]{1,32}$/', $name)) { $name = 'Sonar64'; }
			$cnt = (int)s64m_q("SELECT COUNT(*) FROM sonar_tokens WHERE userid = :u AND kind = 'node' AND revoked_at IS NULL", array('u' => $u))->fetchColumn();
			if($cnt >= S64M_MAX_TOKENS) {
				$msg = $okMsg(s64w_t('Höchstens ' . S64M_MAX_TOKENS . ' aktive Sonar-Token je Account – bitte erst ein altes sperren.', 'At most ' . S64M_MAX_TOKENS . ' active Sonar tokens per account – please revoke an old one first.'), 'warning');
			} else {
				for($try = 0; ; $try++) {
					$tok = s64m_new_token();
					try {
						s64m_q("INSERT INTO sonar_tokens (userid, kind, name, token_hash, node_id, created_at) VALUES (:u, 'node', :n, :h, NULL, :c)",
							array('u' => $u, 'n' => $name, 'h' => hash('sha256', $tok), 'c' => s64_dt()));
						break;
					} catch(PDOException $e) { if($try >= 2 OR ($e->errorInfo[1] ?? 0) != 1062) { throw $e; } } // Hash schon vergeben (praktisch nie): neu wuerfeln
				}
				$newToken = $tok;
				if(function_exists('add_log')) { add_log($pdo, $userid, "0", "Sonar64", "Sonar-Token erzeugt."); }
			}
		} elseif($act === 'token_revoke') {
			$id = (int)($_POST['id'] ?? 0);
			$st = s64m_q("UPDATE sonar_tokens SET revoked_at = :t WHERE id = :id AND userid = :u AND kind = 'node' AND revoked_at IS NULL", array('t' => s64_dt(), 'id' => $id, 'u' => $u));
			if($st->rowCount() > 0) { // wie DELETE /sonar/tokens/{id}: Knoten aus, IP und genauer Standort weg
				s64m_q("UPDATE sonar_nodes SET active = 0 WHERE token_id = :id AND userid = :u", array('id' => $id, 'u' => $u));
				s64m_q("UPDATE sonar_nodes SET ip4 = NULL, ip6 = NULL, lat = NULL, lon = NULL, pub_lat = NULL, pub_lon = NULL WHERE token_id = :id AND userid = :u AND role = 'node'", array('id' => $id, 'u' => $u));
				if(function_exists('add_log')) { add_log($pdo, $userid, "0", "Sonar64", "Sonar-Token gesperrt."); }
				$msg = $okMsg(s64w_t('Token gesperrt, der zugehörige Knoten ist abgemeldet.', 'Token revoked, the node using it is signed off.'), 'warning');
			}
		} elseif($act === 'node_save') {
			$n = s64m_q("SELECT node_id, role, name, jitter_seed FROM sonar_nodes WHERE node_id = :n AND userid = :u AND active = 1", array('n' => $sel, 'u' => $u))->fetch(PDO::FETCH_ASSOC);
			$name = trim((string)($_POST['name'] ?? ''));
			$access = (string)($_POST['access'] ?? '');
			$device = strtolower(trim((string)($_POST['device'] ?? '')));
			$lat = s64m_coord((string)($_POST['lat'] ?? ''), 90); $lon = s64m_coord((string)($_POST['lon'] ?? ''), 180);
			$err = '';
			if(!$n OR $n['role'] !== 'node') { $err = s64w_t('Knoten nicht gefunden (Anker stellt ipv64 ein).', 'Node not found (anchors are set by ipv64).'); }
			elseif(!preg_match('/^[A-Za-z0-9._-](?:[A-Za-z0-9._-]| (?! )){1,30}[A-Za-z0-9._-]\z/', $name)) { $err = s64w_t('Name: 3 bis 32 Zeichen aus A–Z, a–z, 0–9, Leerzeichen, Punkt, Unterstrich, Bindestrich (keine doppelten Leerzeichen).', 'Name: 3 to 32 characters from A–Z, a–z, 0–9, space, dot, underscore, hyphen (no double spaces).'); }
			elseif($name !== $n['name'] AND preg_match('/^(anker|anchor|ipv64|sonar64|admin)/i', $name)) { $err = s64w_t('Dieser Name ist reserviert.', 'This name is reserved.'); }
			elseif(!in_array($access, S64_ACCESS, true)) { $err = s64w_t('Bitte eine Anschlussart wählen.', 'Please choose an access type.'); }
			elseif(!preg_match('/^[a-z0-9-]{0,16}$/', $device)) { $err = s64w_t('Gerät: höchstens 16 Zeichen a–z, 0–9, Bindestrich.', 'Device: at most 16 characters a–z, 0–9, hyphen.'); }
			elseif($lat === false OR $lon === false OR ($lat === null) !== ($lon === null)) { $err = s64w_t('Standort: Breite (−90…90) und Länge (−180…180) beide angeben oder beide leer lassen.', 'Location: give latitude (−90…90) and longitude (−180…180) both or leave both empty.'); }
			if($err !== '') {
				$msg = $okMsg($err, 'danger');
			} else {
				$seed = (int)$n['jitter_seed'] !== 0 ? (int)$n['jitter_seed'] : random_int(1, 2147483646); // setzt sonst /sonar/register
				if($device === '') { $device = 'other'; }
				$plat = null; $plon = null;
				if($lat !== null) {
					$pc = s64_pub_coords((float)$lat, (float)$lon, $seed);
					$plat = (float)($pc['lat'] ?? $pc[0]); $plon = (float)($pc['lon'] ?? $pc[1]);
				}
				try {
					$slug = $name !== $n['name'] ? s64m_slug($name, $sel) : null;
					s64m_q("UPDATE sonar_nodes SET name = :name, slug = COALESCE(:slug, slug), access = :a, device = :d, lat = :lat, lon = :lon, pub_lat = :plat, pub_lon = :plon, jitter_seed = :s WHERE node_id = :n AND userid = :u",
						array('name' => $name, 'slug' => $slug, 'a' => $access, 'd' => $device, 'lat' => $lat, 'lon' => $lon, 'plat' => $plat, 'plon' => $plon, 's' => $seed, 'n' => $sel, 'u' => $u));
					$msg = $okMsg(s64w_t('Gespeichert.', 'Saved.'));
				} catch(PDOException $e) {
					if(($e->errorInfo[1] ?? 0) != 1062) { throw $e; }
					$msg = $okMsg(s64w_t('Dieser Name ist schon vergeben.', 'This name is already taken.'), 'danger');
				}
			}
		}
	}
	$d24 = gmdate('Y-m-d H:i:s', $now - 86400);
	$tokens = s64m_q("SELECT t.id, t.name, t.node_id, t.created_at, t.last_used_at, t.revoked_at, n.name nname FROM sonar_tokens t LEFT JOIN sonar_nodes n ON n.node_id = t.node_id
		WHERE t.userid = :u AND t.kind = 'node' AND (t.revoked_at IS NULL OR t.revoked_at >= :d) ORDER BY t.revoked_at IS NOT NULL, t.created_at DESC LIMIT 40",
		array('u' => $u, 'd' => gmdate('Y-m-d H:i:s', $now - 30 * 86400)))->fetchAll(PDO::FETCH_ASSOC);
	$nodes = s64m_q("SELECT node_id, role, name, slug, lat, lon, access, device, measured, budget, mode, version, asn4, asname4, asn6, asname6, place, reach4, reach6,
		trust, uptime30, first_seen, last_seen, last_report FROM sonar_nodes WHERE userid = :u AND active = 1 ORDER BY first_seen, id", array('u' => $u))->fetchAll(PDO::FETCH_ASSOC);
	$cur = null;
	foreach($nodes as $x) { if($x['node_id'] === $sel) { $cur = $x; } }
	if($cur === null AND !empty($nodes)) { $cur = $nodes[0]; }
	$mine = $against = $inbound = array();
	if($cur !== null) {
		$p = array('n' => $cur['node_id'], 'd' => $d24);
		$mine = s64m_q("SELECT r.at, r.dst peer, r.fam, r.method, r.sent, r.recv, r.min_ms, r.avg_ms, r.max_ms, r.valid, r.reason, n.name, n.slug, n.asname4, n.asname6, n.place
			FROM sonar_results r LEFT JOIN sonar_nodes n ON n.node_id = r.dst WHERE r.src = :n AND r.at >= :d ORDER BY r.at DESC LIMIT " . S64M_ROWS, $p)->fetchAll(PDO::FETCH_ASSOC);
		$against = s64m_q("SELECT r.at, r.src peer, r.fam, r.method, r.sent, r.recv, r.min_ms, r.avg_ms, r.max_ms, r.valid, r.reason, n.name, n.slug, n.asname4, n.asname6, n.place
			FROM sonar_results r LEFT JOIN sonar_nodes n ON n.node_id = r.src WHERE r.dst = :n AND r.at >= :d AND r.valid = 1 AND (n.trust IS NULL OR n.trust <> 'quarantine') ORDER BY r.at DESC LIMIT " . S64M_ROWS, $p)->fetchAll(PDO::FETCH_ASSOC);
		$inbound = s64m_q("SELECT i.at, i.fam, i.count, i.from_short, n.name, n.slug, n.asname4, n.asname6 FROM sonar_inbound i
			LEFT JOIN sonar_nodes n ON n.active = 1 AND CONVERT(LEFT(SHA2(n.node_id, 256), 8) USING ascii) = CONVERT(i.from_short USING ascii)
			WHERE i.node_id = :n AND i.at >= :d ORDER BY i.at DESC LIMIT " . S64M_ROWS, $p)->fetchAll(PDO::FETCH_ASSOC);
	}
} catch(Throwable $e) {
	error_log('sonar/me.php: ' . $e->getMessage());
	echo '<div class="alert alert-danger" role="alert">' . s64w_h(s64w_t('Sonar64 ist gerade nicht verfügbar.', 'Sonar64 is currently not available.')) . '</div>';
	s64w_foot(); include("../footer.php");
	exit;
}
echo $msg;

if($newToken !== '') { ?>
	<div class="alert alert-success" role="alert">
		<p class="mb-1"><b><?php echo s64w_h(s64w_t('Neues Sonar-Token – nur jetzt sichtbar, bitte sofort kopieren:', 'New Sonar token – only visible now, please copy it right away:')); ?></b></p>
		<div class="input-group input-group-sm mb-2" style="max-width:40em">
			<input type="text" class="form-control text-monospace" id="s64NewToken" value="<?php echo s64w_h($newToken); ?>" readonly autocomplete="off">
			<div class="input-group-append"><button class="btn btn-outline-secondary" type="button" data-s64-copy="s64NewToken" title="<?php echo s64w_h(s64w_t('Kopieren', 'Copy')); ?>"><i class="fa-solid fa-copy"></i></button></div>
		</div>
		<p class="small mb-1"><?php echo s64w_h(s64w_t('Als Container (Datenordner behalten, sonst entsteht nach jedem Neustart ein neuer Knoten):', 'As a container (keep the data folder, otherwise every restart creates a new node):')); ?></p>
		<pre class="small mb-1 s64-pre">docker run -d --name sonar64 --restart unless-stopped -v sonar64:/data -e SONAR64_TOKEN=<?php echo s64w_h($newToken); ?> ghcr.io/ipv64net/sonar64</pre>
		<p class="small mb-0"><?php echo s64w_h(s64w_t('Raspberry Pi Zero, MikroTik und weitere Wege:', 'Raspberry Pi Zero, MikroTik and more:')); ?> <a href="https://node64.de/docs/sonar64/" target="_blank" rel="noopener">node64.de/docs/sonar64/</a>.
			<?php echo s64w_h(s64w_t('In Node64 brauchst du kein Token: das Modul legt sich selbst eins an.', 'In Node64 you need no token: the module creates its own.')); ?></p>
	</div>
<?php }

if(empty($nodes)) { ?>
	<div class="card mb-3"><div class="card-body small">
		<p class="mb-1"><b><?php echo s64w_h(s64w_t('Noch kein Knoten angemeldet.', 'No node signed up yet.')); ?></b></p>
		<p class="mb-0"><?php echo s64w_h(s64w_t('In Node64 das Modul Sonar64 einschalten – oder unten ein Sonar-Token erzeugen und sonar64 damit starten. Der Knoten erscheint hier nach seiner ersten Anmeldung.',
			'Switch on the Sonar64 module in Node64 – or create a Sonar token below and start sonar64 with it. The node appears here after it first signs up.')); ?></p>
	</div></div>
<?php } else {
	$cid = $cur['node_id'];
	if(count($nodes) > 1) { ?>
	<ul class="nav nav-tabs small mb-2">
		<?php foreach($nodes as $x) { ?>
		<li class="nav-item"><a class="nav-link<?php echo $x['node_id'] === $cid ? ' active' : ''; ?>" href="<?php echo s64w_h(s64w_url('me.php', array('node' => $x['node_id']))); ?>"><?php echo s64w_h($x['name']); ?></a></li>
		<?php } ?>
	</ul>
	<?php }
	$online = ($cur['last_seen'] !== null && strtotime($cur['last_seen'] . ' UTC') >= $now - S64_ONLINE);
	$days = $cur['first_seen'] ? max(0, (int)floor(($now - strtotime($cur['first_seen'] . ' UTC')) / 86400)) : 0;
	$up = (float)$cur['uptime30'];
	// Fortschritt zur naechsten Stufe (Startwerte Plan Abschnitt 6)
	$next = match((string)$cur['trust']) { 'new' => array('stable', 7, 0.90), 'stable' => array('trusted', 60, 0.97), 'trusted' => array('pillar', 180, 0.97), default => null };
	?>
	<div class="row">
		<div class="col-12 col-lg-7 pb-3"><div class="card h-100"><div class="card-body p-3">
			<div class="d-flex flex-wrap align-items-center mb-2" style="gap:.5rem">
				<h5 class="mb-0"><?php echo s64w_h($cur['name']); ?></h5><?php echo s64w_trust_badge((string)$cur['trust']); ?>
				<span class="badge <?php echo $online ? 'badge-success' : 'badge-secondary'; ?>"><?php echo s64w_h($online ? 'online' : 'offline'); ?></span>
				<?php if(preg_match('/^[a-z0-9][a-z0-9_-]{0,39}$/', (string)$cur['slug'])) { ?><a class="small ml-auto" href="<?php echo s64w_h(s64w_url('node.php', array('slug' => $cur['slug']))); ?>"><i class="fa-solid fa-globe"></i> <?php echo s64w_h(s64w_t('Öffentliche Seite', 'Public page')); ?></a><?php } ?>
			</div>
			<table class="table table-sm small mb-2 s64-kv"><tbody>
				<tr><th>Node-ID</th><td><code><?php echo s64w_h($cid); ?></code> · <?php echo s64w_h($cur['role'] === 'anchor' ? s64w_t('Anker', 'Anchor') : s64w_t('Knoten', 'Node')); ?> · <?php echo s64w_h((string)$cur['mode']); ?> · <?php echo s64w_h((string)$cur['version']); ?></td></tr>
				<tr><th>Provider</th><td><?php echo s64w_h(trim(($cur['asn4'] ? 'AS' . (int)$cur['asn4'] . ' ' . $cur['asname4'] : '') . ($cur['asn6'] && $cur['asn6'] != $cur['asn4'] ? ' · IPv6 AS' . (int)$cur['asn6'] . ' ' . $cur['asname6'] : '')) ?: '–'); ?></td></tr>
				<tr><th><?php echo s64w_h(s64w_t('Erreichbar', 'Reachable')); ?></th><td>IPv4: <?php echo s64w_h(s64m_reach($cur['reach4'])); ?> · IPv6: <?php echo s64w_h(s64m_reach($cur['reach6'])); ?></td></tr>
				<tr><th><?php echo s64w_h(s64w_t('Teilnahme', 'Participation')); ?></th><td><?php echo s64w_h(((int)$cur['measured'] === 1 ? s64w_t('misst und wird gemessen', 'measures and is measured') : s64w_t('misst nur ausgehend', 'measures outgoing only')) . ' · Budget ' . $cur['budget']); ?>
					<span class="text-muted">(<?php echo s64w_h(s64w_t('stellt der Knoten selbst ein', 'set on the node itself')); ?>)</span></td></tr>
				<tr><th><?php echo s64w_h(s64w_t('Dabei seit', 'Member since')); ?></th><td><?php echo s64w_h(s64m_time($cur['first_seen'])); ?> (<?php echo $days; ?> <?php echo s64w_h(s64w_t('Tage', 'days')); ?>)</td></tr>
				<tr><th><?php echo s64w_h(s64w_t('Letzte Meldung', 'Last report')); ?></th><td><?php echo s64w_h(s64m_time($cur['last_report'])); ?></td></tr>
				<tr><th><?php echo s64w_h(s64w_t('Verfügbarkeit (30 Tage)', 'Availability (30 days)')); ?></th><td><?php echo s64w_h(number_format($up * 100, 1, s64w_lang() === 'en' ? '.' : ',', '') . ' %'); ?></td></tr>
			</tbody></table>
			<?php if($next !== null) { [$nt, $nd, $nu] = $next; ?>
			<div class="small"><b><?php echo s64w_h(s64w_t('Weg zur nächsten Stufe:', 'Way to the next level:')); ?></b> <?php echo s64w_trust_badge($nt); ?>
				<div class="d-flex align-items-center mt-1"><span style="width:9em"><?php echo s64w_h(min($days, $nd) . ' / ' . $nd . ' ' . s64w_t('Tage', 'days')); ?></span>
					<div class="progress flex-grow-1" style="height:.5rem"><div class="progress-bar" style="width:<?php echo (int)round(min(1, $days / $nd) * 100); ?>%"></div></div></div>
				<div class="d-flex align-items-center mt-1"><span style="width:9em"><?php echo s64w_h(s64w_t('Verfügbarkeit', 'Availability') . ' ≥ ' . round($nu * 100) . ' %'); ?></span>
					<div class="progress flex-grow-1" style="height:.5rem"><div class="progress-bar <?php echo $up >= $nu ? 'bg-success' : ''; ?>" style="width:<?php echo (int)round(min(1, $up / $nu) * 100); ?>%"></div></div></div>
				<p class="text-muted mb-0 mt-1"><?php echo s64w_h($nt === 'pillar' ? s64w_t('Säulen werden auch gemessen (UDP 6464 oder ICMP) und laufen sehr stabil.', 'Pillars are also measured (UDP 6464 or ICMP) and run very stably.')
					: s64w_t('Dazu müssen die Werte plausibel sein; Abstufung erfolgt sofort bei unplausiblen Meldungen.', 'Values must also be plausible; unplausible reports lower the level immediately.')); ?></p>
			</div>
			<?php } elseif($cur['trust'] === 'quarantine') { ?>
			<div class="alert alert-warning small mb-0"><?php echo s64w_h(s64w_t('Quarantäne: Der Knoten misst weiter, seine Werte zählen aber nicht und er erscheint nicht öffentlich. Häufige Ursachen: falscher Standort, fehlerhafte Uhrzeit, gestörte Leitung.',
				'Quarantine: the node keeps measuring, but its values do not count and it is not shown publicly. Common causes: wrong location, wrong clock, disturbed line.')); ?></div>
			<?php } ?>
		</div></div></div>

		<div class="col-12 col-lg-5 pb-3"><div class="card h-100"><div class="card-header p-2"><i class="fa-solid fa-sliders text-primary"></i> <?php echo s64w_h(s64w_t('Angaben', 'Details')); ?></div><div class="card-body p-2">
		<?php if($cur['role'] !== 'node') { ?>
			<p class="small text-muted mb-0"><?php echo s64w_h(s64w_t('Anker stellt ipv64 ein.', 'Anchors are set by ipv64.')); ?></p>
		<?php } else { ?>
			<form method="post" action="<?php echo s64w_h(s64w_url('me.php', array('node' => $cid))); ?>" class="small" autocomplete="off">
				<input type="hidden" name="csrf" value="<?php echo s64w_h($csrf); ?>"><input type="hidden" name="action" value="node_save"><input type="hidden" name="node" value="<?php echo s64w_h($cid); ?>">
				<div class="form-group mb-2"><label class="mb-0" for="s64Name"><?php echo s64w_h(s64w_t('Anzeigename (öffentlich)', 'Display name (public)')); ?></label>
					<input class="form-control form-control-sm" id="s64Name" name="name" required minlength="3" maxlength="32" pattern="[A-Za-z0-9._\-][A-Za-z0-9 ._\-]{1,30}[A-Za-z0-9._\-]" value="<?php echo s64w_h($cur['name']); ?>"></div>
				<div class="form-row">
					<div class="form-group col-6 mb-2"><label class="mb-0" for="s64Access"><?php echo s64w_h(s64w_t('Anschluss', 'Access')); ?></label>
						<select class="form-control form-control-sm" id="s64Access" name="access" required>
							<?php foreach(S64_ACCESS as $a) { ?><option value="<?php echo $a; ?>"<?php echo $a === $cur['access'] ? ' selected' : ''; ?>><?php echo s64w_h(s64m_access($a)); ?></option><?php } ?>
						</select></div>
					<div class="form-group col-6 mb-2"><label class="mb-0" for="s64Device"><?php echo s64w_h(s64w_t('Gerät', 'Device')); ?></label>
						<input class="form-control form-control-sm" id="s64Device" name="device" maxlength="16" pattern="[a-z0-9\-]{0,16}" list="s64Devices" value="<?php echo s64w_h($cur['device']); ?>">
						<datalist id="s64Devices"><option value="node64"><option value="pi"><option value="mikrotik"><option value="linux"><option value="other"></datalist></div>
				</div>
				<label class="mb-0"><?php echo s64w_h(s64w_t('Standort – Punkt auf der Karte setzen oder eingeben', 'Location – click the map or type it')); ?></label>
				<svg id="s64Pick" class="s64-map s64-pick" role="img" aria-label="<?php echo s64w_h(s64w_t('Karte zum Setzen des Standorts', 'Map to set the location')); ?>"></svg>
				<div class="form-row">
					<div class="form-group col-5 mb-2"><input class="form-control form-control-sm" id="s64Lat" name="lat" inputmode="decimal" maxlength="14" placeholder="<?php echo s64w_h(s64w_t('Breite', 'Latitude')); ?>" value="<?php echo s64w_h($cur['lat'] === null ? '' : round((float)$cur['lat'], 5)); ?>"></div>
					<div class="form-group col-5 mb-2"><input class="form-control form-control-sm" id="s64Lon" name="lon" inputmode="decimal" maxlength="14" placeholder="<?php echo s64w_h(s64w_t('Länge', 'Longitude')); ?>" value="<?php echo s64w_h($cur['lon'] === null ? '' : round((float)$cur['lon'], 5)); ?>"></div>
					<div class="form-group col-2 mb-2"><button type="button" class="btn btn-sm btn-outline-secondary btn-block" id="s64Geo" title="<?php echo s64w_h(s64w_t('Standort des Browsers übernehmen', 'Use the browser location')); ?>"><i class="fa-solid fa-location-crosshairs"></i></button></div>
				</div>
				<p class="text-muted mb-2"><?php echo s64w_h(s64w_t('Der genaue Punkt bleibt bei ipv64 (Plausibilitätsprüfung); öffentlich erscheint er um bis zu 1 km verschoben.', 'The exact point stays with ipv64 (plausibility check); publicly it appears shifted by up to 1 km.')); ?></p>
				<button class="btn btn-sm btn-primary"><i class="fa-solid fa-floppy-disk"></i> <?php echo s64w_h(s64w_t('Speichern', 'Save')); ?></button>
			</form>
		<?php } ?>
		</div></div></div>
	</div>

	<div class="card mb-3"><div class="card-header p-2 d-flex align-items-center"><span><i class="fa-solid fa-arrow-right-from-bracket text-primary"></i> <?php echo s64w_h(s64w_t('Pings von mir (24 h, neueste zuerst)', 'Pings from me (24 h, newest first)')); ?></span>
		<a class="btn btn-sm btn-outline-secondary py-0 ml-auto" href="<?php echo s64w_h(s64w_url('me.php', array('node' => $cid))); ?>"><i class="fa-solid fa-rotate"></i> <?php echo s64w_h(s64w_t('Aktualisieren', 'Refresh')); ?></a></div>
		<?php s64m_results_table($mine, true); ?></div>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-arrow-right-to-bracket text-primary"></i> <?php echo s64w_h(s64w_t('Pings gegen mich (24 h, aus den Meldungen der anderen, bis 5 min verzögert)', 'Pings against me (24 h, from the others\' reports, up to 5 min delayed)')); ?></div>
		<?php s64m_results_table($against, false); ?></div>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-satellite-dish text-primary"></i> <?php echo s64w_h(s64w_t('Auf UDP 6464 beantwortet (24 h)', 'Answered on UDP 6464 (24 h)')); ?></div>
		<div class="table-responsive"><table class="table table-sm table-striped mb-0 small"><thead><tr><th><?php echo s64w_h(s64w_t('Zeit', 'Time')); ?></th><th><?php echo s64w_h(s64w_t('Von', 'From')); ?></th><th>Provider</th><th><?php echo s64w_h(s64w_t('Protokoll', 'Protocol')); ?></th><th class="text-right"><?php echo s64w_h(s64w_t('Pakete', 'Packets')); ?></th></tr></thead><tbody>
		<?php if(empty($inbound)) { echo '<tr><td colspan="5" class="text-muted">' . s64w_h((int)$cur['measured'] === 1 ? s64w_t('Keine Proben auf UDP 6464 in den letzten 24 Stunden.', 'No probes on UDP 6464 in the last 24 hours.') : s64w_t('Der Knoten misst nur ausgehend und beantwortet UDP 6464 nicht.', 'The node measures outgoing only and does not answer UDP 6464.')) . '</td></tr>'; }
		foreach($inbound as $r) {
			$as = ((int)$r['fam'] === 6 AND (string)$r['asname6'] !== '') ? $r['asname6'] : $r['asname4'];
			echo '<tr><td class="text-nowrap">' . s64w_h(s64m_time($r['at'])) . '</td><td>' . s64m_node_link($r['name'], $r['slug'], (string)$r['from_short']) . '</td><td>' . s64w_h($as ?? '–') . '</td><td>IPv' . (int)$r['fam'] . '</td><td class="text-right">' . (int)$r['count'] . '</td></tr>';
		} ?>
		</tbody></table></div></div>
<?php } ?>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-key text-primary"></i> <?php echo s64w_h(s64w_t('Sonar-Token', 'Sonar tokens')); ?></div><div class="card-body p-2">
		<p class="small text-muted mb-2"><?php echo s64w_h(s64w_t('Ein Sonar-Token berechtigt nur zum Mitmessen – nicht zu deinem Account oder deinen Domains. Gut für Router und kleine Geräte. Ein Token gehört nach dem ersten Start zu genau einem Knoten; Sperren meldet diesen Knoten ab.',
			'A Sonar token only allows taking part in measuring – not access to your account or domains. Good for routers and small devices. After the first start a token belongs to exactly one node; revoking signs that node off.')); ?></p>
		<div class="table-responsive"><table class="table table-sm mb-2 small"><thead><tr><th><?php echo s64w_h(s64w_t('Name', 'Name')); ?></th><th><?php echo s64w_h(s64w_t('Knoten', 'Node')); ?></th><th><?php echo s64w_h(s64w_t('Erzeugt', 'Created')); ?></th><th><?php echo s64w_h(s64w_t('Zuletzt benutzt', 'Last used')); ?></th><th></th></tr></thead><tbody>
		<?php if(empty($tokens)) { echo '<tr><td colspan="5" class="text-muted">' . s64w_h(s64w_t('Noch kein Sonar-Token.', 'No Sonar token yet.')) . '</td></tr>'; }
		foreach($tokens as $t) { ?>
			<tr<?php echo $t['revoked_at'] !== null ? ' class="text-muted"' : ''; ?>><td><?php echo s64w_h($t['name']); ?></td><td><?php echo s64w_h($t['nname'] ?? ($t['node_id'] ? $t['node_id'] : s64w_t('noch nicht gestartet', 'not started yet'))); ?></td>
				<td class="text-nowrap"><?php echo s64w_h(s64m_time($t['created_at'])); ?></td><td class="text-nowrap"><?php echo s64w_h(s64m_time($t['last_used_at'])); ?></td>
				<td class="text-right"><?php if($t['revoked_at'] !== null) { echo s64w_h(s64w_t('gesperrt', 'revoked')); } else { ?>
					<form method="post" class="d-inline" action="<?php echo s64w_h(s64w_url('me.php')); ?>" data-s64-confirm="<?php echo s64w_h(s64w_t('Token sperren? Der Knoten damit wird abgemeldet und misst nicht mehr.', 'Revoke token? The node using it is signed off and stops measuring.')); ?>">
						<input type="hidden" name="csrf" value="<?php echo s64w_h($csrf); ?>"><input type="hidden" name="action" value="token_revoke"><input type="hidden" name="id" value="<?php echo (int)$t['id']; ?>">
						<button class="btn btn-sm btn-outline-danger py-0"><i class="fa-solid fa-ban"></i> <?php echo s64w_h(s64w_t('Sperren', 'Revoke')); ?></button></form>
				<?php } ?></td></tr>
		<?php } ?>
		</tbody></table></div>
		<form method="post" class="form-inline small" style="gap:.5rem" action="<?php echo s64w_h(s64w_url('me.php')); ?>" autocomplete="off">
			<input type="hidden" name="csrf" value="<?php echo s64w_h($csrf); ?>"><input type="hidden" name="action" value="token_new">
			<label for="s64TokName"><?php echo s64w_h(s64w_t('Bezeichnung', 'Label')); ?></label>
			<input class="form-control form-control-sm" id="s64TokName" name="name" maxlength="32" pattern="[A-Za-z0-9 ._\-]{1,32}" placeholder="<?php echo s64w_h(s64w_t('z. B. Pi Wohnzimmer', 'e.g. Pi living room')); ?>">
			<button class="btn btn-sm btn-primary"><i class="fa-solid fa-plus"></i> <?php echo s64w_h(s64w_t('Token erzeugen', 'Create token')); ?></button>
			<span class="text-muted"><?php echo s64w_h(s64w_t('höchstens ' . S64M_MAX_TOKENS . ' aktive', 'at most ' . S64M_MAX_TOKENS . ' active')); ?></span>
		</form>
	</div></div>
	<p class="small text-muted"><?php echo s64w_h(s64w_t('Datenschutz: Öffentlich erscheinen nur Anzeigename, verschleierter Standort, Provider, Anschlussart, Gerät und Stufe – nie IP-Adressen oder dein Account.',
		'Privacy: only display name, blurred location, provider, access type, device and level are public – never IP addresses or your account.')); ?></p>
<?php s64w_foot(); include("../footer.php"); ?>
