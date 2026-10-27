<?php
/**
 * IPv64.net – CDN64 (srv07/srv08.cdn64.de): Uebersicht aller Namen, Modus 3 (direkt zum Ziel) anlegen und
 * verwalten, Modus 1/2 (Tunnel, eingerichtet in Node64) anzeigen und ausschalten. Die Seite ruft serverseitig die
 * API v2 (/cdn64o) mit dem Account-Key des angemeldeten Nutzers auf - Webseite, API und Node nutzen so dieselben
 * Pruefungen. Planung: docs/CDN64-ONLINE.md (Abschnitt 8.6) im Node64-Repo.
 */
include("header.php");

const C64W_API = 'https://ipv64.net/api/v2';

/** API v2 aufrufen (als der angemeldete Nutzer). Rueckgabe: [HTTP-Code, data|Fehler]. */
function c64w_api(string $method, string $path, ?array $body = null): array {
	global $account;
	$ctx = stream_context_create(array('http' => array('method' => $method, 'timeout' => 30, 'ignore_errors' => true,
		'header' => "Authorization: Bearer " . $account['apikey'] . "\r\nContent-Type: application/json\r\nAccept: application/json\r\nUser-Agent: ipv64-web-cdn64\r\n",
		'content' => $body !== null ? json_encode($body) : '')));
	$raw = @file_get_contents(C64W_API . $path, false, $ctx);
	$code = 0;
	if(isset($http_response_header[0]) AND preg_match('#\s(\d{3})#', $http_response_header[0], $m)) { $code = (int)$m[1]; }
	$j = json_decode((string)$raw, true);
	if($code >= 200 AND $code < 300) { return array($code, $j['data'] ?? null); }
	return array($code, is_array($j) ? $j : array('detail' => 'ipv64 API not reachable'));
}

function c64w_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES); }

function c64w_bytes(int $b): string {
	foreach(array('B', 'KB', 'MB', 'GB', 'TB') as $i => $u) { if($b < 1024 ** ($i + 1) OR $u === 'TB') { return round($b / 1024 ** $i, $i ? 1 : 0) . ' ' . $u; } }
	return $b . ' B';
}

function c64w_alert(string $type, string $text): string { return '<div class="alert alert-' . $type . '" role="alert">' . c64w_h($text) . '</div>'; }

/** Fehlertext der API (detail) bzw. eigener Text. */
function c64w_err(array $e): string { return (string)($e['detail'] ?? 'Unknown error'); }
?>
<p></p>
<div class="container">
<?php
if($userid == "") {
	echo c64w_alert('info', 'Please log in to manage CDN64.');
	$node64_hint = "CDN64 without port forwarding: Node64 opens the tunnel from your home network – plus health checks, DNS filter and honeypot in the same container."; $node64_hint_btn = "More about Node64"; $node64_hint_href = "/node64.php?lang=en"; include("node64_hint.php");
	include("footer.php");
	exit;
}
if(empty($_SESSION['c64w_csrf'])) { $_SESSION['c64w_csrf'] = bin2hex(random_bytes(16)); }
$csrf = $_SESSION['c64w_csrf'];
$info = '';

// ---------------------------------------------------------------- Aktionen (POST mit Token)
if($_SERVER['REQUEST_METHOD'] === 'POST') {
	if(!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) {
		$info = c64w_alert('danger', 'Session expired, please try again.');
	} else {
		$act = (string)($_POST['action'] ?? '');
		$id = (int)($_POST['id'] ?? 0);
		$target = function() use ($accountclass): array {
			$t = array('source' => ($_POST['source'] ?? 'records') === 'fixed' ? 'fixed' : 'records', 'scheme' => ($_POST['scheme'] ?? 'https') === 'http' ? 'http' : 'https',
				'verify_tls' => !empty($_POST['verify_tls']), 'prefer_ipv6' => !empty($_POST['prefer_ipv6']), 'frontend' => max(0, min(3, (int)($_POST['frontend'] ?? 2))),
				'cache_mb' => !empty($_POST['cache']) ? (int)($accountclass['cdn_cache_size'] ?? 0) : 0, 'cache_minutes' => 10); // Cache an = Groesse der Klasse
			if($t['source'] === 'fixed') { $t['target'] = trim((string)($_POST['target'] ?? '')); }
			if(($p = (int)($_POST['port'] ?? 0)) > 0) { $t['port'] = $p; }
			return $t;
		};
		switch($act) {
			case 'add':
				[$code, $r] = c64w_api('POST', '/cdn64o/hosts', array_merge(array('fqdn' => strtolower(trim((string)($_POST['fqdn'] ?? ''))), 'mode' => 3, 'via' => 'web'), $target()));
				$info = $code === 201 ? c64w_alert('success', 'CDN64 is active for ' . $r['fqdn'] . ((int)($r['target']['frontend'] ?? 2) === 0 ? '. Add port mappings in the edit view.' : '. The servers fetch a certificate (about a minute), then the name is reachable via HTTPS.'))
					: c64w_alert('danger', c64w_err($r));
				break;
			case 'target':
				[$code, $r] = c64w_api('PUT', "/cdn64o/hosts/$id/target", $target());
				$info = $code === 200 ? c64w_alert('success', 'Target saved. The servers use it within seconds.') : c64w_alert('danger', c64w_err($r));
				break;
			case 'acl':
				$list = array_values(array_filter(array_map('trim', preg_split('/[\s,;]+/', (string)($_POST['list'] ?? '')))));
				$def = in_array($_POST['default'] ?? 'off', array('off', 'allow', 'deny'), true) ? $_POST['default'] : 'off';
				[$code, $r] = c64w_api('PUT', "/cdn64o/hosts/$id/acl", array('default' => $def, 'list' => $list));
				$info = $code === 200 ? c64w_alert('success', 'Allow/block list saved.') : c64w_alert('danger', c64w_err($r));
				break;
			case 'map':
				$tr = ($_POST['transport'] ?? 'tcp') === 'udp' ? 'udp' : 'tcp';
				$tp = (int)($_POST['target_port'] ?? 0);
				[$code, $r] = c64w_api('POST', "/cdn64o/hosts/$id/mappings", array('name' => trim((string)($_POST['name'] ?? '')), 'transport' => $tr, 'target_port' => $tp));
				$lp = 0;
				foreach($code === 201 ? $r : array() as $m) { if($m['transport'] === $tr AND (int)$m['target_port'] === $tp) { $lp = (int)$m['listen_port']; } }
				$info = $code === 201 ? c64w_alert('success', 'Port mapping added: port ' . $lp . ' (' . strtoupper($tr) . ') of the servers goes to port ' . $tp . ' of your target. The servers open it within seconds.')
					: c64w_alert('danger', c64w_err($r));
				break;
			case 'unmap':
				[$code, $r] = c64w_api('DELETE', "/cdn64o/hosts/$id/mappings/" . (int)($_POST['mid'] ?? 0));
				$info = $code === 204 ? c64w_alert('success', 'Port mapping removed.') : c64w_alert('danger', c64w_err($r));
				break;
			case 'pause':
			case 'resume':
				[$code, $r] = c64w_api('PATCH', "/cdn64o/hosts/$id", array('paused' => $act === 'pause'));
				$info = $code === 200 ? c64w_alert('success', $act === 'pause' ? 'CDN64 paused for ' . $r['fqdn'] . ': the servers accept nothing for this name any more and close open connections within seconds. DNS stays on the servers, so your address stays hidden.'
					: 'CDN64 resumed for ' . $r['fqdn'] . '.') : c64w_alert('danger', c64w_err($r));
				break;
			case 'off':
				[$code, $r] = c64w_api('DELETE', "/cdn64o/hosts/$id");
				$info = $code === 204 ? c64w_alert('success', 'CDN64 switched off. DNS points to your previous address again.') : c64w_alert('danger', c64w_err($r));
				break;
		}
	}
}

[$code, $ov] = c64w_api('GET', '/cdn64o');
if($code !== 200) {
	echo c64w_alert('danger', 'CDN64 is not available right now: ' . c64w_err($ov ?? array()));
	include("footer.php");
	exit;
}
$q = $ov['quota'];
$edit = isset($_GET['edit']) ? (int)$_GET['edit'] : 0;
$modeName = array(1 => 'Mode 1 · pass-through', 2 => 'Mode 2 · TLS on the servers', 3 => 'Mode 3 · direct to target');
$domains = array();
$st = $pdo->prepare("SELECT * FROM subdomains WHERE userid = :u AND deactivated = 0 ORDER BY id");
$st->execute(array('u' => $userid));
foreach($st->fetchAll() as $d) { $domains[] = $d['owndomain'] == 1 ? $d['maindomain'] : $d['subdomainname'] . '.' . $d['maindomain']; }
echo $info;
?>
<div class="row">
	<div class="col-12 pb-3">
		<div class="card">
			<div class="card-header p-2"><i class="fa-solid fa-cloud-arrow-up text-primary"></i> CDN64 <small class="text-muted">srv07.cdn64.de (Nuremberg) · srv08.cdn64.de (Falkenstein)</small></div>
			<div class="card-body p-3 small">
				<p class="mb-2">CDN64 makes your service reachable from the internet over IPv4 and IPv6 – also behind DS-Lite or without open ports. Built-in load balancing: visitors are spread across both servers (Nuremberg and Falkenstein) automatically, and if one server fails, the other one takes over.</p>
				<ul class="mb-2">
					<li><b>Mode 1 / Mode 2 (recommended):</b> <a href="https://github.com/ipv64net/node64" target="_blank" rel="noopener">Node64</a> opens an encrypted tunnel from your network to both servers – no open ports, your IP stays hidden. Mode 1 keeps TLS end-to-end, mode 2 terminates TLS on the servers (protection and HTTP/3 there). Set it up with one click in Node64 (<i>PROXY64 › Proxy-Hosts › CDN64</i>).</li>
					<li><b>Pause</b> (<i class="fa-solid fa-pause"></i>, all modes): the servers stop forwarding anything for the name at once, e.g. to protect yourself during an attack. DNS stays on the servers, so your own address is not revealed; settings and statistics stay.</li>
					<li><b>Mode 3 (here):</b> without Node64 – the servers connect to your target directly (your DynDNS address or a fixed target). The target has to be reachable from the internet.</li>
				</ul>
				<p class="mb-0 text-muted">Install Node64: <code>docker run -d --name node64 -p 8080:8080 -v node64-data:/data --restart unless-stopped ghcr.io/ipv64net/node64:latest</code></p>
			</div>
		</div>
	</div>
	<div class="col-12 pb-3">
		<div class="card"><div class="card-body p-2 small">
			<b>Quota:</b> <?php echo (int)$q['domains']['used']; ?> of <?php echo (int)$q['domains']['limit']; ?> CDN domains (old CDN included) ·
			traffic this month <?php echo c64w_bytes((int)($q['traffic_mb']['used'] * 1048576)); ?> of <?php echo c64w_bytes((int)$q['traffic_mb']['limit'] * 1048576); ?>
			<?php if((int)$q['bandwidth_mbit'] > 0) { echo ' · bandwidth up to ' . (int)$q['bandwidth_mbit'] . ' Mbit/s'; } ?>
			· cache up to <?php echo (int)($accountclass['cdn_cache_size'] ?? 0); ?> MB per name
			· port mappings <?php echo (int)($q['mappings']['used'] ?? 0); ?> of <?php echo (int)($q['mappings']['limit'] ?? 0); ?>
		</div></div>
	</div>
<?php
// ---------------------------------------------------------------- Bearbeiten (Modus 3: Ziel; alle: Liste)
$cur = null;
foreach($ov['hosts'] as $h) { if((int)$h['id'] === $edit) { $cur = $h; } }
if($cur !== null AND (int)$cur['mode'] === 3) { // Modus 1/2 verwaltet die Node
	$t = $cur['target'];
	?>
	<div class="col-12 col-lg-6 pb-3">
		<div class="card"><div class="card-header p-2"><i class="fa-solid fa-pen text-primary"></i> <?php echo c64w_h($cur['fqdn']); ?> <span class="badge badge-light"><?php echo c64w_h($modeName[$cur['mode']] ?? ''); ?></span>
			<a class="float-right small" href="cdn64">back</a></div>
		<div class="card-body p-3 small">
		<?php if($t !== null) { ?>
			<form method="post">
				<input type="hidden" name="csrf" value="<?php echo $csrf; ?>"><input type="hidden" name="action" value="target"><input type="hidden" name="id" value="<?php echo (int)$cur['id']; ?>">
				<?php c64w_target_fields($t); ?>
				<button class="btn btn-sm btn-primary" type="submit">Save target</button>
			</form>
		<?php } ?>
		</div></div>
	</div>
	<div class="col-12 col-lg-6 pb-3">
		<div class="card"><div class="card-header p-2"><i class="fa-solid fa-shield-halved text-warning"></i> Allow / block list</div>
		<div class="card-body p-3 small">
			<form method="post">
				<input type="hidden" name="csrf" value="<?php echo $csrf; ?>"><input type="hidden" name="action" value="acl"><input type="hidden" name="id" value="<?php echo (int)$cur['id']; ?>">
				<div class="form-group mb-2"><label class="mb-1">Default</label>
					<select name="default" class="form-control form-control-sm">
						<option value="off" <?php echo $cur['acl']['default'] === 'off' ? 'selected' : ''; ?>>Off – everyone</option>
						<option value="allow" <?php echo $cur['acl']['default'] === 'allow' ? 'selected' : ''; ?>>Allow all – block the addresses below</option>
						<option value="deny" <?php echo $cur['acl']['default'] === 'deny' ? 'selected' : ''; ?>>Deny all – allow only the addresses below</option>
					</select></div>
				<div class="form-group mb-2"><label class="mb-1">IP addresses or networks (one per line, IPv4/IPv6)</label>
					<textarea name="list" rows="5" class="form-control form-control-sm text-monospace" placeholder="177.43.6.1&#10;2001:db8:1234::/48"><?php echo c64w_h(implode("\n", $cur['acl']['list'])); ?></textarea></div>
				<button class="btn btn-sm btn-primary" type="submit">Save list</button>
			</form>
		</div></div>
	</div>
	<div class="col-12 pb-3">
		<div class="card"><div class="card-header p-2"><i class="fa-solid fa-arrow-right-arrow-left text-info"></i> Port mappings (TCP/UDP)</div>
		<div class="card-body p-0 small">
			<form method="post" id="c64map"><input type="hidden" name="csrf" value="<?php echo $csrf; ?>"><input type="hidden" name="action" value="map"><input type="hidden" name="id" value="<?php echo (int)$cur['id']; ?>"></form>
			<table class="table table-sm mb-0">
				<thead><tr><th>Service</th><th>Reach it at</th><th>Port of your target</th><th></th></tr></thead>
				<tbody>
				<?php foreach($cur['mappings'] ?? array() as $m) {
					echo '<tr><td>' . c64w_h($m['name']) . '</td><td class="text-monospace">' . c64w_h($cur['fqdn']) . ':' . (int)$m['listen_port'] . '</td>';
					echo '<td><span class="badge badge-dark">' . (int)$m['target_port'] . '</span> <span class="badge ' . ($m['transport'] === 'udp' ? 'badge-primary' : 'badge-info') . '">' . strtoupper(c64w_h($m['transport'])) . '</span></td>';
					echo '<td class="text-right"><form method="post" class="d-inline" onsubmit="return confirm(\'Remove this port mapping?\')"><input type="hidden" name="csrf" value="' . $csrf . '"><input type="hidden" name="action" value="unmap"><input type="hidden" name="id" value="' . (int)$cur['id'] . '"><input type="hidden" name="mid" value="' . (int)$m['id'] . '"><button class="btn btn-sm btn-outline-danger py-0" title="Remove"><i class="fa-solid fa-trash"></i></button></form></td></tr>';
				} ?>
				<tr>
					<td><input type="text" name="name" form="c64map" maxlength="64" class="form-control form-control-sm" placeholder="e.g. WireGuard"></td>
					<td class="text-muted align-middle">assigned automatically (50000–62000)</td>
					<td><div class="input-group input-group-sm"><input type="number" min="1" max="65535" name="target_port" form="c64map" class="form-control" placeholder="51820" required>
						<select name="transport" form="c64map" class="custom-select"><option value="tcp">TCP</option><option value="udp">UDP</option></select></div></td>
					<td class="text-right"><button class="btn btn-sm btn-primary" type="submit" form="c64map">Add</button></td>
				</tr>
				</tbody>
			</table>
			<p class="text-muted m-2">Raw TCP/UDP to the same target as the website (e.g. WireGuard, SSH, game servers). If the port of your target is free on the servers, you get the same one. The allow/block list applies here too; the target sees the address of the servers, not the visitor's.</p>
		</div></div>
	</div>
<?php
}

/** Felder fuer das Ziel (Modus 3). */
function c64w_target_fields(?array $t): void {
	global $accountclass;
	static $fn = 0; $fn++; // eindeutige IDs, falls Bearbeiten und Hinzufuegen auf einer Seite stehen
	$maxCache = (int)($accountclass['cdn_cache_size'] ?? 0);
	$t = $t ?? array('source' => 'records', 'target' => '', 'port' => 443, 'scheme' => 'https', 'verify_tls' => false, 'prefer_ipv6' => true, 'frontend' => 2, 'cache_mb' => 0, 'cache_minutes' => 10);
	?>
	<div class="form-group mb-2"><label class="mb-1">Target</label>
		<div class="custom-control custom-radio"><input type="radio" id="src_r<?php echo $fn; ?>" name="source" value="records" class="custom-control-input" <?php echo $t['source'] === 'records' ? 'checked' : ''; ?> onchange="var f=this.closest('.form-group').querySelector('input[name=target]');f.disabled=this.value!=='fixed';if(!f.disabled){f.focus();}">
			<label class="custom-control-label" for="src_r<?php echo $fn; ?>">The current A/AAAA records of the name (DynDNS keeps them up to date)</label></div>
		<div class="custom-control custom-radio"><input type="radio" id="src_f<?php echo $fn; ?>" name="source" value="fixed" class="custom-control-input" <?php echo $t['source'] === 'fixed' ? 'checked' : ''; ?> onchange="var f=this.closest('.form-group').querySelector('input[name=target]');f.disabled=this.value!=='fixed';if(!f.disabled){f.focus();}">
			<label class="custom-control-label" for="src_f<?php echo $fn; ?>">Fixed: public IP address or host name</label></div>
		<input type="text" name="target" class="form-control form-control-sm mt-1" placeholder="2001:db8::10 or server.example.org" value="<?php echo c64w_h($t['target'] ?? ''); ?>"<?php echo $t['source'] === 'fixed' ? '' : ' disabled'; ?>><?php /* nur bei „Fixed“ frei; gesperrt wird es nicht gesendet und nur bei fixed gelesen */ ?>
		<?php if(!empty($t['addrs'])) { echo '<small class="text-muted">Currently: ' . c64w_h(implode(', ', $t['addrs'])) . '</small>'; } ?>
	</div>
	<div class="form-row">
		<div class="form-group col-6 mb-2"><label class="mb-1">Backend</label>
			<select name="scheme" class="form-control form-control-sm"><option value="https" <?php echo $t['scheme'] === 'https' ? 'selected' : ''; ?>>HTTPS</option><option value="http" <?php echo $t['scheme'] === 'http' ? 'selected' : ''; ?>>HTTP</option></select></div>
		<div class="form-group col-6 mb-2"><label class="mb-1">Port</label><input type="number" min="1" max="65535" name="port" class="form-control form-control-sm" value="<?php echo (int)$t['port']; ?>"></div>
	</div>
	<div class="form-group mb-2"><label class="mb-1">Frontend</label>
		<select name="frontend" class="form-control form-control-sm">
			<option value="0" <?php echo (int)$t['frontend'] === 0 ? 'selected' : ''; ?>>Off: no website, port mappings only</option>
			<option value="1" <?php echo (int)$t['frontend'] === 1 ? 'selected' : ''; ?>>Level 1: HTTP (port 80) only</option>
			<option value="2" <?php echo (int)$t['frontend'] === 2 ? 'selected' : ''; ?>>Level 2: HTTPS, port 80 redirects to HTTPS</option>
			<option value="3" <?php echo (int)$t['frontend'] === 3 ? 'selected' : ''; ?>>Level 3: HTTPS (port 443) only</option>
		</select></div>
	<div class="custom-control custom-checkbox mb-1"><input type="checkbox" class="custom-control-input" id="ca" name="cache" value="1" <?php echo (int)$t['cache_mb'] > 0 ? 'checked' : ''; ?> <?php echo $maxCache > 0 ? '' : 'disabled'; ?>><label class="custom-control-label" for="ca">Cache <span class="text-muted">(up to <?php echo $maxCache; ?> MB, follows the Cache-Control headers of the target)</span></label></div>
	<div class="custom-control custom-checkbox mb-1"><input type="checkbox" class="custom-control-input" id="vt" name="verify_tls" value="1" <?php echo !empty($t['verify_tls']) ? 'checked' : ''; ?>><label class="custom-control-label" for="vt">Verify the target's certificate</label></div>
	<div class="custom-control custom-checkbox mb-2"><input type="checkbox" class="custom-control-input" id="p6" name="prefer_ipv6" value="1" <?php echo !isset($t['prefer_ipv6']) || $t['prefer_ipv6'] ? 'checked' : ''; ?>><label class="custom-control-label" for="p6">Prefer IPv6</label></div>
	<p class="text-muted mb-2">WebSockets work automatically. Visitors' IP arrives in <code>X-Forwarded-For</code> / <code>X-Real-IP</code>.</p>
	<?php
}
?>
	<?php // Node64 nicht mehr verbunden: ab 48 h Hinweis, nach 14 Tagen raeumt bots/cdn64_orphans.php Tunnel und Namen ab
	$c64wOld = array();
	foreach((array)($ov['tunnels'] ?? array()) as $tn) {
		$since = strtotime((string)($tn['last_seen'] ?: $tn['created_at']));
		if($since AND $since < time() - 48 * 3600) { $c64wOld[$tn['id']] = array('name' => $tn['name'] ?: $tn['id'], 'since' => $since, 'hosts' => array()); }
	}
	foreach((array)$ov['hosts'] as $h) { foreach((array)$h['tunnels'] as $tid) { if(isset($c64wOld[$tid])) { $c64wOld[$tid]['hosts'][] = $h['fqdn']; } } }
	foreach($c64wOld as $o) {
		echo '<div class="col-12"><div class="alert alert-warning small"><i class="fa-solid fa-plug-circle-xmark"></i> <b>Node64 “' . c64w_h($o['name']) . '” has not been connected since ' . date('d M Y', $o['since']) . '.</b> '
			. 'If Node64 does not report to ipv64.net again by then, the tunnel' . ($o['hosts'] ? ' and its names (' . c64w_h(implode(', ', $o['hosts'])) . ')' : '') . ' will be removed automatically on <b>' . date('d M Y', $o['since'] + 14 * 86400) . '</b>'
			. ($o['hosts'] ? ' – DNS then points to the previous addresses again' : '') . '. Start Node64 again to keep ' . ($o['hosts'] ? 'them, or switch the names off below.' : 'it.') . '</div></div>';
	} ?>
	<div class="col-12 pb-3">
		<div class="card"><div class="card-header p-2"><i class="fa-solid fa-list text-primary"></i> Names in CDN64</div>
		<div class="card-body p-0">
			<table class="table table-sm mb-0 small">
				<thead><tr><th>Name</th><th>Mode</th><th>Target / tunnel</th><th>Status</th><th class="text-right">This month</th><th></th></tr></thead>
				<tbody>
				<?php if(empty($ov['hosts'])) { echo '<tr><td colspan="6" class="text-muted p-3">No names yet. Add one with mode 3 below or switch one on in Node64.</td></tr>'; }
				foreach($ov['hosts'] as $h) {
					$tm = $h['traffic_month'];
					$br = fn($a) => str_contains($a, ':') ? '[' . $a . ']' : $a; // IPv6 in Klammern
					$tgt = (int)$h['mode'] === 3 && $h['target'] ? ($h['target']['scheme'] . '://' . ($h['target']['target'] ? $br($h['target']['target']) : implode(', ', array_map($br, (array)$h['target']['addrs']))) . ':' . $h['target']['port'])
						: 'Node64 tunnel ' . implode(', ', $h['tunnels']);
					if(!empty($h['mappings'])) { $tgt .= ' · ' . count($h['mappings']) . ' port' . (count($h['mappings']) > 1 ? 's' : ''); }
					$st = $h['status'] === 'active' ? '<span class="badge badge-success">active</span>' : ($h['status'] === 'blocked' ? '<span class="badge badge-danger">blocked: ' . c64w_h($h['blocked_reason']) . '</span>' : '<span class="badge badge-warning">' . c64w_h($h['status']) . '</span>');
					if(!empty($h['paused'])) { $st = '<span class="badge badge-secondary" title="Paused since ' . c64w_h($h['paused_at'] ?? '') . '"><i class="fa-solid fa-pause"></i> paused</span>'; }
					if($h['acl']['default'] !== 'off') { $st .= ' <span class="badge badge-info">list</span>'; }
					// Schutz (30 Tage): nur 4 Zahlen, Details in Node64 (PROXY64 › CDN64 Statistik)
					$pr = $h['protection'] ?? null; $nf = fn($n) => number_format((int)$n, 0, ',', '.');
					$prot = $pr ? '<br><small class="text-muted text-nowrap"><i class="fa-solid fa-shield-halved"></i> '
						. '<span title="Blocked before reaching your service: blocklists, allow/block list, overload, WAF, attack tools (JA4)">' . $nf($pr['blocked_list'] + $pr['blocked_acl'] + $pr['blocked_flood'] + $pr['blocked_limit'] + $pr['blocked_waf'] + $pr['blocked_ja4']) . ' blocked</span>'
						. ' · <span title="Blocked IP addresses (IPv6 per /64)">' . $nf($pr['blocked_ips']) . ' IPs</span>'
						. ' · <span title="Overload stopped: connection and request limits">' . $nf($pr['blocked_flood'] + $pr['blocked_limit']) . ' overload</span>'
						. ' · <span title="Connections via CDN64 – your own address stayed hidden (of them via IPv4)">' . $nf($pr['conns']) . ' hidden (' . $nf($pr['conns_v4']) . ' IPv4)</span></small>' : '';
					echo '<tr' . (!empty($h['paused']) ? ' class="table-warning"' : '') . '><td class="text-monospace">' . c64w_h($h['fqdn']) . $prot . '</td><td>' . c64w_h($modeName[$h['mode']] ?? $h['mode']) . '</td><td class="text-monospace text-break">' . c64w_h($tgt) . '</td><td>' . $st . '</td>';
					echo '<td class="text-right text-nowrap">' . c64w_bytes($tm['bytes_in'] + $tm['bytes_out']) . ($tm['requests'] ? ' · ' . number_format($tm['requests'], 0, ',', '.') . ' req.' : '') . ($tm['rejected'] ? ' · <span class="text-danger">' . (int)$tm['rejected'] . ' rejected</span>' : '') . '</td>';
					// Modus 1/2: verwaltet in Node64, hier nur ausschalten (Notfall, ohne Zugriff auf die Node)
					echo (int)$h['mode'] !== 3 ? '<td class="text-right text-nowrap"><span class="text-muted mr-1" title="Target, mode, certificate and access lists are managed in Node64. Switching off here also removes it there."><i class="fa-solid fa-lock"></i> Node64</span>'
						: '<td class="text-right text-nowrap"><a class="btn btn-sm btn-outline-primary py-0" href="cdn64?edit=' . (int)$h['id'] . '" title="Edit"><i class="fa-solid fa-pen"></i></a> ';
					// Pause (alle Modi): Server nehmen nichts mehr an, DNS bleibt auf den Servern
					$pa = !empty($h['paused']) ? 'resume' : 'pause';
					echo '<form method="post" class="d-inline"' . ($pa === 'pause' ? ' onsubmit="return confirm(\'Pause CDN64 for ' . c64w_h($h['fqdn']) . '? The servers accept nothing for this name until you resume it. DNS stays on the servers.\')"' : '') . '><input type="hidden" name="csrf" value="' . $csrf . '"><input type="hidden" name="action" value="' . $pa . '"><input type="hidden" name="id" value="' . (int)$h['id'] . '"><button class="btn btn-sm btn-outline-' . ($pa === 'pause' ? 'warning' : 'success') . ' py-0 mr-1" title="' . ($pa === 'pause' ? 'Pause' : 'Resume') . '"><i class="fa-solid fa-' . ($pa === 'pause' ? 'pause' : 'play') . '"></i></button></form>';
					echo '<form method="post" class="d-inline" onsubmit="return confirm(\'Switch off CDN64 for ' . c64w_h($h['fqdn']) . '? DNS points to the previous address again.\')"><input type="hidden" name="csrf" value="' . $csrf . '"><input type="hidden" name="action" value="off"><input type="hidden" name="id" value="' . (int)$h['id'] . '"><button class="btn btn-sm btn-outline-danger py-0" title="Switch off"><i class="fa-solid fa-power-off"></i></button></form></td></tr>';
				} ?>
				</tbody>
			</table>
			<?php if(!empty($ov['hosts'])) { echo '<p class="text-muted small m-2"><i class="fa-solid fa-shield-halved"></i> Protection in the last 30 days. Details in Node64 under <i>PROXY64 › CDN64 statistics</i>.</p>'; } ?>
		</div></div>
	</div>
	<div class="col-12 col-lg-6 pb-3">
		<div class="card"><div class="card-header p-2"><i class="fa-solid fa-plus text-success"></i> Add a name (mode 3, direct to target)</div>
		<div class="card-body p-3 small">
			<form method="post">
				<input type="hidden" name="csrf" value="<?php echo $csrf; ?>"><input type="hidden" name="action" value="add">
				<div class="form-group mb-2"><label class="mb-1">Name (a domain of your account or a name below it)</label>
					<input type="text" name="fqdn" list="c64w_domains" class="form-control form-control-sm" placeholder="www.example.any64.de" required>
					<datalist id="c64w_domains"><?php foreach($domains as $d) { echo '<option value="' . c64w_h($d) . '">'; } ?></datalist></div>
				<?php c64w_target_fields(null); ?>
				<button class="btn btn-sm btn-success" type="submit">Switch on</button>
			</form>
		</div></div>
	</div>
	<div class="col-12 col-lg-6 pb-3">
		<div class="card"><div class="card-header p-2"><i class="fa-solid fa-network-wired text-primary"></i> Node64 tunnels</div>
		<div class="card-body p-3 small">
			<?php // Liste der Nodes nur noch in nodes.php; hier nur die Zahl
			$tunOn = count(array_filter((array)$ov['tunnels'], fn($tn) => !empty($tn['last_seen']) && strtotime($tn['last_seen']) >= time() - 300));
			echo empty($ov['tunnels']) ? '<p class="text-muted mb-2">No Node64 connected yet.</p>'
				: '<p class="mb-2"><b>' . count($ov['tunnels']) . ' tunnel' . (count($ov['tunnels']) === 1 ? '' : 's') . '</b>, ' . $tunOn . ' connected – details in the node overview.</p>'; ?>
			<a class="btn btn-sm btn-outline-primary" href="/nodes.php"><i class="fa-solid fa-server"></i> Node overview</a>
		</div></div>
	</div>
</div>
<?php $node64_hint = "Modes 1 and 2 run through Node64 – the homelab container by ipv64.net with PROXY64, health checks, DNS filter and honeypot."; $node64_hint_btn = "More about Node64"; $node64_hint_href = "/node64.php?lang=en"; include("node64_hint.php"); ?>
</div>
<?php include("footer.php"); ?>
