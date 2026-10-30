<?php
/** Healthchecks 2.0 – Check anlegen/bearbeiten (Formular wie in der Node, plus Messstellen und Bewertung). */
ob_start(); // header.php gibt HTML aus; hc2_redirect()/hc2_json() verwerfen es
include("../header.php");
require_once(__DIR__ . '/hc2_lib.php');
hc2_require_login();
$uid = (int)$userid;
$nodes = hc2_nodes($uid); $acc = hc2_account($uid); $locs = hc2_locations(); $channels = hc2_channels($uid);
$token = (string)($_GET['token'] ?? $_POST['token'] ?? '');
$old = $token !== '' ? hc2_check($uid, $token) : null;
if ($token !== '' && !$old) { echo '<div class="container"><div class="alert alert-danger mt-3">Check nicht gefunden.</div></div>'; include("../footer.php"); exit; }
$errors = array();
$cloneOf = isset($_GET['clone']) ? hc2_check($uid, (string)$_GET['clone']) : null;

// Formularwerte (Standard / aus Check / aus POST)
$f = array('type' => 'http', 'name' => '', 'target' => '', 'interval_sec' => 60, 'retry_interval_sec' => 20, 'retries' => 1, 'connect_timeout' => 5, 'total_timeout' => 10, 'stabilize' => 3, 'ip_mode' => 'auto',
	'tags' => '', 'group_name' => '', 'description' => '', 'parent_token' => '', 'channels' => array(), 'repeat_minutes' => 0, 'notify_down' => 1, 'notify_up' => 1, 'notify_degraded' => 0, 'critical' => 0, 'invert' => 0, 'paused' => 0,
	'execution' => 'online', 'node_id' => (string)($_GET['node'] ?? ''), 'nodes' => isset($_GET['node']) ? array((string)$_GET['node']) : array_slice(array_keys($nodes), 0, 1), 'locations' => array_slice(array_keys($locs), 0, $acc['hc_locations']), 'policy' => 'all',
	'method' => 'GET', 'accept_status' => '200-299', 'follow_redirects' => 1, 'max_redirects' => 5, 'keyword' => '', 'keyword_absent' => 0, 'basic_user' => '', 'basic_password' => '', 'headers' => '', 'body' => '', 'insecure_tls' => 0, 'cert_min_days' => 14,
	'count' => 3, 'max_loss_percent' => 0, 'max_latency_ms' => 0, 'port' => '', 'send' => '', 'expect' => '', 'tls' => 0, 'min_days' => 14, 'server_name' => '', 'skip_chain' => 0, 'skip_hostname' => 0, 'period_seconds' => 3600, 'grace_seconds' => 600, 'docker_host' => '', 'docker_system' => '', 'system_custom' => 0,
	'json_rules' => '', 'json_any' => 0, 'dns_record_type' => 'A', 'dns_resolver' => 'system', 'dns_server' => '', 'dns_expect' => 'any', 'dns_values' => '', 'dns_dnssec' => 0, 'dns_min_ttl' => 0,
	'whois_source' => 'auto', 'whois_min_days' => 14, 'whois_contains' => '');
if ($f['node_id'] !== '' && isset($nodes[$f['node_id']])) { $f['execution'] = 'local'; }
$src = $old ?: $cloneOf;
if ($src) {
	foreach (array('type','name','target','interval_sec','retry_interval_sec','retries','stabilize','ip_mode','tags','group_name','description','repeat_minutes','notify_down','notify_up','notify_degraded','critical','invert','paused','execution','policy') as $k) { $f[$k] = $src[$k]; }
	$f['connect_timeout'] = $src['connect_timeout_ms'] / 1000; $f['total_timeout'] = $src['total_timeout_ms'] / 1000;
	$f['parent_token'] = (string)$src['parent_token']; $f['channels'] = hc2_check_channels($src); $f['node_id'] = (string)$src['node_id']; $f['nodes'] = hc2_check_nodes($src) ?: array_slice(array_keys($nodes), 0, 1); $f['locations'] = array_filter(explode(',', $src['locations']));
	$p = hc2_check_params($src);
	if (!isset($p['cert_min_days'])) { $f['cert_min_days'] = 0; }
	foreach ($p as $k => $v) {
		if ($k === 'headers' && is_array($v)) { $lines = array(); foreach ($v as $hk => $hv) { $lines[] = $hk . ': ' . $hv; } $f['headers'] = implode("\n", $lines); }
		elseif ($k === 'follow_redirects') { $f['follow_redirects'] = $v ? 1 : 0; }
		elseif ($k === 'expect' && $src['type'] === 'port') { $f['expect'] = $v; }
		elseif ($k === 'host' && $src['type'] === 'docker') { $f['docker_host'] = $v; }
		elseif ($k === 'system' && $src['type'] === 'docker') { $f['docker_system'] = $v; }
		elseif ($k === 'json_rules' && is_array($v)) { $f['json_rules'] = hc2_json_rules_text($v); }
		elseif ($src['type'] === 'whois' && in_array($k, array('source', 'min_days', 'contains'), true)) { $f['whois_' . $k] = $k === 'contains' && is_array($v) ? implode("\n", $v) : $v; }
		elseif ($src['type'] === 'dns' && in_array($k, array('record_type', 'resolver', 'server', 'expect', 'values', 'dnssec', 'min_ttl'), true)) { $f['dns_' . ($k === 'min_ttl' ? 'min_ttl' : $k)] = $k === 'values' ? implode("\n", (array)$v) : (is_bool($v) ? ($v ? 1 : 0) : $v); }
		else { $f[$k] = is_bool($v) ? ($v ? 1 : 0) : $v; }
	}
	if ($cloneOf && !$old) { $f['name'] .= ' (Kopie)'; }
}
if (hc2_is_post()) {
	if (!hc2_csrf_ok()) { $errors[] = 'Ungültige Anfrage, bitte Seite neu laden.'; }
	foreach ($f as $k => $v) { if (array_key_exists($k, $_POST)) { $f[$k] = $_POST[$k]; } elseif (in_array($k, array('notify_down','notify_up','notify_degraded','critical','invert','paused','follow_redirects','keyword_absent','insecure_tls','tls','skip_chain','skip_hostname','json_any','dns_dnssec'), true)) { $f[$k] = 0; } }
	$f['channels'] = (array)($_POST['channels'] ?? array()); $f['locations'] = (array)($_POST['locations'] ?? array()); $f['nodes'] = (array)($_POST['nodes'] ?? array());
	if (!$errors) {
		$v = hc2_validate_check(array_merge($f, array('follow_redirects_present' => 1)), $uid, $old);
		$errors = array_merge($errors, $v['errors']);
		if (!$errors) {
			try {
				$row = $v['row'];
				if ($old) {
					// Ausfuehrungsort geaendert? Dann erst speichern (ohne Ort), danach Umhaengen mit Testlauf.
					$newNodes = array_filter(explode(',', (string)$row['nodes']));
					$moved = $row['execution'] !== $old['execution'] || ($row['execution'] !== 'online' && !hc2_same_list($newNodes, hc2_check_nodes($old))) || ($row['execution'] !== 'local' && $row['locations'] !== $old['locations']);
					$target = $row['execution']; $locSel = $row['locations'];
					if ($moved) { $row['execution'] = $old['execution']; $row['node_id'] = $old['node_id']; $row['nodes'] = (string)$old['nodes']; $row['locations'] = $old['locations']; }
					hc2_update_check($uid, $old['token'], $row);
					if ($moved) { hc2_redirect(HC2_BASE . '/move.php?tokens=' . $old['token'] . '&to=' . $target . '&nodes=' . urlencode(implode(',', $newNodes)) . '&locations=' . urlencode($locSel) . '&auto=1&_csrf=' . urlencode((string)($_SESSION['hc2_csrf'] ?? ''))); }
					hc2_flash('success', 'Check gespeichert.');
					hc2_redirect(HC2_BASE . '/check.php?token=' . $old['token']);
				}
				$t = hc2_insert_check($uid, $row);
				hc2_flash('success', 'Check angelegt.' . ($row['execution'] !== 'online' ? ' Die Node übernimmt ihn, sobald sie verbunden ist.' : ''));
				hc2_redirect(HC2_BASE . '/check.php?token=' . $t);
			} catch (Throwable $e) { error_log('hc2 edit: ' . $e->getMessage()); $errors[] = 'Speichern fehlgeschlagen.'; }
		}
	}
}
$chk = function($k) use ($f) { return !empty($f[$k]) && $f[$k] !== '0' ? ' checked' : ''; };
$sel = function($k, $v) use ($f) { return (string)$f[$k] === (string)$v ? ' selected' : ''; };
$val = function($k) use ($f) { return hc2_h($f[$k] ?? ''); };
$others = array_filter(hc2_checks($uid), function($c) use ($old) { return !$old || $c['token'] !== $old['token']; });
?>
<p></p>
<div class="container">
	<?php echo hc2_subnav('index'); ?>
	<?php foreach ($errors as $e) { echo '<div class="alert alert-danger">' . hc2_h($e) . '</div>'; } ?>
	<form method="post" id="hcform">
		<?php echo hc2_csrf_field(); if ($old) { echo '<input type="hidden" name="token" value="' . hc2_h($old['token']) . '">'; } ?>
		<div class="row">
			<div class="col-lg-7">
				<div class="card shadow-sm mb-3">
					<div class="card-header p-2"><i class="fa-solid fa-heart-pulse"></i> <?php echo $old ? 'Check bearbeiten' : 'Neuer Check'; ?></div>
					<div class="card-body">
						<div class="form-row">
							<div class="form-group col-md-4"><label>Typ</label><select class="custom-select" name="type" id="type"><?php foreach (hc2_types() as $k => $v) { echo '<option value="' . $k . '"' . $sel('type', $k) . '>' . hc2_h($v) . '</option>'; } ?></select></div>
							<div class="form-group col-md-8"><label>Name</label><input class="form-control" name="name" value="<?php echo $val('name'); ?>" maxlength="200" required></div>
						</div>
						<div class="form-group" data-not-type="push"><label>Ziel</label><input class="form-control" name="target" id="target" value="<?php echo $val('target'); ?>" maxlength="500" placeholder="https://example.com/  ·  host"><small class="form-text text-muted" id="target_hint"></small></div>
						<div class="alert alert-info small" data-type="push">Ein Push-Check wartet auf regelmäßige Meldungen deines Systems (Cronjob, Backup, Skript). Die Push-URL steht nach dem Anlegen auf der Detailseite.</div>
						<!-- HTTP / Keyword / JSON -->
						<div data-type="http keyword json">
							<div class="form-row">
								<div class="form-group col-md-3"><label>Methode</label><select class="custom-select" name="method"><?php foreach (array('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS') as $m) { echo '<option' . $sel('method', $m) . '>' . $m . '</option>'; } ?></select></div>
								<div class="form-group col-md-4"><label>Erlaubte Statuscodes</label><input class="form-control" name="accept_status" value="<?php echo $val('accept_status'); ?>" placeholder="200-299,301"></div>
								<div class="form-group col-md-5"><label>Weiterleitungen</label><div class="input-group"><input class="form-control" type="number" name="max_redirects" value="<?php echo $val('max_redirects'); ?>" min="0" max="20"><div class="input-group-append"><div class="input-group-text"><input type="checkbox" name="follow_redirects" value="1"<?php echo $chk('follow_redirects'); ?>>&nbsp;folgen</div></div></div></div>
							</div>
							<div class="form-row" data-type="keyword">
								<div class="form-group col-md-8"><label>Schlüsselwort</label><input class="form-control" name="keyword" value="<?php echo $val('keyword'); ?>"></div>
								<div class="form-group col-md-4"><label>&nbsp;</label><div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="keyword_absent" name="keyword_absent" value="1"<?php echo $chk('keyword_absent'); ?>><label class="custom-control-label" for="keyword_absent">darf NICHT vorkommen</label></div></div>
							</div>
							<div class="form-row" data-type="json">
								<div class="form-group col-12"><label>JSON-Bedingungen (eine je Zeile)</label><textarea class="form-control text-monospace" name="json_rules" rows="4" placeholder="status == ok&#10;queue &lt; 100&#10;version exists"><?php echo $val('json_rules'); ?></textarea>
									<small class="form-text text-muted">Pfad Vergleich Wert, z. B. <code>status == ok</code>, <code>queue &lt; 100</code>, <code>items[0].up == true</code>, <code>tags contains web</code>, <code>version exists</code>, <code>name ~ ^web-[0-9]+$</code>. Vergleiche: == != &lt; &lt;= &gt; &gt;= contains !contains ~ (Regex) exists !exists. Der Wert der ersten Bedingung steht in der Meldung.</small>
									<div class="custom-control custom-checkbox mt-1"><input class="custom-control-input" type="checkbox" id="json_any" name="json_any" value="1"<?php echo $chk('json_any'); ?>><label class="custom-control-label" for="json_any">Eine erfüllte Bedingung genügt (sonst müssen alle erfüllt sein)</label></div></div>
							</div>
							<a class="small" data-toggle="collapse" href="#httpmore">Erweitert: Auth, Header, Body, TLS</a>
							<div class="collapse<?php echo ($f['basic_user'] || $f['headers'] || $f['body'] || $f['insecure_tls']) ? ' show' : ''; ?> mt-2" id="httpmore">
								<div class="form-row">
									<div class="form-group col-md-6"><label>Basic-Auth Benutzer</label><input class="form-control" name="basic_user" value="<?php echo $val('basic_user'); ?>" autocomplete="off"></div>
									<div class="form-group col-md-6"><label>Basic-Auth Passwort</label><input class="form-control" type="password" name="basic_password" value="<?php echo $val('basic_password'); ?>" autocomplete="new-password"></div>
									<div class="form-group col-md-6"><label>Header (eine je Zeile: Name: Wert)</label><textarea class="form-control" name="headers" rows="3"><?php echo $val('headers'); ?></textarea></div>
									<div class="form-group col-md-6"><label>Body (POST/PUT)</label><textarea class="form-control" name="body" rows="3"><?php echo $val('body'); ?></textarea></div>
								</div>
								<div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="insecure_tls" name="insecure_tls" value="1"<?php echo $chk('insecure_tls'); ?>><label class="custom-control-label" for="insecure_tls">Zertifikatsfehler ignorieren</label></div>
							</div>
							<div class="form-row mt-2"><div class="form-group col-md-6"><label><i class="fa-solid fa-lock text-success"></i> Zertifikat: warnen unter</label><div class="input-group"><input class="form-control" type="number" name="cert_min_days" min="0" max="3650" value="<?php echo $val('cert_min_days'); ?>"><div class="input-group-append"><span class="input-group-text">Tagen</span></div></div><small class="form-text text-muted">HTTPS: gestört melden, wenn das Zertifikat in weniger Tagen abläuft (0 = aus). Das Ablaufdatum wird immer mitgelesen.</small></div></div>
						</div>
						<!-- DNS -->
						<div data-type="dns">
							<div class="form-row">
								<div class="form-group col-md-3"><label>Eintragstyp</label><select class="custom-select" name="dns_record_type"><?php foreach (hc2_dns_types() as $t) { echo '<option' . $sel('dns_record_type', $t) . '>' . $t . '</option>'; } ?></select></div>
								<div class="form-group col-md-5"><label>Fragen über</label><select class="custom-select" name="dns_resolver" id="dns_resolver"><?php foreach (hc2_dns_resolvers() as $k => $v) { echo '<option value="' . $k . '"' . $sel('dns_resolver', $k) . '>' . hc2_h($v) . '</option>'; } ?></select></div>
								<div class="form-group col-md-4" id="dns_server_box"><label>DNS-Server</label><input class="form-control text-monospace" name="dns_server" value="<?php echo $val('dns_server'); ?>" placeholder="1.1.1.1"></div>
							</div>
							<div class="form-row">
								<div class="form-group col-md-6"><label>Erwartung</label><select class="custom-select" name="dns_expect"><?php foreach (hc2_dns_expects() as $k => $v) { echo '<option value="' . $k . '"' . $sel('dns_expect', $k) . '>' . hc2_h($v) . '</option>'; } ?></select></div>
								<div class="form-group col-md-6"><label>Mindest-TTL (s, 0 = egal)</label><input class="form-control" type="number" name="dns_min_ttl" value="<?php echo $val('dns_min_ttl'); ?>" min="0" max="604800"></div>
								<div class="form-group col-12"><label>Werte (einer je Zeile)</label><textarea class="form-control text-monospace" name="dns_values" rows="2" placeholder="203.0.113.10"><?php echo $val('dns_values'); ?></textarea>
									<small class="form-text text-muted">So wie im Eintrag: IP, Name, „10 mail.example.org“ (MX), Text (TXT). Bei Regex nur das Muster. Groß-/Kleinschreibung und Punkt am Ende spielen keine Rolle. Zuständige Nameserver umgehen Caches und zeigen Änderungen sofort.</small></div>
								<div class="form-group col-12"><div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="dns_dnssec" name="dns_dnssec" value="1"<?php echo $chk('dns_dnssec'); ?>><label class="custom-control-label" for="dns_dnssec">Antwort muss per DNSSEC validiert sein</label></div></div>
							</div>
						</div>
						<!-- ICMP -->
						<div class="form-row" data-type="icmp">
							<div class="form-group col-md-4"><label>Pakete</label><input class="form-control" type="number" name="count" value="<?php echo $val('count'); ?>" min="1" max="20"></div>
							<div class="form-group col-md-4"><label>Max. Verlust %</label><input class="form-control" type="number" name="max_loss_percent" value="<?php echo $val('max_loss_percent'); ?>" min="0" max="100"></div>
							<div class="form-group col-md-4"><label>Max. Latenz ms (0 = aus)</label><input class="form-control" type="number" name="max_latency_ms" value="<?php echo $val('max_latency_ms'); ?>" min="0"></div>
						</div>
						<!-- TCP / Port / Cert -->
						<div class="form-row" data-type="tcp port cert">
							<div class="form-group col-md-3"><label>Port</label><input class="form-control" type="number" name="port" value="<?php echo $val('port'); ?>" min="1" max="65535" placeholder="oder im Ziel"></div>
							<div class="form-group col-md-4" data-type="tcp"><label>Senden</label><input class="form-control text-monospace" name="send" value="<?php echo $val('send'); ?>" placeholder="EHLO x\r\n"></div>
							<div class="form-group col-md-5" data-type="tcp"><label>Erwartete Antwort (Anfang)</label><input class="form-control text-monospace" name="expect" value="<?php echo $f['type'] === 'tcp' ? $val('expect') : ''; ?>" placeholder="SSH-2.0"></div>
							<div class="form-group col-md-9" data-type="port"><label>Erwartung</label><select class="custom-select" name="expect_port" id="expect_port"><option value="open"<?php echo $f['type'] === 'port' && $f['expect'] !== 'closed' ? ' selected' : ''; ?>>Port offen = OK</option><option value="closed"<?php echo $f['type'] === 'port' && $f['expect'] === 'closed' ? ' selected' : ''; ?>>Port geschlossen = OK</option></select></div>
							<div class="form-group col-md-3" data-type="cert"><label>Mind. Restlaufzeit (Tage)</label><input class="form-control" type="number" name="min_days" value="<?php echo $val('min_days'); ?>" min="0" max="3650"></div>
							<div class="form-group col-md-6" data-type="cert"><label>Servername (SNI, optional)</label><input class="form-control" name="server_name" value="<?php echo $val('server_name'); ?>"></div>
							<div class="form-group col-12" data-type="tcp"><div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="tls" name="tls" value="1"<?php echo $chk('tls'); ?>><label class="custom-control-label" for="tls">TLS-Handshake nach dem Verbinden</label></div></div>
							<div class="form-group col-12" data-type="cert"><div class="custom-control custom-checkbox custom-control-inline"><input class="custom-control-input" type="checkbox" id="skip_chain" name="skip_chain" value="1"<?php echo $chk('skip_chain'); ?>><label class="custom-control-label" for="skip_chain">Kette nicht prüfen (private CA)</label></div><div class="custom-control custom-checkbox custom-control-inline"><input class="custom-control-input" type="checkbox" id="skip_hostname" name="skip_hostname" value="1"<?php echo $chk('skip_hostname'); ?>><label class="custom-control-label" for="skip_hostname">Hostname nicht prüfen</label></div></div>
						</div>
						<!-- WHOIS / RDAP -->
						<div class="form-row" data-type="whois">
							<div class="form-group col-12"><small class="form-text text-muted mt-0">Ziel: Domain (Ablauf, Registrar, Status, Nameserver), IP-Adresse oder Netz bzw. AS-Nummer (Netzname, Route/CIDR, Organisation, Land, Stadt). Abfrage höchstens stündlich.</small></div>
							<div class="form-group col-md-4"><label>Quelle</label><select class="custom-select" name="whois_source"><?php foreach (array('auto' => 'Automatisch (RDAP, sonst WHOIS)', 'rdap' => 'Nur RDAP', 'whois' => 'Nur WHOIS (Port 43)') as $wk => $wl) { echo '<option value="' . $wk . '"' . ((string)$f['whois_source'] === $wk ? ' selected' : '') . '>' . $wl . '</option>'; } ?></select></div>
							<div class="form-group col-md-4"><label>Domain: warnen ab Resttagen</label><input class="form-control" type="number" name="whois_min_days" value="<?php echo $val('whois_min_days'); ?>" min="0" max="3650"><small class="form-text text-muted">0 = erst bei Ablauf</small></div>
							<div class="form-group col-12"><label>Erwartete Angaben (optional, je Zeile eine)</label><textarea class="form-control text-monospace" name="whois_contains" rows="3" placeholder="nameserver: ns1.ipv64.net&#10;country: DE&#10;registrar: DENIC"><?php echo $val('whois_contains'); ?></textarea>
								<small class="form-text text-muted">„Text“ oder „Feld: Text“ (registrar, nameserver, status, org, country, city, netname, cidr, asn). Fehlt eine Angabe, gilt der Check als gestört.</small></div>
						</div>
						<!-- Docker -->
						<div class="form-row" data-type="docker">
							<div class="form-group col-12"><label>Docker-Host (leer = Standard der Node)</label><input class="form-control text-monospace" name="docker_host" value="<?php echo $val('docker_host'); ?>" placeholder="unix:///var/run/docker.sock"><input type="hidden" name="docker_system" value="<?php echo $val('docker_system'); ?>"><input type="hidden" name="system_custom" value="<?php echo $val('system_custom'); ?>"></div>
							<div class="col-12"><div class="alert alert-info small">Ziel = Name oder ID des Containers auf der Node. Docker-Checks laufen nur lokal auf der gewählten Node und sind nicht umhängbar.</div></div>
						</div>
						<!-- Push -->
						<div class="form-row" data-type="push">
							<div class="form-group col-md-6"><label>Erwarteter Abstand (s)</label><input class="form-control" type="number" name="period_seconds" value="<?php echo $val('period_seconds'); ?>" min="20"></div>
							<div class="form-group col-md-6"><label>Kulanz (s)</label><input class="form-control" type="number" name="grace_seconds" value="<?php echo $val('grace_seconds'); ?>" min="0"></div>
						</div>
						<div class="form-row">
							<div class="form-group col-md-6"><label>Gruppe</label><div class="input-group"><div class="input-group-prepend"><span class="input-group-text"><i class="fa-solid fa-layer-group text-primary"></i></span></div><input class="form-control" name="group_name" value="<?php echo $val('group_name'); ?>" maxlength="100" list="hc2-groups" placeholder="z. B. Heimnetz, Webseiten"></div>
								<datalist id="hc2-groups"><?php $gs = array(); foreach ($others as $o) { if ($o['group_name'] !== '' && !isset($gs[$o['group_name']])) { $gs[$o['group_name']] = 1; echo '<option value="' . hc2_h($o['group_name']) . '">'; } } ?></datalist>
								<small class="form-text text-muted">Checks mit gleicher Gruppe stehen in der Übersicht zusammen.</small></div>
							<div class="form-group col-md-6"><label>Tags (Komma oder Leerzeichen)</label><input class="form-control" name="tags" value="<?php echo $val('tags'); ?>"></div>
							<div class="form-group col-md-6"><label>Abhängig von</label><select class="custom-select" name="parent_token"><option value="">– keine –</option><?php foreach ($others as $o) { echo '<option value="' . hc2_h($o['token']) . '"' . $sel('parent_token', $o['token']) . '>' . hc2_h($o['name']) . '</option>'; } ?></select><small class="form-text text-muted">Ist der übergeordnete Check gestört, wird dieser nicht gemeldet.</small></div>
						</div>
						<div class="form-group"><label>Beschreibung</label><textarea class="form-control" name="description" rows="2"><?php echo $val('description'); ?></textarea></div>
					</div>
				</div>
				<div class="card shadow-sm mb-3">
					<div class="card-header p-2"><i class="fa-solid fa-clock"></i> Zeiten</div>
					<div class="card-body">
						<div class="form-row">
							<div class="form-group col-6 col-md-3"><label>Intervall (s)</label><input class="form-control" type="number" name="interval_sec" value="<?php echo $val('interval_sec'); ?>" min="5" max="86400"><small class="form-text text-muted">Lokal ab 5 s, online und hybrid ab 20 s.</small></div>
							<div class="form-group col-6 col-md-3"><label>Wiederholung bei Fehler (s)</label><input class="form-control" type="number" name="retry_interval_sec" value="<?php echo $val('retry_interval_sec'); ?>" min="5"></div>
							<div class="form-group col-6 col-md-3"><label>Verbindungs-Timeout (s)</label><input class="form-control" type="number" step="0.5" name="connect_timeout" value="<?php echo $val('connect_timeout'); ?>" min="0.5" max="60"></div>
							<div class="form-group col-6 col-md-3"><label>Gesamt-Timeout (s)</label><input class="form-control" type="number" step="0.5" name="total_timeout" value="<?php echo $val('total_timeout'); ?>" min="1" max="120"></div>
							<div class="form-group col-md-6" data-not-type="push"><label>IP-Version</label><select class="custom-select" name="ip_mode"><option value="auto"<?php echo $sel('ip_mode', 'auto'); ?>>Automatisch (IPv4 und IPv6, wenn vorhanden)</option><option value="ipv4"<?php echo $sel('ip_mode', 'ipv4'); ?>>Nur IPv4</option><option value="ipv6"<?php echo $sel('ip_mode', 'ipv6'); ?>>Nur IPv6</option><option value="both"<?php echo $sel('ip_mode', 'both'); ?>>Beide erzwingen (beide müssen OK sein)</option></select></div>
						</div>
					</div>
				</div>
			</div>
			<div class="col-lg-5">
				<div class="card shadow-sm mb-3">
					<div class="card-header p-2"><i class="fa-solid fa-location-dot"></i> Messstellen und Bewertung</div>
					<div class="card-body">
						<div class="form-group"><label>Ausführungsort</label>
							<select class="custom-select" name="execution" id="execution">
								<option value="online"<?php echo $sel('execution', 'online'); ?>>Online bei ipv64 (von außen)</option>
								<option value="local"<?php echo $sel('execution', 'local'); ?><?php echo $nodes ? '' : ' disabled'; ?>>Lokal auf Nodes (von innen)</option>
								<option value="both"<?php echo $sel('execution', 'both'); ?><?php echo $nodes ? '' : ' disabled'; ?>>Hybrid: Nodes und ipv64</option>
							</select>
							<?php if (!$nodes) { echo '<small class="form-text text-muted">Lokal/Hybrid erst nach <a href="/link.php">Verknüpfung einer Node</a>.</small>'; } elseif ($old) { echo '<small class="form-text text-muted">Beim Wechsel wird vor der Übernahme ein Testlauf gemacht.</small>'; } ?>
						</div>
						<div class="form-group" id="nodebox"><label><i class="fa-solid fa-server text-primary"></i> Messende Nodes</label>
							<?php foreach ($nodes as $id => $n) { $on = in_array($id, (array)$f['nodes'], true); ?>
							<div class="custom-control custom-checkbox"><input class="custom-control-input hc2-node" type="checkbox" id="nd_<?php echo hc2_h($id); ?>" name="nodes[]" value="<?php echo hc2_h($id); ?>"<?php echo $on ? ' checked' : ''; ?>><label class="custom-control-label" for="nd_<?php echo hc2_h($id); ?>"><?php echo hc2_h(hc2_node_label($nodes, $id)); ?><?php echo (int)$n['online'] ? ' <span class="badge badge-success">online</span>' : ' <span class="badge badge-secondary">offline</span>'; ?><?php echo ($old && $id === (string)$old['node_id']) ? ' <span class="badge badge-light" title="Bearbeiten in der Node, Benachrichtigung ohne Verbindung">Besitzer</span>' : ''; ?></label></div>
							<?php } ?>
							<small class="form-text text-muted" data-not-type="docker">Mehrere Nodes möglich, z. B. an verschiedenen Standorten oder mit Zugang über VPN. Jede gewählte Node misst selbst und erscheint als eigene Messstelle.</small>
							<small class="form-text text-warning" data-type="docker">Docker-Checks gehören zu der Node, auf der der Container läuft<?php echo ($old && $old['type'] === 'docker') ? ', und sind nicht umhängbar' : ''; ?>.</small>
						</div>
						<div class="form-group" id="locbox"><label>Standorte</label>
							<?php $i = 0; foreach ($locs as $code => $name) { $i++; $allowed = $i <= $acc['hc_locations']; ?>
							<div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="loc_<?php echo $code; ?>" name="locations[]" value="<?php echo $code; ?>"<?php echo in_array($code, (array)$f['locations'], true) && $allowed ? ' checked' : ''; echo $allowed ? '' : ' disabled'; ?>><label class="custom-control-label" for="loc_<?php echo $code; ?>"><?php echo hc2_h($name); ?><?php echo $allowed ? '' : ' <span class="badge badge-secondary">ab Supporter</span>'; ?></label></div>
							<?php } ?>
							<small class="form-text text-muted">Jeder Standort zählt als Messstelle gegen dein Online-Limit (<?php echo hc2_online_used($uid, $old['token'] ?? ''); ?> von <?php echo $acc['healthcheck_limit'] ?: '∞'; ?> belegt).</small>
							<?php if ($acc['checks_per_day'] > 0) { ?><small class="form-text" id="hc2-proj" data-other="<?php echo hc2_daily_projection($uid, $old['token'] ?? ''); ?>" data-today="<?php echo hc2_checks_today($uid); ?>" data-limit="<?php echo $acc['checks_per_day']; ?>" data-acclocs="<?php echo $acc['hc_locations']; ?>"></small><?php } ?>
						</div>
						<div class="form-group" id="policybox"><label>Gestört, wenn …</label>
							<select class="custom-select" name="policy"><option value="all"<?php echo $sel('policy', 'all'); ?>>alle Messstellen gestört melden (sonst „teilweise gestört“)</option><option value="any"<?php echo $sel('policy', 'any'); ?>>eine Messstelle gestört meldet</option><option value="majority"<?php echo $sel('policy', 'majority'); ?>>die Mehrheit gestört meldet</option></select>
							<div class="custom-control custom-checkbox mt-2"><input class="custom-control-input" type="checkbox" id="notify_degraded" name="notify_degraded" value="1"<?php echo $chk('notify_degraded'); ?>><label class="custom-control-label" for="notify_degraded">auch bei „teilweise gestört“ benachrichtigen</label></div>
						</div>
					</div>
				</div>
				<div class="card shadow-sm mb-3">
					<div class="card-header p-2"><i class="fa-solid fa-bell"></i> Alarmierung</div>
					<div class="card-body">
						<div class="form-row">
							<div class="form-group col-6"><label>Wiederholungen vor Alarm</label><input class="form-control" type="number" name="retries" value="<?php echo $val('retries'); ?>" min="0" max="10"><small class="form-text text-muted">zusätzliche Versuche im Fehlerfall</small></div>
							<div class="form-group col-6"><label>Stabilisierung</label><input class="form-control" type="number" name="stabilize" value="<?php echo $val('stabilize'); ?>" min="1" max="20"><small class="form-text text-muted">Messungen bis zum Zustandswechsel</small></div>
						</div>
						<div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="notify_down" name="notify_down" value="1"<?php echo $chk('notify_down'); ?>><label class="custom-control-label" for="notify_down">bei Störung benachrichtigen</label></div>
						<div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="notify_up" name="notify_up" value="1"<?php echo $chk('notify_up'); ?>><label class="custom-control-label" for="notify_up">bei Entwarnung benachrichtigen</label></div>
						<div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="critical" name="critical" value="1"<?php echo $chk('critical'); ?>><label class="custom-control-label" for="critical">kritisch (Ruhezeiten ignorieren)</label></div>
						<div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="invert" name="invert" value="1"<?php echo $chk('invert'); ?>><label class="custom-control-label" for="invert">Ergebnis umkehren (OK = nicht erreichbar)</label></div>
						<div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="paused" name="paused" value="1"<?php echo $chk('paused'); ?>><label class="custom-control-label" for="paused">pausiert</label></div>
						<div class="form-group mt-2"><label>Erinnerung bei anhaltender Störung (min, 0 = aus)</label><input class="form-control" type="number" name="repeat_minutes" value="<?php echo $val('repeat_minutes'); ?>" min="0" max="10080"></div>
						<div class="form-group"><label>Kanäle</label>
							<?php if (!$channels) { echo '<div class="small text-muted">Noch keine Kanäle. <a href="/notifications.php">Kanal anlegen</a>. Ohne Auswahl gelten die Standardkanäle.</div>'; } ?>
							<?php foreach ($channels as $ch) { ?><div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="ch_<?php echo (int)$ch['id']; ?>" name="channels[]" value="<?php echo (int)$ch['id']; ?>"<?php echo in_array((int)$ch['id'], array_map('intval', (array)$f['channels']), true) ? ' checked' : ''; ?>><label class="custom-control-label" for="ch_<?php echo (int)$ch['id']; ?>"><?php echo hc2_h($ch['name']); ?> <small class="text-muted"><?php echo hc2_h(hc2_channel_types()[$ch['type']]['label'] ?? $ch['type']); echo (int)$ch['is_default'] ? ' · Standard' : ''; echo $ch['node_id'] ? ' · Node' : ''; ?></small></label></div><?php } ?>
							<small class="form-text text-muted">Ohne Auswahl: alle Standardkanäle.</small>
						</div>
					</div>
				</div>
				<button class="btn btn-primary" type="submit"><i class="fa-solid fa-floppy-disk"></i> Speichern</button>
				<a class="btn btn-outline-secondary" href="<?php echo $old ? HC2_BASE . '/check.php?token=' . hc2_h($old['token']) : HC2_BASE . '/'; ?>">Abbrechen</a>
			</div>
		</div>
	</form>
</div>
<?php include("../footer.php"); ?>
<script>
(function(){
	var hints = {http:'Vollständige URL, z. B. https://example.com/status', keyword:'URL, deren Antwort das Schlüsselwort enthalten (oder nicht enthalten) soll', json:'URL, die JSON liefert, z. B. https://example.com/api/health', dns:'Abzufragender Name, z. B. home.example.org (bei PTR auch eine IP-Adresse)', icmp:'Hostname oder IP-Adresse', tcp:'Hostname oder IP-Adresse, ohne Port (Port unten eintragen)', port:'Hostname oder IP-Adresse, ohne Port (Port unten eintragen)', cert:'Hostname oder IP-Adresse, ohne Port (Port unten eintragen)', push:''};
	function sync(){
		var t = $('#type').val(), ex = $('#execution').val();
		$('[data-type]').each(function(){ var ok = $(this).data('type').split(' ').indexOf(t) >= 0; $(this).toggle(ok); });
		$('[data-not-type]').each(function(){ $(this).toggle($(this).data('not-type').split(' ').indexOf(t) < 0); });
		$('#target_hint').text(hints[t] || '');
		$('#dns_server_box').toggle($('#dns_resolver').val() === 'server');
		$('#nodebox').toggle(ex !== 'online'); $('#locbox').toggle(ex !== 'local'); $('#policybox').toggle(ex === 'both');
	}
	$('#type, #execution, #dns_resolver').on('change', sync); sync();
	// Tageskontingent: Verbrauch dieses Checks und des Accounts pro Tag hochrechnen (wie der hub zaehlt, ohne Pushes)
	var $p = $('#hc2-proj');
	function proj(){
		if (!$p.length) { return; }
		var num = function(k){ return parseInt($p.data(k), 10) || 0; }, fmt = function(n){ return n.toLocaleString('de-DE'); };
		var sec = parseInt($('[name=interval_sec]').val(), 10) || 0, locs = $('[name="locations[]"]:checked').length || 2;
		if (num('acclocs') === 1 && locs > 1) { locs = 1; }
		var cost = ($('#execution').val() !== 'local' && $('#type').val() !== 'push' && !$('#paused').prop('checked') && sec > 0) ? Math.floor(86400 / sec) * locs : 0;
		var total = num('other') + cost, limit = num('limit'), over = total > limit;
		var t = (cost > 0 ? 'Dieser Check: ' + fmt(cost) + ' Online-Messungen pro Tag (' + sec + ' s × ' + locs + ' Standort(e)). ' : 'Dieser Check verbraucht kein Tageskontingent (lokal, pausiert oder Push). ')
			+ 'Account gesamt voraussichtlich ' + fmt(total) + ' von ' + fmt(limit) + ' pro Tag (ohne Pushes).';
		if (over) {
			var left = limit - num('today'), msg = ' Das reicht nicht für den ganzen Tag: Ist das Kontingent erreicht, pausieren die Online-Checks bis Mitternacht.';
			if (left > 0) { var at = new Date(Date.now() + left / (total / 1440) * 60000); if (at.toDateString() === new Date().toDateString()) { msg = ' Bei diesem Stand ist das Kontingent heute gegen ' + at.toLocaleTimeString('de-DE', {hour: '2-digit', minute: '2-digit'}) + ' Uhr erreicht, danach pausieren die Online-Checks bis Mitternacht.'; } }
			t += msg;
		}
		$p.text(t).toggleClass('text-warning font-weight-bold', over).toggleClass('text-muted', !over);
	}
	$('form').on('change input', proj); proj();
	// Docker: genau eine Node; ein bestehender Docker-Check bleibt bei seiner Node
	var lockDocker = <?php echo ($old && $old['type'] === 'docker') ? 'true' : 'false'; ?>;
	function single(){ return $('#type').val() === 'docker'; }
	$('.hc2-node').on('change', function(){ if (single() && this.checked) { $('.hc2-node').not(this).prop('checked', false); } });
	function lockNodes(){ $('.hc2-node').prop('disabled', lockDocker && $('#type').val() === 'docker'); if (single() && $('.hc2-node:checked').length > 1) { $('.hc2-node:checked').slice(1).prop('checked', false); } }
	$('#type').on('change', lockNodes); lockNodes();
	$('#hcform').on('submit', function(){ $('.hc2-node:disabled:checked').each(function(){ $('<input type="hidden" name="nodes[]">').val(this.value).appendTo('#hcform'); }); });
	// Port-Erwartung in das gemeinsame Feld "expect" uebernehmen
	$('#hcform').on('submit', function(){ if ($('#type').val() === 'port') { $('<input type="hidden" name="expect">').val($('#expect_port').val()).appendTo(this); } });
})();
</script>
